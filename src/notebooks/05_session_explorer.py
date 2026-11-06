# Databricks notebook source
# MAGIC %md
# MAGIC # 05 · Session explorer
# MAGIC
# MAGIC Analyst-facing queries over the flattened tables:
# MAGIC
# MAGIC 1. Adoption: turns and active users by product and channel
# MAGIC 2. Flagged sessions, newest first
# MAGIC 3. Walk through one session step by step
# MAGIC 4. Detection drill-down for that session
# MAGIC 5. Approval and question flows (Genie One links a continuation turn back to the request)
# MAGIC 6. Tool usage and failure rates
# MAGIC 7. Thumbs-down feedback joined to the turn
# MAGIC
# MAGIC Pick a `conversation_id` in the widget, or leave it blank to use the most recently flagged
# MAGIC session.

# COMMAND ----------

dbutils.widgets.text("catalog", "unity_gateway", "Catalog")
dbutils.widgets.text("schema", "genie_tracing", "Schema")
dbutils.widgets.text("conversation_id", "", "Conversation id (blank = latest flagged)")
dbutils.widgets.text("days", "30", "Lookback days")

CATALOG = dbutils.widgets.get("catalog")
SCHEMA = dbutils.widgets.get("schema")
DAYS = int(dbutils.widgets.get("days"))
FQ = f"`{CATALOG}`.`{SCHEMA}`"

conversation_id = dbutils.widgets.get("conversation_id").strip()
if not conversation_id:
    row = spark.sql(
        f"""
        SELECT conversation_id FROM {FQ}.genie_sessions
        ORDER BY is_flagged DESC, coalesce(flags.last_flagged_at, session_end) DESC
        LIMIT 1
        """
    ).first()
    conversation_id = row.conversation_id if row else None
print(f"Selected conversation: {conversation_id}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 1 · Adoption

# COMMAND ----------

display(
    spark.sql(
        f"""
        SELECT date, product, coalesce(context.channel, 'unknown') AS channel,
               COUNT(*) AS turns, COUNT(DISTINCT requester) AS active_users, COUNT(DISTINCT conversation_id) AS sessions,
               ROUND(AVG(duration_ms) / 1000, 1) AS avg_turn_seconds, COUNT_IF(is_error) AS errors
        FROM {FQ}.genie_turns
        WHERE started_at >= current_timestamp() - INTERVAL {DAYS} DAYS
        GROUP BY ALL ORDER BY date DESC, product, channel
        """
    )
)

# COMMAND ----------

# MAGIC %md
# MAGIC ## 2 · Flagged sessions

# COMMAND ----------

display(
    spark.sql(
        f"""
        SELECT session_start, product, requester, workspace_id, context.channel, conversation_id,
               activity.turn_count, activity.tool_call_count, activity.rejected_tool_call_count, activity.approval_request_count,
               ROUND(risk_score, 2) AS risk_score, flags.has_pii, flags.has_prompt_injection, flags.has_guardrail_signal,
               flags.flag_detectors, flags.flag_labels, substr(context.first_prompt, 1, 160) AS first_prompt
        FROM {FQ}.genie_sessions
        WHERE is_flagged AND session_start >= current_timestamp() - INTERVAL {DAYS} DAYS
        ORDER BY risk_score DESC, flags.last_flagged_at DESC
        """
    )
)

# COMMAND ----------

# MAGIC %md
# MAGIC ## 3 · Walk through a session
# MAGIC
# MAGIC One row per step: the user's turn, then every tool call, approval, question and model call
# MAGIC inside it, in order. `flags` shows which detectors fired on that step.

# COMMAND ----------

display(
    spark.sql(
        f"""
        SELECT step_number, turn_number, started_at, duration_ms, event_type, event_name, tool_name,
               substr(input_text, 1, 400)  AS input_text,
               substr(output_text, 1, 400) AS output_text,
               outcome.outcome, outcome.status_code, outcome.is_rejected_or_refused, detections.flags, span.previous_event, span.next_event
        FROM {FQ}.genie_session_timeline
        WHERE conversation_id = '{conversation_id}'
        ORDER BY step_number
        """
    )
)

# COMMAND ----------

# MAGIC %md
# MAGIC ## 4 · Detections in this session

# COMMAND ----------

display(
    spark.sql(
        f"""
        SELECT span_time, detected_at, detector, flagged, ROUND(score, 3) AS score, label, span.field, details, span.span_id, span.trace_id
        FROM {FQ}.genie_detections
        WHERE conversation_id = '{conversation_id}'
        ORDER BY flagged DESC, span_time, detector
        """
    )
)

# COMMAND ----------

# MAGIC %md
# MAGIC ## 5 · Approval and question flows
# MAGIC
# MAGIC In Genie One, the turn that continues after a user approves or answers is a *separate*
# MAGIC trace whose root span links back to the `request_approval` / `request_answers` span. In
# MAGIC Genie Code the question is an `askUserQuestions` tool call whose result says `answered` or
# MAGIC `declined`.

# COMMAND ----------

display(
    spark.sql(
        f"""
        WITH requests AS (
          SELECT trace_id, span_id, conversation_id, product, requester, started_at, span_type, tool_name,
                 substr(tool_arguments, 1, 300) AS request, substr(tool_result, 1, 200) AS result
          FROM {FQ}.genie_tool_calls
          WHERE span_type IN ('approval_request', 'user_question')
             OR tool_name IN ('askUserQuestions', 'ask_user_questions')
        ),
        continuations AS (
          SELECT t.trace_id AS continuation_trace_id, t.started_at AS continued_at, l AS linked_span_id,
                 substr(t.prompt, 1, 200) AS continuation_prompt
          FROM {FQ}.genie_turns t
          LATERAL VIEW explode(t.links.linked_span_ids) AS l
        )
        SELECT r.started_at, r.product, r.requester, r.conversation_id, r.span_type, r.tool_name, r.request, r.result,
               c.continued_at, c.continuation_prompt
        FROM requests r
        LEFT JOIN continuations c ON c.linked_span_id = r.span_id
        WHERE r.started_at >= current_timestamp() - INTERVAL {DAYS} DAYS
        ORDER BY r.started_at DESC
        """
    )
)

# COMMAND ----------

# MAGIC %md
# MAGIC ## 6 · Tool usage and failure rates

# COMMAND ----------

display(
    spark.sql(
        f"""
        SELECT product, tool_name, COUNT(*) AS calls,
               COUNT_IF(is_error) AS failed, COUNT_IF(is_rejected_or_denied) AS rejected_or_denied,
               ROUND(100 * COUNT_IF(is_error) / COUNT(*), 1) AS failure_pct,
               ROUND(AVG(duration_ms), 0) AS avg_ms
        FROM {FQ}.genie_tool_calls
        WHERE span_type = 'tool_call' AND started_at >= current_timestamp() - INTERVAL {DAYS} DAYS
        GROUP BY ALL ORDER BY calls DESC
        """
    )
)

# COMMAND ----------

# MAGIC %md
# MAGIC ## 7 · Sessions with thumbs-down feedback

# COMMAND ----------

display(
    spark.sql(
        f"""
        SELECT session_start, product, requester, conversation_id, feedback.thumbs_down_count, feedback.thumbs_up_count,
               is_flagged, ROUND(risk_score, 2) AS risk_score, substr(context.first_prompt, 1, 160) AS first_prompt
        FROM {FQ}.genie_sessions
        WHERE feedback.thumbs_down_count > 0
        ORDER BY session_start DESC
        """
    )
)
