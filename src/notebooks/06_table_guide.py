# Databricks notebook source
# MAGIC %md
# MAGIC # 🧭 Genie trace monitoring: table guide
# MAGIC
# MAGIC A guided tour of the `genie_tracing` schema in the order you would actually use it when a
# MAGIC question lands on your desk ("who did what in Genie, and should I worry?"). Each section
# MAGIC explains one table, what to know about it, and runs a query you can adapt.
# MAGIC
# MAGIC | # | Table | Start here when you want to... |
# MAGIC |---|---|---|
# MAGIC | 1 | `genie_sessions` | See which conversations are flagged, by whom, and how risky |
# MAGIC | 2 | `genie_session_timeline` | Walk one conversation step by step |
# MAGIC | 3 | `genie_turns` | Read the exact prompt and response of a turn |
# MAGIC | 4 | `genie_tool_calls` | See what Genie *did*: SQL run, assets edited, approvals asked |
# MAGIC | 5 | `genie_detections` | Inspect the evidence behind a flag |
# MAGIC | 6 | Column tags | Check what governed `class.*` tags the PII scan applied |
# MAGIC | A | `unity_gateway_otel_spans` | Go back to the raw OpenTelemetry source |
# MAGIC | B | `unity_gateway_otel_annotations` | Join thumbs-up / thumbs-down feedback |
# MAGIC
# MAGIC > ⚠️ **These tables contain full prompts, responses, SQL and tool results.** Anyone with
# MAGIC > `SELECT` can read every Genie conversation across every workspace on the metastore. Keep
# MAGIC > access to the security team and use the scoped views in `src/sql/access_control.sql` for
# MAGIC > anyone else.

# COMMAND ----------

# MAGIC %md
# MAGIC ## How the tables fit together
# MAGIC
# MAGIC ![Genie trace monitoring: how the tables fit together](./images/table_guide_architecture.png)
# MAGIC
# MAGIC <sub>Source: <code>docs/table_guide_architecture.svg</code>. After editing it, run <code>docs/render_diagram.sh</code> and redeploy.</sub>
# MAGIC
# MAGIC * **Grain**: a *session* is one conversation (`conversation_id`). A *turn* is one user message
# MAGIC   and its answer (`trace_id`). A *tool call* is one action inside a turn (`span_id`).
# MAGIC * **Refresh**: `genie_turns`, `genie_tool_calls` and `genie_sessions` are materialized views
# MAGIC   refreshed by the job. `genie_detections` is a Delta table the detectors MERGE into.
# MAGIC   `genie_session_timeline` is a plain view, always current.
# MAGIC * **Lag**: trace export is best-effort and the job is hourly, so expect up to an hour or so
# MAGIC   between a Genie turn and its appearance here.

# COMMAND ----------

# MAGIC %md
# MAGIC ## Parameters

# COMMAND ----------

dbutils.widgets.text("catalog", "unity_gateway", "Catalog")
dbutils.widgets.text("schema", "genie_tracing", "Schema")
dbutils.widgets.text("conversation_id", "", "Conversation id (blank = highest-risk recent session)")
dbutils.widgets.text("days", "30", "Lookback days")
dbutils.widgets.text("source_table", "unity_gateway.unified_tracing.unity_gateway_otel_spans", "Raw spans table")
dbutils.widgets.text("annotations_table", "unity_gateway.unified_tracing.unity_gateway_otel_annotations", "Raw annotations table")

CATALOG = dbutils.widgets.get("catalog")
SCHEMA = dbutils.widgets.get("schema")
DAYS = int(dbutils.widgets.get("days"))
SOURCE_TABLE = dbutils.widgets.get("source_table")
ANNOTATIONS_TABLE = dbutils.widgets.get("annotations_table")
FQ = f"`{CATALOG}`.`{SCHEMA}`"

conversation_id = dbutils.widgets.get("conversation_id").strip()
if not conversation_id:
    row = spark.sql(
        f"""
        SELECT conversation_id FROM {FQ}.genie_sessions
        WHERE session_start >= current_timestamp() - INTERVAL {DAYS} DAYS
        ORDER BY risk_score DESC, session_end DESC LIMIT 1
        """
    ).first()
    conversation_id = row.conversation_id if row else ""
print(f"Using conversation_id = {conversation_id or '(none found)'}")


def q(sql: str):
    """Run a query against the guide schema and display it. Binds :conversation_id if used."""
    args = {"conversation_id": conversation_id} if ":conversation_id" in sql else None
    display(spark.sql(sql, args=args))

# COMMAND ----------

# MAGIC %md
# MAGIC ---
# MAGIC ## 1 · `genie_sessions`: start here
# MAGIC
# MAGIC **One row per conversation.** The triage entry point: when, who, which product, and whether any
# MAGIC detector flagged it. Eleven flat columns answer the first questions; the detail sits in five
# MAGIC structs so the table stays narrow. Reach into a struct with dot notation: `flags.has_pii`,
# MAGIC `activity.tools_used`, `context.first_prompt`.
# MAGIC
# MAGIC | Column | Type | What it holds |
# MAGIC |---|---|---|
# MAGIC | `session_date`, `session_start`, `session_end`, `session_minutes` | flat | When. Clustered on `session_date`. |
# MAGIC | `workspace_id`, `requester`, `principal_id` | flat | Who and where. |
# MAGIC | `conversation_id`, `product` | flat | The key and the product (`Genie One` / `Genie Code`). |
# MAGIC | `is_flagged`, `risk_score` | flat | The two columns alerts and dashboards filter on. `risk_score` ∈ [0, 1]. |
# MAGIC | 📊 `activity` | struct | `turn_count`, `error_turn_count`, `refusal_turn_count`, `scheduled_turn_count`, `total_turn_duration_ms`, `tool_call_count`, `failed_tool_call_count`, `rejected_tool_call_count`, `approval_request_count`, `user_question_count`, `model_call_count`, `tools_used` |
# MAGIC | 🚩 `flags` | struct | `has_pii`, `has_prompt_injection`, `has_guardrail_signal`, `flag_count`, `flagged_turn_count`, `flag_detectors`, `flag_labels`, `first_flagged_at`, `last_flagged_at` |
# MAGIC | 🎚️ `risk` | struct | `max_pii_score`, `max_prompt_injection_score`, `max_guardrail_score`, `rejected_tool_call_bonus`. `risk_score` = min(1, 0.4·PII + 0.8·injection + guardrail + bonus). Weights live in `genie_sessions.sql`. |
# MAGIC | 👍 `feedback` | struct | `thumbs_up_count`, `thumbs_down_count` from the annotations table |
# MAGIC | 📝 `context` | struct | `channel` (Genie One: `webapp`, `slack`, `teams`, `databricks_cli`, `public_api`, ...), `agent_name`, `scheduled_task_id`, `first_prompt`, `last_response`, `last_turn_outcome`, `trace_ids` |
# MAGIC
# MAGIC **Things to know**
# MAGIC * `conversation_id` is the Genie One chat thread or the Genie Code notebook / chat. Turns with
# MAGIC   no conversation id (rare) fall back to their `trace_id`.
# MAGIC * `flags.has_guardrail_signal` is *inferred* from outcomes and response text, because classifier
# MAGIC   verdicts are not exported in the trace. Treat it as "worth a look", not proof.
# MAGIC * The SQL alerts fire off `flags.last_flagged_at` and `risk_score`, so this is the table to watch.
# MAGIC * `SELECT activity.*` expands a struct back into columns when you want the wide shape.

# COMMAND ----------

q(f"""
SELECT session_start, session_minutes, workspace_id, requester, product, conversation_id,
       is_flagged, ROUND(risk_score, 2) AS risk_score,
       flags.has_pii, flags.has_prompt_injection, flags.has_guardrail_signal, flags.flag_labels,
       activity.turn_count, activity.tool_call_count, activity.approval_request_count, activity.rejected_tool_call_count,
       feedback.thumbs_down_count,
       context.channel, substr(context.first_prompt, 1, 120) AS first_prompt
FROM {FQ}.genie_sessions
WHERE session_start >= current_timestamp() - INTERVAL {DAYS} DAYS
ORDER BY is_flagged DESC, risk_score DESC, session_start DESC
""")

# COMMAND ----------

# MAGIC %md
# MAGIC ### Who is using Genie, and how much is being flagged?

# COMMAND ----------

q(f"""
SELECT session_date, product,
       COUNT(*)                                   AS sessions,
       COUNT(DISTINCT requester)                  AS users,
       SUM(activity.turn_count)                   AS turns,
       COUNT_IF(is_flagged)                       AS flagged_sessions,
       COUNT_IF(flags.has_pii)                    AS pii_sessions,
       COUNT_IF(flags.has_prompt_injection)       AS injection_sessions,
       COUNT_IF(flags.has_guardrail_signal)       AS guardrail_sessions,
       ROUND(AVG(risk_score), 2)                  AS avg_risk
FROM {FQ}.genie_sessions
WHERE session_start >= current_timestamp() - INTERVAL {DAYS} DAYS
GROUP BY ALL ORDER BY session_date DESC, product
""")

# COMMAND ----------

# MAGIC %md
# MAGIC ---
# MAGIC ## 2 · `genie_session_timeline`: walk one conversation
# MAGIC
# MAGIC **One row per step** in a conversation, in order: the user's turn, then every tool call,
# MAGIC approval request, user question and model call inside it. This is how you replay what
# MAGIC happened without reassembling spans by hand.
# MAGIC
# MAGIC | Column | Type | Meaning |
# MAGIC |---|---|---|
# MAGIC | `started_at`, `ended_at`, `duration_ms` | flat | When |
# MAGIC | `workspace_id`, `requester` | flat | Who and where |
# MAGIC | `conversation_id`, `turn_number`, `step_number`, `product` | flat | Position. Sort by `step_number`. |
# MAGIC | `event_type`, `event_name`, `tool_name` | flat | `turn`, `tool_call`, `approval_request`, `user_question`, `model_call`, `other`; raw span name; normalised tool name (`execute_sql_query`, `editAsset`, ...) |
# MAGIC | `input_text`, `output_text` | flat | Prompt / response for turns, arguments / result for tool calls, output for model calls. Kept flat: may carry PII. |
# MAGIC | `is_flagged` | flat | Any detection on **this** step |
# MAGIC | `outcome` | struct | `status_code`, `outcome`, `error_code`, `is_error`, `is_rejected_or_refused` |
# MAGIC | `detections` | struct | `flags` (as `detector:label`), `max_flag_score` |
# MAGIC | `span` | struct | `trace_id`, `span_id`, `parent_span_id`, `channel`, `previous_event`, `next_event`. The last two are handy for spotting "approval asked → user declined → model carried on". |
# MAGIC
# MAGIC **Things to know**
# MAGIC * It is a view over `genie_turns`, `genie_tool_calls` and `genie_detections`, so it always
# MAGIC   reflects the latest refresh of those.
# MAGIC * **Genie Code exports only a subset of its spans.** Asset edits, runs and user questions
# MAGIC   appear; SQL execution and blocked actions do not. If a turn says "I dropped the table" with
# MAGIC   no tool step beneath it, that is expected, not missing data.
# MAGIC * Always filter on `conversation_id`; the view is not meant to be scanned whole.

# COMMAND ----------

q(f"""
SELECT step_number, turn_number, started_at, duration_ms, event_type, event_name, tool_name,
       substr(input_text, 1, 300)  AS input_text,
       substr(output_text, 1, 300) AS output_text,
       outcome.outcome, outcome.is_error, outcome.is_rejected_or_refused, detections.flags, span.previous_event, span.next_event
FROM {FQ}.genie_session_timeline
WHERE conversation_id = :conversation_id
ORDER BY step_number
""")

# COMMAND ----------

# MAGIC %md
# MAGIC ---
# MAGIC ## 3 · `genie_turns`: the prompt and the answer
# MAGIC
# MAGIC **One row per turn** (the root span of a trace). Prompt and response are lifted out of the
# MAGIC nested `gen_ai.input.messages` / `gen_ai.output.messages` JSON into plain `STRING` columns so
# MAGIC detections, `ai_classify`, `ai_query` and full-text search all work directly.
# MAGIC
# MAGIC | Column | Type | What it holds |
# MAGIC |---|---|---|
# MAGIC | `started_at`, `ended_at`, `duration_ms`, `date` | flat | When. `date` is a clustering key. |
# MAGIC | `workspace_id`, `requester`, `principal_id` | flat | Who and where |
# MAGIC | `conversation_id`, `trace_id`, `span_id`, `product` | flat | Keys. `trace_id` = the turn; `span_id` is its root span, which detections join on. |
# MAGIC | 💬 `prompt`, `response`, `citations`, `input_messages_raw`, `output_messages_raw` | flat | What was said. Kept flat because they are scanned and may carry PII row to row. |
# MAGIC | `is_error`, `is_refusal` | flat | Headline outcome |
# MAGIC | ✅ `outcome` | struct | `status_code`, `status_message`, `genie_status` (Genie One), `run_outcome` (Genie Code: `success`, `refusal`, `error`, `cancelled`, `aborted`, `handoff`), `error_code` |
# MAGIC | 🪪 `context` | struct | `channel`, `surface`, `agent_name`, `agent_id`, `scheduled_task_id`, `actor_resource`, `response_id`, `account_id`, `metastore_id` |
# MAGIC | 🔑 `span` | struct | `record_id`, `time`, `service_name`, `span_name`, `span_kind` |
# MAGIC | ✂️ `completeness` | struct | `payload_truncated`, `truncated_fields`, `content_omitted`, `expected_span_count`, `dropped_span_count`, `trace_schema_version` |
# MAGIC | 🔗 `links` | struct | `linked_trace_ids`, `linked_span_ids`: Genie One continuation turns point back to the approval / question span they answer |
# MAGIC | 🧳 `attributes` | variant | The original attributes, nothing is lost |
# MAGIC
# MAGIC **Things to know**
# MAGIC * `citations` (Genie One) lists the tables and assets Genie used to answer. Good for "which
# MAGIC   datasets are people asking about".
# MAGIC * `context.scheduled_task_id` is set when a Genie One scheduled task, not a human, triggered the turn.
# MAGIC * Genie One attributes are capped at 180 KiB; long tool-heavy turns set `completeness.payload_truncated`.
# MAGIC * To read a dotted attribute not surfaced here: `attributes:['gen_ai.agent.id']::string`.
# MAGIC   Backticks return NULL; use the bracket form.

# COMMAND ----------

q(f"""
SELECT started_at, duration_ms, product, requester, context.channel, is_error, is_refusal,
       outcome.run_outcome, outcome.genie_status, outcome.status_code,
       prompt, response, citations, completeness.payload_truncated, trace_id
FROM {FQ}.genie_turns
WHERE conversation_id = :conversation_id
ORDER BY started_at
""")

# COMMAND ----------

# MAGIC %md
# MAGIC ### Full-text search across every prompt (last N days)
# MAGIC Change the pattern. This is the "did anyone ask Genie about X" query.

# COMMAND ----------

q(f"""
SELECT started_at, product, requester, conversation_id, substr(prompt, 1, 200) AS prompt
FROM {FQ}.genie_turns
WHERE started_at >= current_timestamp() - INTERVAL {DAYS} DAYS
  AND prompt ILIKE '%drop%'
ORDER BY started_at DESC
LIMIT 50
""")

# COMMAND ----------

# MAGIC %md
# MAGIC ---
# MAGIC ## 4 · `genie_tool_calls`: what Genie actually did
# MAGIC
# MAGIC **One row per non-root span**: tool executions, approval requests, user questions and
# MAGIC (Genie Code only) model calls. This is the audit trail of *actions*.
# MAGIC
# MAGIC | Column | Type | Meaning |
# MAGIC |---|---|---|
# MAGIC | `started_at`, `ended_at`, `duration_ms`, `date` | flat | When |
# MAGIC | `workspace_id`, `requester`, `principal_id` | flat | Who and where |
# MAGIC | `conversation_id`, `trace_id`, `span_id`, `product` | flat | Keys; `conversation_id` is inherited from the parent turn |
# MAGIC | `span_type` | flat | `tool_call`, `approval_request`, `user_question`, `model_call`, `other` |
# MAGIC | `tool_name` | flat | Normalised from the attribute or span name: Genie One `execute_sql_query`, `create_dashboard`, `request_uc_asset_access`, ...; Genie Code `editAsset`, `runAsset`, `createAsset`, `askUserQuestions`, `readSkillFile`, ... |
# MAGIC | `tool_arguments`, `tool_result`, `response_text`, `output_messages_raw` | flat | What went in and came out. For `execute_sql_query`, `tool_arguments` holds the SQL and `tool_result` a row count plus a markdown table. `response_text` is model-call output. Kept flat: scanned, may carry PII. |
# MAGIC | `is_error`, `is_rejected_or_denied` | flat | Headline outcome |
# MAGIC | `outcome` | struct | `tool_outcome` (Genie Code: `SUCCESS`, `USER_REJECTED`, `PERMISSION_DENIED`, `BAD_ARGUMENTS`, `TIMEOUT`, `TRIGGERED_OPERATION_FAILED`, ...), `status_code`, `status_message` |
# MAGIC | `span` | struct | `parent_span_id`, `record_id`, `time`, `service_name`, `span_name`, `operation`, `mlflow_span_type`, `tool_call_id`, `channel` |
# MAGIC | `completeness` | struct | `payload_truncated`, `truncated_fields` |
# MAGIC | `attributes` | variant | The original attributes |
# MAGIC
# MAGIC **Things to know**
# MAGIC * **Indirect prompt injection and PII in query results live in `tool_result`.** That is why the
# MAGIC   detectors scan it, not just the prompt.
# MAGIC * Genie Code user questions are tool calls named `askUserQuestions`; the result JSON says
# MAGIC   `"status":"answered"` or `"declined"`. Genie One emits proper `approval_request` /
# MAGIC   `user_question` spans instead, and the follow-up turn links back to them.
# MAGIC * Not every action is here (see section 2). Pair with `genie_turns.response` for the full story.

# COMMAND ----------

q(f"""
SELECT started_at, span_type, tool_name, outcome.tool_outcome, is_error, is_rejected_or_denied, duration_ms,
       substr(tool_arguments, 1, 400) AS tool_arguments,
       substr(tool_result, 1, 400)    AS tool_result,
       trace_id, span_id
FROM {FQ}.genie_tool_calls
WHERE conversation_id = :conversation_id
  AND span_type <> 'model_call'
ORDER BY started_at
""")

# COMMAND ----------

# MAGIC %md
# MAGIC ### Which tools are used, and how often they fail or get rejected

# COMMAND ----------

q(f"""
SELECT product, tool_name,
       COUNT(*)                                            AS calls,
       COUNT(DISTINCT requester)                           AS users,
       COUNT_IF(is_error)                                  AS failed,
       COUNT_IF(is_rejected_or_denied)                     AS rejected_or_denied,
       ROUND(100 * COUNT_IF(is_error) / COUNT(*), 1)       AS failure_pct,
       ROUND(AVG(duration_ms))                             AS avg_ms
FROM {FQ}.genie_tool_calls
WHERE span_type = 'tool_call' AND started_at >= current_timestamp() - INTERVAL {DAYS} DAYS
GROUP BY ALL ORDER BY calls DESC
""")

# COMMAND ----------

# MAGIC %md
# MAGIC ---
# MAGIC ## 5 · `genie_detections`: the evidence behind a flag
# MAGIC
# MAGIC **One row per (span, detector, field).** Every detector writes here, flagged or not, so the
# MAGIC table doubles as a record of what has been scanned. Columns lead with when and who, then the
# MAGIC verdict; the scanned span's identifiers sit in the `span` struct.
# MAGIC
# MAGIC | Column | Meaning |
# MAGIC |---|---|
# MAGIC | `span_time`, `detected_at` | When the scanned span started, and when the detector wrote the row |
# MAGIC | `workspace_id`, `requester`, `conversation_id`, `product` | Who and where; `conversation_id` joins to `genie_sessions` |
# MAGIC | `detector` | Which scanner produced the row (table below) |
# MAGIC | `flagged` | `true` = a finding. `false` rows mean "scanned, nothing found" or an informational signal |
# MAGIC | `score` | Confidence or severity in [0, 1]; feeds `risk_score` |
# MAGIC | `label` | Entity type, class, verdict or rule name |
# MAGIC | `span` (struct) | `trace_id` (the turn), `span_id` (the step), `field` (`prompt`, `response`, `tool_arguments`, `tool_result`, `model_output`, or a rule name), `text_length` |
# MAGIC | `details` | JSON evidence: entity offsets, matched text, vector (`direct` / `indirect`), error messages |
# MAGIC | `detection_id` | `sha2(span_id, detector, field)`; the MERGE key that makes re-runs idempotent |
# MAGIC
# MAGIC | Detector | Notebook | What it finds | Typical score |
# MAGIC |---|---|---|---|
# MAGIC | `pii_presidio` | 02 | Row-level PII (email, phone, card, SSN, IBAN, IP, names, locations) | Presidio confidence, 0.5–1.0 |
# MAGIC | `pii_ai_extract` | 02 (opt-in) | LLM-extracted PII on a sample | 0.8 fixed |
# MAGIC | `prompt_injection_prompt_guard` | 03 | Llama Prompt Guard 2 malicious probability, chunked | model score; flagged ≥ 0.85 |
# MAGIC | `prompt_injection_ai_classify` | 03 | LLM judge: legitimate / destructive-or-boundary-pushing / injection | 0.7 injection, 0.3 boundary (not flagged) |
# MAGIC | `guardrail_signal` | 04 | Rules over outcomes and text: `guardrail_intervention` (0.8), `destructive_action_executed` (0.7), `injection_recognised` (0.6), `refusal_text` (0.5), `boundary_pushing_prompt` (0.5), `tool_user_rejected` (0.5), ...; `approval_requested`, `turn_error`, `tool_error` are informational | rule severity |
# MAGIC
# MAGIC **Things to know**
# MAGIC * `details` never copies the PII value itself for Presidio, only entity type and offsets.
# MAGIC   Slice the source column with those offsets if you need to see the match.
# MAGIC * Guardrail rules re-score their whole lookback window on every run, so editing a pattern
# MAGIC   updates history. Presidio and Prompt Guard only scan fields they have not seen.
# MAGIC * When Prompt Guard and `ai_classify` disagree on the same field, review that row.

# COMMAND ----------

q(f"""
SELECT span_time, detected_at, detector, flagged, ROUND(score, 3) AS score, label, span.field, details, span.span_id
FROM {FQ}.genie_detections
WHERE conversation_id = :conversation_id
ORDER BY flagged DESC, score DESC, span_time
""")

# COMMAND ----------

# MAGIC %md
# MAGIC ### Findings by detector across all sessions

# COMMAND ----------

q(f"""
SELECT detector, label,
       COUNT(*)                        AS findings,
       COUNT(DISTINCT conversation_id) AS sessions,
       COUNT(DISTINCT requester)       AS users,
       ROUND(AVG(score), 2)            AS avg_score,
       MAX(span_time)                  AS latest
FROM {FQ}.genie_detections
WHERE flagged AND span_time >= current_timestamp() - INTERVAL {DAYS} DAYS
GROUP BY ALL ORDER BY detector, findings DESC
""")

# COMMAND ----------

# MAGIC %md
# MAGIC ---
# MAGIC ## 6 · Column tags: what the PII scan told Unity Catalog
# MAGIC
# MAGIC `02_detect_pii` maps Presidio entity types onto the governed tag keys Unity Catalog Data
# MAGIC Classification uses (`class.email_address`, `class.name`, `class.us_ssn`, ...) and applies
# MAGIC them to the column where the PII was found, plus a plain `pii_detected_by = presidio` tag.
# MAGIC
# MAGIC | Why it matters | |
# MAGIC |---|---|
# MAGIC | 🛡️ ABAC | One policy on `hasTag('class.email_address')` masks the column for everyone outside the security group, whether Data Classification or Presidio found it |
# MAGIC | 🔎 Discovery | Catalog Explorer and `system.information_schema.column_tags` show at a glance which trace columns have carried PII |
# MAGIC | 📊 Column vs row | Tags say "this column *has contained* PII". `genie_detections` says *which rows*. Use both. |
# MAGIC
# MAGIC Assigning governed tags needs `ASSIGN` on each tag (account admins by default). If the
# MAGIC notebook reports a permission failure, the detections are still written; only the tag is skipped.

# COMMAND ----------

q(f"""
SELECT table_name, column_name, tag_name, tag_value
FROM system.information_schema.column_tags
WHERE catalog_name = '{CATALOG}' AND schema_name = '{SCHEMA}'
ORDER BY table_name, column_name, tag_name
""")

# COMMAND ----------

# MAGIC %md
# MAGIC ---
# MAGIC ## A · `unity_gateway_otel_spans`: the raw source
# MAGIC
# MAGIC The Unity Gateway **unified trace table**: OpenTelemetry spans for every Genie turn **and** for
# MAGIC AI Gateway model traffic. Everything above is derived from it.
# MAGIC
# MAGIC | Column | Meaning |
# MAGIC |---|---|
# MAGIC | `service_name` | `Genie One`, `genie-code-agent`, or a model endpoint such as `system.ai.claude-...`. **Always filter on this.** |
# MAGIC | `trace_id`, `span_id`, `parent_span_id` | Root span has empty `parent_span_id` (= the turn). |
# MAGIC | `name` | Root: `invoke_agent GenieOne` / `invoke_agent genieCodeAgent`. Children: `execute_tool <tool>`, `request_approval <tool>`, `request_answers ask_user_questions`, `chat`. |
# MAGIC | `attributes` | `VARIANT`. Dotted keys need bracket syntax: `attributes:['enduser.id']::string`. |
# MAGIC | `status.code` | `STATUS_CODE_OK` / `STATUS_CODE_ERROR` |
# MAGIC | `events`, `links` | Policy evaluations (`policy_evaluated`) land in `events`; Genie One continuation turns link back via `links`. |
# MAGIC | `time`, `date` | Clustered on `time`; always include a time filter. |
# MAGIC
# MAGIC **Things to know**
# MAGIC * Trace delivery is best-effort. Audit logs remain the compliance system of record.
# MAGIC * Deleting a Genie conversation does not delete its spans. Retention is yours to set.
# MAGIC * Span names differ from the docs in places; the ETL keys off `parent_span_id` and the
# MAGIC   `gen_ai.operation.name` attribute, so it keeps working if names change again.

# COMMAND ----------

q(f"""
SELECT service_name,
       CASE WHEN service_name IN ('Genie One', 'genie-code-agent') THEN 'Genie' ELSE 'AI Gateway model traffic' END AS category,
       COUNT(*)                 AS spans,
       COUNT(DISTINCT trace_id) AS traces,
       MIN(time)                AS first_seen,
       MAX(time)                AS last_seen
FROM {SOURCE_TABLE}
WHERE time >= current_timestamp() - INTERVAL {DAYS} DAYS
GROUP BY ALL ORDER BY category, spans DESC
""")

# COMMAND ----------

# MAGIC %md
# MAGIC ### The raw spans behind the selected conversation's first turn
# MAGIC Useful when you need an attribute the ETL does not surface.

# COMMAND ----------

q(f"""
WITH first_turn AS (
  SELECT trace_id FROM {FQ}.genie_turns WHERE conversation_id = :conversation_id ORDER BY started_at LIMIT 1
)
SELECT s.time, s.name, s.parent_span_id, s.status.code AS status_code, to_json(s.attributes) AS attributes
FROM {SOURCE_TABLE} s
JOIN first_turn t ON t.trace_id = s.trace_id
ORDER BY s.start_time_unix_nano
""")

# COMMAND ----------

# MAGIC %md
# MAGIC ---
# MAGIC ## B · `unity_gateway_otel_annotations`: user feedback
# MAGIC
# MAGIC Thumbs-up / thumbs-down and other annotations on traces. `genie_sessions` already rolls these
# MAGIC up (`feedback.thumbs_up_count`, `feedback.thumbs_down_count`); query the raw table when you need the comment or
# MAGIC the history of a rating.
# MAGIC
# MAGIC | Column | Meaning |
# MAGIC |---|---|
# MAGIC | `target_type`, `target_id` | `TRACE` and the `trace_id` it rates |
# MAGIC | `name`, `value` | `user_feedback` with a boolean `value` (true = 👍) |
# MAGIC | `annotation_id`, `annotation_change_type`, `updated_at` | Ratings can change; take the latest row per `annotation_id` and ignore `delete` |
# MAGIC | `comment`, `created_by` | Free text and who left it |
# MAGIC
# MAGIC `value` and `metadata` are `VARIANT`; cast them (`value::string`) before displaying from Python, or older Spark Connect clients refuse the schema.

# COMMAND ----------

q(f"""
WITH latest AS (
  SELECT annotation_id, target_id, name, value::string AS value, comment, created_by, updated_at, annotation_change_type,
         ROW_NUMBER() OVER (PARTITION BY annotation_id ORDER BY updated_at DESC) AS rn
  FROM {ANNOTATIONS_TABLE}
  WHERE target_type = 'TRACE'
)
SELECT l.updated_at, l.name, l.value, l.comment, l.created_by, l.annotation_change_type,
       t.product, t.requester, t.conversation_id, substr(t.prompt, 1, 160) AS prompt
FROM latest l
LEFT JOIN {FQ}.genie_turns t ON t.trace_id = l.target_id
WHERE l.rn = 1
ORDER BY l.updated_at DESC
LIMIT 100
""")

# COMMAND ----------

# MAGIC %md
# MAGIC ---
# MAGIC ## Where to go next
# MAGIC
# MAGIC | Need | Go to |
# MAGIC |---|---|
# MAGIC | Be told when something is flagged | The four SQL alerts in `resources/genie_tracing_alerts.alert.yml` (unpause them) |
# MAGIC | Tune what counts as PII | `02_detect_pii`: `pii_threshold`, `ignore_entities`, `allowlist_terms` |
# MAGIC | Tune prompt-injection sensitivity | `03_detect_prompt_injection`: `prompt_guard_threshold`, `run_ai_classify` |
# MAGIC | Add guardrail wording you have seen | `04_detect_guardrail_signals`: `INTERVENTION_PATTERNS`, `REFUSAL_PATTERNS` |
# MAGIC | Change the risk formula | `src/pipelines/sessions/transformations/genie_sessions.sql` |
# MAGIC | Restrict who can read these tables | `src/sql/access_control.sql` |
