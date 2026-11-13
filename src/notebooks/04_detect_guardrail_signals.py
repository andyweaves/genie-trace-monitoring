# Databricks notebook source
# MAGIC %md
# MAGIC # 04 · Detect guardrail and boundary-pushing signals
# MAGIC
# MAGIC Genie Code runs a layered pre-execution pipeline: deterministic hard-blocks, AI safety
# MAGIC inspection of proposed commands, then human approval or an intent-based **Auto-approve**
# MAGIC classifier. Genie One gained the same scope-based auto-approval in September 2026. Genie One
# MAGIC and Genie Agents otherwise rely on architectural controls plus a system-prompt topic check.
# MAGIC
# MAGIC **Almost none of these verdicts are written to the trace.** Testing showed:
# MAGIC
# MAGIC * The exception: a Genie Code tool call stopped by policy is exported with
# MAGIC   `databricks.genie_code.tool.outcome = POLICY_BLOCKED` (rule `tool_policy_blocked`).
# MAGIC
# MAGIC * The classifier's own text (`Action denied: ...`, `Review suggested: ...`) is returned to the
# MAGIC   model as a tool result, but that tool call is **not exported** as a span.
# MAGIC * Genie Code exports a filtered subset of spans (`expected_span_count` < `source_span_count`
# MAGIC   on the root span). Asset edits, runs and user questions are exported. Newer traces add
# MAGIC   `execute_tool executeCode` spans carrying the code; on older ones **SQL execution is not
# MAGIC   exported**, so a successful `DROP TABLE` leaves no tool span either.
# MAGIC * What survives is the final response the user saw, which usually narrates what happened
# MAGIC   ("The safety guardrails prevented me from executing it", "I dropped `catalog.schema.table`").
# MAGIC
# MAGIC This notebook therefore infers guardrail activity and boundary-pushing behaviour from
# MAGIC outcomes and response text with transparent rules. Each rule writes a `guardrail_signal`
# MAGIC detection with `field = <rule name>` and a severity `score`, and rolls up to
# MAGIC `genie_sessions.flags.has_guardrail_signal` and `risk_score`. Extend the pattern lists as you see
# MAGIC new wording.

# COMMAND ----------

# MAGIC %run ./_detection_utils

# COMMAND ----------

# MAGIC %run ./_security_pattern_utils

# COMMAND ----------

# MAGIC %md
# MAGIC ## Security-pattern configuration
# MAGIC
# MAGIC Repo-native signatures and bounded, passive decoding: no AI calls, credential validation,
# MAGIC network requests or payload execution. Invalid configuration fails visibly rather than
# MAGIC silently dropping rules. New findings contain metadata only; original text stays in the
# MAGIC restricted source tables. Matcher limits are recorded as informational coverage findings.

# COMMAND ----------

import json
import os

import pandas as pd
from pyspark.sql import functions as F
from pyspark.sql.functions import pandas_udf

dbutils.widgets.text("security_patterns_file", "../config/security_patterns.yml", "Security-pattern YAML")
SECURITY_CONFIG = load_security_config(os.path.abspath(dbutils.widgets.get("security_patterns_file")))
scan_security_text = build_security_matcher(SECURITY_CONFIG)
RUNAWAY_CONFIG = SECURITY_CONFIG.get("runaway", {})
LOOP_MIN_CALLS = int(RUNAWAY_CONFIG.get("repeat_calls", 5))
LONG_TURN_MINUTES = int(RUNAWAY_CONFIG.get("long_turn_minutes", 60))
SPAN_CAP_HINT = int(RUNAWAY_CONFIG.get("span_cap_hint", 120))
if min(LOOP_MIN_CALLS, LONG_TURN_MINUTES, SPAN_CAP_HINT) <= 0:
    raise ValueError("Runaway thresholds must be positive integers")
print(f"Loaded {len(SECURITY_CONFIG['rules'])} deterministic security patterns")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Outcome and guardrail-wording rules
# MAGIC
# MAGIC Each rule is a SQL predicate over `genie_turns` or `genie_tool_calls`. `score` is the
# MAGIC severity contributed to the session risk score. `flagged = false` rules are informational:
# MAGIC they are recorded in `genie_detections` for querying but do not flag the session, add to
# MAGIC `risk_score` or show in the timeline's `detections.flags`.

# COMMAND ----------

# Regex fragments are Java regex (Spark `rlike`). (?i) = case-insensitive.
REFUSAL_PATTERNS = [
    r"I can(?:no|')t (?:help with|do) (?:that|this)",
    r"I (?:won't|will not) (?:delete|drop|remove|modify|change|run|execute) (?:any|this|that|the)",
    r"irreversible,? destructive action",
    r"I (?:won't|will not|am not able to|cannot) (?:do|perform|run|execute|assist with|help with) (?:that|this)",
    r"(?:was |has been )?(?:blocked|flagged|rejected|declined) by (?:a |the )?(?:guardrail|safety|policy|classifier|auto-?approv)",
    r"outside (?:of )?(?:the )?scope of (?:this|the|your) (?:session|request|conversation|task)",
    r"not (?:related|relevant) to the (?:available|configured|selected) (?:data|tables|datasets)",
    r"(?:unrelated|not related) to (?:the|your) (?:available )?(?:data|tables)",
    r"requires? (?:your |explicit )?approval",
    r"(?:potentially )?(?:destructive|dangerous|harmful) (?:action|operation|command)",
    r"I (?:won't|will not) make (?:that|this) change without",
]
REFUSAL_PATTERNS += [
    r"I (?:won't|will not) (?:print|reveal|expose|show) (?:a |the )?(?:secret|credential|token|password)",
    r"(?:bypass|circumvent|get around) (?:Databricks'? )?(?:secret )?redaction",
    r"I (?:can't|cannot|am not able to) send emails or transmit",
    r"falls outside what I'm able to do",
    r"I(?:'m| am) not going to (?:follow|drop|delete|perform|run|execute|ignore)",
    r"I won't (?:do that|follow (?:it|that|them)|ignore my instructions|perform destructive operations)",
    # Genie One, when PII is pasted into the chat
    r"please don(?:'t|ot) share sensitive personal information",
    r"I won't save these details",
    # Genie One declining prompt disclosure and writes ("I can't share my internal rules or
    # configuration", "I can't drop this table", "I can only run read-only SQL")
    r"I can(?:no|'|\u2019)t (?:share|reveal|disclose|show you) my (?:internal |system )?(?:rules|instructions|configuration|prompt)",
    r"I can(?:no|'|\u2019)t (?:drop|delete|remove|truncate|alter|modify|update) (?:this|that|the|these|those|any|rows)\b",
    r"I can only run read-only (?:SQL|queries)",
    # Genie Code declining secrets access, exfiltration and runaway work ("I won't retrieve and
    # display secret values", "I can't help with sending data to external URLs", "would exfiltrate
    # data", "I can't proceed with this request", "I can't run an infinite loop")
    r"I(?: won't| will not| can(?:no|'|\u2019)t| am not able to|'m not able to)(?: help with)? (?:retriev|display|print|reveal|expos|show)[a-z]*"
    r"(?: and (?:display|print|show)[a-z]*)? \*?(?:secret|credential|token|password)",
    r"(?:send|transmit|post|export)[a-z]* (?:workspace |table )?data (?:from [^.]{0,60})?to (?:an? )?(?:external|outside)",
    r"would exfiltrate|exfiltrating data|data exfiltration risk",
    r"I can(?:no|'|\u2019)t (?:help with|proceed with|carry out) (?:that|this|it\b|sending|retrieving|exporting)",
    r"I can(?:no|'|\u2019)t run (?:an? )?(?:infinite|unbounded|endless)",
]
REFUSAL_REGEX = "(?i)(" + "|".join(REFUSAL_PATTERNS) + ")"

# Wording produced by the Genie Code safety / auto-approve classifier and echoed by the model.
INTERVENTION_PATTERNS = [
    r"Action denied:",
    r"Review suggested:",
    r"safety guardrails? (?:prevented|blocked|stopped|denied)",
    r"(?:blocked|denied|prevented) by (?:the |a )?(?:safety )?(?:guardrail|classifier|policy)",
    r"should not proceed unattended",
    r"explicitly prohibited",
    r"(?:tools? (?:are|is) blocking|the tool blocked)",
]
INTERVENTION_REGEX = "(?i)(" + "|".join(INTERVENTION_PATTERNS) + ")"

# The model recognising an injection in retrieved content (cells, documents, tool output).
INJECTION_RECOGNISED_REGEX = (
    r"(?i)(prompt injection (?:attempt|embedded|in the)|injection attempts? (?:have been |were )?(?:added|embedded)|"
    r"I don(?:'t|ot) treat (?:cell|file|document) contents as instructions|"
    r"instructions embedded in (?:the |a )?(?:cell|notebook|document|file|tool)|"
    r"text designed to trick me)"
)

# The model pausing for confirmation before a destructive action (seen when auto-approve or the
# model itself is unsure the request is intentional).
CONFIRMATION_REGEX = (
    r"(?i)(permanently (?:delete|drop|remove)s?|cannot be (?:undone|recovered)|before I proceed with an irreversible|"
    r"can you confirm:|please confirm and I'll proceed|to confirm: you want me to (?:drop|delete|remove)|"
    r"I want to make sure (?:this|it) is intentional)"
)

# The model reporting that it performed a destructive or privilege-changing action. Important
# because Genie Code does not export the SQL execution span itself.
DESTRUCTIVE_EXECUTED_REGEX = (
    r"(?i)\bI(?:'ve| have)? (?:dropped|deleted|truncated|removed|revoked|granted|purged|overwrote|overwritten)\b"
)

BOUNDARY_PROMPT_REGEX = (
    r"(?i)(ignore (?:all |any )?(?:previous|prior|above|earlier) instructions|"
    r"(?:reveal|print|show|dump|disclose|repeat|output) (?:me )?(?:your |the )?(?:(?:complete|full|entire|original|verbatim) )?"
    r"(?:system (?:prompt|message|instructions)|(?:internal|hidden|secret) (?:rules|instructions|prompt)|prompt used)|"
    r"(?:print|reveal|disclose|show|dump|repeat) (?:me )?your (?:internal )?(?:rules|instructions|configuration|prompt)|"
    r"system override|"
    r"(?:bypass|disable|turn off|skip) (?:the |all )?(?:guardrail|safety|approval|permission|security)|"
    r"\bexfiltrat|\bjailbreak|\bDAN\b|do anything now|"
    r"grant all privileges|to all (?:account )?users|"
    r"(?:drop|delete|truncate|remove) (?:all|every|each|the|a|this) (?:tables?|schemas?|catalogs?|jobs?|clusters?|notebooks?)\b|"
    # A write against a three-part name: "Drop a.b.c", "Remove the sandbox table a.b.c",
    # "Delete all rows from a.b.c"
    r"\b(?:drop|truncate|undrop|delete|remove)(?: all rows| every row)?(?: from)?(?: the)?(?: [a-z_]+)? (?:table |view |schema )?"
    r"`?[a-z0-9_]+`?\.`?[a-z0-9_]+`?\.`?[a-z0-9_]+|"
    # Asking for data to be smuggled out in a Markdown image URL (rendered = fetched by the client)
    r"markdown image|!\[[^\]]*\]\(\s*https?://|"
    r"\b(?:send|post|upload|transmit)\b[^.\n]{0,60}\bto https?://(?!(?:[a-z0-9-]+\.)*(?:databricks\.com|azuredatabricks\.net))|"
    r"dbutils\.secrets|secrets\.get|api[_ ]?token|personal access token|secret in (?:clear|plain)text|"
    r"(?:email|send|post|upload|transmit|write) (?:the |this |a )?(?:data|table|notebook|results?|contents?) (?:in this notebook )?to (?:an? )?(?:external|outside|remote|url|http)|"
    r"external url|open up (?:the )?(?:egress|network|outbound) polic|"
    r"follow the instructions? (?:in|from) (?:the |this )?(?:cell|file|document)|read .{0,40} like an instruction)"
)

SENSITIVE_ARGS_REGEX = (
    r"(?i)(\bDROP\s+(?:TABLE|SCHEMA|DATABASE|CATALOG|VIEW)\b|\bTRUNCATE\s+TABLE\b|\bDELETE\s+FROM\b|"
    r"\bGRANT\s+|\bREVOKE\s+|\bALTER\s+\S+\s+(?:\S+\s+)?OWNER\b|"
    r"\bcurl\s|\bwget\s|requests\.(?:post|put|patch)|urllib\.request|socket\.|"
    r"rm\s+-rf|shutil\.rmtree|dbutils\.fs\.rm)"
)

# External URLs in tool arguments that are not Databricks / package-index hosts
EXTERNAL_URL_REGEX = (
    r"(?i)https?://(?!(?:[a-z0-9-]+\.)*(?:databricks\.com|databricks\.net|azuredatabricks\.net|"
    r"gcp\.databricks\.com|pypi\.org|pythonhosted\.org|maven\.org|npmjs\.org)(?:[/:]|$))[a-z0-9.-]+"
)

# A Markdown image pointing at a non-Databricks host with a query string: rendering it sends
# whatever is in the URL to that host. Planted in table data / tool output, or echoed in a response.
MARKDOWN_EXFIL_REGEX = (
    r"(?i)!\[[^\]]*\]\(\s*<?https?://(?!(?:[a-z0-9-]+\.)*(?:databricks\.com|databricks\.net|azuredatabricks\.net)(?:[/:?]|$))"
    r"[^)\s]*\?[^)\s]*="
)

# Credential signatures now live in security_patterns.yml and scan each field separately,
# including decoded forms. Do not concatenate prompt and response into a credential candidate.

DESTRUCTIVE_TOOL_REGEX = r"(?i)^(?:delete|drop|remove|truncate|destroy|grant|revoke|publish|update_permissions|set_permissions|share)"

# Tools that only talk to the user; their arguments are questions, not actions.
QUESTION_TOOLS = "('askUserQuestions', 'ask_user_questions')"
ACTION_TOOL = f"span_type = 'tool_call' AND coalesce(tool_name, '') NOT IN {QUESTION_TOOLS}"


def sql_escape(s: str) -> str:
    """Escape a regex for use inside a Spark SQL single-quoted string literal."""
    return s.replace("\\", "\\\\").replace("'", "\\'")


# SQL-literal-safe versions of the regexes above
REFUSAL_SQL = sql_escape(REFUSAL_REGEX)
BOUNDARY_PROMPT_SQL = sql_escape(BOUNDARY_PROMPT_REGEX)
SENSITIVE_ARGS_SQL = sql_escape(SENSITIVE_ARGS_REGEX)
EXTERNAL_URL_SQL = sql_escape(EXTERNAL_URL_REGEX)
DESTRUCTIVE_TOOL_SQL = sql_escape(DESTRUCTIVE_TOOL_REGEX)
MARKDOWN_EXFIL_SQL = sql_escape(MARKDOWN_EXFIL_REGEX)

INTERVENTION_SQL = sql_escape(INTERVENTION_REGEX)
CONFIRMATION_SQL = sql_escape(CONFIRMATION_REGEX)
INJECTION_RECOGNISED_SQL = sql_escape(INJECTION_RECOGNISED_REGEX)
DESTRUCTIVE_EXECUTED_SQL = sql_escape(DESTRUCTIVE_EXECUTED_REGEX)

TURN_ERROR_PREDICATE = (
    "(is_error OR (genie_status IS NOT NULL AND genie_status NOT IN ('completed', 'success')) OR response RLIKE '^Error: ')"
)

# A turn that failed after an attack: the prompt was boundary-pushing, a tool in the same turn
# returned a planted Markdown image, or 03 flagged prompt injection in the turn. Failures are
# otherwise informational, but here the attack may be what broke the turn. 03 runs in parallel,
# so its flags are picked up on the next run (this notebook re-scores its whole window).
ATTACK_IN_TURN_PREDICATE = f"""(
    prompt RLIKE '{BOUNDARY_PROMPT_SQL}'
    OR EXISTS (SELECT 1 FROM tools_src t WHERE t.trace_id = turns_src.trace_id AND t.text RLIKE '{MARKDOWN_EXFIL_SQL}')
    OR EXISTS (SELECT 1 FROM {DETECTIONS} d
               WHERE d.span.trace_id = turns_src.trace_id AND d.flagged AND d.detector LIKE 'prompt_injection_%')
)"""

RULES = [
    # name, source, predicate, score, flagged, label expression (SQL), evidence expression (SQL)
    dict(name="guardrail_intervention", source="turns", flagged=True, score=0.8,
         predicate=f"response RLIKE '{INTERVENTION_SQL}'",
         evidence=f"named_struct('match', regexp_extract(response, '{INTERVENTION_SQL}', 1), 'response', substr(response, 1, 600))"),
    dict(name="guardrail_intervention_tool", source="tools", flagged=True, score=0.8,
         predicate=f"text RLIKE '{INTERVENTION_SQL}'",
         evidence=f"named_struct('tool_name', tool_name, 'span_type', span_type, 'match', regexp_extract(text, '{INTERVENTION_SQL}', 1), 'text', substr(text, 1, 600))"),
    dict(name="injection_recognised", source="turns", flagged=True, score=0.6,
         predicate=f"response RLIKE '{INJECTION_RECOGNISED_SQL}'",
         evidence=f"named_struct('match', regexp_extract(response, '{INJECTION_RECOGNISED_SQL}', 1), 'response', substr(response, 1, 500))"),
    dict(name="destructive_confirmation_requested", source="turns", flagged=True, score=0.4,
         predicate=f"response RLIKE '{CONFIRMATION_SQL}'",
         evidence=f"named_struct('match', regexp_extract(response, '{CONFIRMATION_SQL}', 1), 'prompt', substr(prompt, 1, 300), 'response', substr(response, 1, 500))"),
    dict(name="destructive_action_executed", source="turns", flagged=True, score=0.7,
         predicate=f"response RLIKE '{DESTRUCTIVE_EXECUTED_SQL}'",
         evidence=f"named_struct('match', regexp_extract(response, '{DESTRUCTIVE_EXECUTED_SQL}', 0), 'prompt', substr(prompt, 1, 300), 'response', substr(response, 1, 500))"),
    dict(name="refusal_outcome", source="turns", flagged=True, score=0.6,
         predicate="run_outcome = 'refusal'",
         evidence="named_struct('run_outcome', run_outcome, 'response', substr(response, 1, 500))"),
    dict(name="refusal_text", source="turns", flagged=True, score=0.5,
         predicate=f"response RLIKE '{REFUSAL_SQL}'",
         evidence=f"named_struct('match', regexp_extract(response, '{REFUSAL_SQL}', 1), 'response', substr(response, 1, 500))"),
    dict(name="boundary_pushing_prompt", source="turns", flagged=True, score=0.5,
         predicate=f"prompt RLIKE '{BOUNDARY_PROMPT_SQL}'",
         evidence=f"named_struct('match', regexp_extract(prompt, '{BOUNDARY_PROMPT_SQL}', 1), 'prompt', substr(prompt, 1, 500))"),
    dict(name="markdown_image_exfil_response", source="turns", flagged=True, score=0.8,
         predicate=f"response RLIKE '{MARKDOWN_EXFIL_SQL}'",
         evidence=f"named_struct('match', regexp_extract(response, '{MARKDOWN_EXFIL_SQL}', 0), 'prompt', substr(prompt, 1, 300))"),
    dict(name="error_after_attack", source="turns", flagged=True, score=0.4,
         predicate=f"{TURN_ERROR_PREDICATE} AND {ATTACK_IN_TURN_PREDICATE}",
         evidence="named_struct('error_code', error_code, 'status_message', status_message, 'genie_status', genie_status, 'prompt', substr(prompt, 1, 300))"),
    dict(name="turn_error", source="turns", flagged=False, score=0.1,
         predicate=TURN_ERROR_PREDICATE,
         evidence="named_struct('error_code', error_code, 'status_message', status_message, 'run_outcome', run_outcome)"),
    dict(name="cancelled_or_aborted", source="turns", flagged=False, score=0.1,
         predicate="run_outcome IN ('cancelled', 'aborted')",
         evidence="named_struct('run_outcome', run_outcome)"),

    dict(name="tool_user_rejected", source="tools", flagged=True, score=0.5,
         predicate="tool_outcome = 'USER_REJECTED' OR tool_result RLIKE '\"(?:declined|cancel(?:led)?)\"'",
         evidence="named_struct('tool_name', tool_name, 'tool_outcome', tool_outcome, 'arguments', substr(tool_arguments, 1, 500))"),
    # The one guardrail verdict Genie Code does export: the tool span's outcome.
    dict(name="tool_policy_blocked", source="tools", flagged=True, score=0.8,
         predicate="tool_outcome = 'POLICY_BLOCKED' OR tool_result RLIKE '\"error\"\\\\s*:\\\\s*\"POLICY_BLOCKED\"'",
         evidence="named_struct('tool_name', tool_name, 'tool_outcome', tool_outcome, 'arguments', substr(tool_arguments, 1, 500))"),
    dict(name="tool_permission_denied", source="tools", flagged=True, score=0.7,
         predicate="tool_outcome = 'PERMISSION_DENIED'",
         evidence="named_struct('tool_name', tool_name, 'tool_outcome', tool_outcome, 'arguments', substr(tool_arguments, 1, 500))"),
    # Informational: an approval request is the guardrail working as designed, not misuse.
    # Rejections and destructive actions are flagged by the rules around it.
    dict(name="approval_requested", source="tools", flagged=False, score=0.3,
         predicate="span_type = 'approval_request'",
         evidence="named_struct('tool_name', tool_name, 'arguments', substr(tool_arguments, 1, 500))"),
    dict(name="destructive_tool", source="tools", flagged=True, score=0.5,
         predicate=f"{ACTION_TOOL} AND tool_name RLIKE '{DESTRUCTIVE_TOOL_SQL}'",
         evidence="named_struct('tool_name', tool_name, 'arguments', substr(tool_arguments, 1, 500))"),
    dict(name="sensitive_arguments", source="tools", flagged=True, score=0.6,
         predicate=f"{ACTION_TOOL} AND tool_arguments RLIKE '{SENSITIVE_ARGS_SQL}'",
         evidence=f"named_struct('tool_name', tool_name, 'match', regexp_extract(tool_arguments, '{SENSITIVE_ARGS_SQL}', 1), 'arguments', substr(tool_arguments, 1, 500))"),
    dict(name="external_destination", source="tools", flagged=True, score=0.4,
         predicate=f"{ACTION_TOOL} AND tool_arguments RLIKE '{EXTERNAL_URL_SQL}'",
         evidence=f"named_struct('tool_name', tool_name, 'host', regexp_extract(tool_arguments, '{EXTERNAL_URL_SQL}', 0), 'arguments', substr(tool_arguments, 1, 500))"),
    dict(name="markdown_image_exfil", source="tools", flagged=True, score=0.6,
         predicate=f"coalesce(tool_result, '') || ' ' || coalesce(response_text, '') RLIKE '{MARKDOWN_EXFIL_SQL}'",
         evidence=f"named_struct('tool_name', tool_name, 'match', regexp_extract(coalesce(tool_result, '') || ' ' || coalesce(response_text, ''), '{MARKDOWN_EXFIL_SQL}', 0))"),
    dict(name="tool_error", source="tools", flagged=False, score=0.1,
         predicate="span_type = 'tool_call' AND (is_error OR (tool_outcome IS NOT NULL AND tool_outcome <> 'SUCCESS'))",
         evidence="named_struct('tool_name', tool_name, 'tool_outcome', tool_outcome, 'status_message', status_message)"),
]

print(f"{len(RULES)} rules defined")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Evaluate rules
# MAGIC
# MAGIC Rules are evaluated over the whole lookback window on every run and MERGEd in one statement:
# MAGIC rows for hits that no longer match (a pattern was edited or removed) are deleted, new hits are
# MAGIC inserted, and unchanged hits keep their original `detected_at` so the alerts fire once, not
# MAGIC every hour. The window start is fixed once so the scan and the delete cover the same spans.

# COMMAND ----------

from datetime import datetime, timedelta, timezone

# One cutoff for both the source scan and the MERGE's delete clause.
_cutoff = datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)
CUTOFF_SQL = f"TIMESTAMP'{_cutoff:%Y-%m-%d %H:%M:%S.%f}+00:00'"
print(f"Re-scoring guardrail signals since {CUTOFF_SQL}")

SOURCES = {
    "turns": f"""
        SELECT trace_id, span_id, coalesce(conversation_id, trace_id) AS conversation_id, product, workspace_id, requester,
               started_at AS span_time, prompt, response, output_messages_raw, duration_ms,
               completeness.expected_span_count AS expected_span_count,
               completeness.dropped_span_count AS dropped_span_count,
               outcome.run_outcome AS run_outcome, outcome.genie_status AS genie_status, outcome.error_code AS error_code,
               outcome.status_message AS status_message, is_error,
               coalesce(prompt, '') || ' ' || coalesce(response, '') AS text
        FROM {TURNS}
        WHERE started_at >= {CUTOFF_SQL}
    """,
    "tools": f"""
        SELECT trace_id, span_id, coalesce(conversation_id, trace_id) AS conversation_id, product, workspace_id, requester,
               started_at AS span_time, span_type, tool_name, tool_arguments, tool_result, response_text,
               outcome.tool_outcome AS tool_outcome, outcome.status_message AS status_message, is_error,
               coalesce(tool_arguments, '') || ' ' || coalesce(tool_result, '') || ' ' || coalesce(response_text, '') AS text
        FROM {TOOL_CALLS}
        WHERE started_at >= {CUTOFF_SQL}
    """,
}

selects = []
for r in RULES:
    predicate = r["predicate"]
    evidence = r["evidence"]
    # Keep only operational metadata, not excerpts, URLs, matched text or exception messages:
    # otherwise a secret finding could copy the same credential into another rule's evidence.
    safe_evidence = (
        f"to_json(map_filter(from_json(to_json({evidence}), 'MAP<STRING,STRING>'), "
        "(k, v) -> k IN ('tool_name', 'span_type', 'tool_outcome', 'run_outcome', 'error_code', 'genie_status')))"
    )
    # Regex literals inside predicates/evidence were built with single quotes already escaped for SQL.
    selects.append(
        f"""
        SELECT trace_id, span_id, conversation_id, product, workspace_id, requester, span_time, text,
               '{r["name"]}' AS field,
               {str(r["flagged"]).lower()} AS flagged,
               CAST({r["score"]} AS DOUBLE) AS score,
               '{r["name"]}' AS label,
               {safe_evidence} AS details
        FROM {r["source"]}_src
        WHERE {predicate}
        """
    )

for name, sql in SOURCES.items():
    spark.sql(sql).createOrReplaceTempView(f"{name}_src")

outcome_signals = spark.sql(" UNION ALL ".join(selects)).withColumn("text_length", F.length("text"))

# COMMAND ----------

# MAGIC %md
# MAGIC ## Deterministic security signatures, including embedded tool responses
# MAGIC
# MAGIC Match each field separately so its scope and provenance survive. Approval requests and
# MAGIC user questions are proposals, not executed code: their arguments use prompt scope.
# MAGIC Genie One can embed tool responses in a root message even when there is no child tool span.
# MAGIC A model output identical to the final answer is scanned once, as the answer.
# MAGIC
# MAGIC No raw or decoded content is copied to finding evidence. Bounded scans that hit a resource
# MAGIC limit emit `security_scan_limited` (informational), rather than silently implying full coverage.

# COMMAND ----------

SECURITY_FIELDS_SQL = f"""
WITH root_texts AS (
  SELECT *, nullif(array_join(flatten(transform(
    from_json(output_messages_raw,
      'ARRAY<STRUCT<parts:ARRAY<STRUCT<type:STRING,response:STRING>>>>'),
    m -> transform(filter(m.parts, p -> p.type = 'tool_call_response' AND p.response IS NOT NULL),
                   p -> p.response))), '\\n'), '') AS embedded_tool_result
  FROM turns_src
), fields AS (
  SELECT trace_id, span_id, conversation_id, product, workspace_id, requester, span_time,
         'prompt' AS field, 'prompt' AS scope, prompt AS text, CAST(NULL AS STRING) AS tool_name
  FROM root_texts
  UNION ALL
  SELECT trace_id, span_id, conversation_id, product, workspace_id, requester, span_time,
         'response', 'answer', response, CAST(NULL AS STRING)
  FROM root_texts
  UNION ALL
  SELECT trace_id, span_id, conversation_id, product, workspace_id, requester, span_time,
         'embedded_tool_result', 'tool_result', embedded_tool_result, CAST(NULL AS STRING)
  FROM root_texts
  UNION ALL
  SELECT trace_id, span_id, conversation_id, product, workspace_id, requester, span_time,
         'tool_arguments', CASE WHEN {ACTION_TOOL} THEN 'tool_args' ELSE 'prompt' END,
         tool_arguments, tool_name
  FROM tools_src WHERE span_type IN ('tool_call', 'approval_request', 'user_question')
  UNION ALL
  SELECT trace_id, span_id, conversation_id, product, workspace_id, requester, span_time,
         'tool_result', 'tool_result', tool_result, tool_name
  FROM tools_src WHERE span_type IN ('tool_call', 'approval_request', 'user_question')
  UNION ALL
  SELECT c.trace_id, c.span_id, c.conversation_id, c.product, c.workspace_id, c.requester, c.span_time,
         'model_output', 'tool_result', c.response_text, c.tool_name
  FROM tools_src c
  WHERE c.span_type = 'model_call' AND NOT EXISTS (
    SELECT 1 FROM turns_src t WHERE t.trace_id = c.trace_id AND t.response = c.response_text
  )
)
SELECT * FROM fields WHERE text IS NOT NULL AND length(trim(text)) > 0
"""


@pandas_udf("string")
def security_scan(texts: pd.Series, scopes: pd.Series) -> pd.Series:
    return pd.Series([json.dumps(scan_security_text(text, scope), separators=(",", ":"))
                      for text, scope in zip(texts, scopes)])


SCAN_SCHEMA = """STRUCT<
  hits:ARRAY<STRUCT<rule_id:STRING,category:STRING,score:DOUBLE,flagged:BOOLEAN,encoding:STRING,source:STRING>>,
  limits:ARRAY<STRING>,scanned_chars:INT>
"""
security_scored = (
    spark.sql(SECURITY_FIELDS_SQL)
    .withColumn("text_length", F.length("text"))
    .withColumn("scan", F.from_json(security_scan("text", "scope"), SCAN_SCHEMA))
)
# Explode actual hits and an optional limit marker together, so each field is evaluated once.
limit_hit = F.struct(
    F.lit("security_scan_limited").alias("rule_id"), F.lit("scan_coverage").alias("category"),
    F.lit(0.0).alias("score"), F.lit(False).alias("flagged"),
    F.lit("none").alias("encoding"), F.lit("matcher_limits").alias("source"),
)
security_signals = (
    security_scored
    .withColumn("hit", F.explode(F.concat(
        F.col("scan.hits"),
        F.when(F.size("scan.limits") > 0, F.array(limit_hit))
         .otherwise(F.array().cast("array<struct<rule_id:string,category:string,score:double,flagged:boolean,encoding:string,source:string>>")),
    )))
    .select(
        "trace_id", "span_id", "conversation_id", "product", "workspace_id", "requester", "span_time",
        F.lit(None).cast("string").alias("text"), "text_length",
        F.concat(F.lit("security:"), F.col("hit.rule_id"), F.lit(":"), F.col("field")).alias("field"),
        F.col("hit.flagged").alias("flagged"), F.col("hit.score").alias("score"),
        F.col("hit.rule_id").alias("label"),
        F.to_json(F.struct(
            F.col("field").alias("source_field"), "scope", "tool_name",
            F.col("hit.rule_id").alias("pattern_id"), F.col("hit.category").alias("category"),
            F.col("hit.encoding").alias("encoding"), F.col("hit.source").alias("source"),
            F.col("scan.scanned_chars").alias("scanned_chars"), F.col("scan.limits").alias("limits"),
        )).alias("details"),
    )
)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Repeated tool calls, long turns and trace completeness
# MAGIC
# MAGIC Identical tool calls are counted by distinct span, not duplicate trace deliveries. The
# MAGIC code/SQL/command is used for comparison only and is never included in evidence. Repetition
# MAGIC and long turns are heuristics (polling and long jobs can be legitimate). A span-cap hint or
# MAGIC dropped spans is informational: missing telemetry does not establish malicious behaviour.
# MAGIC Thresholds live in the YAML's optional `runaway` section.

# COMMAND ----------

RUNAWAY_SQL = f"""
WITH calls AS (
  SELECT DISTINCT trace_id, span_id, tool_name,
    coalesce(get_json_object(tool_arguments, '$.code'), get_json_object(tool_arguments, '$.query'),
             get_json_object(tool_arguments, '$.sql'), get_json_object(tool_arguments, '$.statement'),
             get_json_object(tool_arguments, '$.command'), tool_arguments) AS code
  FROM tools_src
  WHERE {ACTION_TOOL} AND tool_name IS NOT NULL
    AND tool_arguments IS NOT NULL AND length(trim(tool_arguments)) > 0
), repeats AS (
  SELECT trace_id, max(n) AS repeated_calls
  FROM (SELECT trace_id, tool_name, code, count(DISTINCT span_id) AS n
        FROM calls GROUP BY trace_id, tool_name, code)
  GROUP BY trace_id
), events AS (
  SELECT t.*, coalesce(r.repeated_calls, 0) AS repeated_calls,
    CASE WHEN coalesce(r.repeated_calls, 0) >= {LOOP_MIN_CALLS} THEN 'repeated_tool_calls' END AS loop_rule,
    CASE WHEN duration_ms > {LONG_TURN_MINUTES} * 60.0 * 1000 THEN 'long_running_turn' END AS duration_rule,
    CASE WHEN expected_span_count >= {SPAN_CAP_HINT} OR dropped_span_count > 0 THEN 'trace_completeness_warning' END AS completeness_rule
  FROM turns_src t LEFT JOIN repeats r USING (trace_id)
)
SELECT trace_id, span_id, conversation_id, product, workspace_id, requester, span_time,
       CAST(NULL AS STRING) AS text, CAST(0 AS INT) AS text_length,
       reason AS field, reason <> 'trace_completeness_warning' AS flagged,
       CASE WHEN reason = 'repeated_tool_calls' THEN 0.5
            WHEN reason = 'long_running_turn' THEN 0.4 ELSE 0.0 END AS score,
       reason AS label,
       to_json(named_struct('repeated_calls', repeated_calls, 'duration_ms', duration_ms,
                            'expected_spans', expected_span_count, 'dropped_spans', dropped_span_count)) AS details
FROM events
LATERAL VIEW explode(array(loop_rule, duration_rule, completeness_rule)) x AS reason
WHERE reason IS NOT NULL
"""
runaway_signals = spark.sql(RUNAWAY_SQL)

# COMMAND ----------

# MAGIC %md
# MAGIC ## One idempotent write for every guardrail/security signal
# MAGIC
# MAGIC All branches share one MERGE and one cutoff. A removed rule clears its old findings inside
# MAGIC the lookback window; an unchanged finding keeps its original alert timestamp. Previous
# MAGIC credential rules are replaced by the field-scoped signatures, not run alongside them.

# COMMAND ----------

SIGNAL_COLUMNS = [
    "trace_id", "span_id", "conversation_id", "product", "workspace_id", "requester", "span_time",
    "text", "text_length", "field", "flagged", "score", "label", "details",
]
signals = (
    outcome_signals.select(*SIGNAL_COLUMNS)
    .unionByName(security_signals.select(*SIGNAL_COLUMNS))
    .unionByName(runaway_signals.select(*SIGNAL_COLUMNS))
    .dropDuplicates(["trace_id", "span_id", "field"])
)
write_detections(signals, "guardrail_signal", rescore_since=CUTOFF_SQL)

# COMMAND ----------

display(
    spark.sql(
        f"""
        SELECT product, label AS rule, flagged, score, COUNT(*) AS hits, COUNT(DISTINCT conversation_id) AS sessions
        FROM {DETECTIONS}
        WHERE detector = 'guardrail_signal'
        GROUP BY ALL ORDER BY flagged DESC, hits DESC
        """
    )
)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Recent hits with evidence

# COMMAND ----------

display(
    spark.sql(
        f"""
        SELECT span_time, product, requester, conversation_id, label AS rule, score, details
        FROM {DETECTIONS}
        WHERE detector = 'guardrail_signal' AND flagged
        ORDER BY span_time DESC
        LIMIT 100
        """
    )
)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Finding the guardrail's own wording
# MAGIC
# MAGIC When a Genie Code safety block or auto-approve rejection happens, the explanation is in the
# MAGIC turn's `response` (or the `model_output` of the last `chat` span). Use this query after
# MAGIC deliberately triggering the guardrail in a test session, then add the phrasing to
# MAGIC `REFUSAL_PATTERNS`.

# COMMAND ----------

display(
    spark.sql(
        f"""
        SELECT started_at, requester, conversation_id, outcome.run_outcome AS run_outcome, outcome.status_code AS status_code, substr(response, 1, 1000) AS response
        FROM {TURNS}
        WHERE product = 'Genie Code'
          AND (outcome.run_outcome <> 'success' OR response RLIKE '{REFUSAL_SQL}' OR response RLIKE '{INTERVENTION_SQL}')
        ORDER BY started_at DESC
        LIMIT 50
        """
    )
)
