-- genie_tool_calls: one row per non-root Genie span: tool executions, approval requests,
-- user questions and (Genie Code only) model calls.
--
-- Span names differ between products and between the docs and what is actually exported
-- (Genie Code currently emits `execute_tool <name>` rather than the documented
-- `tool.execute:<name>`), so classification uses gen_ai.operation.name first and falls back
-- to name patterns.

CREATE OR REFRESH MATERIALIZED VIEW genie_tool_calls
(
  CONSTRAINT trace_id_present EXPECT (trace_id IS NOT NULL) ON VIOLATION DROP ROW
)
CLUSTER BY (date, conversation_id)
COMMENT 'One row per Genie tool call, approval request, user question or model call span. Flat: when, who, keys, span_type, tool_name, arguments / results / model output, is_error, is_rejected_or_denied. Structs: outcome, span, completeness.'
TBLPROPERTIES (
  'quality' = 'silver',
  'delta.enableRowTracking' = 'true'
)
AS
WITH children AS (
  SELECT *
  FROM ${source_table}
  WHERE (service_name = '${genie_code_service}'
         OR array_contains(transform(split('${genie_one_services}', ','), s -> trim(s)), service_name))
    AND parent_span_id IS NOT NULL AND parent_span_id <> ''
),
roots AS (
  SELECT
    trace_id,
    attributes:['gen_ai.conversation.id']::string AS conversation_id,
    attributes:['databricks.genie.channel']::string AS channel
  FROM ${source_table}
  WHERE (service_name = '${genie_code_service}'
         OR array_contains(transform(split('${genie_one_services}', ','), s -> trim(s)), service_name))
    AND (parent_span_id IS NULL OR parent_span_id = '')
),
typed AS (
  SELECT
    c.trace_id,
    c.span_id,
    c.parent_span_id,
    c.record_id,
    c.time,
    c.date,
    timestamp_micros(CAST(c.start_time_unix_nano / 1000 AS BIGINT)) AS started_at,
    timestamp_micros(CAST(c.end_time_unix_nano   / 1000 AS BIGINT)) AS ended_at,
    (c.end_time_unix_nano - c.start_time_unix_nano) / 1e6            AS duration_ms,
    c.service_name,
    CASE WHEN c.service_name = '${genie_code_service}' THEN 'Genie Code' ELSE 'Genie One' END AS product,
    c.name                                                           AS span_name,
    c.attributes:['gen_ai.operation.name']::string                   AS operation,
    c.attributes:['mlflow.spanType']::string                         AS mlflow_span_type,

    c.attributes:workspace_id::string                                AS workspace_id,
    c.attributes:['enduser.id']::string                              AS requester,
    c.attributes:['databricks.principal_id']::string                 AS principal_id,
    r.conversation_id,
    r.channel,

    c.attributes:['gen_ai.tool.name']::string                        AS tool_name_attr,
    c.attributes:['gen_ai.tool.call.id']::string                     AS tool_call_id,
    c.attributes:['gen_ai.tool.call.arguments']::string              AS tool_arguments,
    c.attributes:['gen_ai.tool.call.result']::string                 AS tool_result,
    c.attributes:['databricks.genie_code.tool.outcome']::string      AS tool_outcome,
    c.attributes:['gen_ai.output.messages']::string                  AS output_messages_raw,

    c.status.code                                                    AS status_code,
    c.status.message                                                 AS status_message,
    c.attributes:['databricks.trace.payload_truncated']::string      AS payload_truncated,
    c.attributes:['databricks.genie_code.truncated_fields']::string  AS truncated_fields,
    c.attributes
  FROM children c
  LEFT JOIN roots r ON r.trace_id = c.trace_id
)
SELECT
  -- When
  started_at, ended_at, duration_ms, date,
  -- Who and where
  workspace_id, requester, principal_id,
  -- Keys
  conversation_id, trace_id, span_id, product,

  -- What happened
  CASE
    WHEN operation = 'execute_tool' OR span_name LIKE 'execute_tool %' OR span_name LIKE 'tool.execute:%' THEN 'tool_call'
    WHEN operation = 'request_approval' OR span_name LIKE 'request_approval %'                              THEN 'approval_request'
    WHEN operation = 'request_answers'  OR span_name LIKE 'request_answers %'                               THEN 'user_question'
    WHEN operation = 'chat' OR span_name = 'chat' OR mlflow_span_type = 'LLM'                                THEN 'model_call'
    ELSE 'other'
  END                                                                AS span_type,
  coalesce(
    tool_name_attr,
    nullif(regexp_extract(span_name, '^(?:execute_tool |tool\\.execute:|request_approval |request_answers )(.*)$', 1), '')
  )                                                                  AS tool_name,

  -- Text (flat: scanned for PII / injection, may carry PII row to row)
  tool_arguments,
  tool_result,
  coalesce(
    nullif(array_join(filter(flatten(transform(
      from_json(output_messages_raw,
        'ARRAY<STRUCT<role:STRING, content:STRING, parts:ARRAY<STRUCT<type:STRING, content:STRING, text:STRING>>>>'),
      m -> CASE WHEN m.parts IS NOT NULL
                THEN transform(filter(m.parts, p -> p.type IS NULL OR p.type = 'text'), p -> coalesce(p.content, p.text))
                ELSE array(m.content) END)), x -> x IS NOT NULL), '\n'), ''),
    output_messages_raw)                                             AS response_text,
  output_messages_raw,

  -- Headline outcome
  status_code = 'STATUS_CODE_ERROR'                                  AS is_error,
  -- POLICY_BLOCKED: the Genie Code guardrail stopped the call
  coalesce(tool_outcome IN ('USER_REJECTED', 'PERMISSION_DENIED', 'POLICY_BLOCKED'), false) AS is_rejected_or_denied,

  -- Detail, grouped
  named_struct(
    'tool_outcome',   tool_outcome,
    'status_code',    status_code,
    'status_message', status_message
  )                                                                  AS outcome,
  named_struct(
    'parent_span_id',   parent_span_id,
    'record_id',        record_id,
    'time',             time,
    'service_name',     service_name,
    'span_name',        span_name,
    'operation',        operation,
    'mlflow_span_type', mlflow_span_type,
    'tool_call_id',     tool_call_id,
    'channel',          channel
  )                                                                  AS span,
  named_struct(
    'payload_truncated', payload_truncated,
    'truncated_fields',  truncated_fields
  )                                                                  AS completeness,
  attributes
FROM typed;
