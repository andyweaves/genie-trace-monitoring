-- genie_turns: one row per Genie conversation turn (the root span of each trace).
--
-- Source: the Unity Gateway unified trace table (${source_table}). Only Genie One and Genie Code
-- spans are selected; AI Gateway model traffic in the same table is ignored.
--
-- Prompt / response text is lifted out of the nested gen_ai.input.messages /
-- gen_ai.output.messages JSON so detections can run on plain STRING columns. The original
-- VARIANT attributes are kept so nothing is lost.
--
-- Defined as a materialized view so a refresh picks up late or re-exported spans. Switch to a
-- streaming table (CREATE OR REFRESH STREAMING TABLE ... FROM STREAM(...)) if you prefer
-- append-only incremental processing.

CREATE OR REFRESH MATERIALIZED VIEW genie_turns
(
  CONSTRAINT trace_id_present EXPECT (trace_id IS NOT NULL) ON VIOLATION DROP ROW,
  CONSTRAINT requester_present EXPECT (requester IS NOT NULL)
)
CLUSTER BY (date, conversation_id)
COMMENT 'One row per Genie One / Genie Code turn (root span). Flat: when, who, keys, prompt / response / raw payloads, is_error, is_refusal. Structs: outcome, context, span, completeness, links.'
TBLPROPERTIES (
  'quality' = 'silver',
  'delta.enableRowTracking' = 'true'
)
AS
WITH roots AS (
  SELECT *
  FROM ${source_table}
  WHERE service_name IN ('${genie_one_service}', '${genie_code_service}')
    AND (parent_span_id IS NULL OR parent_span_id = '')
),
typed AS (
  SELECT
    trace_id,
    span_id,
    record_id,
    time,
    date,
    timestamp_micros(CAST(start_time_unix_nano / 1000 AS BIGINT)) AS started_at,
    timestamp_micros(CAST(end_time_unix_nano   / 1000 AS BIGINT)) AS ended_at,
    (end_time_unix_nano - start_time_unix_nano) / 1e6              AS duration_ms,
    service_name,
    CASE WHEN service_name = '${genie_code_service}' THEN 'Genie Code' ELSE 'Genie One' END AS product,
    name                                                           AS span_name,
    kind                                                           AS span_kind,

    -- Identity and location
    attributes:workspace_id::string                                AS workspace_id,
    attributes:['enduser.id']::string                              AS requester,
    attributes:['databricks.principal_id']::string                 AS principal_id,
    attributes:['databricks.genie.account_id']::string             AS account_id,
    attributes:['databricks.genie.metastore_id']::string           AS metastore_id,

    -- Conversation identifiers
    attributes:['gen_ai.conversation.id']::string                  AS conversation_id,
    attributes:['databricks.genie.response_id']::string            AS response_id,
    coalesce(attributes:['gen_ai.agent.name']::string,
             attributes:['agent.name']::string)                    AS agent_name,
    attributes:['gen_ai.agent.id']::string                         AS agent_id,
    attributes:['databricks.genie.surface']::string                AS surface,
    attributes:['databricks.genie.channel']::string                AS channel,
    attributes:['databricks.genie.scheduled_task_id']::string      AS scheduled_task_id,
    attributes:['databricks.actor.resource']::string               AS actor_resource,

    -- Raw message payloads (JSON strings)
    attributes:['gen_ai.input.messages']::string                   AS input_messages_raw,
    attributes:['gen_ai.output.messages']::string                  AS output_messages_raw,
    attributes:['databricks.genie.citations']::string              AS citations,

    -- Outcome
    status.code                                                    AS status_code,
    status.message                                                 AS status_message,
    attributes:['databricks.genie.status']::string                 AS genie_status,
    attributes:['databricks.genie.error_code']::string             AS error_code,
    attributes:['databricks.genie_code.run.outcome']::string       AS run_outcome,

    -- Completeness / truncation markers
    attributes:['databricks.genie_code.content_omitted']::string   AS content_omitted,
    attributes:['databricks.genie_code.truncated_fields']::string  AS truncated_fields,
    attributes:['databricks.trace.payload_truncated']::string      AS payload_truncated,
    attributes:['databricks.genie_code.expected_span_count']::int  AS expected_span_count,
    attributes:['databricks.genie_code.dropped_span_count']::int   AS dropped_span_count,
    attributes:['databricks.genie_code.trace_schema_version']::string AS trace_schema_version,

    -- Links to approval / question spans from an earlier trace in the same chat
    transform(links, l -> l.trace_id)                              AS linked_trace_ids,
    transform(links, l -> l.span_id)                               AS linked_span_ids,

    attributes
  FROM roots
),
messages AS (
  SELECT
    *,
    from_json(input_messages_raw,
      'ARRAY<STRUCT<role:STRING, content:STRING, parts:ARRAY<STRUCT<type:STRING, content:STRING, text:STRING>>>>') AS input_msgs,
    from_json(output_messages_raw,
      'ARRAY<STRUCT<role:STRING, content:STRING, parts:ARRAY<STRUCT<type:STRING, content:STRING, text:STRING>>>>') AS output_msgs
  FROM typed
)
SELECT
  -- When
  started_at, ended_at, duration_ms, date,
  -- Who and where
  workspace_id, requester, principal_id,
  -- Keys
  conversation_id, trace_id, span_id, product,

  -- Text the user typed and read (flat: scanned for PII / injection, may carry PII row to row)
  coalesce(
    nullif(array_join(filter(flatten(transform(input_msgs, m ->
      CASE WHEN m.parts IS NOT NULL
           THEN transform(filter(m.parts, p -> p.type IS NULL OR p.type = 'text'), p -> coalesce(p.content, p.text))
           ELSE array(m.content) END)), x -> x IS NOT NULL), '\n'), ''),
    input_messages_raw)                                             AS prompt,
  coalesce(
    nullif(array_join(filter(flatten(transform(output_msgs, m ->
      CASE WHEN m.parts IS NOT NULL
           THEN transform(filter(m.parts, p -> p.type IS NULL OR p.type = 'text'), p -> coalesce(p.content, p.text))
           ELSE array(m.content) END)), x -> x IS NOT NULL), '\n'), ''),
    output_messages_raw)                                            AS response,
  citations,
  input_messages_raw,
  output_messages_raw,

  -- Headline outcome
  status_code = 'STATUS_CODE_ERROR'                                 AS is_error,
  coalesce(run_outcome = 'refusal', false)                          AS is_refusal,

  -- Detail, grouped
  named_struct(
    'status_code',    status_code,
    'status_message', status_message,
    'genie_status',   genie_status,
    'error_code',     error_code,
    'run_outcome',    run_outcome
  )                                                                 AS outcome,
  named_struct(
    'channel',           channel,
    'surface',           surface,
    'agent_name',        agent_name,
    'agent_id',          agent_id,
    'scheduled_task_id', scheduled_task_id,
    'actor_resource',    actor_resource,
    'response_id',       response_id,
    'account_id',        account_id,
    'metastore_id',      metastore_id
  )                                                                 AS context,
  named_struct(
    'record_id',    record_id,
    'time',         time,
    'service_name', service_name,
    'span_name',    span_name,
    'span_kind',    span_kind
  )                                                                 AS span,
  named_struct(
    'payload_truncated',    payload_truncated,
    'truncated_fields',     truncated_fields,
    'content_omitted',      content_omitted,
    'expected_span_count',  expected_span_count,
    'dropped_span_count',   dropped_span_count,
    'trace_schema_version', trace_schema_version
  )                                                                 AS completeness,
  named_struct(
    'linked_trace_ids', linked_trace_ids,
    'linked_span_ids',  linked_span_ids
  )                                                                 AS links,
  attributes
FROM messages;
