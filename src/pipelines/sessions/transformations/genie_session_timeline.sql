-- genie_session_timeline: every turn, tool call, approval request, user question and model
-- call in a conversation as one ordered list of steps, so a session can be walked through
-- start to end. Published as a plain view (cheap filter on conversation_id).
--
--   SELECT * FROM genie_session_timeline WHERE conversation_id = '...' ORDER BY step_number;

CREATE VIEW genie_session_timeline
COMMENT 'Ordered step-by-step timeline of each Genie conversation. Flat: when, who, position, event, input / output text, is_flagged. Structs: outcome, detections, span.'
AS
WITH turn_events AS (
  SELECT
    coalesce(conversation_id, trace_id) AS conversation_id,
    product, workspace_id, requester, context.channel AS channel,
    trace_id, span_id, CAST(NULL AS STRING) AS parent_span_id,
    started_at, ended_at, duration_ms,
    'turn'                               AS event_type,
    span.span_name                       AS event_name,
    CAST(NULL AS STRING)                 AS tool_name,
    prompt                               AS input_text,
    response                             AS output_text,
    outcome.status_code                  AS status_code,
    coalesce(outcome.run_outcome, outcome.genie_status) AS outcome,
    outcome.error_code                   AS error_code,
    is_error,
    is_refusal                           AS is_rejected_or_refused,
    started_at                           AS turn_started_at
  FROM ${catalog}.${schema}.genie_turns
),
child_events AS (
  SELECT
    coalesce(c.conversation_id, c.trace_id) AS conversation_id,
    c.product, c.workspace_id, c.requester, c.span.channel AS channel,
    c.trace_id, c.span_id, c.span.parent_span_id AS parent_span_id,
    c.started_at, c.ended_at, c.duration_ms,
    c.span_type                              AS event_type,
    c.span.span_name                         AS event_name,
    c.tool_name,
    c.tool_arguments                         AS input_text,
    coalesce(c.tool_result, c.response_text) AS output_text,
    c.outcome.status_code                    AS status_code,
    c.outcome.tool_outcome                   AS outcome,
    CAST(NULL AS STRING)                     AS error_code,
    c.is_error,
    c.is_rejected_or_denied                  AS is_rejected_or_refused,
    t.started_at                             AS turn_started_at
  FROM ${catalog}.${schema}.genie_tool_calls c
  LEFT JOIN ${catalog}.${schema}.genie_turns t ON t.trace_id = c.trace_id
),
events AS (
  SELECT * FROM turn_events
  UNION ALL
  SELECT * FROM child_events
),
flags AS (
  SELECT
    span.span_id AS span_id,
    array_sort(array_distinct(collect_list(detector || ':' || coalesce(label, '')))) AS flags,
    max(score) AS max_flag_score
  FROM ${catalog}.${schema}.genie_detections
  WHERE flagged
  GROUP BY span.span_id
),
ordered AS (
  SELECT
    e.*,
    f.flags, f.max_flag_score,
    dense_rank()  OVER (PARTITION BY e.conversation_id ORDER BY e.turn_started_at, e.trace_id) AS turn_number,
    row_number()  OVER (PARTITION BY e.conversation_id
                        ORDER BY e.turn_started_at, e.trace_id,
                                 CASE WHEN e.event_type = 'turn' THEN 0 ELSE 1 END,
                                 e.started_at, e.span_id)                                       AS step_number,
    lag(e.event_name)  OVER (PARTITION BY e.conversation_id
                             ORDER BY e.turn_started_at, e.trace_id,
                                      CASE WHEN e.event_type = 'turn' THEN 0 ELSE 1 END,
                                      e.started_at, e.span_id)                                  AS previous_event,
    lead(e.event_name) OVER (PARTITION BY e.conversation_id
                             ORDER BY e.turn_started_at, e.trace_id,
                                      CASE WHEN e.event_type = 'turn' THEN 0 ELSE 1 END,
                                      e.started_at, e.span_id)                                  AS next_event
  FROM events e
  LEFT JOIN flags f ON f.span_id = e.span_id
)
SELECT
  -- When
  started_at, ended_at, duration_ms,
  -- Who and where
  workspace_id, requester,
  -- Position in the conversation
  conversation_id, turn_number, step_number, product,
  -- What happened
  event_type, event_name, tool_name,
  -- Text (flat: may carry PII row to row)
  input_text, output_text,
  -- Headline flag
  coalesce(size(flags) > 0, false)                AS is_flagged,

  -- Detail, grouped
  named_struct(
    'status_code',            status_code,
    'outcome',                outcome,
    'error_code',             error_code,
    'is_error',               is_error,
    'is_rejected_or_refused', is_rejected_or_refused
  )                                               AS outcome,
  named_struct(
    'flags',          coalesce(flags, array()),
    'max_flag_score', max_flag_score
  )                                               AS detections,
  named_struct(
    'trace_id',       trace_id,
    'span_id',        span_id,
    'parent_span_id', parent_span_id,
    'channel',        channel,
    'previous_event', previous_event,
    'next_event',     next_event
  )                                               AS span
FROM ordered;
