-- genie_sessions: one row per Genie conversation (session) with activity rollups and
-- detection flags. Rebuilt after the detection notebooks run.
--
-- A session is a gen_ai.conversation.id. For Genie Code that is the notebook / chat; for
-- Genie One it is the chat thread. Turns with no conversation id fall back to their trace id.

CREATE OR REFRESH MATERIALIZED VIEW genie_sessions
CLUSTER BY (session_date, product)
COMMENT 'One row per Genie conversation. Flat: when/who, conversation_id, product, is_flagged, risk_score, severity. Structs: activity, flags, risk, feedback, context.'
TBLPROPERTIES ('quality' = 'gold')
AS
WITH turns AS (
  SELECT
    coalesce(conversation_id, trace_id) AS conversation_id,
    *
  EXCEPT (conversation_id)
  FROM ${catalog}.${schema}.genie_turns
),
turn_agg AS (
  SELECT
    conversation_id,
    min_by(product, started_at)                   AS product,
    min_by(workspace_id, started_at)              AS workspace_id,
    min_by(requester, started_at)                 AS requester,
    min_by(principal_id, started_at)              AS principal_id,
    min_by(context.channel, started_at)           AS channel,
    min_by(context.agent_name, started_at)        AS agent_name,
    max(context.scheduled_task_id)                AS scheduled_task_id,
    min(started_at)                               AS session_start,
    max(coalesce(ended_at, started_at))           AS session_end,
    CAST(min(started_at) AS DATE)                 AS session_date,
    count(*)                                      AS turn_count,
    count_if(is_error)                            AS error_turn_count,
    count_if(is_refusal)                          AS refusal_turn_count,
    count_if(context.scheduled_task_id IS NOT NULL) AS scheduled_turn_count,
    sum(duration_ms)                              AS total_turn_duration_ms,
    min_by(prompt, started_at)                    AS first_prompt,
    max_by(response, started_at)                  AS last_response,
    max_by(coalesce(outcome.run_outcome, outcome.genie_status, outcome.status_code), started_at) AS last_turn_outcome,
    sort_array(collect_list(trace_id))            AS trace_ids
  FROM turns
  GROUP BY conversation_id
),
tool_agg AS (
  SELECT
    coalesce(conversation_id, trace_id)           AS conversation_id,
    count_if(span_type = 'tool_call')             AS tool_call_count,
    count_if(span_type = 'tool_call' AND is_error) AS failed_tool_call_count,
    count_if(is_rejected_or_denied)               AS rejected_tool_call_count,
    count_if(span_type = 'approval_request')      AS approval_request_count,
    count_if(span_type = 'user_question' OR tool_name IN ('askUserQuestions', 'ask_user_questions')) AS user_question_count,
    count_if(span_type = 'model_call')            AS model_call_count,
    array_sort(array_distinct(collect_list(CASE WHEN span_type = 'tool_call' THEN tool_name END))) AS tools_used
  FROM ${catalog}.${schema}.genie_tool_calls
  GROUP BY coalesce(conversation_id, trace_id)
),
detections AS (
  SELECT
    conversation_id,
    bool_or(flagged AND detector LIKE 'pii_%')              AS has_pii,
    bool_or(flagged AND detector LIKE 'prompt_injection_%') AS has_prompt_injection,
    bool_or(flagged AND detector = 'guardrail_signal')      AS has_guardrail_signal,
    count_if(flagged)                                       AS flag_count,
    count(DISTINCT CASE WHEN flagged THEN span.trace_id END) AS flagged_turn_count,
    array_sort(array_distinct(collect_list(CASE WHEN flagged THEN detector END)))  AS flag_detectors,
    array_sort(array_distinct(collect_list(CASE WHEN flagged THEN label END)))     AS flag_labels,
    min(CASE WHEN flagged THEN detected_at END)             AS first_flagged_at,
    max(CASE WHEN flagged THEN detected_at END)             AS last_flagged_at,
    max(CASE WHEN flagged AND detector LIKE 'pii_%' THEN score END)              AS max_pii_score,
    max(CASE WHEN flagged AND detector LIKE 'prompt_injection_%' THEN score END) AS max_prompt_injection_score,
    max(CASE WHEN flagged AND detector = 'guardrail_signal' THEN score END)      AS max_guardrail_score,
    -- Every PII entity type found in the session (not only each finding's top label), from details
    array_sort(array_distinct(flatten(collect_list(
      CASE WHEN flagged AND detector LIKE 'pii_%'
           THEN transform(from_json(details:entities, 'ARRAY<STRUCT<type: STRING>>'), e -> e.type) END
    ))))                                                    AS pii_entity_types
  FROM ${catalog}.${schema}.genie_detections
  GROUP BY conversation_id
),
feedback AS (
  -- Latest state of each thumbs up / down annotation on a trace
  SELECT
    r.conversation_id,
    count_if(NOT f.thumbs_up) AS thumbs_down_count,
    count_if(f.thumbs_up)     AS thumbs_up_count
  FROM (
    SELECT
      target_id AS trace_id,
      try_cast(value::string AS BOOLEAN) AS thumbs_up,
      annotation_change_type,
      row_number() OVER (PARTITION BY annotation_id ORDER BY updated_at DESC) AS rn
    FROM ${annotations_table}
    WHERE name = 'user_feedback' AND target_type = 'TRACE'
  ) f
  JOIN turns r ON r.trace_id = f.trace_id
  WHERE f.rn = 1 AND f.annotation_change_type <> 'delete'
  GROUP BY r.conversation_id
),
risk_inputs AS (
  SELECT
    t.conversation_id,
    coalesce(d.has_pii OR d.has_prompt_injection OR d.has_guardrail_signal, false) AS is_flagged,
    -- PII scores are already weighted by entity type in 02_detect_pii, so they count in full.
    coalesce(d.max_pii_score, 0)
      + coalesce(d.max_prompt_injection_score, 0) * 0.8
      + coalesce(d.max_guardrail_score, 0)                                     AS base_score,
    CASE WHEN coalesce(c.rejected_tool_call_count, 0) > 0 THEN 0.2 ELSE 0.0 END AS rejected_tool_call_bonus,
    -- A name together with a date of birth, phone number or location identifies a person far
    -- better than either alone.
    CASE WHEN array_contains(d.pii_entity_types, 'PERSON')
              AND arrays_overlap(d.pii_entity_types, array('DATE_OF_BIRTH', 'PHONE_NUMBER', 'LOCATION'))
         THEN 0.2 ELSE 0.0 END                                                 AS pii_combination_bonus
  FROM turn_agg t
  LEFT JOIN tool_agg   c ON c.conversation_id = t.conversation_id
  LEFT JOIN detections d ON d.conversation_id = t.conversation_id
),
risk AS (
  SELECT
    *,
    least(1.0, base_score + rejected_tool_call_bonus + pii_combination_bonus) AS risk_score
  FROM risk_inputs
)
SELECT
  -- When and who
  t.session_date,
  t.session_start,
  t.session_end,
  round((unix_millis(t.session_end) - unix_millis(t.session_start)) / 60000.0, 2)::DOUBLE AS session_minutes,
  t.workspace_id,
  t.requester,
  t.principal_id,

  -- Keys and the two most-filtered flags stay flat
  t.conversation_id,
  t.product,
  r.is_flagged,
  r.risk_score,
  CASE WHEN NOT r.is_flagged    THEN 'none'
       WHEN r.risk_score >= 0.8 THEN 'high'
       WHEN r.risk_score >= 0.5 THEN 'medium'
       ELSE 'low' END                                                    AS severity,

  -- What happened in the session
  named_struct(
    'turn_count',               t.turn_count,
    'error_turn_count',         t.error_turn_count,
    'refusal_turn_count',       t.refusal_turn_count,
    'scheduled_turn_count',     t.scheduled_turn_count,
    'total_turn_duration_ms',   t.total_turn_duration_ms,
    'tool_call_count',          coalesce(c.tool_call_count, 0),
    'failed_tool_call_count',   coalesce(c.failed_tool_call_count, 0),
    'rejected_tool_call_count', coalesce(c.rejected_tool_call_count, 0),
    'approval_request_count',   coalesce(c.approval_request_count, 0),
    'user_question_count',      coalesce(c.user_question_count, 0),
    'model_call_count',         coalesce(c.model_call_count, 0),
    'tools_used',               coalesce(c.tools_used, array())
  )                                                                      AS activity,

  -- Detection flags and evidence pointers
  named_struct(
    'has_pii',              coalesce(d.has_pii, false),
    'has_prompt_injection', coalesce(d.has_prompt_injection, false),
    'has_guardrail_signal', coalesce(d.has_guardrail_signal, false),
    'flag_count',           coalesce(d.flag_count, 0),
    'flagged_turn_count',   coalesce(d.flagged_turn_count, 0),
    'flag_detectors',       coalesce(d.flag_detectors, array()),
    'flag_labels',          coalesce(d.flag_labels, array()),
    'pii_entity_types',     coalesce(d.pii_entity_types, array()),
    'first_flagged_at',     d.first_flagged_at,
    'last_flagged_at',      d.last_flagged_at
  )                                                                      AS flags,

  -- What drove risk_score = min(1, PII (weighted by entity type) + 0.8 x injection + guardrail
  -- + 0.2 if a tool call was rejected + 0.2 if a name appears with a DOB, phone or location).
  named_struct(
    'max_pii_score',              d.max_pii_score,
    'max_prompt_injection_score', d.max_prompt_injection_score,
    'max_guardrail_score',        d.max_guardrail_score,
    'rejected_tool_call_bonus',   r.rejected_tool_call_bonus::DOUBLE,
    'pii_combination_bonus',      r.pii_combination_bonus::DOUBLE
  )                                                                      AS risk,

  -- Thumbs up / down from the annotations table
  named_struct(
    'thumbs_up_count',   coalesce(fb.thumbs_up_count, 0),
    'thumbs_down_count', coalesce(fb.thumbs_down_count, 0)
  )                                                                      AS feedback,

  -- Enough context to recognise the session without opening it
  named_struct(
    'channel',           t.channel,
    'agent_name',        t.agent_name,
    'scheduled_task_id', t.scheduled_task_id,
    'first_prompt',      t.first_prompt,
    'last_response',     t.last_response,
    'last_turn_outcome', t.last_turn_outcome,
    'trace_ids',         t.trace_ids
  )                                                                      AS context
FROM turn_agg t
LEFT JOIN tool_agg   c  ON c.conversation_id  = t.conversation_id
LEFT JOIN detections d  ON d.conversation_id  = t.conversation_id
LEFT JOIN feedback   fb ON fb.conversation_id = t.conversation_id
JOIN      risk       r  ON r.conversation_id  = t.conversation_id;
