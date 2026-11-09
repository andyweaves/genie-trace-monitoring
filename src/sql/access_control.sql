-- Access control for the genie_tracing schema.
--
-- The derived tables copy full prompts, responses, tool arguments and tool results out of the
-- unified trace table. Anyone with SELECT can read every Genie conversation across every
-- workspace attached to the metastore, including data they could not otherwise query.
-- Apply these before granting access beyond the security team.
--
-- Replace <catalog>, <schema>, <security_group>, <workspace_admin_group> and
-- <pipeline_and_job_identity> (section 4) before running.

-- ---------------------------------------------------------------------------------------------
-- 1. Baseline grants: security reviewers get read, nobody else.
-- ---------------------------------------------------------------------------------------------
GRANT USE CATALOG ON CATALOG <catalog> TO `<security_group>`;
GRANT USE SCHEMA, SELECT ON SCHEMA <catalog>.<schema> TO `<security_group>`;

-- ---------------------------------------------------------------------------------------------
-- 2. Row filter: workspace admins only see their own workspace's sessions.
--    The function compares the row's workspace_id to a mapping table you maintain.
-- ---------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS <catalog>.<schema>.workspace_admin_mapping (
  group_name   STRING,
  workspace_id STRING
);

CREATE OR REPLACE FUNCTION <catalog>.<schema>.filter_by_workspace(ws STRING)
RETURNS BOOLEAN
RETURN is_account_group_member('<security_group>')
    OR EXISTS (
      SELECT 1 FROM <catalog>.<schema>.workspace_admin_mapping m
      WHERE m.workspace_id = ws AND is_account_group_member(m.group_name)
    );

-- Row filters cannot be set on materialized views after the fact; declare them in the
-- pipeline SQL (WITH ROW FILTER ... ON (workspace_id)) or filter inside a view:
CREATE OR REPLACE VIEW <catalog>.<schema>.genie_sessions_scoped AS
SELECT * FROM <catalog>.<schema>.genie_sessions
WHERE <catalog>.<schema>.filter_by_workspace(workspace_id);

CREATE OR REPLACE VIEW <catalog>.<schema>.genie_session_timeline_scoped AS
SELECT * FROM <catalog>.<schema>.genie_session_timeline
WHERE <catalog>.<schema>.filter_by_workspace(workspace_id);

GRANT SELECT ON VIEW <catalog>.<schema>.genie_sessions_scoped TO `<workspace_admin_group>`;
GRANT SELECT ON VIEW <catalog>.<schema>.genie_session_timeline_scoped TO `<workspace_admin_group>`;

-- ---------------------------------------------------------------------------------------------
-- 3. Column mask: redact prompt / response text for anyone outside the security group.
-- ---------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION <catalog>.<schema>.mask_text(txt STRING)
RETURNS STRING
RETURN CASE WHEN is_account_group_member('<security_group>') THEN txt
            ELSE '[redacted: ' || length(txt) || ' chars]' END;

-- Apply inside the scoped views (masks on MVs must be declared in the pipeline definition):
CREATE OR REPLACE VIEW <catalog>.<schema>.genie_sessions_scoped AS
SELECT * EXCEPT (context),
       named_struct(
         'channel',           context.channel,
         'agent_name',        context.agent_name,
         'scheduled_task_id', context.scheduled_task_id,
         'first_prompt',      <catalog>.<schema>.mask_text(context.first_prompt),
         'last_response',     <catalog>.<schema>.mask_text(context.last_response),
         'last_turn_outcome', context.last_turn_outcome,
         'trace_ids',         context.trace_ids
       ) AS context
FROM <catalog>.<schema>.genie_sessions
WHERE <catalog>.<schema>.filter_by_workspace(workspace_id);

-- ---------------------------------------------------------------------------------------------
-- 4. ABAC on governed tags: mask every column carrying one of the class.* tags 02_detect_pii
--    applies (ENTITY_TO_CLASS_TAG), for everyone except the security group. Data Classification
--    applies the same tags, so one policy covers both. Create via Catalog Explorer → schema →
--    Policies, or with the statement below.
--
--    Before you create it:
--    * EXCEPT the identities that run the two pipelines and the job (the bundle deployer, or
--      the prod run_as user / service principal). Pipelines evaluate policies as their owner or
--      run-as identity: if that identity is masked, genie_sessions permanently stores masked
--      text, and the detection notebooks scan "[redacted: N chars]" instead of the prompt.
--    * Tags only land on the columns 02 scans: genie_turns.prompt / response and
--      genie_tool_calls.tool_arguments / tool_result / response_text. The same text is also in
--      input_messages_raw, output_messages_raw, the attributes VARIANT and
--      genie_sessions.context, which are not tagged. Keep the grants in section 1 as the
--      primary control; this policy narrows what a granted reader sees.
--    * Keep the tag list in step with ENTITY_TO_CLASS_TAG in 02_detect_pii.
--    * Needs serverless or DBR 16.4+ to read the masked tables, and EXECUTE on mask_text.
-- ---------------------------------------------------------------------------------------------
-- CREATE POLICY mask_pii_in_genie_tracing
--   ON SCHEMA <catalog>.<schema>
--   COMMENT 'Mask Genie text columns tagged with a PII class, except for the security group'
--   COLUMN MASK <catalog>.<schema>.mask_text
--   TO `account users`
--   EXCEPT `<security_group>`, `<pipeline_and_job_identity>`
--   FOR TABLES
--   MATCH COLUMNS
--        has_tag('class.name')            OR has_tag('class.email_address')     OR has_tag('class.phone_number')
--     OR has_tag('class.location')        OR has_tag('class.date_of_birth')
--     OR has_tag('class.credit_card')     OR has_tag('class.iban_code')         OR has_tag('class.us_bank_number')
--     OR has_tag('class.us_ssn')          OR has_tag('class.us_itin')
--     OR has_tag('class.us_passport')     OR has_tag('class.us_driver_license') OR has_tag('class.uk_nhs')
--     OR has_tag('class.medical_license')
--     OR has_tag('class.ip_address')      OR has_tag('class.mac_address')       OR has_tag('class.url')
--   AS col
--   ON COLUMN col;

-- ---------------------------------------------------------------------------------------------
-- 5. Retention: traces are not deleted when a Genie conversation is deleted.
--    Decide how long to keep derived rows and enforce it on the detections table.
-- ---------------------------------------------------------------------------------------------
-- DELETE FROM <catalog>.<schema>.genie_detections WHERE span_time < current_timestamp() - INTERVAL 180 DAYS;
