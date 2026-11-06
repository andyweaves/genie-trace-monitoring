-- Access control for the genie_tracing schema.
--
-- The derived tables copy full prompts, responses, tool arguments and tool results out of the
-- unified trace table. Anyone with SELECT can read every Genie conversation across every
-- workspace attached to the metastore, including data they could not otherwise query.
-- Apply these before granting access beyond the security team.
--
-- Replace <catalog>, <schema>, <security_group>, <workspace_admin_group> before running.

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
-- 4. ABAC on governed tags (Beta): mask every column tagged class.* in this schema, for
--    everyone except the security group. Covers tags set by Data Classification and by
--    02_detect_pii. Create via Catalog Explorer → schema → Policies, or:
-- ---------------------------------------------------------------------------------------------
-- CREATE POLICY mask_pii_in_genie_tracing
--   ON SCHEMA <catalog>.<schema>
--   COLUMN MASK <catalog>.<schema>.mask_text
--   TO `account users`
--   EXCEPT `<security_group>`
--   FOR TABLES
--   MATCH COLUMNS hasTagValue('class.email_address') OR hasTag('class.name') OR hasTag('class.phone_number')
--                 OR hasTag('class.credit_card') OR hasTag('class.us_ssn') OR hasTag('class.location') AS col
--   ON COLUMN col;

-- ---------------------------------------------------------------------------------------------
-- 5. Retention: traces are not deleted when a Genie conversation is deleted.
--    Decide how long to keep derived rows and enforce it on the detections table.
-- ---------------------------------------------------------------------------------------------
-- DELETE FROM <catalog>.<schema>.genie_detections WHERE span_time < current_timestamp() - INTERVAL 180 DAYS;
