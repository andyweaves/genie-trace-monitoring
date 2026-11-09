# Databricks notebook source
# MAGIC %md
# MAGIC # Detection utilities (shared)
# MAGIC
# MAGIC Helpers shared by the detection notebooks via `%run ./_detection_utils`.
# MAGIC
# MAGIC * Reads configuration from job parameters / widgets.
# MAGIC * Creates the `genie_detections` table if it does not exist.
# MAGIC * Builds the set of text fields (prompt, response, tool arguments, tool results, model
# MAGIC   output) that a detector has not scanned yet.
# MAGIC * Idempotently MERGEs detector output into `genie_detections`.

# COMMAND ----------

# MAGIC %md
# MAGIC ## Configuration

# COMMAND ----------

dbutils.widgets.text("catalog", "unity_gateway", "Catalog")
dbutils.widgets.text("schema", "genie_tracing", "Schema")
dbutils.widgets.text("libs_volume", "genie_tracing_libs", "Libraries volume")
dbutils.widgets.text("prompt_guard_endpoint", "genie-prompt-guard-2", "Prompt Guard endpoint")
dbutils.widgets.text("lookback_days", "7", "Detection lookback (days)")

CATALOG = dbutils.widgets.get("catalog")
SCHEMA = dbutils.widgets.get("schema")
LIBS_VOLUME = dbutils.widgets.get("libs_volume")
PROMPT_GUARD_ENDPOINT = dbutils.widgets.get("prompt_guard_endpoint")
LOOKBACK_DAYS = int(dbutils.widgets.get("lookback_days"))

FQ = f"`{CATALOG}`.`{SCHEMA}`"
TURNS = f"{FQ}.genie_turns"
TOOL_CALLS = f"{FQ}.genie_tool_calls"
DETECTIONS = f"{FQ}.genie_detections"
VOLUME_PATH = f"/Volumes/{CATALOG}/{SCHEMA}/{LIBS_VOLUME}"

print(f"catalog.schema     : {CATALOG}.{SCHEMA}")
print(f"detections table   : {DETECTIONS}")
print(f"lookback           : {LOOKBACK_DAYS} days")
print(f"prompt guard       : {PROMPT_GUARD_ENDPOINT}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Detections table
# MAGIC
# MAGIC One row per (span, detector, field). `flagged = true` rows drive the session flags and
# MAGIC alerts; `flagged = false` rows record that a field was scanned (or carry informational
# MAGIC signals) so it is not re-scanned on the next run. Columns lead with when / who, then the
# MAGIC verdict; the scanned span's identifiers sit in the `span` struct.

# COMMAND ----------

DETECTIONS_DDL = f"""
CREATE TABLE IF NOT EXISTS {DETECTIONS} (
  span_time       TIMESTAMP COMMENT 'Start time of the scanned span',
  detected_at     TIMESTAMP COMMENT 'When the detection row was written',
  workspace_id    STRING,
  requester       STRING,
  conversation_id STRING    COMMENT 'Conversation / session id',
  product         STRING    COMMENT 'Genie One or Genie Code',
  detector        STRING    COMMENT 'pii_presidio | pii_ai_extract | prompt_injection_prompt_guard | prompt_injection_ai_classify | guardrail_signal',
  flagged         BOOLEAN   COMMENT 'True when the detector considers this a finding',
  score           DOUBLE    COMMENT 'Detector confidence / severity in [0, 1]',
  label           STRING    COMMENT 'Detector-specific label (entity type, class, verdict, rule name)',
  span            STRUCT<trace_id: STRING, span_id: STRING, field: STRING, text_length: INT>
                            COMMENT 'What was scanned: the turn (trace_id), the span, the field (prompt | response | tool_arguments | tool_result | model_output | <rule name>) and its length',
  details         STRING    COMMENT 'JSON with detector-specific evidence (offsets, entities, matched text, ...)',
  detection_id    STRING    NOT NULL COMMENT 'sha2(span_id | detector | field); MERGE key'
)
CLUSTER BY (span_time, detector)
COMMENT 'Per-span detection results for Genie traces: PII, prompt injection and guardrail signals.'
TBLPROPERTIES ('delta.enableRowTracking' = 'true', 'delta.enableChangeDataFeed' = 'true')
"""


def ensure_detections_table():
    spark.sql(DETECTIONS_DDL)


ensure_detections_table()

# COMMAND ----------

# MAGIC %md
# MAGIC ## Candidate text fields
# MAGIC
# MAGIC Every free-text field in the flattened tables, one row per (span, field), limited to the
# MAGIC lookback window. `candidates(detector, fields)` removes rows the detector has already
# MAGIC scanned.

# COMMAND ----------

from pyspark.sql import functions as F

ALL_FIELDS = ["prompt", "response", "tool_arguments", "tool_result", "model_output"]


def text_fields(lookback_days: int = LOOKBACK_DAYS):
    """DataFrame of (trace_id, span_id, conversation_id, product, workspace_id, requester, span_time, field, text)."""
    since = f"current_timestamp() - INTERVAL {int(lookback_days)} DAYS"
    sql = f"""
    WITH t AS (
      SELECT trace_id, span_id, coalesce(conversation_id, trace_id) AS conversation_id, product, workspace_id,
             requester, started_at AS span_time, 'prompt' AS field, prompt AS text
      FROM {TURNS} WHERE started_at >= {since}
      UNION ALL
      SELECT trace_id, span_id, coalesce(conversation_id, trace_id), product, workspace_id,
             requester, started_at, 'response', response
      FROM {TURNS} WHERE started_at >= {since}
      UNION ALL
      SELECT trace_id, span_id, coalesce(conversation_id, trace_id), product, workspace_id,
             requester, started_at, 'tool_arguments', tool_arguments
      FROM {TOOL_CALLS} WHERE started_at >= {since} AND span_type IN ('tool_call', 'approval_request', 'user_question')
      UNION ALL
      SELECT trace_id, span_id, coalesce(conversation_id, trace_id), product, workspace_id,
             requester, started_at, 'tool_result', tool_result
      FROM {TOOL_CALLS} WHERE started_at >= {since} AND span_type IN ('tool_call', 'approval_request', 'user_question')
      UNION ALL
      -- model_call output, excluding the final answer that is already scanned as the turn's response
      SELECT c.trace_id, c.span_id, coalesce(c.conversation_id, c.trace_id), c.product, c.workspace_id,
             c.requester, c.started_at, 'model_output', c.response_text
      FROM {TOOL_CALLS} c
      WHERE c.started_at >= {since} AND c.span_type = 'model_call'
        AND NOT EXISTS (SELECT 1 FROM {TURNS} t WHERE t.trace_id = c.trace_id AND t.response = c.response_text)
    )
    SELECT * FROM t WHERE text IS NOT NULL AND length(trim(text)) > 0
    """
    return spark.sql(sql)


def candidates(detector: str, fields=None, lookback_days: int = LOOKBACK_DAYS):
    """Text fields not yet scanned by `detector`."""
    df = text_fields(lookback_days)
    if fields:
        df = df.where(df.field.isin(list(fields)))
    scanned = (
        spark.table(DETECTIONS)
        .where(f"detector = '{detector}'")
        .select(F.col("span.span_id").alias("span_id"), F.col("span.field").alias("field"))
        .distinct()
    )
    return df.join(scanned, on=["span_id", "field"], how="left_anti")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Writing detections
# MAGIC
# MAGIC `write_detections(df, detector)` expects the candidate columns plus `flagged`, `score`,
# MAGIC `label`, `details`, and optionally `error`. It derives `detection_id` and `detected_at` and
# MAGIC MERGEs, so re-running a detector over the same spans is safe.
# MAGIC
# MAGIC * **Evaluated once.** The scored rows are written to a staging table first and the MERGE and
# MAGIC   counts read from it, so a UDF or billed AI Function behind `df` runs exactly once.
# MAGIC * **Errors are retried.** Rows with a non-null `error` are not written, so the field is still a
# MAGIC   candidate on the next run (until it ages out of the lookback window).
# MAGIC * **Stable `detected_at`.** An existing row keeps its `detected_at` unless its verdict (`flagged`
# MAGIC   or `score`) changed, so alerts keyed on `detected_at` fire once per finding.
# MAGIC * **Window re-scoring.** With `rescore_since`, this detector's rows from that time on that are no
# MAGIC   longer produced are deleted in the same MERGE (used by the guardrail rules).

# COMMAND ----------

DETECTION_COLUMNS = [
    "span_time", "detected_at", "workspace_id", "requester",
    "conversation_id", "product", "detector", "flagged", "score", "label",
    "span", "details", "detection_id",
]


def write_detections(df, detector: str, rescore_since: str = None) -> int:
    """MERGE detector output into genie_detections. Returns the number of rows written.

    rescore_since: optional SQL timestamp expression. When set, rows for `detector` with
    span_time >= rescore_since that are not in `df` are deleted (full re-score of the window).
    """
    error_col = F.col("error").cast("string") if "error" in df.columns else F.lit(None).cast("string")
    out = (
        df.withColumn("detector", F.lit(detector))
        .withColumn("detection_id", F.sha2(F.concat_ws("|", F.col("span_id"), F.col("detector"), F.col("field")), 256))
        .withColumn("detected_at", F.current_timestamp())
        .withColumn("text_length", F.coalesce(F.col("text_length"), F.length("text")) if "text_length" in df.columns else F.length("text"))
        .withColumn("flagged", F.coalesce(F.col("flagged"), F.lit(False)))
        .withColumn("score", F.coalesce(F.col("score").cast("double"), F.lit(0.0)))
        .withColumn("details", F.col("details").cast("string"))
        .withColumn("span", F.struct(
            F.col("trace_id").alias("trace_id"),
            F.col("span_id").alias("span_id"),
            F.col("field").alias("field"),
            F.col("text_length").cast("int").alias("text_length"),
        ))
        .select(*DETECTION_COLUMNS, error_col.alias("error"))
    )

    # Materialise once: the MERGE and the counts below all read the staging table.
    staging = f"{FQ}.`_staging_detections_{detector}`"
    out.write.mode("overwrite").option("overwriteSchema", "true").saveAsTable(staging)
    try:
        stats = spark.sql(f"""
          SELECT count_if(error IS NULL)             AS n,
                 count_if(error IS NULL AND flagged) AS flagged,
                 count_if(error IS NOT NULL)         AS errors
          FROM {staging}
        """).first()
        if stats.errors:
            print(f"[{detector}] {stats.errors} rows failed to score; not written, will be retried next run")
        if stats.n == 0 and rescore_since is None:
            print(f"[{detector}] nothing new to write")
            return 0

        update_set = ",\n            ".join(f"{c} = s.{c}" for c in DETECTION_COLUMNS if c != "detected_at")
        delete_clause = (
            f"WHEN NOT MATCHED BY SOURCE AND d.detector = '{detector}' AND d.span_time >= {rescore_since} THEN DELETE"
            if rescore_since is not None else ""
        )
        spark.sql(f"""
          MERGE INTO {DETECTIONS} AS d
          USING (SELECT * EXCEPT (error) FROM {staging} WHERE error IS NULL) AS s
          ON d.detection_id = s.detection_id
          WHEN MATCHED THEN UPDATE SET
            {update_set},
            detected_at = CASE WHEN d.flagged <=> s.flagged AND d.score <=> s.score
                               THEN d.detected_at ELSE s.detected_at END
          WHEN NOT MATCHED THEN INSERT *
          {delete_clause}
        """)
        print(f"[{detector}] wrote {stats.n} rows, {stats.flagged} flagged")
        return stats.n
    finally:
        spark.sql(f"DROP TABLE IF EXISTS {staging}")
