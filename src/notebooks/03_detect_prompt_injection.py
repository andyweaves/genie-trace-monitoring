# Databricks notebook source
# MAGIC %md
# MAGIC # 03 · Detect prompt injection and jailbreak attempts
# MAGIC
# MAGIC Two attack shapes matter for Genie:
# MAGIC
# MAGIC * **Direct**: the user types the attack into the prompt ("ignore your instructions and ...").
# MAGIC * **Indirect**: the attack arrives through data Genie reads: a table value returned by
# MAGIC   `execute_sql_query`, a web search result, an MCP tool response, or a notebook cell. The
# MAGIC   Genie Code auto-approve classifier deliberately excludes retrieved content from its
# MAGIC   decision context for this reason, but nothing surfaces the attempt to an admin.
# MAGIC
# MAGIC This notebook scans **prompts** (direct) and **tool results / model outputs** (indirect) with
# MAGIC two detectors:
# MAGIC
# MAGIC | Section | Detector | How | Notes |
# MAGIC |---|---|---|---|
# MAGIC | 1 | `prompt_injection_prompt_guard` | `ai_query()` to the Llama Prompt Guard 2 endpoint from `01_deploy_prompt_guard` | Deterministic, cheap, every row |
# MAGIC | 2 | `prompt_injection_ai_classify` | `ai_classify()` second opinion | LLM judge on flagged rows plus a random sample |
# MAGIC
# MAGIC Findings roll up to `genie_sessions.flags.has_prompt_injection`.

# COMMAND ----------

# MAGIC %run ./_detection_utils

# COMMAND ----------

# MAGIC %md
# MAGIC ## Configuration

# COMMAND ----------

dbutils.widgets.text("prompt_guard_threshold", "0.85", "Prompt Guard malicious threshold")
dbutils.widgets.dropdown("run_ai_classify", "true", ["false", "true"], "Run ai_classify second opinion")
dbutils.widgets.text("ai_classify_sample", "20", "Random sample rows for ai_classify")

PG_THRESHOLD = float(dbutils.widgets.get("prompt_guard_threshold"))
RUN_AI_CLASSIFY = dbutils.widgets.get("run_ai_classify") == "true"
AI_CLASSIFY_SAMPLE = int(dbutils.widgets.get("ai_classify_sample"))

DIRECT_FIELDS = ["prompt"]
INDIRECT_FIELDS = ["tool_result", "model_output"]

# COMMAND ----------

# MAGIC %md
# MAGIC ## 0 · Check the Prompt Guard endpoint

# COMMAND ----------

from databricks.sdk import WorkspaceClient
from databricks.sdk.service.serving import EndpointStateReady

ws = WorkspaceClient()
try:
    ep = ws.serving_endpoints.get(PROMPT_GUARD_ENDPOINT)
    print(f"{PROMPT_GUARD_ENDPOINT}: state={ep.state.ready}, config_update={ep.state.config_update}")
    PROMPT_GUARD_AVAILABLE = ep.state.ready == EndpointStateReady.READY  # NOT_READY must not match
except Exception as e:  # noqa: BLE001
    print(f"Endpoint {PROMPT_GUARD_ENDPOINT} not available ({type(e).__name__}). Run 01_deploy_prompt_guard first.")
    PROMPT_GUARD_AVAILABLE = False

# COMMAND ----------

# MAGIC %md
# MAGIC ## 1 · Prompt Guard 2 via `ai_query`
# MAGIC
# MAGIC `ai_query` fans the rows out to the endpoint and parses the response into a STRUCT. The
# MAGIC endpoint chunks long text internally and returns the maximum malicious probability.
# MAGIC `failOnError => false` keeps one bad row from failing the whole scan; rows that errored are
# MAGIC not written, so they are retried on the next run.

# COMMAND ----------

from pyspark.sql import functions as F

if PROMPT_GUARD_AVAILABLE:
    pg_candidates = candidates("prompt_injection_prompt_guard", fields=DIRECT_FIELDS + INDIRECT_FIELDS)
    print(f"Fields to scan with Prompt Guard: {pg_candidates.count()}")
    pg_candidates.createOrReplaceTempView("_pg_candidates")

    scored = spark.sql(
        f"""
        SELECT *,
               ai_query('{PROMPT_GUARD_ENDPOINT}',
                        named_struct('text', text),
                        returnType  => 'STRUCT<label:STRING, score:DOUBLE, flagged:BOOLEAN, n_chunks:INT>',
                        failOnError => false) AS pg
        FROM _pg_candidates
        """
    )

    pg_detections = (
        scored
        .withColumn("score", F.coalesce(F.col("pg.result.score"), F.lit(0.0)))
        .withColumn("flagged", F.col("score") >= F.lit(PG_THRESHOLD))
        .withColumn("label", F.when(F.col("flagged"), F.lit("MALICIOUS")).otherwise(F.lit("BENIGN")))
        .withColumn("details", F.to_json(F.struct(
            F.when(F.col("field").isin(DIRECT_FIELDS), F.lit("direct")).otherwise(F.lit("indirect")).alias("vector"),
            F.col("pg.result.n_chunks").alias("n_chunks"),
        )))
        .withColumn("error", F.when(F.col("pg.result").isNull(),
                                    F.coalesce(F.col("pg.errorMessage"), F.lit("no result from endpoint"))))
        .drop("pg")
    )
    write_detections(pg_detections, "prompt_injection_prompt_guard")
else:
    print("Prompt Guard scan skipped.")

# COMMAND ----------

display(
    spark.sql(
        f"""
        SELECT product, span.field AS field, details:vector::string AS vector, flagged, COUNT(*) AS spans, ROUND(AVG(score), 3) AS avg_score, ROUND(MAX(score), 3) AS max_score
        FROM {DETECTIONS}
        WHERE detector = 'prompt_injection_prompt_guard'
        GROUP BY ALL ORDER BY flagged DESC, spans DESC
        """
    )
)

# COMMAND ----------

# MAGIC %md
# MAGIC ## 2 · `ai_classify` second opinion
# MAGIC
# MAGIC A foundation model judge catches semantic attacks a small classifier misses. With only two
# MAGIC labels it over-reaches: "Drop this table" was classed as an injection in testing. A third
# MAGIC class, *destructive or boundary-pushing request*, absorbs those; they are recorded but do not
# MAGIC flag the session (the rules in `04_detect_guardrail_signals` cover that). The judge is billed
# MAGIC per call and non-deterministic, so it runs on rows Prompt Guard flagged plus a random sample.
# MAGIC Disagreements between the two detectors are the rows worth reviewing.

# COMMAND ----------

if RUN_AI_CLASSIFY:
    flagged_rows = (
        spark.table(DETECTIONS)
        .where("detector = 'prompt_injection_prompt_guard' AND flagged")
        .select(F.col("span.span_id").alias("span_id"), F.col("span.field").alias("field"))
    )
    base = candidates("prompt_injection_ai_classify", fields=DIRECT_FIELDS + INDIRECT_FIELDS)
    to_judge = (
        base.join(flagged_rows, on=["span_id", "field"], how="left_semi")
        .unionByName(base.orderBy(F.rand()).limit(AI_CLASSIFY_SAMPLE))
        .dropDuplicates(["span_id", "field"])
    )
    to_judge.createOrReplaceTempView("_ai_classify_candidates")

    judged = spark.sql(
        """
        SELECT *,
               ai_classify(
                 substr(text, 1, 8000),
                 array('legitimate data or coding request',
                       'destructive or boundary-pushing request',
                       'prompt injection or jailbreak attempt')
               ) AS verdict
        FROM _ai_classify_candidates
        """
    )
    ai_detections = (
        judged
        .withColumn("flagged", F.col("verdict") == F.lit("prompt injection or jailbreak attempt"))
        # Boundary-pushing requests are recorded (score 0.3, not flagged) so they show in the timeline
        # without marking the session as a prompt-injection case; the regex rules in 04 handle those.
        .withColumn("score", F.when(F.col("flagged"), F.lit(0.7))
                              .when(F.col("verdict") == F.lit("destructive or boundary-pushing request"), F.lit(0.3))
                              .otherwise(F.lit(0.0)))
        .withColumn("label", F.col("verdict"))
        .withColumn("details", F.to_json(F.struct(
            F.when(F.col("field").isin(DIRECT_FIELDS), F.lit("direct")).otherwise(F.lit("indirect")).alias("vector"))))
        .withColumn("error", F.when(F.col("verdict").isNull(), F.lit("ai_classify returned null")))
        .drop("verdict")
    )
    write_detections(ai_detections, "prompt_injection_ai_classify")
else:
    print("ai_classify skipped.")

# COMMAND ----------

# MAGIC %md
# MAGIC ### Where the detectors disagree

# COMMAND ----------

display(
    spark.sql(
        f"""
        SELECT pg.product, pg.span.field AS field, pg.conversation_id, pg.span.span_id AS span_id,
               pg.score AS prompt_guard_score, pg.flagged AS prompt_guard_flagged,
               ac.label AS ai_classify_label, ac.flagged AS ai_classify_flagged
        FROM {DETECTIONS} pg
        JOIN {DETECTIONS} ac
          ON ac.span.span_id = pg.span.span_id AND ac.span.field = pg.span.field AND ac.detector = 'prompt_injection_ai_classify'
        WHERE pg.detector = 'prompt_injection_prompt_guard'
          AND pg.flagged <> ac.flagged
        ORDER BY pg.score DESC
        """
    )
)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Related platform control: Unity Gateway service policies
# MAGIC
# MAGIC The built-in `system.ai.block_jailbreak` service policy evaluates jailbreak and prompt
# MAGIC injection inline for Model Services and MCP Services registered in Unity Catalog, and
# MAGIC records each decision in the unified trace table's `events` column. It does not cover Genie
# MAGIC itself, so the after-the-fact scan above is still needed for Genie traffic, but the two work
# MAGIC well together: the policy protects MCP tools Genie calls, the scan catches what reached Genie.
