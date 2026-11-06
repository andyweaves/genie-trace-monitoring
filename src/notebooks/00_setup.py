# Databricks notebook source
# MAGIC %md
# MAGIC # 00 · Setup
# MAGIC
# MAGIC One-time preparation for the Genie trace monitoring accelerator.
# MAGIC
# MAGIC | Step | What it does |
# MAGIC |---|---|
# MAGIC | 1 | Checks the Unity Gateway trace table is reachable and shows which Genie products are exporting |
# MAGIC | 2 | Creates the target schema, volume and the empty `genie_detections` table |
# MAGIC | 3 | Stages the spaCy English model wheel used by Presidio in the volume |
# MAGIC | 4 | Reports Data Classification status and how to enable it |
# MAGIC | 5 | Prints the preview checklist for Genie One / Genie Code tracing |
# MAGIC
# MAGIC Run on serverless compute. Safe to re-run.

# COMMAND ----------

# MAGIC %md
# MAGIC ## Configuration

# COMMAND ----------

dbutils.widgets.text("catalog", "unity_gateway", "Catalog")
dbutils.widgets.text("schema", "genie_tracing", "Schema")
dbutils.widgets.text("libs_volume", "genie_tracing_libs", "Libraries volume")
dbutils.widgets.text("source_table", "unity_gateway.unified_tracing.unity_gateway_otel_spans", "Unified trace table")
dbutils.widgets.text("spacy_model", "en_core_web_md", "spaCy model")
dbutils.widgets.text("spacy_version", "3.8.0", "spaCy model version")

CATALOG = dbutils.widgets.get("catalog")
SCHEMA = dbutils.widgets.get("schema")
LIBS_VOLUME = dbutils.widgets.get("libs_volume")
SOURCE_TABLE = dbutils.widgets.get("source_table")
SPACY_MODEL = dbutils.widgets.get("spacy_model")
SPACY_VERSION = dbutils.widgets.get("spacy_version")

FQ = f"`{CATALOG}`.`{SCHEMA}`"
VOLUME_PATH = f"/Volumes/{CATALOG}/{SCHEMA}/{LIBS_VOLUME}"
WHEEL_DIR = f"{VOLUME_PATH}/wheels"
WHEEL_NAME = f"{SPACY_MODEL}-{SPACY_VERSION}-py3-none-any.whl"
WHEEL_URL = f"https://github.com/explosion/spacy-models/releases/download/{SPACY_MODEL}-{SPACY_VERSION}/{WHEEL_NAME}"

# COMMAND ----------

# MAGIC %md
# MAGIC ## 1 · Check the source trace table
# MAGIC
# MAGIC The unified trace table is shared with AI Gateway model traffic. Only rows with a Genie
# MAGIC `service_name` matter here. If Genie One shows zero traces, the **Genie One Tracing**
# MAGIC preview is probably off in this workspace, or nobody has used Genie One since it was enabled.

# COMMAND ----------

display(
    spark.sql(
        f"""
        SELECT service_name,
               COUNT(*)                   AS spans,
               COUNT(DISTINCT trace_id)   AS traces,
               MIN(time)                  AS first_seen,
               MAX(time)                  AS last_seen,
               CASE WHEN service_name IN ('Genie One', 'genie-code-agent') THEN 'Genie' ELSE 'other AI Gateway traffic' END AS category
        FROM {SOURCE_TABLE}
        GROUP BY service_name
        ORDER BY category, spans DESC
        """
    )
)

# COMMAND ----------

# MAGIC %md
# MAGIC ## 2 · Schema, volume and detections table
# MAGIC
# MAGIC The bundle creates the schema and volume too; these statements make the notebook usable
# MAGIC standalone.

# COMMAND ----------

spark.sql(f"CREATE SCHEMA IF NOT EXISTS {FQ} COMMENT 'Genie One / Genie Code trace monitoring'")
spark.sql(f"CREATE VOLUME IF NOT EXISTS {FQ}.`{LIBS_VOLUME}` COMMENT 'Wheels and model files for detection notebooks'")
dbutils.fs.mkdirs(WHEEL_DIR)

spark.sql(
    f"""
    CREATE TABLE IF NOT EXISTS {FQ}.genie_detections (
      span_time       TIMESTAMP,
      detected_at     TIMESTAMP,
      workspace_id    STRING,
      requester       STRING,
      conversation_id STRING,
      product         STRING,
      detector        STRING,
      flagged         BOOLEAN,
      score           DOUBLE,
      label           STRING,
      span            STRUCT<trace_id: STRING, span_id: STRING, field: STRING, text_length: INT>,
      details         STRING,
      detection_id    STRING    NOT NULL
    )
    CLUSTER BY (span_time, detector)
    COMMENT 'Per-span detection results for Genie traces: PII, prompt injection and guardrail signals.'
    TBLPROPERTIES ('delta.enableRowTracking' = 'true', 'delta.enableChangeDataFeed' = 'true')
    """
)
print(f"Schema {CATALOG}.{SCHEMA}, volume {VOLUME_PATH} and genie_detections are ready.")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 3 · Stage the spaCy model wheel for Presidio
# MAGIC
# MAGIC Presidio's NER recognisers (PERSON, LOCATION, ...) need a spaCy model. Serverless UDFs
# MAGIC have no internet access, so the model is installed from a wheel in the volume via the job's
# MAGIC environment `dependencies`. This cell downloads the wheel from GitHub. If your workspace
# MAGIC blocks GitHub egress (this one does), download it on your laptop and upload it to the path
# MAGIC printed below. Presidio still runs without the model, using pattern recognisers only
# MAGIC (email, phone, credit card, IBAN, IP, SSN, ...).

# COMMAND ----------

import os
import requests

wheel_path = f"{WHEEL_DIR}/{WHEEL_NAME}"

if os.path.exists(wheel_path):
    print(f"Wheel already staged: {wheel_path}")
else:
    try:
        print(f"Downloading {WHEEL_URL} ...")
        with requests.get(WHEEL_URL, stream=True, timeout=60) as r:
            r.raise_for_status()
            with open(wheel_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=1 << 20):
                    f.write(chunk)
        print(f"Staged {wheel_path} ({os.path.getsize(wheel_path) / 1e6:.1f} MB)")
    except Exception as e:  # noqa: BLE001
        print(f"Could not download the wheel ({type(e).__name__}: {e}).")
        print("Download it elsewhere and upload it to:")
        print(f"  {wheel_path}")
        print(f"  databricks fs cp {WHEEL_NAME} dbfs:{wheel_path} --profile <profile>")

display(dbutils.fs.ls(WHEEL_DIR))

# COMMAND ----------

# MAGIC %md
# MAGIC ## 4 · Data Classification
# MAGIC
# MAGIC Unity Catalog Data Classification scans column samples and applies governed `class.*`
# MAGIC tags (for example `class.email_address`, `class.name`, `class.us_ssn`). It is enabled per
# MAGIC catalog: **Catalog Explorer → catalog → Details → Data Classification → Enable**, choosing
# MAGIC all schemas or just `genie_tracing`. New tables are typically scanned within 24 hours.
# MAGIC
# MAGIC Classification is column-level: it tells you the `prompt` column *has contained* PII, not
# MAGIC which rows. Row-level findings come from `02_detect_pii` (Presidio), which also applies the
# MAGIC same `class.*` tags so ABAC policies can key off either source.

# COMMAND ----------

try:
    display(
        spark.sql(
            f"""
            SELECT table_name, column_name, class_tag, confidence, frequency, latest_detected_time
            FROM system.data_classification.results
            WHERE catalog_name = '{CATALOG}' AND schema_name = '{SCHEMA}' AND class_tag <> ''
            ORDER BY latest_detected_time DESC
            """
        )
    )
except Exception as e:  # noqa: BLE001
    print(f"Could not read system.data_classification.results ({type(e).__name__}). "
          "Access is account-admin only by default and requires serverless compute.")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 5 · Preview checklist
# MAGIC
# MAGIC All of the following must be true before Genie traces appear:
# MAGIC
# MAGIC 1. Unity Gateway is enabled for the account.
# MAGIC 2. An account admin has enabled **Enhanced Unity Gateway** (account console → Previews).
# MAGIC 3. A metastore admin has set up the unified trace table for this metastore.
# MAGIC 4. A workspace admin has turned on **Genie One Tracing** and/or **Genie Code Tracing**
# MAGIC    (username menu → Previews).
# MAGIC
# MAGIC Only new turns are exported after a preview is enabled; nothing is backfilled.
# MAGIC Trace delivery is best-effort. Audit logs remain the system of record for compliance.
