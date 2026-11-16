# Databricks notebook source
# MAGIC %md
# MAGIC # Deploy Lakewatch detection rules
# MAGIC
# MAGIC Turns the findings in `genie_detections` (and the composite risk in `genie_sessions`) into
# MAGIC [Lakewatch](https://docs.databricks.com/aws/en/lakewatch/) detection rules, each with MITRE
# MAGIC ATT&CK and ATLAS mappings, OWASP LLM / Agentic Top 10 and DASF annotations, an objective and
# MAGIC a triage runbook. The rules are defined in `src/lakewatch/rule_catalog.yml`. This notebook
# MAGIC validates them, optionally previews them over recent data, and creates or updates them through
# MAGIC the Lakewatch rules API (`/api/2.0/lakewatch/rules`, Beta). There is no bundle resource for
# MAGIC Lakewatch rules yet, so the `genie_tracing_setup` job runs this notebook instead.
# MAGIC
# MAGIC | Mode | What it does |
# MAGIC |---|---|
# MAGIC | `dry_run` | Validate, preview and show the plan plus each rule's YAML (for **Edit as YAML** in the UI). Changes nothing. |
# MAGIC | `deploy` | As `dry_run`, then create new rules and update changed ones. With `prune = true`, also delete rules this repo created that are no longer in the catalog. |
# MAGIC
# MAGIC **Prerequisites**: Lakewatch enabled in the workspace, a serverless or pro SQL warehouse for
# MAGIC detections, and `SELECT` on the genie_tracing tables for the principal the rules run as
# MAGIC (`run_as_principal`, default: whoever runs this notebook).

# COMMAND ----------

# MAGIC %run ./_lakewatch_utils

# COMMAND ----------

# MAGIC %md
# MAGIC ## 1. Parameters
# MAGIC
# MAGIC `catalog` / `schema` locate the genie_tracing tables that rules read. `lakewatch_catalog` /
# MAGIC `lakewatch_schema` is where the rules are created in Unity Catalog. The catalog must be one
# MAGIC Lakewatch is set up for.

# COMMAND ----------

import json
import os

dbutils.widgets.text("catalog", "unity_gateway", "Catalog of the genie_tracing tables")
dbutils.widgets.text("schema", "genie_tracing", "Schema of the genie_tracing tables")
dbutils.widgets.text("lakewatch_catalog", "", "Lakewatch catalog for the rules (default: catalog)")
dbutils.widgets.text("lakewatch_schema", "", "Schema for the rules (default: schema)")
dbutils.widgets.text("warehouse_id", "", "SQL warehouse ID that runs the rules")
dbutils.widgets.text("rule_catalog_file", "../lakewatch/rule_catalog.yml", "Rule catalog YAML")
dbutils.widgets.text("run_as_principal", "", "Run rules as (user email or SP application ID; blank = you)")
dbutils.widgets.text("schedule", "", "Override schedule for every rule, e.g. 1h (blank = catalog)")
dbutils.widgets.dropdown("enabled", "true", ["true", "false"], "Rules scheduled")
dbutils.widgets.dropdown("mode", "dry_run", ["dry_run", "deploy"], "Mode")
dbutils.widgets.dropdown("prune", "false", ["false", "true"], "Delete managed rules no longer in the catalog")
dbutils.widgets.text("preview_days", "7", "Preview each rule over the last N days (0 = skip)")
dbutils.widgets.text("rules", "", "Only these rules (comma-separated; blank = all)")

CATALOG = dbutils.widgets.get("catalog").strip()
SCHEMA = dbutils.widgets.get("schema").strip()
LW_CATALOG = dbutils.widgets.get("lakewatch_catalog").strip() or CATALOG
LW_SCHEMA = dbutils.widgets.get("lakewatch_schema").strip() or SCHEMA
WAREHOUSE_ID = dbutils.widgets.get("warehouse_id").strip()
RULE_CATALOG_FILE = os.path.abspath(dbutils.widgets.get("rule_catalog_file").strip())
RUN_AS = dbutils.widgets.get("run_as_principal").strip() or None
SCHEDULE = dbutils.widgets.get("schedule").strip() or None
ENABLED = dbutils.widgets.get("enabled") == "true"
MODE = dbutils.widgets.get("mode")
PRUNE = dbutils.widgets.get("prune") == "true"
PREVIEW_DAYS = int(dbutils.widgets.get("preview_days") or 0)
ONLY = {r.strip() for r in dbutils.widgets.get("rules").split(",") if r.strip()}

if not WAREHOUSE_ID:
    raise ValueError("warehouse_id is required: Lakewatch rules run on a SQL warehouse")
if SCHEDULE and not DURATION_RE.match(SCHEDULE):
    raise ValueError(f"schedule {SCHEDULE!r} is not a duration such as 1h or 15m")

FQ = f"`{CATALOG}`.`{SCHEMA}`"
CTX = dict(
    catalog_name=LW_CATALOG, schema_name=LW_SCHEMA, warehouse_id=WAREHOUSE_ID,
    detections=f"{FQ}.genie_detections", sessions=f"{FQ}.genie_sessions",
    timeline=f"{FQ}.genie_session_timeline",
    run_as_principal=RUN_AS, enabled=ENABLED, schedule=SCHEDULE,
)
print(f"mode={MODE} prune={PRUNE}; rules in {LW_CATALOG}.{LW_SCHEMA}, reading {FQ}, warehouse {WAREHOUSE_ID}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 2. Lakewatch API client
# MAGIC
# MAGIC Thin wrapper over the workspace REST client, using the notebook's own credentials. Listing
# MAGIC is paged and scoped to the target catalog and schema.

# COMMAND ----------

from databricks.sdk import WorkspaceClient

w = WorkspaceClient()
API = "/api/2.0/lakewatch"


def lw(method, path, query=None, body=None):
    return w.api_client.do(method, f"{API}/{path}", query=query, body=body) or {}


def list_rules():
    rules, token = [], None
    while True:
        query = {"catalog_name": LW_CATALOG, "schema_name": LW_SCHEMA, "page_size": 100}
        if token:
            query["page_token"] = token
        page = lw("GET", "rules", query=query)
        rules += page.get("rules", [])
        token = page.get("next_page_token")
        if not token:
            return rules


try:
    rule_config = lw("GET", f"catalogs/{LW_CATALOG}/ruleConfig")
except Exception as e:
    raise RuntimeError(
        f"Lakewatch API not reachable for catalog {LW_CATALOG!r}. Check that Lakewatch is enabled "
        f"in this workspace and that lakewatch_catalog is a Lakewatch catalog. ({e})"
    ) from e
CATEGORIES = tuple(rule_config.get("effective_detection_categories") or DEFAULT_CATEGORIES)
print("Detection categories:", ", ".join(CATEGORIES))

# COMMAND ----------

# MAGIC %md
# MAGIC ## 3. Load and validate the rule catalog
# MAGIC
# MAGIC Validation covers severities, fidelities, categories (against this catalog's Lakewatch
# MAGIC configuration), MITRE IDs and tactic names, API size limits, and that no query selects
# MAGIC free-text columns. Any problem stops the notebook before anything changes.

# COMMAND ----------

import yaml

with open(RULE_CATALOG_FILE, encoding="utf-8") as f:
    RULE_CATALOG = yaml.safe_load(f)
validate_catalog(RULE_CATALOG, categories=CATEGORIES)
selected = [r for r in RULE_CATALOG["rules"] if not ONLY or r["name"] in ONLY]
missing = ONLY - {r["name"] for r in selected}
if missing:
    raise ValueError(f"rules not in the catalog: {sorted(missing)}")
PAYLOADS = [build_payload(r, RULE_CATALOG, CTX) for r in selected]

display(spark.createDataFrame(
    [(p["rule_name"], p["severity"], p["fidelity"], p["category"],
      p["annotations"].get("mitre_techniques", ""), p["annotations"].get("owasp_llm_top10", ""),
      p["annotations"].get("owasp_agentic_top10", ""), p["annotations"].get("dasf_risks", ""))
     for p in PAYLOADS],
    "rule STRING, severity STRING, fidelity STRING, category STRING, mitre STRING, owasp_llm STRING, "
    "owasp_agentic STRING, dasf STRING",
))

# COMMAND ----------

# MAGIC %md
# MAGIC ## 4. Preview over recent data
# MAGIC
# MAGIC Runs each rule's SQL over the last `preview_days`, with the Lakewatch time-range macros
# MAGIC replaced by a fixed window, and counts the signals it would have produced. This catches
# MAGIC missing tables, permission problems and noisy rules before deployment. A rule with no signals
# MAGIC is fine; it just had nothing to find.

# COMMAND ----------

if PREVIEW_DAYS > 0:
    start, end = f"current_timestamp() - INTERVAL {PREVIEW_DAYS} DAYS", "current_timestamp()"
    preview_rows = []
    for p in PAYLOADS:
        sql = preview_query(p["batch"]["sql"]["query"], start, end)
        try:
            row = spark.sql(
                f"SELECT count(*) AS signals, coalesce(sum(hit_count), 0) AS hits, "
                f"count(DISTINCT requester) AS requesters FROM ({sql})"
            ).first()
            preview_rows.append((p["rule_name"], p["severity"], row.signals, row.hits, row.requesters, None))
        except Exception as e:
            preview_rows.append((p["rule_name"], p["severity"], None, None, None, str(e).splitlines()[0][:300]))
    display(spark.createDataFrame(
        preview_rows,
        "rule STRING, severity STRING, signals LONG, hits LONG, requesters LONG, error STRING",
    ))
    errors = [r for r in preview_rows if r[-1]]
    if errors:
        raise RuntimeError(f"{len(errors)} rule queries failed in preview: {[r[0] for r in errors]}")
else:
    print("Preview skipped (preview_days = 0)")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 5. Plan
# MAGIC
# MAGIC Rules are matched by name in the target schema. Unchanged rules (same `content_hash`
# MAGIC annotation) are skipped. Updates use an `update_mask` limited to the fields this notebook
# MAGIC owns, so a suppression set by an analyst in the UI survives a redeploy. Only rules annotated
# MAGIC `managed_by: genie-trace-monitoring` are ever deleted.

# COMMAND ----------

existing = list_rules()
plan = plan_changes(PAYLOADS, existing, prune=PRUNE and not ONLY)
display(spark.createDataFrame(
    [(action, name, resource) for action, name, resource, _ in plan],
    "action STRING, rule STRING, resource STRING",
))

# COMMAND ----------

# MAGIC %md
# MAGIC ## 6. Rule YAML
# MAGIC
# MAGIC The same definition the API receives, for review or for pasting into **Detection rules >
# MAGIC Create detection rule > Edit as YAML** where the API cannot be used.

# COMMAND ----------

if MODE == "dry_run":
    for action, name, _, payload in plan:
        if payload is not None and action != "unchanged":
            print(f"# ---- {name} ({action})\n{payload_yaml(payload)}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 7. Apply
# MAGIC
# MAGIC Only in `deploy` mode. Each change is applied on its own, and failures are collected and
# MAGIC reported together at the end, so one bad rule does not block the rest.

# COMMAND ----------

results = []
if MODE == "deploy":
    for action, name, resource, payload in plan:
        try:
            if action == "create":
                created = lw("POST", "rules", body=payload)
                results.append((action, name, created.get("name"), "ok"))
            elif action == "update":
                body = dict(payload, name=resource)
                lw("PATCH", resource, query={"update_mask": update_mask(payload)}, body=body)
                results.append((action, name, resource, "ok"))
            elif action == "delete":
                lw("DELETE", resource)
                results.append((action, name, resource, "ok"))
            else:
                results.append((action, name, resource, "skipped"))
        except Exception as e:
            results.append((action, name, resource, f"error: {str(e).splitlines()[0][:300]}"))
    display(spark.createDataFrame(results, "action STRING, rule STRING, resource STRING, status STRING"))
    failed = [r for r in results if r[3].startswith("error")]
    if failed:
        raise RuntimeError(f"{len(failed)} rule changes failed: {[r[1] for r in failed]}")
else:
    print("dry_run: nothing changed. Set mode = deploy to apply the plan above.")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 8. Deployed rules and recent signals
# MAGIC
# MAGIC Rules created by this repo in the target schema, and the signals they produced in the last
# MAGIC seven days, from the Lakewatch signals view (`<lakewatch_catalog>.__lakewatch.signals`).

# COMMAND ----------

deployed = [r for r in list_rules() if (r.get("annotations") or {}).get("managed_by") == MANAGED_BY]
display(spark.createDataFrame(
    [(r.get("effective_rule_name") or r.get("rule_name"), r.get("severity"), r.get("name"),
      str((r.get("schedule") or {}).get("enabled", True)), r.get("effective_run_as_principal"))
     for r in deployed] or [("(none)", None, None, None, None)],
    "rule STRING, severity STRING, resource STRING, enabled STRING, run_as STRING",
))

try:
    display(spark.sql(f"SELECT * FROM `{LW_CATALOG}`.`__lakewatch`.signals LIMIT 0"))
    print("Signals view is available; query it for recent signals from the rules above.")
except Exception as e:
    print(f"Signals view not readable yet ({str(e).splitlines()[0][:200]})")
