# Databricks notebook source
# MAGIC %md
# MAGIC # 02 · Detect PII in Genie prompts, responses and tool traffic
# MAGIC
# MAGIC Customers worry that users paste personal data into Genie and that it then travels to the
# MAGIC LLM. Genie does not redact PII before sending prompts to the model, so the realistic control
# MAGIC is **trust but monitor**: scan every turn after the fact, flag sessions, and tag the columns.
# MAGIC
# MAGIC This notebook shows three complementary approaches on the same data:
# MAGIC
# MAGIC | Section | Approach | Granularity | Cost |
# MAGIC |---|---|---|---|
# MAGIC | 1 | **Microsoft Presidio** in a pandas UDF | Row-level: entity types, scores, offsets | Compute only |
# MAGIC | 2 | **AI Functions** (`ai_extract`) | Row-level, LLM-based, optional | Billed per call |
# MAGIC | 3 | **Unity Catalog Data Classification** | Column-level governed `class.*` tags | Included |
# MAGIC | 4 | Apply the same governed `class.*` tags from Presidio findings | Column-level | — |
# MAGIC
# MAGIC Findings are written to `genie_detections` (`detector = pii_presidio` / `pii_ai_extract`) and
# MAGIC roll up to `genie_sessions.flags.has_pii`.

# COMMAND ----------

# MAGIC %run ./_detection_utils

# COMMAND ----------

# MAGIC %md
# MAGIC ## Configuration

# COMMAND ----------

import json

# Severity weight per entity type: a finding's score = Presidio confidence x weight, so a card number
# in cleartext outranks a name. Unlisted types use PII_DEFAULT_WEIGHT.
DEFAULT_PII_WEIGHTS = {
    "CREDIT_CARD": 1.0, "US_SSN": 1.0, "US_BANK_NUMBER": 1.0, "IBAN_CODE": 1.0, "US_ITIN": 1.0, "CRYPTO": 1.0,
    "US_PASSPORT": 0.9, "US_DRIVER_LICENSE": 0.9, "UK_NHS": 0.9,
    "DATE_OF_BIRTH": 0.6,
    "PHONE_NUMBER": 0.5, "EMAIL_ADDRESS": 0.5,
    "PERSON": 0.3, "LOCATION": 0.3, "MEDICAL_LICENSE": 0.3,
    "IP_ADDRESS": 0.2,
}

dbutils.widgets.text("spacy_model", "en_core_web_md", "spaCy model")
dbutils.widgets.text("pii_threshold", "0.5", "Presidio score threshold")
dbutils.widgets.text("ignore_entities", "DATE_TIME,URL,NRP,ORGANIZATION,UUID", "Presidio entity types to ignore")
dbutils.widgets.text("allowlist_terms", "Delta,Databricks,Unity Catalog,Spark,Lakehouse,Genie,Photon,Iceberg,Lakebase,UC,Catalog Explorer,Databricks Apps,Databricks SQL,Model Serving,Vector Search", "Terms never treated as PII")
dbutils.widgets.dropdown("run_ai_extract", "false", ["false", "true"], "Run ai_extract comparison")
dbutils.widgets.text("ai_extract_sample", "25", "ai_extract sample rows")
dbutils.widgets.dropdown("apply_governed_tags", "true", ["false", "true"], "Apply class.* tags to columns")
dbutils.widgets.text("pii_weights", json.dumps(DEFAULT_PII_WEIGHTS), "Severity weight per entity type (JSON)")
dbutils.widgets.text("pii_default_weight", "0.5", "Weight for entity types not listed")

SPACY_MODEL = dbutils.widgets.get("spacy_model")
PII_THRESHOLD = float(dbutils.widgets.get("pii_threshold"))
IGNORE_ENTITIES = [e.strip() for e in dbutils.widgets.get("ignore_entities").split(",") if e.strip()]
ALLOWLIST_TERMS = [t.strip().lower() for t in dbutils.widgets.get("allowlist_terms").split(",") if t.strip()]
RUN_AI_EXTRACT = dbutils.widgets.get("run_ai_extract") == "true"
AI_EXTRACT_SAMPLE = int(dbutils.widgets.get("ai_extract_sample"))
APPLY_GOVERNED_TAGS = dbutils.widgets.get("apply_governed_tags") == "true"
PII_WEIGHTS = {k: float(v) for k, v in json.loads(dbutils.widgets.get("pii_weights")).items()}
PII_DEFAULT_WEIGHT = float(dbutils.widgets.get("pii_default_weight"))

# COMMAND ----------

# MAGIC %md
# MAGIC ## 1 · Presidio: row-level PII detection
# MAGIC
# MAGIC Presidio combines regex / checksum recognisers (email, phone, credit card, IBAN, IP, SSN,
# MAGIC passport, ...) with spaCy NER (PERSON, LOCATION, ...). The analyzer is built once per
# MAGIC executor and reused across batches. If the spaCy model wheel is not installed the engine
# MAGIC falls back to a blank English pipeline, which keeps the pattern recognisers working.
# MAGIC
# MAGIC Matches equal to the requester's own user name are dropped: Genie Code tool arguments
# MAGIC routinely contain the user's workspace path, and that is not a leak. `ORGANIZATION`,
# MAGIC `DATE_TIME`, `URL` and `NRP` are ignored by default: product and vendor names are not PII
# MAGIC and dominate Genie traffic. NER matches on allow-listed product terms (`allowlist_terms`) and
# MAGIC on locale codes such as `en_GB` are dropped too; spaCy labels both as LOCATION.
# MAGIC
# MAGIC **Dates of birth.** Presidio has no date-of-birth recogniser, and its generic `DATE_TIME` is
# MAGIC ignored because Genie traffic is full of dates. A custom `DATE_OF_BIRTH` recogniser matches
# MAGIC common date formats, and a match only counts when birth wording (`DOB`, `date of birth`,
# MAGIC `born`, `birthday`, ...) sits just before or after it, so dates in SQL and query results stay
# MAGIC quiet.
# MAGIC
# MAGIC **Severity.** The scan records each entity's confidence in `details`; section 1b then sets each
# MAGIC finding's `score` to confidence x the entity type's weight (`pii_weights`) and its `label` to
# MAGIC the most severe entity.

# COMMAND ----------

import json
import re

import pandas as pd
from pyspark.sql import functions as F
from pyspark.sql.functions import pandas_udf

_ANALYZER = None


def _get_analyzer(spacy_model: str):
    global _ANALYZER
    if _ANALYZER is None:
        import spacy
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import SpacyNlpEngine

        try:
            nlp = spacy.load(spacy_model)
        except Exception:  # noqa: BLE001  model wheel not installed → pattern recognisers only
            nlp = spacy.blank("en")

        class LoadedSpacyNlpEngine(SpacyNlpEngine):
            def __init__(self, loaded):
                super().__init__()
                self.nlp = {"en": loaded}

        _ANALYZER = AnalyzerEngine(nlp_engine=LoadedSpacyNlpEngine(nlp), supported_languages=["en"])
        _ANALYZER.registry.add_recognizer(_dob_recognizer())
    return _ANALYZER


_MONTH = r"(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\.?"
DOB_PATTERNS = [
    ("dob_numeric", r"\b\d{1,2}[/.-]\d{1,2}[/.-](?:19|20)\d{2}\b"),                           # 12/03/1985
    ("dob_iso", r"\b(?:19|20)\d{2}[/.-]\d{1,2}[/.-]\d{1,2}\b"),                               # 1985-03-12
    ("dob_day_month", rf"\b\d{{1,2}}(?:st|nd|rd|th)?\s+{_MONTH},?\s+(?:19|20)\d{{2}}\b"),       # 12 March 1985
    ("dob_month_day", rf"\b{_MONTH}\s+\d{{1,2}}(?:st|nd|rd|th)?,?\s+(?:19|20)\d{{2}}\b"),       # March 12, 1985
]
# A date only counts as a date of birth with birth wording just before (60 chars) or after (25 chars),
# a year at least DOB_MIN_AGE_YEARS ago (so "birthday lunch on 2024-06-01" is not a DOB), and outside
# tool arguments (SQL / code, where "WHERE dob > '1990-01-01'" is a filter, not someone's birth date).
DOB_CONTEXT_RE = re.compile(r"(?i)\b(?:d\.?o\.?b|date\s+of\s+birth|birth\s*date|birthday|born)\b")
DOB_YEAR_RE = re.compile(r"(?:19|20)\d{2}")
DOB_MIN_AGE_YEARS = 10
DOB_EXCLUDED_FIELDS = {"tool_arguments"}


def _dob_recognizer():
    from presidio_analyzer import Pattern, PatternRecognizer

    return PatternRecognizer(
        supported_entity="DATE_OF_BIRTH",
        patterns=[Pattern(name, regex, 0.85) for name, regex in DOB_PATTERNS],
        supported_language="en",
    )


PRESIDIO_SCHEMA = "STRUCT<flagged:BOOLEAN, score:DOUBLE, label:STRING, entity_types:ARRAY<STRING>, entity_count:INT, details:STRING, error:STRING>"


LOCALE_RE = re.compile(r"^[a-z]{2,3}[_-][A-Z]{2}$")
# NER hits that look like code identifiers (snake_case, dotted names, backticked) rather than prose
IDENTIFIER_RE = re.compile(r"^[`'\"]?[A-Za-z0-9]+(?:[_.][A-Za-z0-9]+)+[`'\"]?$")
# Prose-like token: letters, spaces, hyphens, apostrophes only (no digits, code punctuation)
PROSE_RE = re.compile(r"^[A-Za-z][A-Za-z' -]*[A-Za-z]$")
# NER entities (PERSON, LOCATION) only count in fields users type or read as prose.
NER_FIELDS = {"prompt", "response"}
NER_ENTITIES = {"PERSON", "LOCATION", "ORGANIZATION", "NRP"}


def make_presidio_udf(spacy_model: str, threshold: float, ignore: list, allowlist: list):
    ignore_set = set(ignore)
    allow_set = set(allowlist)

    @pandas_udf(PRESIDIO_SCHEMA)
    def presidio_scan(texts: pd.Series, requesters: pd.Series, fields: pd.Series) -> pd.DataFrame:
        import datetime

        analyzer = _get_analyzer(spacy_model)
        max_dob_year = datetime.date.today().year - DOB_MIN_AGE_YEARS
        rows = []
        for text, requester, field in zip(texts, requesters, fields):
            text = "" if text is None else str(text)
            requester = ("" if requester is None else str(requester)).lower()
            try:
                results = analyzer.analyze(text=text, language="en", score_threshold=threshold)
            except Exception as e:  # noqa: BLE001
                # Not written to genie_detections, so the field is retried on the next run.
                rows.append({"flagged": False, "score": 0.0, "label": None, "entity_types": [], "entity_count": 0,
                             "details": None, "error": f"{type(e).__name__}: {e}"[:500]})
                continue
            kept = []
            for r in results:
                if r.entity_type in ignore_set:
                    continue
                snippet = text[r.start : r.end]
                if r.entity_type == "EMAIL_ADDRESS" and snippet.lower() == requester:
                    continue
                if r.entity_type == "DATE_OF_BIRTH":
                    window = text[max(0, r.start - 60) : r.start] + " " + text[r.end : r.end + 25]
                    year = DOB_YEAR_RE.search(snippet)
                    if (field in DOB_EXCLUDED_FIELDS or not DOB_CONTEXT_RE.search(window)
                            or not year or int(year.group(0)) > max_dob_year):
                        continue  # an ordinary date, not a date of birth
                if r.entity_type in NER_ENTITIES:
                    token = snippet.strip()
                    if field not in NER_FIELDS:
                        continue  # SQL, JSON and markdown tables: NER is noise here
                    if token.lower() in allow_set or LOCALE_RE.match(token) or IDENTIFIER_RE.match(token):
                        continue
                    if not PROSE_RE.match(token):
                        continue
                    if r.entity_type == "PERSON" and len(token.split()) < 2:
                        continue  # single-token "names" are overwhelmingly column or product names
                    if r.entity_type == "LOCATION" and (len(token) < 3 or token.isupper()):
                        continue  # country / region codes (US, GB, EMEA) are not personal data
                kept.append({"type": r.entity_type, "score": round(float(r.score), 3), "start": r.start, "end": r.end})
            types = sorted({k["type"] for k in kept})
            top = max(kept, key=lambda k: k["score"]) if kept else None
            rows.append({
                "flagged": bool(kept),
                "score": float(top["score"]) if top else 0.0,
                "label": top["type"] if top else None,
                "entity_types": types,
                "entity_count": len(kept),
                "details": json.dumps({"entities": kept[:50], "truncated": len(kept) > 50}),
                "error": None,
            })
        return pd.DataFrame(rows)

    return presidio_scan


presidio_scan = make_presidio_udf(SPACY_MODEL, PII_THRESHOLD, IGNORE_ENTITIES, ALLOWLIST_TERMS)

# COMMAND ----------

pii_candidates = candidates("pii_presidio")
print(f"Fields to scan with Presidio: {pii_candidates.count()}")

scanned = (
    pii_candidates
    .withColumn("r", presidio_scan(F.col("text"), F.col("requester"), F.col("field")))
    .select("*", "r.flagged", "r.score", "r.label", "r.details", "r.error")
    .drop("r")
)
write_detections(scanned, "pii_presidio")

# COMMAND ----------

# MAGIC %md
# MAGIC ### 1b · Weight findings by entity type
# MAGIC
# MAGIC Re-scores every flagged PII finding (new and historical, Presidio and `ai_extract`) from the
# MAGIC entities recorded in `details`: `score` = the highest confidence x weight, `label` = that
# MAGIC entity's type. Runs on every execution, so editing `pii_weights` re-weights history.
# MAGIC `detected_at` is not touched, so re-weighting never re-triggers alerts.

# COMMAND ----------


def sql_weight_map(weights: dict) -> str:
    return "map(" + ", ".join(f"'{k}', CAST({float(v)} AS DOUBLE)" for k, v in sorted(weights.items())) + ")"


PII_ENTITIES_SQL = "from_json(details:entities, 'ARRAY<STRUCT<type: STRING, score: DOUBLE>>')"
# Ascending sort on (severity, type); the last element is the most severe entity.
PII_RANKED_SQL = (
    f"array_sort(transform({PII_ENTITIES_SQL}, e -> named_struct("
    f"'severity', round(e.score * coalesce(try_element_at({sql_weight_map(PII_WEIGHTS)}, e.type), "
    f"CAST({PII_DEFAULT_WEIGHT} AS DOUBLE)), 3), 'type', e.type)))"
)

spark.sql(f"""
  UPDATE {DETECTIONS}
  SET score = element_at({PII_RANKED_SQL}, -1).severity,
      label = element_at({PII_RANKED_SQL}, -1).type
  WHERE detector LIKE 'pii_%'
    AND flagged
    AND size({PII_ENTITIES_SQL}) > 0
""")
print("Re-weighted PII findings with", json.dumps(PII_WEIGHTS))

# COMMAND ----------

display(
    spark.sql(
        f"""
        SELECT product, span.field AS field, label AS entity_type, COUNT(*) AS findings, COUNT(DISTINCT conversation_id) AS sessions
        FROM {DETECTIONS}
        WHERE detector = 'pii_presidio' AND flagged
        GROUP BY ALL ORDER BY findings DESC
        """
    )
)

# COMMAND ----------

# MAGIC %md
# MAGIC ## 2 · AI Functions comparison (`ai_extract`), optional
# MAGIC
# MAGIC `ai_extract` asks a foundation model to pull named entities out of free text. It
# MAGIC understands context (a name inside a SQL string literal versus a column called `name`),
# MAGIC but it is billed per call and non-deterministic, so it is run on a sample by default.
# MAGIC `ai_mask` is the sibling that returns redacted text instead of the entities.

# COMMAND ----------

if RUN_AI_EXTRACT:
    labels = ["person", "email", "phone", "address", "credit_card", "national_id", "date_of_birth"]
    # ai_extract label -> Presidio entity type, so weights and the session rollup apply unchanged
    AI_EXTRACT_TO_ENTITY = {
        "person": "PERSON", "email": "EMAIL_ADDRESS", "phone": "PHONE_NUMBER", "address": "LOCATION",
        "credit_card": "CREDIT_CARD", "national_id": "US_SSN", "date_of_birth": "DATE_OF_BIRTH",
    }
    to_entity = F.create_map(*[F.lit(x) for kv in AI_EXTRACT_TO_ENTITY.items() for x in kv])
    label_arr = ", ".join(f"'{l}'" for l in labels)
    sample = candidates("pii_ai_extract", fields=["prompt", "response"]).orderBy(F.rand()).limit(AI_EXTRACT_SAMPLE)
    sample.createOrReplaceTempView("_pii_ai_sample")
    extracted = spark.sql(
        f"""
        SELECT *, ai_extract(text, array({label_arr})) AS ents
        FROM _pii_ai_sample
        """
    )
    found = (
        extracted
        .withColumn("ents_map", F.map_filter(F.from_json(F.to_json(F.col("ents")), "MAP<STRING,STRING>"), lambda k, v: v.isNotNull() & (F.length(F.trim(v)) > 0)))
        .withColumn("entity_types", F.map_keys("ents_map"))
        .withColumn("flagged", F.size("entity_types") > 0)
        .withColumn("score", F.when(F.col("flagged"), F.lit(0.8)).otherwise(F.lit(0.0)))
        .withColumn("label", F.element_at("entity_types", 1))
        # Types only, values are never copied. ai_extract gives no confidence: 0.8 is assumed, then
        # weighted by entity type in section 1b on the next run (or re-run 1b now).
        .withColumn("details", F.to_json(F.struct(F.transform("entity_types", lambda t: F.struct(
            F.coalesce(F.try_element_at(to_entity, t), F.upper(t)).alias("type"),
            F.lit(0.8).alias("score"),
        )).alias("entities"))))
        .withColumn("error", F.when(F.col("ents").isNull(), F.lit("ai_extract returned null")))
        .drop("ents", "ents_map", "entity_types")
    )
    write_detections(found, "pii_ai_extract")
    # Read back from genie_detections rather than `found`, which would call ai_extract again.
    display(
        spark.sql(
            f"""
            SELECT d.detected_at, d.product, d.span.field AS field, d.flagged, d.label, d.details,
                   substr(CASE d.span.field WHEN 'prompt' THEN t.prompt ELSE t.response END, 1, 120) AS text
            FROM {DETECTIONS} d
            LEFT JOIN {TURNS} t ON t.span_id = d.span.span_id
            WHERE d.detector = 'pii_ai_extract'
            ORDER BY d.detected_at DESC
            LIMIT {AI_EXTRACT_SAMPLE}
            """
        )
    )
else:
    print("Skipped (set run_ai_extract = true to run the ai_extract comparison).")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 3 · Unity Catalog Data Classification
# MAGIC
# MAGIC With Data Classification enabled on the catalog, Databricks samples the flattened columns
# MAGIC and applies governed `class.*` tags automatically. Results land in
# MAGIC `system.data_classification.results`. This is the zero-code option, but it is column-level
# MAGIC and sample-based, so it cannot say *which* turn contained PII.

# COMMAND ----------

try:
    display(
        spark.sql(
            f"""
            SELECT table_name, column_name, class_tag, confidence, frequency, first_detected_time, latest_detected_time
            FROM system.data_classification.results
            WHERE catalog_name = '{CATALOG}' AND schema_name = '{SCHEMA}' AND class_tag <> ''
            ORDER BY table_name, column_name
            """
        )
    )
except Exception as e:  # noqa: BLE001
    print(f"Could not read system.data_classification.results ({type(e).__name__}): account-admin only by default.")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 4 · Apply governed `class.*` tags from Presidio findings
# MAGIC
# MAGIC Presidio entity types are mapped onto the governed tag keys Data Classification uses, and
# MAGIC the tags are applied to the source column of each finding. ABAC policies written against
# MAGIC `class.*` then cover both automatic and Presidio-detected PII. Assigning governed tags needs
# MAGIC `ASSIGN` on each tag (account admins by default); failures are reported, not fatal.

# COMMAND ----------

# Presidio entity type -> the most specific governed class.* tag Databricks Data Classification uses,
# so ABAC policies written against class.* cover both. Types with no matching tag (CRYPTO, NRP,
# DATE_TIME, UUID) are not tagged.
ENTITY_TO_CLASS_TAG = {
    "EMAIL_ADDRESS": "class.email_address",
    "PHONE_NUMBER": "class.phone_number",
    "PERSON": "class.name",
    "LOCATION": "class.location",
    "DATE_OF_BIRTH": "class.date_of_birth",
    "CREDIT_CARD": "class.credit_card",
    "IBAN_CODE": "class.iban_code",
    "US_BANK_NUMBER": "class.us_bank_number",
    "US_SSN": "class.us_ssn",
    "US_ITIN": "class.us_itin",
    "US_PASSPORT": "class.us_passport",
    "US_DRIVER_LICENSE": "class.us_driver_license",
    "UK_NHS": "class.uk_nhs",
    "MEDICAL_LICENSE": "class.medical_license",
    "IP_ADDRESS": "class.ip_address",
    "MAC_ADDRESS": "class.mac_address",
    "URL": "class.url",
}

FIELD_TO_COLUMN = {
    "prompt": (f"{FQ}.genie_turns", "prompt"),
    "response": (f"{FQ}.genie_turns", "response"),
    "tool_arguments": (f"{FQ}.genie_tool_calls", "tool_arguments"),
    "tool_result": (f"{FQ}.genie_tool_calls", "tool_result"),
    "model_output": (f"{FQ}.genie_tool_calls", "response_text"),
}


def set_column_tags(table: str, column: str, tags: dict):
    tag_sql = ", ".join(f"'{k}' = '{v}'" for k, v in tags.items())
    # genie_turns / genie_tool_calls are materialized views; try both ALTER forms.
    errors = []
    for stmt in (
        f"ALTER TABLE {table} ALTER COLUMN {column} SET TAGS ({tag_sql})",
        f"ALTER MATERIALIZED VIEW {table} ALTER COLUMN {column} SET TAGS ({tag_sql})",
    ):
        try:
            spark.sql(stmt)
            return True, None
        except Exception as e:  # noqa: BLE001
            errors.append(f"{type(e).__name__}: {str(e)[:200]}")
    return False, errors[-1]


if APPLY_GOVERNED_TAGS:
    findings = spark.sql(
        f"""
        SELECT span.field AS field, label AS entity_type, COUNT(*) AS n
        FROM {DETECTIONS}
        WHERE detector IN ('pii_presidio') AND flagged AND label IS NOT NULL
        GROUP BY span.field, label
        """
    ).collect()

    per_column = {}
    for row in findings:
        tag = ENTITY_TO_CLASS_TAG.get(row.entity_type)
        if not tag or row.field not in FIELD_TO_COLUMN:
            continue
        per_column.setdefault(FIELD_TO_COLUMN[row.field], {})[tag] = ""

    for (table, column), tags in per_column.items():
        tags = dict(tags)
        tags["pii_detected_by"] = "presidio"  # plain (non-governed) tag, always assignable by the owner
        ok, err = set_column_tags(table, column, tags)
        status = "tagged" if ok else f"FAILED ({err})"
        print(f"{table}.{column}: {sorted(tags)} -> {status}")
    if not per_column:
        print("No PII findings to tag yet.")
else:
    print("Skipped tag application (apply_governed_tags = false).")

# COMMAND ----------

display(
    spark.sql(
        f"""
        SELECT table_name, column_name, tag_name, tag_value
        FROM system.information_schema.column_tags
        WHERE catalog_name = '{CATALOG}' AND schema_name = '{SCHEMA}'
        ORDER BY table_name, column_name, tag_name
        """
    )
)
