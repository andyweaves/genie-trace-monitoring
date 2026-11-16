# Databricks notebook source
# MAGIC %md
# MAGIC # Lakewatch rule utilities
# MAGIC
# MAGIC Pure functions shared by `07_deploy_lakewatch_rules` and the local tests: load and validate
# MAGIC `src/lakewatch/rule_catalog.yml`, render each rule's detection SQL, build the Lakewatch rules
# MAGIC API payload, and plan create / update / delete against the rules already deployed. No Spark,
# MAGIC network or workspace calls. PyYAML is needed only to load the catalog and export YAML.

# COMMAND ----------

# MAGIC %md
# MAGIC ## Constants
# MAGIC
# MAGIC Every rule emits the same output columns, so signals from all rules can be triaged the same
# MAGIC way. Signals carry identifiers, labels and scores only. `investigate` is a query over
# MAGIC `genie_session_timeline`, which holds the full text behind its own access controls.

# COMMAND ----------

import hashlib
import json
import re

MANAGED_BY = "genie-trace-monitoring"
REPO_URL = "https://github.com/andyweaves/genie-trace-monitoring"

SEVERITIES = ("Informational", "Low", "Medium", "High", "Critical")
FIDELITIES = ("FIDELITY_DEVELOPMENT", "FIDELITY_INVESTIGATIVE", "FIDELITY_MEDIUM", "FIDELITY_HIGH")
DEFAULT_CATEGORIES = ("Static Signature", "Fuzzy Signature", "Behavioral", "Statistical", "Learning (AI/ML)")
DEDUPLICATION_MODES = ("DEDUPLICATION_DEFAULT", "DEDUPLICATION_ENABLED", "DEDUPLICATION_DISABLED")
KINDS = ("match", "sequence", "custom")
DETECTORS = (
    "pii_presidio", "pii_ai_extract", "prompt_injection_prompt_guard",
    "prompt_injection_ai_classify", "guardrail_signal",
)
SOURCE_FIELDS = ("prompt", "response", "tool_arguments", "tool_result", "model_output", "embedded_tool_result")

# Tactic names as published: Enterprise ATT&CK v20 (Defense Evasion was split into Stealth and
# Defense Impairment) and ATLAS 5.6.
TACTICS = {
    "mitre-attack": {
        "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
        "Privilege Escalation", "Stealth", "Defense Impairment", "Credential Access", "Discovery",
        "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact",
    },
    "mitre-atlas": {
        "Reconnaissance", "Resource Development", "Initial Access", "AI Model Access", "Execution",
        "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery",
        "Lateral Movement", "Collection", "AI Attack Staging", "Command and Control", "Exfiltration",
        "Impact",
    },
}
TECHNIQUE_ID = {
    "mitre-attack": re.compile(r"^T\d{4}$"),
    "mitre-atlas": re.compile(r"^AML\.T\d{4}$"),
}
SUB_TECHNIQUE_ID = re.compile(r"^(?P<parent>(?:AML\.)?T\d{4})\.\d{3}$")

# Columns every rule query returns. All but event_time are recorded as signal context.
OUTPUT_COLUMNS = (
    "conversation_id", "requester", "product", "workspace_id", "event_time", "hit_count",
    "turn_count", "max_score", "labels", "detectors", "fields", "tools", "trace_ids", "investigate",
)
CONTEXT_KEYS = tuple(c for c in OUTPUT_COLUMNS if c != "event_time")

# Free-text columns of the source tables. A rule query must not select them, so no prompt,
# response, argument or result text can reach a signal (signals sit outside the table ACLs).
FREE_TEXT_COLUMNS = (
    "prompt", "response", "tool_arguments", "tool_result", "response_text", "text",
    "first_prompt", "last_response", "input_messages_raw", "output_messages_raw", "attributes",
)
# The only keys a rule may read from genie_detections.details (none carry content).
ALLOWED_DETAIL_PATHS = ("$.source_field", "$.tool_name", "$.entities")

RUNBOOK_MAX_CHARS = 4096
MAX_REFERENCES = 3
MAX_REFERENCE_CHARS = 512
MAX_MITRE = 64
LABEL_RE = re.compile(r"^[A-Za-z0-9_ .:/()-]{1,128}$")
RULE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{2,127}$")
DURATION_RE = re.compile(r"^(?:\d+d)?(?:\d+h)?(?:\d+m)?(?:\d+s)?$")

# Fields this deployer owns on a rule; everything else (suppression, run-as when unset) is left
# alone on update.
MANAGED_FIELDS = (
    "description", "annotations", "category", "severity", "fidelity", "objective", "mitre",
    "deduplication", "deduplication_time_window", "schedule", "batch", "output", "references",
    "runbook", "timerange",
)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Load and validate the catalog
# MAGIC
# MAGIC Validation fails loudly with every problem at once: a malformed rule must not silently drop
# MAGIC out of the deployed set.

# COMMAND ----------


def load_catalog(path):
    import yaml

    with open(path, encoding="utf-8") as f:
        catalog = yaml.safe_load(f)
    validate_catalog(catalog)
    return catalog


def _match_entries(rule):
    kind = rule.get("kind", "match")
    if kind == "match":
        return list(rule.get("match") or [])
    if kind == "sequence":
        return list(rule.get("first") or []) + list(rule.get("then") or [])
    return []


def _validate_match(entry, where, problems):
    if not isinstance(entry, dict):
        problems.append(f"{where}: match entry must be a mapping")
        return
    unknown = set(entry) - {"detector", "labels", "exclude_labels", "fields", "min_score", "include_unflagged"}
    if unknown:
        problems.append(f"{where}: unknown match keys {sorted(unknown)}")
    if entry.get("detector") not in DETECTORS:
        problems.append(f"{where}: detector must be one of {DETECTORS}, got {entry.get('detector')!r}")
    for key in ("labels", "exclude_labels"):
        values = entry.get(key)
        if values is None:
            continue
        if not isinstance(values, list) or not values:
            problems.append(f"{where}: {key} must be a non-empty list")
            continue
        for label in values:
            if not isinstance(label, str) or not LABEL_RE.match(label):
                problems.append(f"{where}: invalid label {label!r}")
    for field in entry.get("fields") or []:
        if field not in SOURCE_FIELDS:
            problems.append(f"{where}: field {field!r} not in {SOURCE_FIELDS}")
    if "min_score" in entry and not (isinstance(entry["min_score"], (int, float)) and 0 <= entry["min_score"] <= 1):
        problems.append(f"{where}: min_score must be a number in [0, 1]")


def _validate_mitre(mappings, where, problems):
    if not isinstance(mappings, list):
        problems.append(f"{where}: mitre must be a list")
        return
    if len(mappings) > MAX_MITRE:
        problems.append(f"{where}: at most {MAX_MITRE} MITRE mappings")
    seen = set()
    for i, m in enumerate(mappings):
        w = f"{where}.mitre[{i}]"
        taxonomy = m.get("taxonomy")
        if taxonomy not in TACTICS:
            problems.append(f"{w}: taxonomy must be one of {sorted(TACTICS)}")
            continue
        if m.get("tactic") not in TACTICS[taxonomy]:
            problems.append(f"{w}: unknown {taxonomy} tactic {m.get('tactic')!r}")
        if not TECHNIQUE_ID[taxonomy].match(str(m.get("technique_id", ""))):
            problems.append(f"{w}: technique_id {m.get('technique_id')!r} is not a {taxonomy} technique ID")
        if not m.get("technique"):
            problems.append(f"{w}: technique name is required")
        sub = m.get("sub_technique_id")
        if sub:
            parsed = SUB_TECHNIQUE_ID.match(sub)
            if not parsed or parsed.group("parent") != m.get("technique_id"):
                problems.append(f"{w}: sub_technique_id {sub!r} does not belong to {m.get('technique_id')}")
            if not m.get("sub_technique"):
                problems.append(f"{w}: sub_technique name is required with sub_technique_id")
        key = (taxonomy, m.get("tactic"), m.get("technique_id"), sub)
        if key in seen:
            problems.append(f"{w}: duplicate mapping {key}")
        seen.add(key)


def validate_catalog(catalog, categories=DEFAULT_CATEGORIES):
    """Raise ValueError listing every problem in the catalog."""
    problems = []
    if not isinstance(catalog, dict) or catalog.get("version") != 1:
        raise ValueError("rule catalog must be a mapping with version: 1")
    defaults = catalog.get("defaults") or {}
    for key in ("schedule", "extend_lookback"):
        if key in defaults and not DURATION_RE.match(str(defaults[key])):
            problems.append(f"defaults.{key}: {defaults[key]!r} is not a duration such as 1h or 15m")
    if defaults.get("deduplication", "DEDUPLICATION_DEFAULT") not in DEDUPLICATION_MODES:
        problems.append(f"defaults.deduplication must be one of {DEDUPLICATION_MODES}")

    rules = catalog.get("rules")
    if not isinstance(rules, list) or not rules:
        raise ValueError("rule catalog has no rules")
    names = set()
    for i, rule in enumerate(rules):
        name = rule.get("name", f"rules[{i}]")
        where = f"rule {name}"
        if not RULE_NAME_RE.match(str(rule.get("name", ""))):
            problems.append(f"{where}: name must match {RULE_NAME_RE.pattern}")
        if name in names:
            problems.append(f"{where}: duplicate rule name")
        names.add(name)
        for key in ("description", "summary", "objective"):
            if not str(rule.get(key) or "").strip():
                problems.append(f"{where}: {key} is required")
        if rule.get("severity") not in SEVERITIES:
            problems.append(f"{where}: severity must be one of {SEVERITIES}")
        if rule.get("fidelity") not in FIDELITIES:
            problems.append(f"{where}: fidelity must be one of {FIDELITIES}")
        if rule.get("category") not in categories:
            problems.append(f"{where}: category {rule.get('category')!r} is not one of {tuple(categories)}")
        kind = rule.get("kind", "match")
        if kind not in KINDS:
            problems.append(f"{where}: kind must be one of {KINDS}")
        if kind == "match" and not rule.get("match"):
            problems.append(f"{where}: match rules need at least one match entry")
        if kind == "sequence" and not (rule.get("first") and rule.get("then")):
            problems.append(f"{where}: sequence rules need first and then")
        if kind == "custom" and not str(rule.get("query") or "").strip():
            problems.append(f"{where}: custom rules need a query")
        for j, entry in enumerate(_match_entries(rule)):
            _validate_match(entry, f"{where} match[{j}]", problems)
        _validate_mitre(rule.get("mitre") or [], where, problems)
        for placeholder in re.findall(r"\{([a-z_]+)\}", rule.get("summary", "")):
            if placeholder not in CONTEXT_KEYS:
                problems.append(f"{where}: summary placeholder {{{placeholder}}} is not an output column")
        for key in ("triage", "false_positives", "response"):
            if not isinstance(rule.get(key), list) or not rule.get(key):
                problems.append(f"{where}: {key} must be a non-empty list")
        frameworks = rule.get("frameworks") or {}
        for key, values in frameworks.items():
            if key not in ("owasp_llm", "owasp_agentic", "dasf") or not isinstance(values, list):
                problems.append(f"{where}: frameworks.{key} must be a list under owasp_llm, owasp_agentic or dasf")

    not_signalled = catalog.get("not_signalled") or {}
    for detector in not_signalled:
        if detector not in DETECTORS:
            problems.append(f"not_signalled: unknown detector {detector!r}")

    if not problems:
        # Rendering checks the generated SQL and the runbook size; use placeholder targets.
        ctx = example_context()
        for rule in rules:
            try:
                build_payload(rule, catalog, ctx)
            except ValueError as e:
                problems.append(str(e))
    if problems:
        raise ValueError("Invalid Lakewatch rule catalog:\n  - " + "\n  - ".join(problems))


def covered_labels(catalog):
    """{detector: set(labels) or {'*'}} covered by any rule, plus not_signalled labels."""
    covered = {}
    for rule in catalog["rules"]:
        for entry in _match_entries(rule):
            labels = entry.get("labels") or ["*"]
            covered.setdefault(entry["detector"], set()).update(labels)
    for detector, labels in (catalog.get("not_signalled") or {}).items():
        covered.setdefault(detector, set()).update(labels)
    return covered


def example_context():
    return dict(
        catalog_name="example_catalog", schema_name="example_schema", warehouse_id="0000000000000000",
        detections="example_catalog.genie_tracing.genie_detections",
        sessions="example_catalog.genie_tracing.genie_sessions",
        timeline="example_catalog.genie_tracing.genie_session_timeline",
        run_as_principal=None, enabled=True, schedule=None,
    )

# COMMAND ----------

# MAGIC %md
# MAGIC ## Render the detection SQL
# MAGIC
# MAGIC * `match`: findings first written in the run window (`IN_TIMERANGE(detected_at)`), one row per
# MAGIC   conversation. `detected_at` only moves when a finding is new or its score rises, so a re-scan
# MAGIC   by the hourly job does not produce a new signal.
# MAGIC * `sequence`: a `first` finding and a `then` finding at the same time or later in one
# MAGIC   conversation, searched over `lookback_days`, where at least one of them is new in the window.
# MAGIC * `custom`: hand-written SQL with `{detections}`, `{sessions}`, `{timeline}`,
# MAGIC   `{lookback_days}` and `{investigate}` placeholders.

# COMMAND ----------


def _sql_str(value):
    return "'" + str(value).replace("\\", "\\\\").replace("'", "\\'") + "'"


def _sql_list(values):
    return "(" + ", ".join(_sql_str(v) for v in values) + ")"


def match_predicate(entry):
    parts = [f"detector = {_sql_str(entry['detector'])}"]
    if not entry.get("include_unflagged"):
        parts.append("flagged")
    if entry.get("labels"):
        parts.append(f"label IN {_sql_list(entry['labels'])}")
    if entry.get("exclude_labels"):
        parts.append(f"coalesce(label, '') NOT IN {_sql_list(entry['exclude_labels'])}")
    if "min_score" in entry:
        parts.append(f"score >= {float(entry['min_score'])}")
    if entry.get("fields"):
        parts.append(f"source_field IN {_sql_list(entry['fields'])}")
    return "(" + " AND ".join(parts) + ")"


def _any_of(entries):
    return "(" + "\n      OR ".join(match_predicate(e) for e in entries) + ")"


def _investigate(timeline):
    return (
        f"concat('SELECT * FROM {timeline} WHERE conversation_id = ''', conversation_id, "
        "''' ORDER BY step_number')"
    )


def _base_cte(detections, time_filter):
    # Outcome rules store the rule name in span.field; security signatures store
    # security:<pattern>:<field> and keep the scanned field in details.source_field.
    return f"""base AS (
  SELECT
    coalesce(d.conversation_id, d.span.trace_id) AS conversation_id,
    d.requester, d.product, d.workspace_id, d.span_time, d.detected_at,
    d.detector, d.flagged, d.label, d.score,
    d.span.trace_id AS trace_id,
    CASE WHEN d.span.field LIKE 'security:%' THEN get_json_object(d.details, '$.source_field')
         WHEN d.detector = 'guardrail_signal' THEN NULL
         ELSE d.span.field END AS source_field,
    get_json_object(d.details, '$.tool_name') AS tool_name
  FROM {detections} d
  WHERE {time_filter}
)"""


def _render_match(rule, ctx):
    return f"""WITH {_base_cte(ctx['detections'], 'IN_TIMERANGE(d.detected_at)')},
hits AS (
  SELECT * FROM base
  WHERE {_any_of(rule['match'])}
)
SELECT
  conversation_id,
  max(requester)                                                      AS requester,
  max(product)                                                        AS product,
  max(workspace_id)                                                   AS workspace_id,
  min(span_time)                                                      AS event_time,
  count(*)                                                            AS hit_count,
  count(DISTINCT trace_id)                                            AS turn_count,
  round(max(score), 3)                                                AS max_score,
  array_join(array_sort(collect_set(label)), ', ')                    AS labels,
  array_join(array_sort(collect_set(detector)), ', ')                 AS detectors,
  array_join(array_sort(collect_set(source_field)), ', ')             AS fields,
  array_join(array_sort(collect_set(tool_name)), ', ')                AS tools,
  array_join(slice(array_sort(collect_set(trace_id)), 1, 10), ', ')   AS trace_ids,
  {_investigate(ctx['timeline'])} AS investigate
FROM hits
GROUP BY conversation_id"""


def _render_sequence(rule, ctx):
    days = int(rule.get("lookback_days", 7))
    first, then = _any_of(rule["first"]), _any_of(rule["then"])
    time_filter = f"d.span_time >= TIMERANGE_NOW() - INTERVAL {days} DAYS"
    return f"""WITH {_base_cte(ctx['detections'], time_filter)},
first_hits AS (SELECT * FROM base WHERE {first}),
then_hits AS (SELECT * FROM base WHERE {then}),
new_conversations AS (
  SELECT conversation_id FROM first_hits WHERE IN_TIMERANGE(detected_at)
  UNION
  SELECT conversation_id FROM then_hits WHERE IN_TIMERANGE(detected_at)
),
pairs AS (
  SELECT
    t.conversation_id, t.requester, t.product, t.workspace_id, t.tool_name,
    f.span_time AS first_time, greatest(f.score, t.score) AS score,
    f.label AS first_label, t.label AS then_label,
    f.detector AS first_detector, t.detector AS then_detector,
    f.source_field AS first_field, t.source_field AS then_field,
    f.trace_id AS first_trace_id, t.trace_id AS then_trace_id
  FROM first_hits f
  JOIN then_hits t ON t.conversation_id = f.conversation_id AND t.span_time >= f.span_time
  JOIN new_conversations n ON n.conversation_id = f.conversation_id
)
SELECT
  conversation_id,
  max(requester)                                                      AS requester,
  max(product)                                                        AS product,
  max(workspace_id)                                                   AS workspace_id,
  min(first_time)                                                     AS event_time,
  count(*)                                                            AS hit_count,
  size(array_union(collect_set(first_trace_id), collect_set(then_trace_id))) AS turn_count,
  round(max(score), 3)                                                AS max_score,
  concat(array_join(array_sort(collect_set(first_label)), ', '), ' -> ',
         array_join(array_sort(collect_set(then_label)), ', '))       AS labels,
  array_join(array_sort(array_union(collect_set(first_detector), collect_set(then_detector))), ', ') AS detectors,
  array_join(array_sort(array_union(collect_set(first_field), collect_set(then_field))), ', ') AS fields,
  array_join(array_sort(collect_set(tool_name)), ', ')                AS tools,
  array_join(slice(array_sort(array_union(collect_set(first_trace_id), collect_set(then_trace_id))), 1, 10), ', ') AS trace_ids,
  {_investigate(ctx['timeline'])} AS investigate
FROM pairs
GROUP BY conversation_id"""


def _render_custom(rule, ctx):
    query = rule["query"].strip()
    for key, value in (
        ("{detections}", ctx["detections"]), ("{sessions}", ctx["sessions"]),
        ("{timeline}", ctx["timeline"]), ("{lookback_days}", str(int(rule.get("lookback_days", 7)))),
        ("{investigate}", _investigate(ctx["timeline"])),
    ):
        query = query.replace(key, value)
    leftover = re.findall(r"\{[a-z_]+\}", query)
    if leftover:
        raise ValueError(f"rule {rule['name']}: unknown query placeholders {leftover}")
    return query


def render_query(rule, ctx):
    kind = rule.get("kind", "match")
    query = {"match": _render_match, "sequence": _render_sequence, "custom": _render_custom}[kind](rule, ctx)
    _check_query(rule["name"], query)
    return query


def _strip_literals(sql):
    return re.sub(r"'(?:[^'\\]|\\.)*'", "''", sql)


def _check_query(name, query):
    if "IN_TIMERANGE(" not in query:
        raise ValueError(f"rule {name}: query must use IN_TIMERANGE so each run only reads its window")
    for path in re.findall(r"get_json_object\([^,]+,\s*'([^']+)'\)", query):
        if path not in ALLOWED_DETAIL_PATHS:
            raise ValueError(f"rule {name}: details path {path!r} is not allowed in a signal")
    code = _strip_literals(query)
    for column in FREE_TEXT_COLUMNS:
        if re.search(rf"(?<![\w$]){column}(?!\w)", code, flags=re.I):
            raise ValueError(f"rule {name}: query references free-text column {column!r}")
    for column in OUTPUT_COLUMNS:
        if not re.search(rf"\b{column}\b", code):
            raise ValueError(f"rule {name}: query does not return output column {column!r}")


def preview_query(query, start_sql, end_sql):
    """Replace the Lakewatch time-range macros so a rule query runs on a plain SQL warehouse.

    start_sql / end_sql are SQL timestamp expressions, e.g. "TIMESTAMP'2026-11-01'".
    """
    query = re.sub(
        r"IN_TIMERANGE\(\s*([^()]+?)\s*\)",
        lambda m: f"({m.group(1)} >= {start_sql} AND {m.group(1)} < {end_sql})",
        query,
    )
    return query.replace("TIMERANGE_NOW()", f"({end_sql})")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Build the API payload
# MAGIC
# MAGIC The payload is the body of `POST /api/2.0/lakewatch/rules`; the same structure is what the
# MAGIC Lakewatch UI shows under **Edit as YAML**. Framework mappings go into `annotations` (and are
# MAGIC repeated in the objective so analysts see them), the triage guidance into `runbook`.

# COMMAND ----------


def _mitre_url(m):
    tid = m.get("sub_technique_id") or m["technique_id"]
    if m["taxonomy"] == "mitre-atlas":
        return f"https://atlas.mitre.org/techniques/{tid}"
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def _references(rule):
    refs = [f"{REPO_URL}#detections"]
    for taxonomy in ("mitre-atlas", "mitre-attack"):
        first = next((m for m in rule.get("mitre") or [] if m["taxonomy"] == taxonomy), None)
        if first:
            refs.append(_mitre_url(first))
    if len(refs) < MAX_REFERENCES and (rule.get("frameworks") or {}).get("owasp_llm"):
        refs.append("https://genai.owasp.org/llm-top-10/")
    return refs[:MAX_REFERENCES]


def _runbook(rule, ctx):
    lines = ["## Triage"] + [f"- {s}" for s in rule["triage"]]
    lines += ["", "## Known false positives"] + [f"- {s}" for s in rule["false_positives"]]
    lines += ["", "## Response"] + [f"- {s}" for s in rule["response"]]
    lines += [
        "",
        "## Signal context",
        "- `conversation_id`, `requester`, `product`, `workspace_id`: the Genie session and who ran it.",
        "- `labels` / `detectors`: which detections fired; `fields`: where (prompt, response, tool_arguments, tool_result, ...).",
        "- `max_score`: highest detector score; `hit_count` / `turn_count`: how many findings and turns.",
        f"- `investigate`: query over `{ctx['timeline']}`, the step-by-step session with full text. "
        "Signals never contain prompt or result text, so it is access-controlled there.",
    ]
    runbook = "\n".join(lines)
    if len(runbook) > RUNBOOK_MAX_CHARS:
        raise ValueError(f"rule {rule['name']}: runbook is {len(runbook)} chars, max {RUNBOOK_MAX_CHARS}")
    return runbook


def _objective(rule, ctx):
    text = rule["objective"].strip()
    frameworks = rule.get("frameworks") or {}
    extra = []
    if frameworks.get("owasp_llm"):
        extra.append("OWASP Top 10 for LLM Applications: " + "; ".join(frameworks["owasp_llm"]))
    if frameworks.get("owasp_agentic"):
        extra.append("OWASP Top 10 for Agentic Applications: " + "; ".join(frameworks["owasp_agentic"]))
    if frameworks.get("dasf"):
        extra.append("Databricks AI Security Framework (DASF) risks: " + "; ".join(frameworks["dasf"]))
    source = ctx["sessions"] if rule.get("kind") == "custom" and "{sessions}" in rule.get("query", "") else ctx["detections"]
    extra.append(f"Data source: {source} (written by the genie_tracing_monitoring job).")
    return text + "\n\n" + "\n".join(extra)


def _annotations(rule):
    frameworks = rule.get("frameworks") or {}
    detectors, labels = set(), set()
    for entry in _match_entries(rule):
        detectors.add(entry["detector"])
        labels.update(entry.get("labels") or [])
    out = {
        "managed_by": MANAGED_BY,
        "source_repo": REPO_URL,
        "rule_kind": rule.get("kind", "match"),
        "domain": "genai",
        "data_source": "genie_detections" if rule.get("kind") != "custom" or "{detections}" in rule.get("query", "") else "genie_sessions",
        "products": "Genie One, Genie Code",
    }
    if detectors:
        out["detectors"] = ", ".join(sorted(detectors))
    if labels:
        out["detection_labels"] = ", ".join(sorted(labels))
    if frameworks.get("owasp_llm"):
        out["owasp_llm_top10"] = ", ".join(v.split(" ", 1)[0] for v in frameworks["owasp_llm"])
    if frameworks.get("owasp_agentic"):
        out["owasp_agentic_top10"] = ", ".join(v.split(" ", 1)[0] for v in frameworks["owasp_agentic"])
    if frameworks.get("dasf"):
        out["dasf_risks"] = ", ".join(v.split(" ", 1)[0] for v in frameworks["dasf"])
    techniques = sorted({m.get("sub_technique_id") or m["technique_id"] for m in rule.get("mitre") or []})
    if techniques:
        out["mitre_techniques"] = ", ".join(techniques)
    return out


def content_hash(payload):
    body = {k: v for k, v in payload.items() if k != "annotations"}
    body["annotations"] = {k: v for k, v in payload.get("annotations", {}).items() if k != "content_hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()[:16]


def build_payload(rule, catalog, ctx):
    defaults = catalog.get("defaults") or {}
    payload = {
        "catalog_name": ctx["catalog_name"],
        "schema_name": ctx["schema_name"],
        "rule_name": rule["name"],
        "description": rule["description"].strip(),
        "category": rule["category"],
        "severity": rule["severity"],
        "fidelity": rule["fidelity"],
        "objective": _objective(rule, ctx),
        "mitre": [dict(m) for m in rule.get("mitre") or []],
        "deduplication": rule.get("deduplication", defaults.get("deduplication", "DEDUPLICATION_DEFAULT")),
        "deduplication_time_window": str(rule.get("deduplication_time_window",
                                                  defaults.get("deduplication_time_window", "automatic"))),
        "schedule": {
            "at_least_every": str(ctx.get("schedule") or rule.get("schedule") or defaults.get("schedule", "1h")),
            "enabled": bool(ctx.get("enabled", True)),
        },
        "timerange": {"extend_lookback": str(rule.get("extend_lookback", defaults.get("extend_lookback", "15m")))},
        "batch": {"sql": {"query": render_query(rule, ctx)}, "warehouse_id": ctx["warehouse_id"]},
        "output": {
            "summary": rule["summary"].strip(),
            "context": {k: "{" + k + "}" for k in CONTEXT_KEYS},
            "default_context": False,
            "event_time_column": "event_time",
        },
        "references": _references(rule),
        "runbook": _runbook(rule, ctx),
        "annotations": _annotations(rule),
    }
    if ctx.get("run_as_principal"):
        payload["run_as_principal"] = ctx["run_as_principal"]
    for ref in payload["references"]:
        if len(ref) > MAX_REFERENCE_CHARS:
            raise ValueError(f"rule {rule['name']}: reference longer than {MAX_REFERENCE_CHARS} chars")
    payload["annotations"]["content_hash"] = content_hash(payload)
    return payload


def build_payloads(catalog, ctx):
    return [build_payload(rule, catalog, ctx) for rule in catalog["rules"]]


def payload_yaml(payload):
    import yaml

    class _Literal(str):
        pass

    def _literal(dumper, value):
        return dumper.represent_scalar("tag:yaml.org,2002:str", value, style="|")

    yaml.add_representer(_Literal, _literal, Dumper=yaml.SafeDumper)
    body = json.loads(json.dumps(payload))
    body["batch"]["sql"]["query"] = _Literal(body["batch"]["sql"]["query"] + "\n")
    body["objective"] = _Literal(body["objective"] + "\n")
    body["runbook"] = _Literal(body["runbook"] + "\n")
    return yaml.safe_dump(body, sort_keys=False, allow_unicode=True, width=120)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Plan changes against deployed rules
# MAGIC
# MAGIC Rules are matched by name within the target catalog and schema. A rule whose
# MAGIC `content_hash` annotation is unchanged is skipped; others are updated with an explicit
# MAGIC `update_mask`, so fields this deployer does not own (for example a suppression set by an
# MAGIC analyst) are kept. Only rules annotated `managed_by: genie-trace-monitoring` are pruned.

# COMMAND ----------


def plan_changes(payloads, existing, prune=False):
    """Return a list of (action, rule_name, resource_name, payload).

    existing: rule objects from the list API (any view that has rule names and annotations).
    action: create | update | unchanged | delete.
    """
    by_name = {}
    for rule in existing:
        name = rule.get("effective_rule_name") or rule.get("rule_name")
        by_name[name] = rule
    plan = []
    for payload in payloads:
        current = by_name.pop(payload["rule_name"], None)
        if current is None:
            plan.append(("create", payload["rule_name"], None, payload))
        elif (current.get("annotations") or {}).get("content_hash") == payload["annotations"]["content_hash"]:
            plan.append(("unchanged", payload["rule_name"], current["name"], payload))
        else:
            plan.append(("update", payload["rule_name"], current["name"], payload))
    if prune:
        for name, rule in sorted(by_name.items()):
            if (rule.get("annotations") or {}).get("managed_by") == MANAGED_BY:
                plan.append(("delete", name, rule["name"], None))
    return plan


def update_mask(payload):
    fields = [f for f in MANAGED_FIELDS if f in payload]
    if "run_as_principal" in payload:
        fields.append("run_as_principal")
    return ",".join(fields)
