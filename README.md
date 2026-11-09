# Genie trace monitoring

A trust-but-monitor accelerator for Databricks **Genie One** and **Genie Code**, built on the
Unity Gateway unified trace table. It flattens every Genie turn and tool call into queryable
tables, runs PII, prompt-injection and guardrail-signal detections over them, rolls the results
up per session with a severity, and sends one alert listing the sessions worth reviewing.

Everything is a [Databricks Asset Bundle](https://docs.databricks.com/dev-tools/bundles/):
two serverless Lakeflow pipelines, one job, one SQL alert, seven notebooks, deployable to any
workspace with a single `databricks bundle deploy`.

## Contents

- [Why](#why)
- [How it works](#how-it-works)
- [What gets built](#what-gets-built)
- [Quick start](#quick-start)
- [Detections](#detections)
- [Tuning](#tuning)
- [PII: Presidio and Data Classification](#pii-presidio-and-data-classification)
- [What the trace does and does not contain](#what-the-trace-does-and-does-not-contain)
- [Related platform controls](#related-platform-controls)
- [Repository layout](#repository-layout)
- [License](#license)

## Why

Customers adopting Genie raise three concerns that the product does not answer on its own:

| Concern | What Genie does today | What this accelerator adds |
|---|---|---|
| Users paste PII into prompts and it reaches the LLM | No redaction before the model call. Zero-retention agreements with model partners. | Row-level PII detection on prompts, responses, tool arguments and tool results; governed `class.*` tags on the columns; per-session `has_pii` flag and a severity weighted by entity type (a card number outranks a name). |
| How strong are the guardrails and safety classifiers | Genie Code: deterministic hard-blocks, AI safety inspection, human approval or an intent-based Auto-approve classifier. Genie One: scope-based Auto-approve for tool actions, otherwise architectural controls plus a system-prompt topic check. | Transparent rules over the *outcomes* the trace does record (refusals, rejected or denied tool calls, approval requests, destructive tool arguments, refusal text) with a per-session `risk_score`. |
| Does Auto-approve open the door to prompt injection | The approval classifier excludes retrieved content from its context, but nothing surfaces attempts to an admin. | Llama Prompt Guard 2 via `ai_query` over prompts (direct) and tool results (indirect), with an `ai_classify` second opinion. |

## How it works

### Data flow

![How the tables fit together](src/notebooks/images/table_guide_architecture.png)

Five stages, left to right: the raw Unity Gateway spans are flattened into turns and tool calls,
the detectors scan every free-text field and write one row per finding, the session rollup joins
it all back together per conversation with a `risk_score` and `severity`, and the "sessions to
review" alert reports sessions with new findings. Dashed boxes are sources the bundle does not
own; the orange table is the only one written by notebooks rather than a pipeline; green is where
triage starts; red is the alert. Source SVG: `docs/table_guide_architecture.svg`, rendered by
`docs/render_diagram.sh`.

### What runs when

The hourly job `genie_tracing_monitoring` drives everything. The three detectors run in parallel
and each only scans text it has not seen before; the guardrail rules re-score their whole lookback
window so pattern changes update history, and the PII step re-weights existing findings. The
sessions rollup runs even if a detector failed, and the alert is evaluated last, against the
finished tables.

```mermaid
flowchart TD
    etl["pipeline task<br/>genie_tracing_etl<br/><i>refresh genie_turns, genie_tool_calls</i>"]
    pii["02_detect_pii<br/><i>Presidio pandas UDF<br/>+ governed class.* tags</i>"]
    inj["03_detect_prompt_injection<br/><i>ai_query → Prompt Guard 2<br/>+ ai_classify second opinion</i>"]
    gr["04_detect_guardrail_signals<br/><i>rules over outcomes and text</i>"]
    sess["pipeline task<br/>genie_tracing_sessions<br/><i>refresh genie_sessions, timeline</i>"]
    al["alert task<br/><i>sessions to review,<br/>on the finished tables</i>"]

    etl --> pii
    etl --> inj
    etl --> gr
    pii --> sess
    inj --> sess
    gr --> sess
    sess --> al

    classDef pipe fill:#f5f7fa,stroke:#1b3139,color:#1b3139
    classDef nb fill:#fff4e5,stroke:#b86e00,color:#1b3139
    classDef alert fill:#fdecec,stroke:#b42318,color:#1b3139
    class etl,sess pipe
    class pii,inj,gr nb
    class al alert
```

### How a flag is born

```mermaid
flowchart LR
    text["Text field on a span<br/><i>prompt · response · tool_arguments<br/>tool_result · model_output</i>"]
    p["Presidio + DOB recogniser<br/><i>entities, offsets,<br/>weighted by entity type</i>"]
    g["Prompt Guard 2<br/><i>malicious probability</i>"]
    c["ai_classify<br/><i>LLM judge</i>"]
    r["Guardrail rules<br/><i>Action denied:, I dropped …,<br/>USER_REJECTED, …</i>"]
    d["genie_detections<br/><i>detector · flagged · score · label · evidence</i>"]
    s["genie_sessions<br/><i>flags.has_pii / has_prompt_injection /<br/>has_guardrail_signal · risk_score · severity</i>"]
    a["Alert: sessions to review<br/><i>new findings only,<br/>24 h of context</i>"]

    text --> p & g & c & r --> d --> s --> a

    classDef det fill:#fff4e5,stroke:#b86e00,color:#1b3139
    classDef gold fill:#e8f3ec,stroke:#1f7a4d,color:#1b3139
    classDef alert fill:#fdecec,stroke:#b42318,color:#1b3139
    class p,g,c,r,d det
    class s gold
    class a alert
```

## What gets built

```
<catalog>.genie_tracing
├── genie_turns              MV     one row per turn (root span): when/who, keys, prompt, response + outcome / context / span / completeness / links structs
├── genie_tool_calls         MV     one row per tool call / approval / question / model call: when/who, keys, tool, arguments, result + outcome / span structs
├── genie_detections         table  one row per (span, detector, field): when/who, detector, flagged, score, label + span struct, evidence
├── genie_sessions           MV     one row per conversation: when/who, is_flagged, risk_score, severity + activity / flags / risk / feedback / context structs
├── genie_session_timeline   view   ordered step-by-step walkthrough: when/who, position, event, text, is_flagged + outcome / detections / span structs
└── genie_tracing_libs       volume wheels for Presidio's spaCy model
```

**Column convention** across all tables: when, then who, then keys, then any free text (prompt,
response, tool arguments and results) as flat columns because they are scanned and may carry PII
row to row, then one or two headline flags, then metadata grouped into structs (`outcome`,
`context`, `span`, `completeness`, `links`, `flags`, `risk`, `activity`, `feedback`,
`detections`). Reach into a struct with dot notation, e.g. `outcome.run_outcome`.

Pipelines use materialized views so a refresh picks up late or re-exported spans. Switch
`genie_turns` and `genie_tool_calls` to streaming tables if you prefer append-only incremental
processing (`CREATE OR REFRESH STREAMING TABLE ... FROM STREAM(...)`).

### Bundle resources

| Resource | File | Purpose |
|---|---|---|
| Schema + volume | `resources/genie_tracing.schema.yml` | Target schema and wheel volume |
| Pipeline `genie_tracing_etl` | `src/pipelines/etl/` | `genie_turns`, `genie_tool_calls` |
| Pipeline `genie_tracing_sessions` | `src/pipelines/sessions/` | `genie_sessions`, `genie_session_timeline` |
| Job `genie_tracing_monitoring` | `resources/genie_tracing_monitoring.job.yml` | ETL → 3 detection notebooks → sessions → alert task. Hourly, paused by default. |
| SQL alert "sessions to review" | `resources/genie_tracing_alerts.alert.yml` | One digest across PII, prompt injection and guardrail signals: per session `severity`, `risk_score` and the top score per category. Evaluated by the job's alert task (its own schedule stays paused). Triggers only on sessions with a new finding since the previous run; the notification lists those first, then every session flagged in the last `alert_lookback_hours` for context (ids, labels, scores; never prompt text), with links to the tables to investigate. |

### Notebooks (`src/notebooks/`, Python source format)

| Notebook | Purpose |
|---|---|
| `00_setup.py` | Source table check, schema / volume / detections table, stage spaCy wheel, Data Classification status, preview checklist |
| `01_deploy_prompt_guard.py` | Get Llama Prompt Guard 2 weights (from Hugging Face, or copied out of a Prompt Guard model already registered in UC), log a batch-scoring pyfunc with 512-token chunking, deploy endpoint `genie-prompt-guard-2` |
| `02_detect_pii.py` | Presidio pandas UDF (row-level) with a context-gated `DATE_OF_BIRTH` recogniser, severity weighting by entity type (re-applied to history every run), optional `ai_extract` comparison, Data Classification results, apply governed `class.*` tags |
| `03_detect_prompt_injection.py` | `ai_query` to Prompt Guard over prompts and tool results, `ai_classify` second opinion, disagreement review |
| `04_detect_guardrail_signals.py` | Rule-based signals over outcomes and text; query to discover the guardrail's own wording |
| `05_session_explorer.py` | Adoption, flagged sessions, session walkthrough, approval flows, tool usage, thumbs-down |
| `06_table_guide.py` | Guided tour of every table in triage order, with a brief and a runnable query per table. **Start here if you are new to the schema.** |
| `_detection_utils.py` | Shared config, `genie_detections` DDL, candidate selection, idempotent MERGE into `genie_detections` (scored once via a staging table; errored rows skipped for retry) |

`src/sql/access_control.sql` has grants, a workspace row filter, column masks and an ABAC
policy sketch. Apply them before widening access: **the derived tables contain full prompts,
responses, SQL and tool results**, readable by anyone with `SELECT`.

## Quick start

### Prerequisites

1. Unity Gateway enabled, **Enhanced Unity Gateway** preview on at the account level, the
   unified trace table set up by a metastore admin, and the **Genie One Tracing** / **Genie Code
   Tracing** previews on in each workspace you want to monitor. Nothing is backfilled.
2. `SELECT` on the unified trace table and `CREATE` on the target catalog.
3. An existing **serverless or pro** SQL warehouse for the alert (set `warehouse_name`); job alert
   tasks do not run on classic warehouses.
4. For `01_deploy_prompt_guard`, either a Prompt Guard 2 model already registered in Unity
   Catalog (`model_source = uc_model`, no token needed) or a Databricks secret holding a Hugging
   Face token with access to Meta Llama models (`model_source = huggingface`, default scope
   `genie_tracing`, key `hf_token`).
5. The spaCy model wheel in the libs volume (see `00_setup`). If GitHub egress is blocked from
   your workspace, download `en_core_web_md-3.8.0-py3-none-any.whl` elsewhere and upload it.
   The job's `detect_pii` task installs it as a dependency and fails until it is staged; the
   prompt-injection and guardrail tasks run in a separate environment and are unaffected. Run
   interactively, `02_detect_pii` falls back to Presidio's pattern recognisers without it.
6. Databricks CLI ≥ 1.0 authenticated to the workspace.

### Deploy

```bash
git clone https://github.com/andyweaves/genie-trace-monitoring
cd genie-trace-monitoring

# Point the bundle at your workspace. Either pass --profile on every command, or:
cp databricks.local.yml.example databricks.local.yml   # gitignored; set profile, host, warehouse_name, workspace_url

databricks bundle validate -t dev
databricks bundle deploy   -t dev

# One-time, in the workspace:
#   run src/notebooks/00_setup                 stages the spaCy wheel, creates genie_detections
#   run src/notebooks/01_deploy_prompt_guard   deploys the Prompt Guard 2 endpoint

databricks bundle run genie_tracing_monitoring -t dev
```

Then open `src/notebooks/06_table_guide` in the workspace and walk through the tables.

The job deploys **paused**. Unpause it when you are happy with the output
(`schedule_pause_status: UNPAUSED`, or in the UI). The `prod` target unpauses it for you. The
alert needs no unpausing: the job evaluates it as its last step, once `genie_sessions` is rebuilt,
so a session is never checked against a half-refreshed table. A failed detector does not stop the
session rollup or the alert for what the other detectors found.

Variables you will most likely override (in `databricks.local.yml` or with `--var`):

| Variable | Default | Meaning |
|---|---|---|
| `catalog` / `schema` | `unity_gateway` / `genie_tracing` | Where the derived tables live |
| `source_table` | `unity_gateway.unified_tracing.unity_gateway_otel_spans` | Your unified trace table |
| `annotations_table` | `..._otel_annotations` | Its feedback sibling |
| `warehouse_name` | `Serverless Starter Warehouse` | Serverless or pro SQL warehouse for the alert |
| `prompt_guard_endpoint` | `genie-prompt-guard-2` | Endpoint created by `01_deploy_prompt_guard` |
| `detection_lookback_days` | `7` | How far back each run re-evaluates |
| `alert_email` | deployer | Who gets alert notifications |
| `alert_lookback_hours` | `24` | Hours of flagged sessions listed in each alert notification (the alert still only triggers on new findings) |
| `workspace_url` | `workspace.host` | Base URL for table links in alert notifications. Set it when the host comes only from `--profile` (it is empty then) |

## Detections

| Detector | Notebook | How | Writes |
|---|---|---|---|
| `pii_presidio` | 02 | Microsoft Presidio in a pandas UDF: regex / checksum recognisers everywhere, spaCy NER only on prompt and response, with product-term and identifier filters, plus a context-gated `DATE_OF_BIRTH` recogniser | most severe entity type, confidence × severity weight, offsets (never the value) |
| `pii_ai_extract` | 02, opt-in | `ai_extract` on a sample, for comparison | entity types found, mapped to Presidio types and weighted the same way |
| `prompt_injection_prompt_guard` | 03 | `ai_query` to a Llama Prompt Guard 2 endpoint; 512-token chunking with max pooling; prompts = direct vector, tool results and model output = indirect | malicious probability |
| `prompt_injection_ai_classify` | 03 | `ai_classify` three-way judge on Prompt Guard hits plus a random sample | legitimate / destructive-or-boundary-pushing / injection |
| `guardrail_signal` | 04 | Transparent rules over outcomes and response text | one row per rule hit, severity-weighted |

Guardrail rules, highest severity first: `guardrail_intervention` (classifier prefixes such as
`Action denied:` and `Review suggested:`), `destructive_action_executed` ("I dropped …"),
`tool_permission_denied`, `injection_recognised`, `refusal_text`, `boundary_pushing_prompt`,
`tool_user_rejected`, `sensitive_arguments`, `destructive_confirmation_requested`,
`external_destination`, plus informational `approval_requested`, `turn_error` and `tool_error`
(recorded in `genie_detections`, but they do not flag the session or add to `risk_score`).

PII findings are weighted by entity type (`pii_weights` on `02_detect_pii`): a finding's `score` is
Presidio's confidence × the type's weight, and its `label` is the most severe entity.

| Weight | Entity types |
|---|---|
| 1.0 | `CREDIT_CARD`, `US_SSN`, `US_BANK_NUMBER`, `IBAN_CODE`, `US_ITIN`, `CRYPTO` |
| 0.9 | `US_PASSPORT`, `US_DRIVER_LICENSE`, `UK_NHS` |
| 0.6 | `DATE_OF_BIRTH` |
| 0.5 | `PHONE_NUMBER`, `EMAIL_ADDRESS`, anything not listed (`pii_default_weight`) |
| 0.3 | `PERSON`, `LOCATION`, `MEDICAL_LICENSE` |
| 0.2 | `IP_ADDRESS` |

Session `risk_score` = min(1, PII + 0.8·injection + guardrail severity + 0.2 if a tool call was
rejected + 0.2 if a name appears with a date of birth, phone number or location). `severity` is
**high** at ≥ 0.8, **medium** at ≥ 0.5, otherwise **low** (`none` when not flagged). A name alone
scores about 0.26 (low), a name with a date of birth about 0.7 (medium), a card number 1.0 (high).
Weights live in `src/pipelines/sessions/transformations/genie_sessions.sql`.

## Tuning

* **Presidio**: `pii_threshold`, `ignore_entities` (default ignores `ORGANIZATION`, `DATE_TIME`,
  `URL`, `NRP`, `UUID`) and `allowlist_terms` on `02_detect_pii`. The requester's own email is never
  counted. NER entities are only accepted in prose fields, `PERSON` needs two words, `LOCATION`
  needs three letters and mixed case. A date counts as `DATE_OF_BIRTH` only with birth wording
  (`DOB`, `date of birth`, `born`, `birthday`, ...) right next to it, a year at least 10 years ago,
  and outside tool arguments (where `WHERE dob > '1990-01-01'` is a filter, not a birth date).
* **PII severity**: `pii_weights` (JSON) and `pii_default_weight` on `02_detect_pii`. Every run
  re-weights existing findings too, without re-triggering the alert.
* **Prompt Guard**: `prompt_guard_threshold` on `03_detect_prompt_injection` (default 0.85). The
  22M model catches direct jailbreak phrasing reliably but scored a table-embedded
  "SYSTEM: … DROP TABLE" row as benign in testing. Keep the `ai_classify` second opinion on, or
  deploy the 86M variant, for indirect injection.
* **Guardrail wording**: extend `INTERVENTION_PATTERNS`, `REFUSAL_PATTERNS`, `CONFIRMATION_REGEX`
  and `DESTRUCTIVE_EXECUTED_REGEX` in `04_detect_guardrail_signals` as you see new phrasing. The
  last cell of that notebook lists recent non-success turns to mine for it.
* **Scan scope**: a model-call output identical to the turn's final response is scanned once, as
  the response. Guardrail rules re-score their lookback window on every run in a single MERGE:
  hits that no longer match are deleted, unchanged hits keep their original `detected_at`, so the
  alert only counts a hit as new once rather than every hour.
* **Failed scans**: rows where Presidio, Prompt Guard or `ai_classify` errored are not written,
  so they are retried on the next run while still inside the lookback window.
* **Diagram**: `src/notebooks/images/table_guide_architecture.png` (used above and in
  `06_table_guide`) is rendered from `docs/table_guide_architecture.svg` by
  `docs/render_diagram.sh`. Re-render it whenever a table is added, renamed or re-wired.

## PII: Presidio and Data Classification

[Unity Catalog Data Classification](https://docs.databricks.com/aws/en/data-governance/unity-catalog/data-classification)
can find PII with no code at all, so it is natural to ask whether it can replace the Presidio
scan in `02_detect_pii`. For governance it is excellent; for monitoring it is not enough on its
own, because it works at the **column** level.

| Capability | Presidio (`02_detect_pii`) | Data Classification only |
|---|---|---|
| Which session, turn and field contained PII | ✅ one finding per span and field | ❌ which *column* has contained PII |
| `has_pii`, `severity`, `risk_score` per session | ✅ | ❌ |
| "Sessions to review" alert on new PII | ✅ every hourly run | ❌ |
| Severity weighting (card ≫ name), name + date-of-birth bonus | ✅ | ❌ |
| Governed `class.*` tags for ABAC | ✅ on the five scanned columns | ✅ on the columns it classifies, including raw payload copies |
| Freshness | Hourly | Background scan, new columns typically within 24 hours |
| Effort | Presidio, spaCy wheel, allow-list tuning | Enable it |

The core limitation: the first prompt containing a name tags `genie_turns.prompt` with
`class.name`, and the column stays tagged. A card number pasted the next day produces no new
signal, because classification answers "has this column ever contained PII", not "which
conversation just did".

### Recommended: use both

* **Presidio** for monitoring: row-level findings, session severity and the alert.
* **Data Classification** for tag coverage. `02_detect_pii` only tags the columns it scans
  (`prompt`, `response`, `tool_arguments`, `tool_result`, `response_text`); the same text is also
  in `input_messages_raw`, `output_messages_raw`, the `attributes` VARIANT and
  `genie_sessions.context`. Classification scans the materialized views' columns, so with
  auto-tagging on, the ABAC policy in `src/sql/access_control.sql` also masks the raw copies it
  classifies. Check which columns actually got tags (`06_table_guide`, section 6): struct and
  VARIANT columns such as `context` and `attributes` may not be classified, so keep the grants in
  `access_control.sql` as the primary control.

To enable it alongside Presidio:

1. Catalog Explorer → catalog → **Details** → **Data Classification** → **Enable**, for the whole
   catalog or just the `genie_tracing` schema. Needs `MANAGE` (or ownership) and serverless
   compute.
2. Turn on **auto-tagging** for the classes the ABAC policy matches (`class.name`,
   `class.email_address`, `class.phone_number`, `class.location`, `class.date_of_birth`,
   `class.credit_card`, `class.us_ssn`, ...). Applying tags needs `APPLY TAG` and `ASSIGN`.
3. Check results with the `system.data_classification.results` query in `00_setup` (section 4) or
   `02_detect_pii` (section 3), and the applied tags in `06_table_guide` (section 6).

### Data Classification only

For a deployment that will not run Presidio:

* Remove the `detect_pii` task from `resources/genie_tracing_monitoring.job.yml`, and from
  `sessions_pipeline`'s `depends_on`. The spaCy wheel (prerequisite 5) and the `detections`
  environment are then no longer needed.
* `has_pii` stays false, PII contributes nothing to `risk_score`, and the "sessions to review"
  alert covers prompt injection and guardrail signals only. PII becomes a **governance control**
  (tag, then mask with ABAC) rather than a monitored signal.
* `genie_session_timeline` and `genie_detections` no longer show PII; use Catalog Explorer or
  `system.data_classification.results` to see which columns have carried it.

### Caveats

* `system.data_classification.results` stores **sample values** from the scanned columns, which
  here means fragments of real prompts. Restrict `SELECT` on it as tightly as the
  `genie_tracing` schema itself.
* Detections typically land within 24 hours; a full rescan can be triggered from the UI.
* Turning auto-tagging off stops new tags but does not remove existing ones.
* Regular views (`genie_session_timeline`) are only scanned with the Beta view-scanning preview,
  and view columns are not tagged by default.
* Classification is billed as serverless compute; the first scan costs more than later
  incremental ones.

## What the trace does and does not contain

Verified against live traces in November 2026. These shape what the detectors can and cannot do.

* **Classifier verdicts are not in the trace.** The `Action denied: …` / `Review suggested: …`
  text the Genie Code safety and Auto-approve classifiers produce is returned to the model as a
  tool result, but that tool call is not exported as a span.
* **Genie Code exports a filtered subset of spans** (`expected_span_count` < `source_span_count`
  on the root span). Asset create / edit / run and user questions are exported; **SQL execution is
  not**. A successful `DROP TABLE` therefore leaves no tool span, only the response text
  "I dropped …". `destructive_action_executed` exists for exactly this reason.
* **What survives is the final response the user saw**, which usually narrates the outcome
  ("The safety guardrails prevented me from executing it"). The guardrail-signal detector keys
  off that text. It will get sharper the day verdicts arrive as span events.
* The unified trace table is shared with AI Gateway model traffic; everything here filters on
  `service_name IN ('Genie One', 'genie-code-agent')`.
* Span names differ from the docs: Genie Code tool spans are `execute_tool <name>` (not
  `tool.execute:<name>`), user questions are `execute_tool askUserQuestions` with a result of
  `answered` or `declined`, and the Genie One root span is `invoke_agent GenieOne` (not
  `OneChat`). The ETL identifies root spans by empty `parent_span_id` and classifies children by
  the operation attribute first, then by name, so it is insensitive to these.
* Genie One `execute_sql_query` tool spans carry the SQL in `tool_arguments` and the result as a
  markdown table in `tool_result`, which is where indirect prompt injection and PII in query
  results would appear. Both are scanned.
* Genie One attributes are capped at 180 KiB and 128 tool spans per turn; truncated spans carry
  `databricks.trace.payload_truncated`, surfaced as `completeness.payload_truncated`.
* Genie Agent (Genie Space) conversations are not traced; only the `ask_genie_space` tool call is.
* Trace delivery is best-effort. Audit logs remain the compliance system of record.
* Deleting a Genie conversation does not delete its traces. Set a retention policy.

## Related platform controls

* **Unity Gateway service policies** (`system.ai.block_jailbreak`, `system.ai.detect_sensitive_data`)
  evaluate inline for Model and MCP services registered in Unity Catalog and record decisions in
  the trace table's `events` column. They do not cover Genie itself, which is why this
  accelerator scans after the fact.
* **Unity Catalog Data Classification** tags columns automatically; `02_detect_pii` applies the
  same `class.*` tags from row-level findings so one ABAC policy covers both. See
  [PII: Presidio and Data Classification](#pii-presidio-and-data-classification) for how they fit
  together.
* **`system.access.assistant_events`** records one row per Genie Code message (who, where, when)
  without content, useful as a cross-check on trace completeness.

## Repository layout

```
.
├── databricks.yml                     bundle definition, variables, targets (no workspace secrets)
├── databricks.local.yml.example       template for your gitignored profile / warehouse overrides
├── resources/
│   ├── genie_tracing.schema.yml       schema + wheel volume
│   ├── genie_tracing_etl.pipeline.yml
│   ├── genie_tracing_sessions.pipeline.yml
│   ├── genie_tracing_monitoring.job.yml
│   └── genie_tracing_alerts.alert.yml "sessions to review" alert
├── src/
│   ├── pipelines/etl/transformations/        genie_turns.sql, genie_tool_calls.sql
│   ├── pipelines/sessions/transformations/   genie_sessions.sql, genie_session_timeline.sql
│   ├── notebooks/                            00 … 06 + _detection_utils, images/
│   └── sql/access_control.sql
└── docs/
    ├── table_guide_architecture.svg   diagram source
    └── render_diagram.sh              renders the PNG used in 06_table_guide
```

## License

Apache 2.0. See [LICENSE](LICENSE).
