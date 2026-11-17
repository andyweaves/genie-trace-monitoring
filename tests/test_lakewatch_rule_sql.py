"""Opt-in warehouse tests of rendered Lakewatch rule SQL against synthetic, SELECT-only fixtures.

Set GENIE_TRACE_TEST_PROFILE and GENIE_TRACE_TEST_WAREHOUSE explicitly. The rule queries read an
inline VALUES fixture instead of genie_detections; nothing is created and no real data is read.
"""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
PROFILE = os.environ.get("GENIE_TRACE_TEST_PROFILE")
WAREHOUSE = os.environ.get("GENIE_TRACE_TEST_WAREHOUSE")
SPEC = importlib.util.spec_from_file_location("lakewatch_utils", ROOT / "src/notebooks/_lakewatch_utils.py")
UTILS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(UTILS)
CATALOG = UTILS.load_catalog(ROOT / "src/lakewatch/rule_catalog.yml")
RULES = {r["name"]: r for r in CATALOG["rules"]}

# (conversation, minutes after start, detector, label, source field). Each conversation tests one
# ordering case for the lethal trifecta.
FINDINGS = [
    # c_in_order: injection, then PII, then an external send -> fires
    ("c_in_order", 0, "prompt_injection_prompt_guard", "MALICIOUS", "tool_result"),
    ("c_in_order", 1, "pii_presidio", "US_SSN", "tool_result"),
    ("c_in_order", 2, "guardrail_signal", "external_http_write", "tool_arguments"),
    # c_data_first: credential first, then injection, then a rendered exfil image -> fires
    ("c_data_first", 0, "guardrail_signal", "credential_databricks_pat", "prompt"),
    ("c_data_first", 1, "guardrail_signal", "indirect_instruction_override", "tool_result"),
    ("c_data_first", 2, "guardrail_signal", "markdown_external_query", "response"),
    # c_exfil_too_early: the send happens before the private data arrives -> no signal
    ("c_exfil_too_early", 0, "prompt_injection_ai_classify", "prompt injection or jailbreak attempt", "prompt"),
    ("c_exfil_too_early", 1, "guardrail_signal", "external_destination", "tool_arguments"),
    ("c_exfil_too_early", 2, "pii_presidio", "EMAIL_ADDRESS", "response"),
    # c_no_injection: private data and a send, but no untrusted instructions -> no signal
    ("c_no_injection", 0, "pii_presidio", "CREDIT_CARD", "prompt"),
    ("c_no_injection", 1, "guardrail_signal", "external_http_write", "tool_arguments"),
    # c_ip_only: an IP address is not private data for this rule -> no signal
    ("c_ip_only", 0, "prompt_injection_prompt_guard", "MALICIOUS", "prompt"),
    ("c_ip_only", 1, "pii_presidio", "IP_ADDRESS", "response"),
    ("c_ip_only", 2, "guardrail_signal", "external_http_write", "tool_arguments"),
    # c_image_in_data: a planted image in tool output is not yet external communication -> no signal
    ("c_image_in_data", 0, "prompt_injection_prompt_guard", "MALICIOUS", "tool_result"),
    ("c_image_in_data", 1, "pii_presidio", "US_SSN", "tool_result"),
    ("c_image_in_data", 2, "guardrail_signal", "markdown_external_query", "tool_result"),
]


def fixture_sql(detected_minutes_ago=5):
    rows = []
    for i, (cid, minute, detector, label, field) in enumerate(FINDINGS):
        span_field = f"security:{label}:{field}" if detector == "guardrail_signal" else field
        details = (json.dumps({"source_field": field, "pattern_id": label, "tool_name": "fixture_tool"})
                   if detector == "guardrail_signal" else None)
        rows.append(
            "(" + ", ".join([
                f"timestampadd(MINUTE, {minute}, TIMESTAMP'2026-01-01 00:00:00')",
                f"current_timestamp() - INTERVAL {detected_minutes_ago} MINUTES",
                "'workspace'", "'tester@example.com'", f"'{cid}'", "'Genie Code'",
                f"'{detector}'", "true", "0.9", f"'{label}'",
                f"named_struct('trace_id', 't_{cid}_{minute}', 'span_id', 's{i}', 'field', '{span_field}', 'text_length', 10)",
                ("'" + details.replace("'", "\\'") + "'") if details else "CAST(NULL AS STRING)",
            ]) + ")"
        )
    return ("(SELECT * FROM VALUES " + ",\n".join(rows) + " AS t(span_time, detected_at, workspace_id, requester, "
            "conversation_id, product, detector, flagged, score, label, span, details))")


def execute_select(sql):
    body = {"warehouse_id": WAREHOUSE, "statement": sql, "wait_timeout": "50s",
            "on_wait_timeout": "CANCEL", "row_limit": 100}
    result = subprocess.run(
        ["databricks", "api", "post", "/api/2.0/sql/statements", "--profile", PROFILE,
         "--json", json.dumps(body)], capture_output=True, text=True, timeout=90, check=True,
    )
    response = json.loads(result.stdout)
    if response["status"]["state"] != "SUCCEEDED":
        raise AssertionError(response["status"])
    names = [column["name"] for column in response["manifest"]["schema"]["columns"]]
    return [dict(zip(names, row)) for row in response.get("result", {}).get("data_array", [])]


def run_rule(name, detected_minutes_ago=5):
    ctx = dict(UTILS.example_context(), detections=fixture_sql(detected_minutes_ago))
    query = UTILS.render_query(RULES[name], ctx)
    # The fixture spans are in 2026-01; anchor "now" there so the 7-day leg lookback covers them,
    # while the run window still covers detected_at (minutes before the real current time).
    preview = UTILS.preview_query(query, "current_timestamp() - INTERVAL 1 HOUR", "current_timestamp()")
    preview = preview.replace("(current_timestamp()) - INTERVAL 7 DAYS", "TIMESTAMP'2025-12-25'")
    return {row["conversation_id"]: row for row in execute_select(preview)}


@unittest.skipUnless(PROFILE and WAREHOUSE, "explicit SQL test profile/warehouse not set")
class LethalTrifectaSqlTests(unittest.TestCase):
    def test_fires_only_when_all_legs_precede_the_external_communication(self):
        signals = run_rule("genie_lethal_trifecta")
        self.assertEqual(sorted(signals), ["c_data_first", "c_in_order"])

    def test_labels_list_each_leg_and_links_are_present(self):
        row = run_rule("genie_lethal_trifecta")["c_in_order"]
        self.assertEqual(row["labels"],
                         "injection: MALICIOUS | private_data: US_SSN | external_communication: external_http_write")
        self.assertTrue(row["dashboard_url"].endswith("f_investigate~conversation=c_in_order"))
        self.assertIn("/explore/data/example_catalog/genie_tracing/genie_session_timeline", row["catalog_explorer_url"])
        self.assertIn("ORDER BY step_number", row["investigate"])

    def test_old_findings_do_not_signal_again(self):
        self.assertEqual(run_rule("genie_lethal_trifecta", detected_minutes_ago=600), {})


if __name__ == "__main__":
    unittest.main()
