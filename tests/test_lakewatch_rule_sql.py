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


def run_query(name, detections):
    ctx = dict(UTILS.example_context(), detections=detections)
    query = UTILS.render_query(RULES[name], ctx)
    # The fixture spans are in 2026-01; anchor "now" there so the 7-day leg lookback covers them,
    # while the run window still covers detected_at (minutes before the real current time).
    preview = UTILS.preview_query(query, "current_timestamp() - INTERVAL 1 HOUR", "current_timestamp()")
    preview = preview.replace("(current_timestamp()) - INTERVAL 7 DAYS", "TIMESTAMP'2025-12-25'")
    return execute_select(preview)


def run_rule(name, detected_minutes_ago=5):
    return {row["conversation_id"]: row for row in run_query(name, fixture_sql(detected_minutes_ago))}


# Rate rules: (requester, conversation, minutes after start, label, tool, turn, span, detected
# minutes ago). Each requester tests one case; findings detected 600 minutes ago are old.
RATE_FINDINGS = [
    # u_burst: five blocked or refused turns in 40 minutes over two conversations -> fires
    ("u_burst", "c_burst_1", 0, "refusal_text", None, "t_b1", "s_b1", 5),
    ("u_burst", "c_burst_1", 10, "guardrail_intervention", None, "t_b2", "s_b2", 5),
    ("u_burst", "c_burst_1", 20, "refusal_outcome", None, "t_b3", "s_b3", 5),
    ("u_burst", "c_burst_2", 30, "tool_permission_denied", "run_sql", "t_b4", "s_b4", 5),
    ("u_burst", "c_burst_2", 40, "refusal_text", None, "t_b5", "s_b5", 5),
    # u_straddle: five turns 59 minutes apart, across a clock hour -> fires
    ("u_straddle", "c_straddle", 30, "refusal_text", None, "t_s1", "s_s1", 5),
    ("u_straddle", "c_straddle", 45, "refusal_text", None, "t_s2", "s_s2", 5),
    ("u_straddle", "c_straddle", 60, "refusal_text", None, "t_s3", "s_s3", 5),
    ("u_straddle", "c_straddle", 75, "refusal_text", None, "t_s4", "s_s4", 5),
    ("u_straddle", "c_straddle", 89, "refusal_text", None, "t_s5", "s_s5", 5),
    # u_spread: five turns, but never more than three in one hour -> no signal
    ("u_spread", "c_spread", 0, "refusal_text", None, "t_p1", "s_p1", 5),
    ("u_spread", "c_spread", 20, "refusal_text", None, "t_p2", "s_p2", 5),
    ("u_spread", "c_spread", 40, "refusal_text", None, "t_p3", "s_p3", 5),
    ("u_spread", "c_spread", 70, "refusal_text", None, "t_p4", "s_p4", 5),
    ("u_spread", "c_spread", 100, "refusal_text", None, "t_p5", "s_p5", 5),
    # u_old: a burst whose findings were all detected in an earlier run -> no signal
    ("u_old", "c_old", 0, "refusal_text", None, "t_o1", "s_o1", 600),
    ("u_old", "c_old", 1, "refusal_text", None, "t_o2", "s_o2", 600),
    ("u_old", "c_old", 2, "refusal_text", None, "t_o3", "s_o3", 600),
    ("u_old", "c_old", 3, "refusal_text", None, "t_o4", "s_o4", 600),
    ("u_old", "c_old", 4, "refusal_text", None, "t_o5", "s_o5", 600),
    # u_tool: five blocked calls of one tool and four of another, all in two turns -> one
    # stuck-on-block signal (run_python), and no repeat-offender signal (only two turns)
    *[("u_tool", "c_tool", i, "tool_policy_blocked", "run_python", f"t_t{i % 2}", f"s_ta{i}", 5) for i in range(5)],
    *[("u_tool", "c_tool", i, "tool_policy_blocked", "run_sql", f"t_t{i % 2}", f"s_tb{i}", 5) for i in range(4)],
    # u_noise: five turns with an unrelated label -> no signal
    *[("u_noise", "c_noise", i, "external_destination", None, f"t_n{i}", f"s_n{i}", 5) for i in range(5)],
    # u_approvals: ten unflagged approval requests in an hour -> approval spike; nine -> none
    *[("u_approvals", "c_appr", i * 5, "approval_requested", "editAsset", "t_a", f"s_a{i}", 5) for i in range(10)],
    *[("u_few_approvals", "c_few", i * 5, "approval_requested", "editAsset", "t_f", f"s_f{i}", 5) for i in range(9)],
    # Keyword watchlist: the prefix is literal, so `_` is not a LIKE wildcard
    ("u_keyword", "c_keyword", 0, "confidential_keyword_codename_1", None, "t_k1", "s_k1", 5),
    ("u_not_keyword", "c_not_keyword", 0, "confidential_keywordx1", None, "t_k2", "s_k2", 5),
]


def rate_fixture_sql():
    rows = []
    for requester, cid, minute, label, tool, trace, span, detected_ago in RATE_FINDINGS:
        details = json.dumps({"tool_name": tool} if tool else {})
        flagged = "false" if label == "approval_requested" else "true"
        rows.append(
            "(" + ", ".join([
                f"timestampadd(MINUTE, {minute}, TIMESTAMP'2026-01-01 00:00:00')",
                f"current_timestamp() - INTERVAL {detected_ago} MINUTES",
                "'workspace'", f"'{requester}@example.com'", f"'{cid}'", "'Genie Code'",
                "'guardrail_signal'", flagged, "0.8", f"'{label}'",
                f"named_struct('trace_id', '{trace}', 'span_id', '{span}', 'field', '{label}', 'text_length', 10)",
                "'" + details.replace("'", "\\'") + "'",
            ]) + ")"
        )
    return ("(SELECT * FROM VALUES " + ",\n".join(rows) + " AS t(span_time, detected_at, workspace_id, requester, "
            "conversation_id, product, detector, flagged, score, label, span, details))")


def run_rate_rule(name):
    return {row["requester"].split("@")[0]: row for row in run_query(name, rate_fixture_sql())}


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



@unittest.skipUnless(PROFILE and WAREHOUSE, "explicit SQL test profile/warehouse not set")
class RateRuleSqlTests(unittest.TestCase):
    def test_repeat_offender_uses_a_sliding_window_of_distinct_turns(self):
        signals = run_rate_rule("genie_repeat_offender")
        self.assertEqual(sorted(signals), ["u_burst", "u_straddle"])
        burst = signals["u_burst"]
        self.assertEqual(int(burst["hit_count"]), 5)
        self.assertEqual(burst["conversation_id"], "c_burst_2", "links go to the latest conversation")
        self.assertEqual(burst["labels"], "guardrail_intervention, refusal_outcome, refusal_text, tool_permission_denied")
        self.assertTrue(burst["dashboard_url"].endswith("f_investigate~conversation=c_burst_2"))

    def test_stuck_on_block_groups_by_tool(self):
        signals = run_query("genie_agent_stuck_on_block", rate_fixture_sql())
        self.assertEqual([(r["requester"], r["tools"], int(r["hit_count"])) for r in signals],
                         [("u_tool@example.com", "run_python", 5)])

    def test_approval_spike_counts_unflagged_requests(self):
        signals = run_rate_rule("genie_approval_spike")
        self.assertEqual(sorted(signals), ["u_approvals"])
        self.assertEqual(int(signals["u_approvals"]["hit_count"]), 10)


    def test_confidential_keyword_prefix_is_literal(self):
        signals = run_query("genie_confidential_keyword", rate_fixture_sql())
        self.assertEqual([(r["conversation_id"], r["labels"]) for r in signals],
                         [("c_keyword", "confidential_keyword_codename_1")])


if __name__ == "__main__":
    unittest.main()
