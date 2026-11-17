"""Local tests of the Lakewatch rule catalog and its renderer: no Spark, network or workspace."""

import ast
import importlib.util
import json
from pathlib import Path
import re
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("lakewatch_utils", ROOT / "src/notebooks/_lakewatch_utils.py")
UTILS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(UTILS)
CATALOG_PATH = ROOT / "src/lakewatch/rule_catalog.yml"
CATALOG = UTILS.load_catalog(CATALOG_PATH)
CTX = UTILS.example_context()
PAYLOADS = {p["rule_name"]: p for p in UTILS.build_payloads(CATALOG, CTX)}
RULES = {r["name"]: r for r in CATALOG["rules"]}


def guardrail_labels():
    """Every label 04_detect_guardrail_signals can write: outcome rules, runaway rules, signatures."""
    notebook = (ROOT / "src/notebooks/04_detect_guardrail_signals.py").read_text()
    labels = set(re.findall(r'dict\(name="([a-z_]+)"', notebook))
    labels |= set(re.findall(r"THEN '([a-z_]+)' END AS [a-z_]+_rule", notebook))
    labels.add("security_scan_limited")
    patterns = yaml.safe_load((ROOT / "src/config/security_patterns.yml").read_text())
    flagged = {r["id"]: r["flagged"] for r in patterns["rules"]}
    return labels | set(flagged), flagged


def default_pii_weights():
    tree = ast.parse((ROOT / "src/notebooks/02_detect_pii.py").read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", None) == "DEFAULT_PII_WEIGHTS":
            return ast.literal_eval(node.value)
    raise AssertionError("DEFAULT_PII_WEIGHTS not found")


class CoverageTests(unittest.TestCase):
    def test_every_guardrail_label_is_signalled_or_excluded(self):
        known, _ = guardrail_labels()
        covered = UTILS.covered_labels(CATALOG)["guardrail_signal"]
        self.assertEqual(sorted(known - covered), [], "guardrail labels with no Lakewatch rule")

    def test_catalog_only_names_labels_that_exist(self):
        known, _ = guardrail_labels()
        covered = UTILS.covered_labels(CATALOG)["guardrail_signal"] - {"*"}
        self.assertEqual(sorted(covered - known), [], "catalog labels that 04 never writes (typo?)")

    def test_flagged_labels_are_not_excluded(self):
        _, flagged = guardrail_labels()
        excluded = set(CATALOG["not_signalled"]["guardrail_signal"])
        self.assertEqual(sorted(l for l in excluded if flagged.get(l)), [])

    def test_unflagged_signatures_need_include_unflagged(self):
        _, flagged = guardrail_labels()
        for rule in CATALOG["rules"]:
            for entry in rule.get("match") or []:
                for label in entry.get("labels") or []:
                    if flagged.get(label) is False:
                        self.assertTrue(entry.get("include_unflagged"), f"{rule['name']}: {label} is unflagged")

    def test_each_flagged_label_has_one_primary_rule(self):
        # A label may appear in several match rules only when they split it by source field.
        owners = {}
        for rule in CATALOG["rules"]:
            for entry in rule.get("match") or []:
                for label in entry.get("labels") or []:
                    owners.setdefault((entry["detector"], label), []).append((rule["name"], entry.get("fields")))
        for key, rules in owners.items():
            if len(rules) > 1:
                self.assertTrue(all(fields for _, fields in rules), f"{key} matched by {rules} without fields")
                all_fields = [f for _, fields in rules for f in fields]
                self.assertEqual(len(all_fields), len(set(all_fields)), f"{key} fields overlap: {rules}")

    def test_sensitive_pii_matches_high_weight_entities(self):
        weights = default_pii_weights()
        high = sorted(k for k, v in weights.items() if v >= 0.9)
        for entry in RULES["genie_sensitive_pii"]["match"]:
            self.assertEqual(sorted(entry["labels"]), high)
        for entry in RULES["genie_personal_data"]["match"]:
            self.assertEqual(sorted(entry["exclude_labels"]), high)

    def test_injection_detectors_split_by_field(self):
        direct = {e["detector"]: e.get("fields") for e in RULES["genie_direct_prompt_injection"]["match"]}
        indirect = {e["detector"]: e.get("fields") for e in RULES["genie_indirect_prompt_injection"]["match"]}
        for detector in ("prompt_injection_prompt_guard", "prompt_injection_ai_classify"):
            self.assertEqual(direct[detector], ["prompt"])
            self.assertEqual(sorted(indirect[detector]), ["model_output", "tool_result"])


class PayloadTests(unittest.TestCase):
    def test_required_fields_and_limits(self):
        for name, p in PAYLOADS.items():
            with self.subTest(rule=name):
                for key in ("catalog_name", "schema_name", "rule_name", "severity", "fidelity", "schedule", "output"):
                    self.assertTrue(p.get(key), key)
                self.assertIn(p["severity"], UTILS.SEVERITIES)
                self.assertIn(p["fidelity"], UTILS.FIDELITIES)
                self.assertLessEqual(len(p["runbook"]), UTILS.RUNBOOK_MAX_CHARS)
                self.assertLessEqual(len(p["references"]), UTILS.MAX_REFERENCES)
                self.assertLessEqual(len(p["mitre"]), UTILS.MAX_MITRE)
                self.assertEqual(p["output"]["event_time_column"], "event_time")
                self.assertFalse(p["output"]["default_context"])
                self.assertEqual(p["annotations"]["managed_by"], UTILS.MANAGED_BY)
                self.assertTrue(all(isinstance(v, str) for v in p["annotations"].values()))

    def test_every_query_uses_the_run_window(self):
        for name, p in PAYLOADS.items():
            self.assertIn("IN_TIMERANGE(", p["batch"]["sql"]["query"], name)
            self.assertNotRegex(p["batch"]["sql"]["query"], r"(?i)\b(now|current_timestamp)\(\)", name)

    def test_no_free_text_reaches_a_signal(self):
        for name, p in PAYLOADS.items():
            code = UTILS._strip_literals(p["batch"]["sql"]["query"])
            for column in UTILS.FREE_TEXT_COLUMNS:
                self.assertNotRegex(code, rf"(?i)(?<![\w$]){column}(?!\w)", f"{name} reads {column}")
            self.assertNotIn("details AS", code)

    def test_free_text_check_rejects_content_columns(self):
        rule = dict(RULES["genie_high_risk_session"])
        rule["query"] = rule["query"].replace("s.requester,", "s.context.first_prompt AS requester,")
        with self.assertRaisesRegex(ValueError, "free-text column 'first_prompt'"):
            UTILS.render_query(rule, CTX)

    def test_details_paths_are_allowlisted(self):
        rule = dict(RULES["genie_pii_combination"])
        rule["query"] = rule["query"].replace("'$.entities'", "'$.match'")
        with self.assertRaisesRegex(ValueError, "details path"):
            UTILS.render_query(rule, CTX)

    def test_investigate_query_uses_timeline_columns(self):
        timeline = (ROOT / "src/pipelines/sessions/transformations/genie_session_timeline.sql").read_text()
        final_select = timeline[timeline.rindex("SELECT"):]
        for name, p in PAYLOADS.items():
            order_by = re.search(r"ORDER BY (\w+)'\)", p["batch"]["sql"]["query"])
            self.assertIsNotNone(order_by, name)
            self.assertRegex(final_select, rf"\b{order_by.group(1)}\b", f"{name}: timeline has no {order_by.group(1)}")
            self.assertIn("conversation_id", final_select)

    def test_summary_and_context_only_use_output_columns(self):
        for name, p in PAYLOADS.items():
            for placeholder in re.findall(r"\{([a-z_]+)\}", p["output"]["summary"]):
                self.assertIn(placeholder, UTILS.CONTEXT_KEYS, name)
            self.assertEqual(set(p["output"]["context"]), set(UTILS.CONTEXT_KEYS))

    def test_mitre_mappings_are_well_formed(self):
        for name, p in PAYLOADS.items():
            for m in p["mitre"]:
                self.assertIn(m["taxonomy"], UTILS.TACTICS)
                self.assertIn(m["tactic"], UTILS.TACTICS[m["taxonomy"]], name)
                if m.get("sub_technique_id"):
                    self.assertTrue(m["sub_technique_id"].startswith(m["technique_id"] + "."), name)
        mapped = [n for n, p in PAYLOADS.items() if not p["mitre"]]
        self.assertEqual(mapped, ["genie_high_risk_session"], "only the composite rule may omit MITRE")

    def test_validation_rejects_bad_metadata(self):
        import copy

        for mutate, message in (
            (lambda r: r.update(severity="Severe"), "severity"),
            (lambda r: r.update(fidelity="HIGH"), "fidelity"),
            (lambda r: r["mitre"].append({"taxonomy": "mitre-attack", "tactic": "Defense Evasion",
                                          "technique_id": "T1027", "technique": "x"}), "tactic"),
            (lambda r: r["mitre"].append({"taxonomy": "mitre-atlas", "tactic": "Execution",
                                          "technique_id": "T1059", "technique": "x"}), "technique_id"),
            (lambda r: r["match"].append({"detector": "guardrail_signal", "labels": ["x'; DROP"]}), "invalid label"),
            (lambda r: r.update(summary="Leak {prompt}"), "summary placeholder"),
        ):
            catalog = copy.deepcopy(CATALOG)
            mutate(catalog["rules"][0])
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                UTILS.validate_catalog(catalog)

    def test_preview_query_replaces_macros(self):
        query = PAYLOADS["genie_injection_then_action"]["batch"]["sql"]["query"]
        preview = UTILS.preview_query(query, "TIMESTAMP'2026-01-01'", "TIMESTAMP'2026-01-02'")
        self.assertNotIn("IN_TIMERANGE", preview)
        self.assertNotIn("TIMERANGE_NOW", preview)
        self.assertIn("detected_at >= TIMESTAMP'2026-01-01' AND detected_at < TIMESTAMP'2026-01-02'", preview)

    def test_yaml_export_round_trips(self):
        for name, p in PAYLOADS.items():
            self.assertEqual(yaml.safe_load(UTILS.payload_yaml(p)), {**p, "batch": {
                **p["batch"], "sql": {"query": p["batch"]["sql"]["query"] + "\n"}},
                "objective": p["objective"] + "\n", "runbook": p["runbook"] + "\n"}, name)

    def test_run_as_is_optional(self):
        self.assertNotIn("run_as_principal", PAYLOADS["genie_credential_exposed"])
        p = UTILS.build_payload(RULES["genie_credential_exposed"], CATALOG, dict(CTX, run_as_principal="sp-app-id"))
        self.assertEqual(p["run_as_principal"], "sp-app-id")
        self.assertIn("run_as_principal", UTILS.update_mask(p))


class TrifectaAndLinkTests(unittest.TestCase):
    def test_lethal_trifecta_is_the_only_critical_rule(self):
        critical = sorted(n for n, p in PAYLOADS.items() if p["severity"] == "Critical")
        self.assertEqual(critical, ["genie_lethal_trifecta"])
        self.assertEqual(PAYLOADS["genie_injection_then_action"]["severity"], "High")

    def test_trifecta_legs(self):
        legs = {leg["name"]: leg["match"] for leg in RULES["genie_lethal_trifecta"]["legs"]}
        self.assertEqual(list(legs), ["injection", "private_data", "external_communication"])
        pii = [e for e in legs["private_data"] if e["detector"].startswith("pii_")]
        self.assertTrue(pii and all(e["exclude_labels"] == ["IP_ADDRESS"] for e in pii))
        rendered = [e for e in legs["external_communication"] if "markdown_external_query" in e.get("labels", [])]
        self.assertEqual(rendered[0]["fields"], ["response"], "a planted image only counts once rendered")
        self.assertNotIn("boundary_pushing_prompt", [l for e in legs["injection"] for l in e.get("labels", [])])

    def test_chain_validation(self):
        import copy

        for mutate, message in (
            (lambda r: r.update(legs=r["legs"][:1]), "at least two legs"),
            (lambda r: r["legs"][1].update(name="injection"), "unique"),
            (lambda r: r["legs"][0].update(match=[]), "each chain leg"),
        ):
            catalog = copy.deepcopy(CATALOG)
            mutate(next(r for r in catalog["rules"] if r["name"] == "genie_lethal_trifecta"))
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                UTILS.validate_catalog(catalog)

    def test_links_on_every_rule(self):
        for name, p in PAYLOADS.items():
            query = p["batch"]["sql"]["query"]
            self.assertIn("f_investigate~conversation=', url_encode(q.conversation_id)) AS dashboard_url", query, name)
            self.assertIn("/explore/data/example_catalog/genie_tracing/genie_session_timeline", query, name)
            self.assertEqual(p["output"]["context"]["dashboard_url"], "{dashboard_url}")

    def test_links_blank_without_dashboard_or_host(self):
        ctx = dict(CTX, dashboard_id="", workspace_url="")
        query = UTILS.render_query(RULES["genie_credential_exposed"], ctx)
        self.assertIn("'' AS dashboard_url", query)
        self.assertIn("'' AS catalog_explorer_url", query)
        self.assertNotIn("Catalog Explorer:", UTILS.build_payload(RULES["genie_credential_exposed"], CATALOG, ctx)["runbook"])

    def test_runbooks_prime_analysts_and_the_triage_agent(self):
        for name, p in PAYLOADS.items():
            for section in ("## Investigate", "## Verdict", "**True positive**", "**Benign positive**",
                            "ORDER BY step_number", "[genie_detections]("):
                self.assertIn(section, p["runbook"], name)

    def test_dashboard_filter_matches_deep_links(self):
        dashboard = json.loads((ROOT / "src/dashboards/genie_session_investigation.lvdash.json").read_text())
        page, widget = UTILS.DASHBOARD_FILTER[2:].split("~")
        pages = {pg["name"]: pg for pg in dashboard["pages"]}
        self.assertIn(page, pages)
        filters = [l["widget"] for l in pages[page]["layout"] if l["widget"]["name"] == widget]
        self.assertEqual(len(filters), 1)
        bound = {q["query"]["datasetName"] for q in filters[0]["queries"]}
        self.assertEqual(bound, {d["name"] for d in dashboard["datasets"]}, "filter must bind every dataset")
        for d in dashboard["datasets"]:
            sql = "".join(d["queryLines"])
            self.assertRegex(sql, r"\bconversation_id\b")
            self.assertNotRegex(sql, r"(?i)\bFROM\s+\S+\.\S+", "dashboard queries must use bare table names")


class PlanTests(unittest.TestCase):
    def test_create_update_unchanged_delete(self):
        payloads = [PAYLOADS["genie_credential_exposed"], PAYLOADS["genie_destructive_action"],
                    PAYLOADS["genie_privilege_change"]]
        existing = [
            {"name": "rules/1", "rule_name": "genie_destructive_action",
             "annotations": {"content_hash": PAYLOADS["genie_destructive_action"]["annotations"]["content_hash"]}},
            {"name": "rules/2", "effective_rule_name": "genie_privilege_change", "annotations": {"content_hash": "old"}},
            {"name": "rules/3", "rule_name": "genie_retired_rule", "annotations": {"managed_by": UTILS.MANAGED_BY}},
            {"name": "rules/4", "rule_name": "someone_elses_rule", "annotations": {}},
        ]
        plan = {name: (action, resource) for action, name, resource, _ in UTILS.plan_changes(payloads, existing, prune=True)}
        self.assertEqual(plan, {
            "genie_credential_exposed": ("create", None),
            "genie_destructive_action": ("unchanged", "rules/1"),
            "genie_privilege_change": ("update", "rules/2"),
            "genie_retired_rule": ("delete", "rules/3"),
        })
        no_prune = UTILS.plan_changes(payloads, existing)
        self.assertNotIn("delete", [a for a, *_ in no_prune])

    def test_content_hash_tracks_changes(self):
        rule = dict(RULES["genie_credential_exposed"], severity="Critical")
        changed = UTILS.build_payload(rule, CATALOG, CTX)
        self.assertNotEqual(changed["annotations"]["content_hash"],
                            PAYLOADS["genie_credential_exposed"]["annotations"]["content_hash"])
        other_warehouse = UTILS.build_payload(RULES["genie_credential_exposed"], CATALOG, dict(CTX, warehouse_id="x"))
        self.assertNotEqual(other_warehouse["annotations"]["content_hash"],
                            PAYLOADS["genie_credential_exposed"]["annotations"]["content_hash"])

    def test_update_mask_covers_managed_fields_only(self):
        mask = UTILS.update_mask(PAYLOADS["genie_credential_exposed"]).split(",")
        self.assertNotIn("catalog_name", mask)
        self.assertNotIn("suppress_until_time", mask)
        self.assertIn("batch", mask)
        self.assertIn("runbook", mask)


if __name__ == "__main__":
    unittest.main()
