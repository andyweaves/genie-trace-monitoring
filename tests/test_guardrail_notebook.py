"""Local tests of the notebook's pure adapter and its single-write contract."""

import ast
import json
from pathlib import Path
import unittest

import pandas as pd

from evaluate_security_traces import score_rows


NOTEBOOK = Path(__file__).resolve().parents[1] / "src/notebooks/04_detect_guardrail_signals.py"


class GuardrailNotebookTests(unittest.TestCase):
    def test_pandas_adapter_round_trips_safe_metadata(self):
        module = ast.parse(NOTEBOOK.read_text())
        function = next(node for node in module.body
                        if isinstance(node, ast.FunctionDef) and node.name == "security_scan")
        function.decorator_list = []  # Exercise the adapter without requiring Spark/Arrow locally.
        seen = []

        def scan(text, scope):
            seen.append((text, scope))
            return {"hits": [], "limits": [], "scanned_chars": len(text or "")}

        namespace = {"pd": pd, "json": json, "scan_security_text": scan}
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(NOTEBOOK), "exec"), namespace)
        result = namespace["security_scan"](pd.Series(["private payload", None]),
                                             pd.Series(["prompt", "answer"]))
        self.assertEqual(seen, [("private payload", "prompt"), (None, "answer")])
        self.assertEqual(json.loads(result.iloc[0])["scanned_chars"], 15)
        self.assertNotIn("private payload", result.iloc[0])
        self.assertEqual(json.loads(result.iloc[1])["scanned_chars"], 0)

    def test_guardrail_branches_share_one_rescoring_merge(self):
        module = ast.parse(NOTEBOOK.read_text())
        writes = [node for node in ast.walk(module) if isinstance(node, ast.Call)
                  and isinstance(node.func, ast.Name) and node.func.id == "write_detections"]
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0].args[1].value, "guardrail_signal")
        cutoff = next(keyword.value for keyword in writes[0].keywords
                      if keyword.arg == "rescore_since")
        self.assertIsInstance(cutoff, ast.Name)
        self.assertEqual(cutoff.id, "CUTOFF_SQL")

    def test_scorecard_prints_no_content_or_untrusted_case_name(self):
        def scan(text, scope):
            return {"hits": [{"rule_id": "test_rule", "flagged": True}],
                    "limits": [], "scanned_chars": len(text)}

        report = score_rows([
            {"text": "sensitive text", "scope": "prompt", "field": "prompt",
             "product": "Genie Code", "test_case": "BN-001"},
            {"text": "another payload", "scope": "answer", "field": "response",
             "product": "Genie One", "test_case": "not-a-safe-case-label"},
        ], scan)
        encoded = json.dumps(report)
        self.assertNotIn("sensitive text", encoded)
        self.assertNotIn("another payload", encoded)
        self.assertNotIn("not-a-safe-case-label", encoded)
        self.assertEqual(report["counts"]["fields_scanned"], 2)
        self.assertEqual(len(report["labelled_cases"]), 1)
        self.assertEqual(report["labelled_cases"][0]["test_case"], "BN-001")


if __name__ == "__main__":
    unittest.main()
