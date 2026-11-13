"""Opt-in warehouse tests of the notebook SQL against synthetic, SELECT-only fixtures.

Set GENIE_TRACE_TEST_PROFILE and GENIE_TRACE_TEST_WAREHOUSE explicitly. No tables,
functions, jobs or views are created, and no real trace content is read.
"""

import ast
import json
import os
from pathlib import Path
import subprocess
import unittest


NOTEBOOK = Path(__file__).resolve().parents[1] / "src/notebooks/04_detect_guardrail_signals.py"
PROFILE = os.environ.get("GENIE_TRACE_TEST_PROFILE")
WAREHOUSE = os.environ.get("GENIE_TRACE_TEST_WAREHOUSE")


def query_templates():
    values = {"LOOP_MIN_CALLS": 5, "LONG_TURN_MINUTES": 60, "SPAN_CAP_HINT": 120}
    wanted = {"QUESTION_TOOLS", "ACTION_TOOL", "SECURITY_FIELDS_SQL", "RUNAWAY_SQL"}
    for node in ast.parse(NOTEBOOK.read_text()).body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) and node.targets[0].id in wanted):
            # Evaluate only our own SQL templates and their string/numeric parameters, not the notebook.
            values[node.targets[0].id] = eval(
                compile(ast.Expression(node.value), str(NOTEBOOK), "eval"),
                {"__builtins__": {}}, values,
            )
    return values


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
    manifest = response["manifest"]
    chunk = response.get("result", {})
    if manifest.get("truncated") or chunk.get("next_chunk_index") is not None:
        raise AssertionError("Incomplete SQL test result")
    names = [column["name"] for column in manifest["schema"]["columns"]]
    return [dict(zip(names, row)) for row in chunk.get("data_array", [])]


@unittest.skipUnless(PROFILE and WAREHOUSE, "explicit SQL test profile/warehouse not set")
class GuardrailSqlTests(unittest.TestCase):
    def test_field_scopes_embedded_results_and_final_answer_dedup(self):
        fixture = """
        WITH turns_src AS (
          SELECT 'trace' AS trace_id, 'root' AS span_id, 'conversation' AS conversation_id,
                 'Genie Code' AS product, 'workspace' AS workspace_id, 'tester' AS requester,
                 current_timestamp() AS span_time, 'root-input' AS prompt, 'root-answer' AS response,
                 '[{"parts":[{"type":"tool_call_response","response":"embedded-result"}]}]' AS output_messages_raw
        ), tools_src AS (
          SELECT t.trace_id, c.span_id, t.conversation_id, t.product, t.workspace_id, t.requester,
                 t.span_time, c.span_type, c.tool_name, c.tool_arguments, c.tool_result, c.response_text
          FROM turns_src t CROSS JOIN VALUES
            ('action', 'tool_call', 'executeCode', 'code', 'result', NULL),
            ('approval', 'approval_request', 'executeCode', 'proposal', NULL, NULL),
            ('question', 'tool_call', 'askUserQuestions', 'question', NULL, NULL),
            ('model-final', 'model_call', NULL, NULL, NULL, 'root-answer'),
            ('model-other', 'model_call', NULL, NULL, NULL, 'intermediate-output')
          AS c(span_id, span_type, tool_name, tool_arguments, tool_result, response_text)
        )
        """
        rows = execute_select(fixture + "SELECT span_id, field, scope, length(text) AS chars FROM ("
                              + query_templates()["SECURITY_FIELDS_SQL"] + ")")
        actual = {(row["span_id"], row["field"]): row["scope"] for row in rows}
        self.assertEqual(actual, {
            ("root", "prompt"): "prompt", ("root", "response"): "answer",
            ("root", "embedded_tool_result"): "tool_result",
            ("action", "tool_arguments"): "tool_args", ("action", "tool_result"): "tool_result",
            ("approval", "tool_arguments"): "prompt", ("question", "tool_arguments"): "prompt",
            ("model-other", "model_output"): "tool_result",
        })
        self.assertTrue(all(int(row["chars"]) > 0 for row in rows))

    def test_runaway_counts_distinct_spans_and_keeps_completeness_informational(self):
        fixture = """
        WITH turns_src AS (
          SELECT trace_id, concat(trace_id, '-root') AS span_id, trace_id AS conversation_id,
                 'Genie Code' AS product, 'workspace' AS workspace_id, 'tester' AS requester,
                 current_timestamp() AS span_time, duration_ms, expected_span_count, dropped_span_count
          FROM VALUES ('loop', 1000.0, 7, 0), ('long', 3660000.0, 1, 0), ('dropped', 1000.0, 1, 1)
          AS t(trace_id, duration_ms, expected_span_count, dropped_span_count)
        ), tools_src AS (
          SELECT 'loop' AS trace_id, span_id, 'tool_call' AS span_type,
                 'executeCode' AS tool_name, '{"code":"work()"}' AS tool_arguments
          FROM VALUES ('a'), ('b'), ('c'), ('d'), ('e'), ('e') AS c(span_id)
        )
        """
        rows = execute_select(fixture + "SELECT trace_id, label, flagged, score, details FROM ("
                              + query_templates()["RUNAWAY_SQL"] + ")")
        actual = {row["trace_id"]: row for row in rows}
        self.assertEqual(set(actual), {"loop", "long", "dropped"})
        self.assertEqual(actual["loop"]["label"], "repeated_tool_calls")
        self.assertEqual(json.loads(actual["loop"]["details"])["repeated_calls"], 5)
        self.assertEqual(actual["long"]["label"], "long_running_turn")
        self.assertEqual(actual["dropped"]["label"], "trace_completeness_warning")
        self.assertEqual(str(actual["dropped"]["flagged"]).lower(), "false")
        self.assertEqual(float(actual["dropped"]["score"]), 0.0)


if __name__ == "__main__":
    unittest.main()
