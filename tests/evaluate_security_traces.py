"""Read-only, local scorecard for exported security-field rows (never prints content).

Input: a JSON array of {product, test_case, field, scope, text} rows returned by a
SELECT against the trace tables. Keep exports outside the repo and delete them
after testing. No Databricks access, AI calls, or source-content output occurs here.

Usage:
    python3 tests/evaluate_security_traces.py /private/tmp/fields.json
"""

import argparse
from collections import Counter, defaultdict
import importlib.util
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]


def load_matcher(patterns):
    path = ROOT / "src/notebooks/_security_pattern_utils.py"
    spec = importlib.util.spec_from_file_location("security_pattern_utils", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.build_security_matcher(module.load_security_config(str(patterns)))


def score_rows(rows, scan):
    counts = Counter()
    by_rule = Counter()
    by_field = Counter()
    limits = Counter()
    cases = defaultdict(lambda: {"rules": set(), "fields": set(), "scanned_fields": 0})
    for row in rows:
        result = scan(row.get("text"), row["scope"])
        counts["fields_scanned"] += 1
        flagged = [hit for hit in result["hits"] if hit["flagged"]]
        informational = [hit for hit in result["hits"] if not hit["flagged"]]
        counts["fields_flagged"] += bool(flagged)
        counts["informational_hits"] += len(informational)
        counts["fields_limited"] += bool(result["limits"])
        limits.update(result["limits"])
        by_rule.update(hit["rule_id"] for hit in flagged)
        if flagged:
            by_field[row["field"]] += 1
        tag = row.get("test_case") or ""
        # Only expose synthetic scorecard tags, never arbitrary user-provided text.
        if re.fullmatch(r"(?i)(?:RT|BN)[-_][0-9]+", tag):
            product = row.get("product")
            product = product if product in ("Genie One", "Genie Code") else "other"
            case = cases[(product, tag.upper())]
            case["scanned_fields"] += 1
            case["rules"].update(hit["rule_id"] for hit in flagged)
            if flagged:
                case["fields"].add(row["field"])
    case_rows = [
        {"product": product, "test_case": tag, "flagged": bool(case["rules"]),
         "rules": sorted(case["rules"]), "fields": sorted(case["fields"]),
         "scanned_fields": case["scanned_fields"]}
        for (product, tag), case in sorted(cases.items())
    ]
    return {
        "counts": dict(counts), "flagged_by_rule": dict(sorted(by_rule.items())),
        "flagged_by_field": dict(sorted(by_field.items())), "limits": dict(limits),
        "labelled_cases": case_rows,
        "note": "Signature matches are review signals, not proof of compromise. RT labels include attacks outside this detector's scope.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path)
    parser.add_argument("--patterns", type=Path, default=ROOT / "src/config/security_patterns.yml")
    args = parser.parse_args()
    with args.export.open() as handle:
        rows = json.load(handle)
    if not isinstance(rows, list):
        parser.error("Export must be a JSON array of field rows")
    print(json.dumps(score_rows(rows, load_matcher(args.patterns)), indent=2))


if __name__ == "__main__":
    main()
