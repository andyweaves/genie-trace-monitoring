"""Check the Lakewatch rule catalog's MITRE mappings against the published MITRE data.

Not part of the unit suite (it needs the MITRE files, which are large and change per release):

    curl -sLo /tmp/enterprise-attack.json \
      https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
    curl -sLo /tmp/ATLAS.yaml https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml
    python3 tests/verify_mitre_mappings.py /tmp/enterprise-attack.json /tmp/ATLAS.yaml

Reports every technique ID that does not exist (or is revoked / deprecated), whose name differs
from the catalog, or that is mapped to a tactic it does not belong to. Exits non-zero on any.
"""

import json
from pathlib import Path
import sys

import yaml


ROOT = Path(__file__).resolve().parents[1]


def attack_index(path):
    data = json.loads(Path(path).read_text())
    objects = data["objects"]
    tactics = {o["x_mitre_shortname"]: o["name"] for o in objects
               if o.get("type") == "x-mitre-tactic" and not o.get("revoked")}
    index = {}
    for o in objects:
        if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        ext = next(r["external_id"] for r in o["external_references"] if r.get("source_name") == "mitre-attack")
        index[ext] = (o["name"], {tactics.get(p["phase_name"], p["phase_name"])
                                  for p in o.get("kill_chain_phases", [])})
    return index


def atlas_index(path):
    data = yaml.safe_load(Path(path).read_text())
    matrix = data["matrices"][0]
    tactics = {t["id"]: t["name"] for t in matrix["tactics"]}
    index = {}
    for t in matrix["techniques"]:
        parent = t.get("specializes") or t.get("subtechnique-of")
        own = {tactics[x] for x in t.get("tactics", [])}
        index[t["id"]] = (t["name"], own, parent)
    # Sub-techniques inherit their parent's tactics.
    return {tid: (name, own or index.get(parent, (None, set(), None))[1]) for tid, (name, own, parent) in index.items()}


def main(attack_path, atlas_path):
    indexes = {"mitre-attack": attack_index(attack_path), "mitre-atlas": atlas_index(atlas_path)}
    catalog = yaml.safe_load((ROOT / "src/lakewatch/rule_catalog.yml").read_text())
    problems = []
    for rule in catalog["rules"]:
        for m in rule.get("mitre") or []:
            index = indexes[m["taxonomy"]]
            checks = [(m["technique_id"], m["technique"])]
            if m.get("sub_technique_id"):
                checks.append((m["sub_technique_id"], m["sub_technique"]))
            for tid, name in checks:
                if tid not in index:
                    problems.append(f"{rule['name']}: {tid} not found (or revoked / deprecated)")
                    continue
                published, tactics = index[tid]
                if published != name:
                    problems.append(f"{rule['name']}: {tid} is named {published!r}, catalog says {name!r}")
                if m["tactic"] not in tactics:
                    problems.append(f"{rule['name']}: {tid} is not in tactic {m['tactic']!r} (has {sorted(tactics)})")
    for p in problems:
        print(p)
    print(f"{len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:3]))
