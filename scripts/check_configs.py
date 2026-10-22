"""Validate every YAML/JSON file in the repository (CI config, templates, devcontainer)."""

import json
import pathlib
import sys

import yaml

root = pathlib.Path(".")
bad = 0

for path in sorted(root.rglob("*.yml")) + sorted(root.rglob("*.yaml")):
    if ".git" in path.parts:
        continue
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        extra = ""
        if "workflows" in path.parts:
            extra = " jobs=" + ",".join(doc.get("jobs", {}))
        elif "ISSUE_TEMPLATE" in str(path):
            extra = f" fields={len(doc.get('body', []))}"
        print(f"OK   {path}{extra}")
    except Exception as exc:
        bad += 1
        print(f"FAIL {path}: {exc}")

for path in sorted(root.rglob("*.json")):
    if ".git" in path.parts:
        continue
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
        print(f"OK   {path} (keys={len(doc)})")
    except Exception as exc:
        bad += 1
        print(f"FAIL {path}: {exc}")

print("bad:", bad)
sys.exit(1 if bad else 0)
