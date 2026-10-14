#!/usr/bin/env python3
"""Combine *-features.json files into one CSV without executing package code."""

import csv
import json
from pathlib import Path

RESULTS = Path.home() / "malware-research" / "results"
files = sorted(RESULTS.glob("*-features.json"))
rows = []
for path in files:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(value, dict):
            value.setdefault("feature_file", path.name)
            rows.append(value)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Skipping {path.name}: {exc}")

if not rows:
    raise SystemExit(f"No valid *-features.json files found in {RESULTS}")

columns = sorted({key for row in rows for key in row})
# Put package identifiers first for easier reading.
front = ["name", "version", "package_dir", "feature_file"]
columns = [key for key in front if key in columns] + [
    key for key in columns if key not in front
]
out = RESULTS / "features.csv"
with out.open("w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
print(f"Wrote {len(rows)} samples to {out}")
