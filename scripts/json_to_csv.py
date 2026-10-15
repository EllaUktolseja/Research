#!/usr/bin/env python3
"""Combine *-features.json files into one CSV safely without executing package code."""

import argparse
import csv
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        description="Combine JSON feature files into a CSV."
    )
    parser.add_argument(
        "--input-dir",
        type=Path,
        help="Direktori yang berisi file JSON (default: results/)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Path file output CSV (default: results/features.csv)",
    )
    args = parser.parse_args()

    ROOT = Path(__file__).resolve().parent.parent
    RESULTS = ROOT / "results"

    input_dir = args.input_dir.resolve() if args.input_dir else RESULTS
    out = args.output.resolve() if args.output else RESULTS / "features.csv"

    # Cari semua file JSON yang berakhiran -features.json
    files = sorted(input_dir.glob("*-features.json"))
    rows = []

    for path in files:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(value, dict):
                value.setdefault("feature_file", path.name)
                rows.append(value)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[WARNING] Melewati {path.name}: {exc}")

    if not rows:
        print(f"[INFO] Tidak ada file *-features.json yang valid di {input_dir}")
        return

    out.parent.mkdir(parents=True, exist_ok=True)
    file_exists = out.is_file() and out.stat().st_size > 0

    # LOGIC HEADER: Pastikan urutan kolom sesuai dengan CSV yang sudah ada (jika ada)
    if file_exists:
        with out.open("r", encoding="utf-8-sig") as f:
            reader = csv.reader(f)
            columns = next(reader)  # Ambil header dari file CSV yang sudah ada
    else:
        # Kalau CSV belum ada, bikin header baru dari key yang ada di JSON
        columns = sorted({key for row in rows for key in row})
        front = ["name", "version", "package_dir", "feature_file"]
        columns = [key for key in front if key in columns] + [
            key for key in columns if key not in front
        ]

    # Buka mode 'a' (append) biar data baru nyambung di bawah data lama
    with out.open("a", newline="", encoding="utf-8-sig") as handle:
        # extrasaction="ignore" memastikan kalau ada key di JSON yang ga ada di CSV, bakal diskip aman
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")

        if not file_exists:
            writer.writeheader()

        writer.writerows(rows)

    print(f"[OK] Berhasil menggabungkan {len(rows)} sampel JSON ke dalam {out}")


if __name__ == "__main__":
    main()
