#!/usr/bin/env python3
"""Merge static and runtime features based on sample ID."""

import argparse
import csv
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        description="Merge static and runtime features based on sample ID."
    )
    parser.add_argument("--static", type=Path, help="Path ke features.csv statis")
    parser.add_argument(
        "--runtime", type=Path, help="Path ke runtime_features.csv dinamis"
    )
    parser.add_argument("--output", type=Path, help="Path output combined_features.csv")
    args = parser.parse_args()

    ROOT = Path(__file__).resolve().parent.parent
    RESULTS_DIR = ROOT / "results"

    static_path = args.static.resolve() if args.static else RESULTS_DIR / "features.csv"
    runtime_path = (
        args.runtime.resolve() if args.runtime else RESULTS_DIR / "runtime_features.csv"
    )
    output_path = (
        args.output.resolve() if args.output else RESULTS_DIR / "combined_features.csv"
    )

    if not static_path.is_file():
        print(f"[ERROR] File fitur statis tidak ditemukan: {static_path}")
        return
    if not runtime_path.is_file():
        print(f"[ERROR] File fitur runtime tidak ditemukan: {runtime_path}")
        return

    # Baca data statis
    static_data = {}
    with static_path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        static_fieldnames = list(reader.fieldnames or [])
        for row in reader:
            sample_id = row.get("id")
            if not sample_id:
                pkg_dir = Path(row.get("package_dir", ""))
                sample_id = pkg_dir.name if pkg_dir.name.isdigit() else row.get("name", "")
            row["id"] = str(sample_id)
            static_data[str(sample_id)] = row

    if "id" not in static_fieldnames:
        static_fieldnames.insert(0, "id")

    # Baca data runtime
    runtime_data = {}
    with runtime_path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        runtime_fieldnames = [
            col for col in (reader.fieldnames or []) if col != "sample_id"
        ]
        for row in reader:
            sample_id = str(row.get("sample_id", ""))
            if "sample_id" in row:
                del row["sample_id"]
            runtime_data[sample_id] = row

    # Gabungkan fieldnames (tanpa duplikat)
    seen = set(static_fieldnames)
    combined_fieldnames = list(static_fieldnames)
    for col in runtime_fieldnames:
        if col not in seen:
            combined_fieldnames.append(col)
            seen.add(col)

    # Lakukan proses Merge (Left Join: Statis sebagai acuan utama)
    combined_rows = []
    sorted_ids = sorted(static_data.keys(), key=lambda k: int(k) if k.isdigit() else k)

    for sample_id in sorted_ids:
        s_row = static_data[sample_id]
        r_row = runtime_data.get(sample_id, {})

        merged_row = {**s_row, **r_row}

        # Isi nilai default 0 untuk fitur numerik runtime jika log tidak tersedia
        for col in runtime_fieldnames:
            if col not in merged_row or merged_row[col] == "" or merged_row[col] is None:
                merged_row[col] = "0"

        combined_rows.append(merged_row)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=combined_fieldnames)
        writer.writeheader()
        writer.writerows(combined_rows)

    print("=== Proses Merge Selesai ===")
    print(f"Data Statis  : {len(static_data)} baris")
    print(f"Data Runtime : {len(runtime_data)} baris")
    print(f"Data Gabungan: {len(combined_rows)} baris")
    print(f"[OK] Tersimpan di: {output_path}")


if __name__ == "__main__":
    main()
