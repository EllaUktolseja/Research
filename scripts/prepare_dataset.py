#!/usr/bin/env python3
"""Prepare dataset for Isolation Forest model.
Supports generating static-only, runtime-only, and combined feature matrices.
"""

import argparse
import csv
from pathlib import Path

IDENTIFIERS = {
    "id",
    "name",
    "version",
    "package_dir",
    "feature_file",
    "log_file",
    "manifest_status",
    "sbom_status",
}


def clean_numeric_value(val: str | None) -> float:
    if val is None:
        return 0.0
    val_str = str(val).strip()
    if not val_str:
        return 0.0
    try:
        return float(val_str)
    except (ValueError, TypeError):
        return 0.0


def filter_features(rows: list[dict[str, str]], candidate_cols: list[str], drop_constant: bool = True) -> tuple[list[str], list[str]]:
    numeric_cols = []
    excluded = []

    for col in candidate_cols:
        if col in IDENTIFIERS:
            continue

        values = [clean_numeric_value(row.get(col)) for row in rows]

        if drop_constant and len(set(values)) <= 1:
            excluded.append(col)
            continue

        numeric_cols.append(col)

    return numeric_cols, excluded


def write_csv(output_path: Path, fieldnames: list[str], rows: list[dict]):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            clean_row = {c: r.get(c, 0) for c in fieldnames}
            writer.writerow(clean_row)


def main():
    parser = argparse.ArgumentParser(
        description="Prepare datasets for Static, Runtime, and Hybrid Isolation Forest models."
    )
    parser.add_argument(
        "--input",
        type=Path,
        help="Path ke file input fitur (default: results/combined_features.csv)",
    )
    parser.add_argument(
        "--drop-constant",
        action="store_true",
        default=True,
        help="Eliminasi fitur konstan dengan varians 0 (default: True)",
    )
    parser.add_argument(
        "--keep-all",
        action="store_true",
        help="Jangan eliminasi fitur konstan",
    )
    args = parser.parse_args()

    ROOT = Path(__file__).resolve().parent.parent
    RESULTS_DIR = ROOT / "results"

    input_file = args.input.resolve() if args.input else RESULTS_DIR / "combined_features.csv"
    if not input_file.is_file():
        # Fallback ke features.csv jika combined belum ada
        input_file = RESULTS_DIR / "features.csv"

    if not input_file.is_file():
        print(f"[ERROR] Dataset tidak ditemukan di: {input_file}")
        return

    print(f"[INFO] Memproses dataset dari: {input_file.name}")

    with input_file.open(newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))

    if not rows:
        print("[ERROR] Dataset kosong.")
        return

    drop_const = not args.keep_all

    all_cols = list(rows[0].keys())
    metadata_columns = [c for c in IDENTIFIERS if c in all_cols]

    # Klasifikasi kolom: static vs runtime
    static_candidate_cols = [
        c for c in all_cols
        if c not in IDENTIFIERS and not c.startswith("runtime_")
    ]
    runtime_candidate_cols = [
        c for c in all_cols
        if c not in IDENTIFIERS and c.startswith("runtime_")
    ]

    static_cols, static_excluded = filter_features(rows, static_candidate_cols, drop_constant=drop_const)
    runtime_cols, runtime_excluded = filter_features(rows, runtime_candidate_cols, drop_constant=drop_const)
    combined_cols = static_cols + runtime_cols

    # Simpan Metadata
    metadata_path = RESULTS_DIR / "features_model_metadata.csv"
    metadata_rows = [{c: row.get(c, "") for c in metadata_columns} for row in rows]
    write_csv(metadata_path, metadata_columns, metadata_rows)

    # Simpan Static Model Features
    static_path = RESULTS_DIR / "features_model_static.csv"
    static_rows = [{c: clean_numeric_value(row.get(c)) for c in static_cols} for row in rows]
    write_csv(static_path, static_cols, static_rows)

    # Simpan Runtime Model Features
    runtime_path = RESULTS_DIR / "features_model_runtime.csv"
    runtime_rows = [{c: clean_numeric_value(row.get(c)) for c in runtime_cols} for row in rows]
    write_csv(runtime_path, runtime_cols, runtime_rows)

    # Simpan Combined / Hybrid Model Features
    combined_path = RESULTS_DIR / "features_model_combined.csv"
    default_model_path = RESULTS_DIR / "features_model.csv"
    combined_rows = [{c: clean_numeric_value(row.get(c)) for c in combined_cols} for row in rows]
    write_csv(combined_path, combined_cols, combined_rows)
    write_csv(default_model_path, combined_cols, combined_rows)

    print("\n=== Persiapan Dataset Selesai ===")
    print(f"Total Sampel                : {len(rows)}")
    print(f"Fitur Static/SBOM Digunakan : {len(static_cols)} (Dikecualikan: {len(static_excluded)})")
    print(f"Fitur Runtime/eBPF Digunakan: {len(runtime_cols)} (Dikecualikan: {len(runtime_excluded)})")
    print(f"Fitur Combined Digunakan    : {len(combined_cols)}")
    print(f"\n[OK] Metadata file   : {metadata_path}")
    print(f"[OK] Static dataset  : {static_path}")
    print(f"[OK] Runtime dataset : {runtime_path}")
    print(f"[OK] Combined dataset: {combined_path}")


if __name__ == "__main__":
    main()
