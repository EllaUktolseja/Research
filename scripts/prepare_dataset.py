#!/usr/bin/env python3
import argparse
import csv
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        description="Prepare dataset for Isolation Forest model."
    )
    parser.add_argument(
        "--input",
        type=Path,
        help="Path ke file input fitur (default: results/combined_features.csv atau features.csv)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Path ke output numerik untuk model (default: results/features_model.csv)",
    )
    parser.add_argument(
        "--metadata",
        type=Path,
        help="Path ke output metadata (default: results/features_model_metadata.csv)",
    )
    args = parser.parse_args()

    # Otomatis deteksi root folder (2 level di atas script ini)
    ROOT = Path(__file__).resolve().parent.parent
    RESULTS_DIR = ROOT / "results"

    # Priority: combined_features.csv -> features.csv
    if args.input:
        INPUT = args.input.resolve()
    else:
        combined_file = RESULTS_DIR / "combined_features.csv"
        INPUT = (
            combined_file if combined_file.is_file() else RESULTS_DIR / "features.csv"
        )

    OUTPUT = (
        args.output.resolve() if args.output else RESULTS_DIR / "features_model.csv"
    )
    METADATA = (
        args.metadata.resolve()
        if args.metadata
        else RESULTS_DIR / "features_model_metadata.csv"
    )

    if not INPUT.is_file():
        print(f"[ERROR] Dataset tidak ditemukan di: {INPUT}")
        return

    print(f"[INFO] Memproses dataset dari: {INPUT.name}")

    with INPUT.open(newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))

    if not rows:
        print("[ERROR] Dataset kosong.")
        return

    # Kolom non-numerik / identitas yang dipisah ke metadata
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

    metadata_columns = [c for c in IDENTIFIERS if c in rows[0]]
    numeric_columns = []
    excluded = []

    for column in rows[0]:
        if column in IDENTIFIERS:
            continue

        values = [row.get(column, "").strip() for row in rows]

        # Validasi angka
        try:
            numbers = [float(v) for v in values]
        except (ValueError, TypeError):
            excluded.append((column, "non-numeric/missing"))
            continue

        # Eliminasi kolom konstan (varian nilainya <= 1)
        if len(set(numbers)) <= 1:
            excluded.append((column, "constant"))
            continue

        numeric_columns.append(column)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    # Simpan fitur numerik (X)
    with OUTPUT.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=numeric_columns)
        writer.writeheader()
        writer.writerows([{c: row.get(c, 0) for c in numeric_columns} for row in rows])

    # Simpan metadata (y / identitas)
    with METADATA.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=metadata_columns)
        writer.writeheader()
        writer.writerows(
            [{c: row.get(c, "") for c in metadata_columns} for row in rows]
        )

    print("\n=== Persiapan Dataset Selesai ===")
    print(f"Jumlah sampel             : {len(rows)}")
    print(f"Fitur numerik bervariasi  : {len(numeric_columns)}")
    print(f"Kolom dikecualikan        : {len(excluded)}")
    print(f"\n[OK] Dataset model : {OUTPUT}")
    print(f"[OK] Metadata      : {METADATA}")


if __name__ == "__main__":
    main()
