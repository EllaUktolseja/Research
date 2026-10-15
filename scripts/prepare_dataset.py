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
        help="Path ke file input fitur (default: results/features.csv)",
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

    INPUT = args.input.resolve() if args.input else RESULTS_DIR / "features.csv"
    OUTPUT = (
        args.output.resolve() if args.output else RESULTS_DIR / "features_model.csv"
    )
    METADATA = (
        args.metadata.resolve()
        if args.metadata
        else RESULTS_DIR / "features_model_metadata.csv"
    )

    if not INPUT.is_file():
        print(f"[ERROR] Dataset tidak ditemukan: {INPUT}")
        return

    # Baca file input
    with INPUT.open(newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))

    if not rows:
        print("[ERROR] Dataset kosong.")
        return

    # Kumpulan kolom yang dianggap sebagai identitas (bukan fitur untuk dilatih)
    IDENTIFIERS = {
        "id",  # Tambahan untuk handle sample_id kalau digabung dengan runtime
        "name",
        "version",
        "package_dir",
        "feature_file",
        "log_file",  # Tambahan untuk handle log eBPF
    }

    # Ambil kolom identitas yang memang benar-benar ada di data
    metadata_columns = [c for c in IDENTIFIERS if c in rows[0]]

    numeric_columns = []
    excluded = []

    for column in rows[0]:
        if column in IDENTIFIERS:
            continue

        values = [row.get(column, "").strip() for row in rows]

        # Jangan memasukkan fitur dengan nilai kosong atau nilai non-numerik ke dataset model.
        try:
            numbers = [float(v) for v in values]
        except (ValueError, TypeError):
            excluded.append((column, "non-numeric/missing"))
            continue

        # Kolom konstan (nilainya sama semua di setiap baris) tidak membantu membedakan sampel.
        if len(set(numbers)) <= 1:
            excluded.append((column, "constant"))
            continue

        numeric_columns.append(column)

    # Buat direktori output jika belum ada
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    # Simpan dataset khusus numerik (buat di-load model)
    with OUTPUT.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=numeric_columns)
        writer.writeheader()
        writer.writerows([{c: row[c] for c in numeric_columns} for row in rows])

    # Simpan dataset metadata (buat ngelacak hasil prediksi nanti)
    with METADATA.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=metadata_columns)
        writer.writeheader()
        writer.writerows([{c: row[c] for c in metadata_columns} for row in rows])

    print("=== Persiapan Dataset Selesai ===")
    print(f"Jumlah sampel             : {len(rows)}")
    print(f"Fitur numerik bervariasi  : {len(numeric_columns)}")
    print(f"Kolom dikecualikan        : {len(excluded)}")

    print("\n[INFO] Fitur yang dipakai:")
    for c in numeric_columns:
        print(" -", c)

    print("\n[INFO] Kolom yang dikecualikan:")
    for c, reason in excluded:
        print(f" - {c}: {reason}")

    print(f"\n[OK] Dataset model : {OUTPUT}")
    print(f"[OK] Metadata      : {METADATA}")


if __name__ == "__main__":
    main()
