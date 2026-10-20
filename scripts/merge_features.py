#!/usr/bin/env python3
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

    # Baca data statis, jadikan dictionary dengan key = ID (diambil dari nama folder / path)
    # Catatan: Karena extract_features.py sebelumnya menyimpan package_dir, kita bisa ekstrak ID dari foldernya
    static_data = {}
    with static_path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        static_fieldnames = reader.fieldnames or []
        for row in reader:
            # Mengambil ID dari path folder, misal: .../samples/source/1 -> id = 1
            pkg_dir = Path(row.get("package_dir", ""))
            sample_id = pkg_dir.name if pkg_dir.name.isdigit() else row.get("name")

            # Simpan ID eksplisit ke dalam row
            row["id"] = sample_id
            static_data[sample_id] = row

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
            sample_id = row.get("sample_id", "")
            # Hapus sample_id dari row runtime karena sudah diwakili 'id' di statis
            if "sample_id" in row:
                del row["sample_id"]
            runtime_data[sample_id] = row

    # Gabungkan fieldnames
    combined_fieldnames = static_fieldnames + runtime_fieldnames

    # Lakukan proses Merge (Left Join: Statis sebagai acuan utama)
    combined_rows = []
    for sample_id, s_row in static_data.items():
        r_row = runtime_data.get(sample_id, {})

        # Gabungkan dictionary
        merged_row = {**s_row, **r_row}

        # Isi nilai kosong untuk runtime jika log tidak tersedia (misal error pas eksekusi)
        for col in runtime_fieldnames:
            if col not in merged_row:
                merged_row[col] = "0"  # Default value untuk fitur dinamis yang kosong

        combined_rows.append(merged_row)

    # Tulis hasil gabungan
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
