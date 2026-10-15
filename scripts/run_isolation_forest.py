#!/usr/bin/env python3
import argparse
import csv
from pathlib import Path
from sklearn.ensemble import IsolationForest


def main():
    parser = argparse.ArgumentParser(
        description="Run Isolation Forest for anomaly detection."
    )
    parser.add_argument(
        "--features",
        type=Path,
        help="Path ke file numerik (default: results/features_model.csv)",
    )
    parser.add_argument(
        "--metadata",
        type=Path,
        help="Path ke file metadata (default: results/features_model_metadata.csv)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Path ke output hasil deteksi (default: results/isolation_forest_results.csv)",
    )
    args = parser.parse_args()

    # Setup ROOT dir (2 level ke atas)
    ROOT = Path(__file__).resolve().parent.parent
    RESULTS_DIR = ROOT / "results"

    FEATURES_FILE = (
        args.features.resolve() if args.features else RESULTS_DIR / "features_model.csv"
    )
    METADATA_FILE = (
        args.metadata.resolve()
        if args.metadata
        else RESULTS_DIR / "features_model_metadata.csv"
    )
    OUTPUT_FILE = (
        args.output.resolve()
        if args.output
        else RESULTS_DIR / "isolation_forest_results.csv"
    )

    if not FEATURES_FILE.is_file():
        print(f"[ERROR] File fitur numerik tidak ditemukan: {FEATURES_FILE}")
        return
    if not METADATA_FILE.is_file():
        print(f"[ERROR] File metadata tidak ditemukan: {METADATA_FILE}")
        return

    # Baca file Metadata (nama, versi, id, dll)
    with METADATA_FILE.open(newline="", encoding="utf-8-sig") as f:
        metadata_rows = list(csv.DictReader(f))

    # Baca file Fitur Numerik (X)
    with FEATURES_FILE.open(newline="", encoding="utf-8-sig") as f:
        feature_rows = list(csv.DictReader(f))

    # Pastikan jumlah baris sama karena datanya terpisah
    if len(feature_rows) != len(metadata_rows):
        print(
            f"[ERROR] Jumlah baris fitur ({len(feature_rows)}) dan metadata ({len(metadata_rows)}) tidak sinkron!"
        )
        return

    if len(feature_rows) < 2:
        print("[ERROR] Minimal diperlukan 2 sampel untuk melatih model.")
        return

    feature_columns = list(feature_rows[0].keys())

    # Konversi string CSV ke float
    X = []
    for i, row in enumerate(feature_rows):
        try:
            X.append([float(row[c]) for c in feature_columns])
        except (ValueError, TypeError) as e:
            print(
                f"[ERROR] Baris {i + 2} memiliki nilai non-numerik. Cek script prepare_dataset.py."
            )
            return

    print(
        f"[INFO] Melatih model dengan {len(X)} sampel dan {len(feature_columns)} fitur..."
    )

    # Baseline eksploratif, bukan classifier malware
    model = IsolationForest(n_estimators=200, contamination="auto", random_state=42)
    model.fit(X)

    # Skor lebih rendah = lebih anomali menurut model
    scores = model.decision_function(X)
    predictions = model.predict(X)

    results = []
    for meta, score, prediction in zip(metadata_rows, scores, predictions):
        # Ambil identitas yang relevan, kosongkan jika tidak ada
        res = {
            "id": meta.get("id", ""),
            "name": meta.get("name", "unknown"),
            "version": meta.get("version", "unknown"),
            "log_file": meta.get("log_file", ""),
            "anomaly_score": round(float(score), 6),
            "model_label": ("potential_outlier" if prediction == -1 else "inlier"),
            "interpretation": "exploratory_only",
        }

        # Bersihkan kolom yang isinya string kosong (misal log_file kalau gak dipake)
        res = {k: v for k, v in res.items() if v != ""}
        results.append(res)

    # Urutkan dari skor paling rendah (paling anomali)
    results.sort(key=lambda r: r["anomaly_score"])

    # Simpan hasil prediksi
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_FILE.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

    print(f"\n[OK] Hasil prediksi disimpan di: {OUTPUT_FILE}")
    print("\n=== Exploratory Ranking (Lower Score = More Anomalous) ===")

    # Gw limit print 10 teratas aja di terminal biar ga menuh-menuhin layar kalau sampel lu ribuan
    for i, row in enumerate(results[:10]):
        name_ver = f"{row.get('name', 'unknown')}@{row.get('version', 'unknown')}"
        identifier = row.get("id", name_ver)
        print(
            f"[{i + 1}] {identifier:<25} | score={row['anomaly_score']:<10} | label={row['model_label']}"
        )

    if len(results) > 10:
        print(
            f"... dan {len(results) - 10} sampel lainnya (bisa dicek langsung di CSV)"
        )

    print("\n[WARNING] Anomaly labels are not malware verdicts.")


if __name__ == "__main__":
    main()
