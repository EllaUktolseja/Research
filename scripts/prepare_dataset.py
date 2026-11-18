#!/usr/bin/env python3
"""Prepare feature matrices for Static, Runtime, and Hybrid Isolation Forest models.

Splits features cleanly into static-only, runtime-only (rt_* / runtime_*),
and combined matrices while preserving aligned ground-truth metadata.
"""

from __future__ import annotations

import argparse
import csv
import math
import os
import tempfile
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_RESULTS_DIR = ROOT_DIR / "results"
DEFAULT_INVENTORY = ROOT_DIR / "samples" / "inventory.csv"

METADATA_ORDER = (
    "id",
    "name",
    "reference_label",
    "version",
    "package_dir",
    "feature_file",
    "log_file",
    "manifest_status",
    "sbom_status",
)
IDENTIFIERS = set(METADATA_ORDER)
VALID_LABELS = {"malicious", "benign"}


def is_runtime_col(col: str) -> bool:
    return col.startswith(("rt_", "runtime_"))


def clean_numeric_value(val: str | None) -> float:
    if val is None:
        return 0.0
    val_str = str(val).strip()
    if not val_str:
        return 0.0
    try:
        num = float(val_str)
        if math.isnan(num) or math.isinf(num):
            return 0.0
        return num
    except (ValueError, TypeError):
        return 0.0


def filter_features(
    rows: list[dict[str, str]],
    candidate_cols: list[str],
    drop_constant: bool = True,
) -> tuple[list[str], list[str]]:
    numeric_cols: list[str] = []
    excluded: list[str] = []

    for col in candidate_cols:
        if col in IDENTIFIERS:
            continue

        values = [clean_numeric_value(row.get(col)) for row in rows]
        if drop_constant and len(set(values)) <= 1:
            excluded.append(col)
            continue

        numeric_cols.append(col)

    return numeric_cols, excluded


def atomic_write_csv(
    output_path: Path, fieldnames: list[str], rows: list[dict]
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8-sig",
        newline="",
        dir=str(output_path.parent),
        prefix=f".{output_path.stem}_",
        suffix=".tmp",
        delete=False,
    ) as tmp_file:
        tmp_path = Path(tmp_file.name)
        writer = csv.DictWriter(tmp_file, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow({c: r.get(c, 0) for c in fieldnames})
        tmp_file.flush()
        os.fsync(tmp_file.fileno())

    os.replace(tmp_path, output_path)


def load_inventory_labels(inventory_path: Path) -> dict[str, str]:
    labels: dict[str, str] = {}
    if not inventory_path.is_file():
        return labels

    with inventory_path.open("r", encoding="utf-8-sig", newline="") as f:
        for r in csv.DictReader(f):
            sid = (r.get("id") or "").strip()
            label = (r.get("reference_label") or "").strip().lower()
            if sid and label:
                labels[sid] = label
    return labels


def build_matrix_rows(
    rows: list[dict[str, str]], feature_cols: list[str]
) -> tuple[list[dict[str, float]], int]:
    matrix_rows: list[dict[str, float]] = []
    all_zero_count = 0

    for row in rows:
        vec = {c: clean_numeric_value(row.get(c)) for c in feature_cols}
        if feature_cols and all(v == 0.0 for v in vec.values()):
            all_zero_count += 1
        matrix_rows.append(vec)

    return matrix_rows, all_zero_count


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prepare datasets for Static, Runtime, and Hybrid Isolation Forest models."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=None,
        help="Path ke file input fitur (default: results/combined_features.csv)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_RESULTS_DIR,
        help="Direktori output dataset model (default: results/)",
    )
    parser.add_argument(
        "--inventory",
        type=Path,
        default=DEFAULT_INVENTORY,
        help="Path ke samples/inventory.csv untuk melengkapi reference_label",
    )
    parser.add_argument(
        "--keep-all",
        action="store_true",
        help="Jangan eliminasi fitur konstan (varians 0)",
    )
    parser.add_argument(
        "--include-unknown",
        action="store_true",
        help="Sertakan sampel dengan reference_label bukan benign/malicious",
    )
    args = parser.parse_args()

    results_dir = args.output_dir.expanduser().resolve()
    inventory_file = args.inventory.expanduser().resolve()

    has_combined = True
    if args.input:
        input_file = args.input.expanduser().resolve()
    else:
        input_file = results_dir / "combined_features.csv"
        if not input_file.is_file():
            fallback_static = results_dir / "features.csv"
            if fallback_static.is_file():
                print(
                    "[WARNING] combined_features.csv belum ditemukan; fallback ke features.csv (static-only)."
                )
                input_file = fallback_static
                has_combined = False

    if not input_file.is_file():
        print(f"[ERROR] Dataset tidak ditemukan di: {input_file}")
        return

    print(f"[INFO] Memproses dataset dari: {input_file}")

    with input_file.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            print("[ERROR] Header CSV kosong.")
            return
        all_cols = [c.strip() for c in reader.fieldnames if c is not None]
        raw_rows = [
            {k.strip(): (v or "").strip() for k, v in r.items() if k is not None}
            for r in reader
        ]

    if not raw_rows:
        print("[ERROR] Dataset kosong.")
        return

    labels_map = load_inventory_labels(inventory_file)
    rows: list[dict[str, str]] = []
    skipped_unknown = 0

    for r in raw_rows:
        sid = r.get("id", "")
        lbl = r.get("reference_label", "").lower()
        if lbl not in VALID_LABELS:
            lbl = labels_map.get(sid, "unknown")
        r["reference_label"] = lbl

        if not args.include_unknown and lbl not in VALID_LABELS:
            skipped_unknown += 1
            continue
        rows.append(r)

    if not rows:
        print("[ERROR] Tidak ada sampel valid tersisa setelah filter reference_label.")
        return

    drop_const = not args.keep_all

    metadata_columns = [c for c in METADATA_ORDER if c in all_cols]
    if "reference_label" not in metadata_columns:
        metadata_columns.append("reference_label")

    static_candidate_cols = [
        c for c in all_cols if c not in IDENTIFIERS and not is_runtime_col(c)
    ]
    runtime_candidate_cols = [
        c for c in all_cols if c not in IDENTIFIERS and is_runtime_col(c)
    ]

    if not runtime_candidate_cols:
        has_combined = False

    static_cols, static_excluded = filter_features(
        rows, static_candidate_cols, drop_constant=drop_const
    )
    runtime_cols, runtime_excluded = filter_features(
        rows, runtime_candidate_cols, drop_constant=drop_const
    )
    combined_cols = static_cols + runtime_cols

    # 1. Simpan Metadata (termasuk reference_label untuk evaluasi)
    metadata_path = results_dir / "features_model_metadata.csv"
    metadata_rows = [{c: row.get(c, "") for c in metadata_columns} for row in rows]
    atomic_write_csv(metadata_path, metadata_columns, metadata_rows)

    # 2. Simpan Static Model Features
    static_path = results_dir / "features_model_static.csv"
    static_rows, static_zeros = build_matrix_rows(rows, static_cols)
    atomic_write_csv(static_path, static_cols, static_rows)

    # 3. Simpan Runtime & Combined Model Features (hanya jika kolom runtime tersedia)
    runtime_path = results_dir / "features_model_runtime.csv"
    combined_path = results_dir / "features_model_combined.csv"
    default_model_path = results_dir / "features_model.csv"

    runtime_zeros = 0
    combined_zeros = 0

    if has_combined and runtime_cols:
        runtime_rows, runtime_zeros = build_matrix_rows(rows, runtime_cols)
        atomic_write_csv(runtime_path, runtime_cols, runtime_rows)

        combined_rows, combined_zeros = build_matrix_rows(rows, combined_cols)
        atomic_write_csv(combined_path, combined_cols, combined_rows)
        atomic_write_csv(default_model_path, combined_cols, combined_rows)
    elif has_combined and not runtime_cols:
        print(
            "[WARNING] Kolom runtime ditemukan di header, tetapi semuanya konstan (varians 0) sehingga tereliminasi."
        )

    # Statistik distribusi kelas & rasio anomali (contamination)
    n_total = len(rows)
    n_mal = sum(1 for r in rows if r["reference_label"] == "malicious")
    n_ben = sum(1 for r in rows if r["reference_label"] == "benign")
    mal_ratio = (n_mal / n_total) if n_total else 0.0

    print("\n=== Persiapan Dataset Selesai ===")
    print(
        f"Total Sampel Valid          : {n_total} (skipped unknown: {skipped_unknown})"
    )
    print(
        f"Distribusi Ground Truth     : benign={n_ben}, malicious={n_mal} (rasio malicious={mal_ratio:.2%})"
    )
    print(
        f"Fitur Static/SBOM Digunakan : {len(static_cols)} "
        f"(dibuang konstan: {len(static_excluded)}, all-zero rows: {static_zeros}/{n_total})"
    )
    if runtime_candidate_cols:
        print(
            f"Fitur Runtime/eBPF Digunakan: {len(runtime_cols)} "
            f"(dibuang konstan: {len(runtime_excluded)}, all-zero rows: {runtime_zeros}/{n_total})"
        )
    if has_combined and runtime_cols:
        print(
            f"Fitur Combined Digunakan    : {len(combined_cols)} "
            f"(all-zero rows: {combined_zeros}/{n_total})"
        )
    print(f"\n[OK] Metadata (w/ labels) : {metadata_path}")
    print(f"[OK] Static dataset       : {static_path}")
    if has_combined and runtime_cols:
        print(f"[OK] Runtime dataset      : {runtime_path}")
        print(f"[OK] Combined dataset     : {combined_path}")


if __name__ == "__main__":
    main()
