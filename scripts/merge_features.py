#!/usr/bin/env python3
"""Merge static and runtime behavioral features based on sample ID.

Defaults to an inner join so Isolation Forest is never trained on
zero-imputed runtime rows from unexecuted sandbox samples.
"""

from __future__ import annotations

import argparse
import csv
import os
import tempfile
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_STATIC_CSV = ROOT_DIR / "results" / "features.csv"
DEFAULT_RUNTIME_CSV = ROOT_DIR / "results" / "runtime_features.csv"
DEFAULT_OUTPUT_CSV = ROOT_DIR / "results" / "combined_features.csv"

METADATA_KEYS = {"id", "sample_id", "name", "reference_label"}
IGNORED_LEGACY_COLS = {
    "sample_id",
    "log_file",
    "package_dir",
    "version",
    "manifest_status",
    "sbom_status",
}
VALID_LABELS = {"malicious", "benign"}


def sort_id_key(sample_id: str) -> tuple[int, int | str]:
    return (0, int(sample_id)) if sample_id.isdigit() else (1, sample_id)


def extract_sample_id(row: dict[str, str]) -> str:
    raw_id = (row.get("id") or row.get("sample_id") or "").strip()
    if raw_id:
        return raw_id
    pkg_dir = (row.get("package_dir") or "").strip()
    if pkg_dir:
        tail = Path(pkg_dir).name
        if tail.isdigit():
            return tail
    return ""


def load_feature_table(csv_path: Path) -> tuple[list[str], dict[str, dict[str, str]]]:
    rows_by_id: dict[str, dict[str, str]] = {}
    with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise ValueError(f"Header CSV kosong: {csv_path}")

        fieldnames = [col.strip() for col in reader.fieldnames if col is not None]
        for raw_row in reader:
            clean_row = {
                k.strip(): (v or "").strip()
                for k, v in raw_row.items()
                if k is not None
            }
            sid = extract_sample_id(clean_row)
            if not sid:
                continue
            clean_row["id"] = sid
            rows_by_id[sid] = clean_row

    return fieldnames, rows_by_id


def reconcile_label(static_label: str, runtime_label: str, sample_id: str) -> str:
    s_lbl = (static_label or "unknown").strip().lower()
    r_lbl = (runtime_label or "unknown").strip().lower()

    if s_lbl in VALID_LABELS and r_lbl in VALID_LABELS:
        if s_lbl != r_lbl:
            print(
                f"[WARNING] Konflik reference_label pada ID {sample_id}: "
                f"static={s_lbl!r} vs runtime={r_lbl!r} (memakai static)."
            )
        return s_lbl
    if s_lbl in VALID_LABELS:
        return s_lbl
    if r_lbl in VALID_LABELS:
        return r_lbl
    return "unknown"


def atomic_write_csv(
    output_path: Path, fieldnames: list[str], rows: list[dict[str, str]]
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8-sig",
        newline="",
        dir=str(output_path.parent),
        prefix=".combined_features_",
        suffix=".tmp",
        delete=False,
    ) as tmp_file:
        tmp_path = Path(tmp_file.name)
        writer = csv.DictWriter(tmp_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
        tmp_file.flush()
        os.fsync(tmp_file.fileno())

    os.replace(tmp_path, output_path)


def format_id_preview(ids: list[str], max_items: int = 10) -> str:
    if not ids:
        return "-"
    if len(ids) <= max_items:
        return ", ".join(ids)
    shown = ", ".join(ids[:max_items])
    return f"{shown} ... (+{len(ids) - max_items} lainnya)"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Merge static and runtime behavioral features based on sample ID."
    )
    parser.add_argument(
        "--static",
        type=Path,
        default=DEFAULT_STATIC_CSV,
        help="Path ke features.csv statis (default: results/features.csv)",
    )
    parser.add_argument(
        "--runtime",
        type=Path,
        default=DEFAULT_RUNTIME_CSV,
        help="Path ke runtime_features.csv dinamis (default: results/runtime_features.csv)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_CSV,
        help="Path output combined_features.csv (default: results/combined_features.csv)",
    )
    parser.add_argument(
        "--join",
        choices=["inner", "left"],
        default="inner",
        help="Strategi join: 'inner' (hanya ID lengkap di keduanya, default) atau 'left' (acuan statis).",
    )
    args = parser.parse_args()

    static_path = args.static.expanduser().resolve()
    runtime_path = args.runtime.expanduser().resolve()
    output_path = args.output.expanduser().resolve()

    if not static_path.is_file():
        print(f"[ERROR] File fitur statis tidak ditemukan: {static_path}")
        return
    if not runtime_path.is_file():
        print(f"[ERROR] File fitur runtime tidak ditemukan: {runtime_path}")
        return

    try:
        static_cols_raw, static_data = load_feature_table(static_path)
        runtime_cols_raw, runtime_data = load_feature_table(runtime_path)
    except ValueError as err:
        print(f"[ERROR] {err}")
        return

    static_feature_cols = [
        c
        for c in static_cols_raw
        if c not in METADATA_KEYS and c not in IGNORED_LEGACY_COLS
    ]
    runtime_feature_cols = [
        c
        for c in runtime_cols_raw
        if c not in METADATA_KEYS
        and c not in IGNORED_LEGACY_COLS
        and c not in set(static_feature_cols)
    ]

    meta_header = ["id"]
    if "name" in static_cols_raw:
        meta_header.append("name")
    meta_header.append("reference_label")

    combined_fieldnames = meta_header + static_feature_cols + runtime_feature_cols

    static_ids = set(static_data.keys())
    runtime_ids = set(runtime_data.keys())

    missing_in_runtime = sorted(static_ids - runtime_ids, key=sort_id_key)
    missing_in_static = sorted(runtime_ids - static_ids, key=sort_id_key)

    if args.join == "inner":
        target_ids = sorted(static_ids & runtime_ids, key=sort_id_key)
    else:
        target_ids = sorted(static_ids, key=sort_id_key)

    combined_rows: list[dict[str, str]] = []
    label_counts: dict[str, int] = {}
    zero_container_events = 0

    for sid in target_ids:
        s_row = static_data[sid]
        r_row = runtime_data.get(sid, {})

        final_label = reconcile_label(
            s_row.get("reference_label", ""),
            r_row.get("reference_label", ""),
            sid,
        )
        label_counts[final_label] = label_counts.get(final_label, 0) + 1

        merged: dict[str, str] = {"id": sid}
        if "name" in meta_header:
            merged["name"] = s_row.get("name", sid) or sid
        merged["reference_label"] = final_label

        for col in static_feature_cols:
            val = s_row.get(col, "").strip()
            merged[col] = val if val != "" else "0"

        for col in runtime_feature_cols:
            val = r_row.get(col, "").strip()
            merged[col] = val if val != "" else "0"

        if merged.get("rt_has_container_events") == "0":
            zero_container_events += 1

        combined_rows.append(merged)

    if not combined_rows:
        print(
            "[ERROR] Tidak ada baris yang dapat digabungkan (0 ID cocok antara statis dan runtime)."
        )
        return

    atomic_write_csv(output_path, combined_fieldnames, combined_rows)

    print("=== Ringkasan Merge Fitur ===")
    print(f"Strategi join           : {args.join}")
    print(
        f"Total fitur statis      : {len(static_data)} sampel ({len(static_feature_cols)} fitur)"
    )
    print(
        f"Total fitur runtime     : {len(runtime_data)} sampel ({len(runtime_feature_cols)} fitur)"
    )
    print(
        f"Total data gabungan     : {len(combined_rows)} sampel ({len(static_feature_cols) + len(runtime_feature_cols)} fitur)"
    )
    print(f"Distribusi label        : {label_counts}")
    if zero_container_events > 0:
        print(
            f"Tanpa event container   : {zero_container_events}/{len(combined_rows)} sampel (rt_has_container_events=0)"
        )
    if missing_in_runtime:
        print(
            f"Statis tanpa runtime ({len(missing_in_runtime)}): {format_id_preview(missing_in_runtime)}"
        )
    if missing_in_static:
        print(
            f"Runtime tanpa statis ({len(missing_in_static)}): {format_id_preview(missing_in_static)}"
        )
    print(f"[OK] Tersimpan di: {output_path}")


if __name__ == "__main__":
    main()
