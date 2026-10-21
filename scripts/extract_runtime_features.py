#!/usr/bin/env python3
"""Extract runtime features from Tetragon eBPF logs."""

import argparse
import json
import csv
from collections import Counter
from pathlib import Path
from typing import Any

RUNTIME_FEATURE_COLUMNS = [
    "sample_id",
    "log_file",
    "runtime_process_exec_count",
    "runtime_process_exit_count",
    "runtime_tcp_connect_count",
    "runtime_unique_dst_ip_count",
    "runtime_unique_dst_port_count",
    "runtime_unique_process_binary_count",
    "runtime_spawn_shell_count",
    "runtime_invalid_json_lines",
]

SHELL_BINARIES = {"sh", "bash", "zsh", "dash", "busybox", "/bin/sh", "/bin/bash", "/usr/bin/sh", "/usr/bin/bash"}


def extract_from_logfile(input_path: Path, sample_id: str) -> dict[str, Any]:
    counts = Counter()
    dst_ips = set()
    dst_ports = set()
    processes = set()
    shell_spawns = 0
    invalid_lines = 0

    with input_path.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                invalid_lines += 1
                continue

            # Process execution and exit
            for event_type in ("process_exec", "process_exit"):
                block = event.get(event_type)
                if block:
                    counts[event_type] += 1
                    process = block.get("process", {})
                    binary = process.get("binary")
                    if binary:
                        processes.add(binary)
                        bin_name = Path(binary).name
                        if bin_name in SHELL_BINARIES or binary in SHELL_BINARIES:
                            if event_type == "process_exec":
                                shell_spawns += 1

            # Kprobes
            block = event.get("process_kprobe")
            if not block:
                continue

            fn_name = block.get("function_name", "")
            if fn_name in {"tcp_connect", "sys_enter_connect", "__sys_connect"}:
                counts["runtime_tcp_connect_count"] += 1

                process = block.get("process", {})
                binary = process.get("binary")
                if binary:
                    processes.add(binary)

                for arg in block.get("args", []):
                    # Format 1: sock_arg (tcp_connect)
                    sock = arg.get("sock_arg", {})
                    ip = sock.get("daddr")
                    port = sock.get("dport")

                    # Format 2: sockaddr (sys_enter_connect)
                    sockaddr = arg.get("sockaddr_arg", {})
                    if not ip:
                        ip = sockaddr.get("sin_addr") or sockaddr.get("sin6_addr")
                    if port is None:
                        port = sockaddr.get("sin_port")

                    if ip:
                        dst_ips.add(str(ip))
                    if port is not None:
                        dst_ports.add(int(port))

    return {
        "sample_id": str(sample_id),
        "log_file": input_path.name,
        "runtime_process_exec_count": counts["process_exec"],
        "runtime_process_exit_count": counts["process_exit"],
        "runtime_tcp_connect_count": counts["runtime_tcp_connect_count"],
        "runtime_unique_dst_ip_count": len(dst_ips),
        "runtime_unique_dst_port_count": len(dst_ports),
        "runtime_unique_process_binary_count": len(processes),
        "runtime_spawn_shell_count": shell_spawns,
        "runtime_invalid_json_lines": invalid_lines,
    }


def save_or_update_csv(rows: list[dict[str, Any]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    rows_by_id: dict[str, dict[str, Any]] = {}

    if output_path.is_file():
        with output_path.open(encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            for r in reader:
                sid = r.get("sample_id", "")
                if sid:
                    rows_by_id[sid] = r

    for row in rows:
        sid = str(row["sample_id"])
        rows_by_id[sid] = row

    with output_path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=RUNTIME_FEATURE_COLUMNS)
        writer.writeheader()
        # Sort by integer ID if numeric
        sorted_keys = sorted(rows_by_id.keys(), key=lambda k: int(k) if k.isdigit() else k)
        for k in sorted_keys:
            r = rows_by_id[k]
            clean_r = {col: r.get(col, 0) for col in RUNTIME_FEATURE_COLUMNS}
            writer.writerow(clean_r)


def main():
    parser = argparse.ArgumentParser(
        description="Extract runtime features from Tetragon eBPF logs."
    )
    parser.add_argument(
        "--input",
        type=Path,
        help="Path ke file event eBPF tunggal (misal logs/tetragon-node-control.jsonl atau results/ebpf/1.json)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Path ke output CSV (default: results/runtime_features.csv)",
    )
    parser.add_argument(
        "--sample-id",
        type=str,
        default=None,
        help="ID sampel untuk baris ini",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Ekstrak semua file log yang ada di folder results/ebpf/*.json",
    )
    args = parser.parse_args()

    ROOT = Path(__file__).resolve().parent.parent
    RESULTS_DIR = ROOT / "results"
    output_path = args.output.resolve() if args.output else RESULTS_DIR / "runtime_features.csv"

    if args.all:
        ebpf_dir = RESULTS_DIR / "ebpf"
        json_files = sorted(
            ebpf_dir.glob("*.json"),
            key=lambda p: int(p.stem) if p.stem.isdigit() else p.stem,
        )
        if not json_files:
            print(f"[ERROR] Tidak ada file .json di {ebpf_dir}")
            return

        extracted_rows = []
        for jf in json_files:
            sid = jf.stem
            row = extract_from_logfile(jf, sid)
            extracted_rows.append(row)
            print(f"[OK] Extracted runtime log ID {sid:<3} ({jf.name})")

        save_or_update_csv(extracted_rows, output_path)
        print(f"\n[OK] Berhasil memperbarui {len(extracted_rows)} baris di {output_path}")
        return

    # Single file mode
    input_path = args.input.resolve() if args.input else ROOT / "logs" / "tetragon-node-control.jsonl"
    if not input_path.exists():
        print(f"[ERROR] File log tidak ditemukan: {input_path}")
        return

    inferred_id = args.sample_id or input_path.stem
    row = extract_from_logfile(input_path, inferred_id)
    save_or_update_csv([row], output_path)

    print("\n=== Hasil Ekstraksi Runtime ===")
    print(json.dumps(row, indent=2))
    print(f"\n[OK] Runtime features tersimpan di: {output_path}")


if __name__ == "__main__":
    main()
