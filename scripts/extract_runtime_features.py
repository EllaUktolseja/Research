#!/usr/bin/env python3
import argparse
import json
import csv
from collections import Counter
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        description="Extract runtime features from Tetragon eBPF logs."
    )
    parser.add_argument(
        "--input",
        type=Path,
        help="Path ke file events.jsonl (default: logs/tetragon-node-control.jsonl)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Path ke output CSV (default: results/runtime_features.csv)",
    )
    parser.add_argument(
        "--sample-id",
        type=str,
        default="unknown",
        help="ID sampel untuk melacak baris ini milik package mana",
    )
    args = parser.parse_args()

    # Setup ROOT dir (2 level ke atas dari folder scripts/)
    ROOT = Path(__file__).resolve().parent.parent
    LOGS_DIR = ROOT / "logs"
    RESULTS_DIR = ROOT / "results"

    input_path = (
        args.input.resolve() if args.input else LOGS_DIR / "tetragon-node-control.jsonl"
    )
    output_path = (
        args.output.resolve() if args.output else RESULTS_DIR / "runtime_features.csv"
    )

    if not input_path.exists():
        print(f"[ERROR] File log tidak ditemukan: {input_path}")
        return

    counts = Counter()
    dst_ips = set()
    dst_ports = set()
    processes = set()
    invalid_lines = 0

    print(f"[INFO] Membaca log dari: {input_path}")

    with input_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                invalid_lines += 1
                continue

            for event_type in ("process_exec", "process_exit"):
                block = event.get(event_type)
                if block:
                    counts[event_type] += 1
                    process = block.get("process", {})
                    binary = process.get("binary")
                    if binary:
                        processes.add(binary)

            block = event.get("process_kprobe")
            if not block:
                continue

            if block.get("function_name") != "tcp_connect":
                continue

            counts["runtime_tcp_connect_count"] += 1

            process = block.get("process", {})
            binary = process.get("binary")
            if binary:
                processes.add(binary)

            for arg in block.get("args", []):
                sock = arg.get("sock_arg", {})
                ip = sock.get("daddr")
                port = sock.get("dport")

                if ip:
                    dst_ips.add(ip)
                if port is not None:
                    dst_ports.add(port)

    row = {
        "sample_id": args.sample_id,
        "log_file": input_path.name,
        "runtime_process_exec_count": counts["process_exec"],
        "runtime_process_exit_count": counts["process_exit"],
        "runtime_tcp_connect_count": counts["runtime_tcp_connect_count"],
        "runtime_unique_dst_ip_count": len(dst_ips),
        "runtime_unique_dst_port_count": len(dst_ports),
        "runtime_unique_process_binary_count": len(processes),
        "runtime_invalid_json_lines": invalid_lines,
    }

    # Bikin folder results kalau belum ada
    output_path.parent.mkdir(parents=True, exist_ok=True)
    file_exists = output_path.is_file() and output_path.stat().st_size > 0

    # Simpan ke CSV dengan mode 'a' (append)
    with output_path.open("a", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=row.keys())
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)

    print("\n=== Hasil Ekstraksi ===")
    print(json.dumps(row, indent=2))
    print(
        f"\n[OK] Runtime features berhasil diekstrak dan ditambahkan ke: {output_path}"
    )


if __name__ == "__main__":
    main()
