import json
import csv
import sys
from collections import Counter
from pathlib import Path

if len(sys.argv) != 3:
    print("Usage: python3 extract_runtime_features.py <events.jsonl> <output.csv>")
    sys.exit(1)

input_path = Path(sys.argv[1])
output_path = Path(sys.argv[2])

counts = Counter()
dst_ips = set()
dst_ports = set()
processes = set()
invalid_lines = 0

with input_path.open(encoding="utf-8") as f:
    for line in f:
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
    "runtime_process_exec_count": counts["process_exec"],
    "runtime_process_exit_count": counts["process_exit"],
    "runtime_tcp_connect_count": counts["runtime_tcp_connect_count"],
    "runtime_unique_dst_ip_count": len(dst_ips),
    "runtime_unique_dst_port_count": len(dst_ports),
    "runtime_unique_process_binary_count": len(processes),
    "runtime_invalid_json_lines": invalid_lines,
}

output_path.parent.mkdir(parents=True, exist_ok=True)
with output_path.open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=row.keys())
    writer.writeheader()
    writer.writerow(row)

print(json.dumps(row, indent=2))
print(f"Saved: {output_path}")
