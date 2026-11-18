#!/usr/bin/env python3
"""Extract runtime behavioral features from Tetragon eBPF logs.

Filters strictly for container-scoped events, excludes harness wrapper processes
and wrapper flags, and captures DNS lookup attempts (port 53), outbound connections,
sensitive file opens, and anomalous child process executions.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_INVENTORY = ROOT_DIR / "samples" / "inventory.csv"
DEFAULT_EBPF_DIR = ROOT_DIR / "results" / "ebpf"
DEFAULT_OUTPUT_CSV = ROOT_DIR / "results" / "runtime_features.csv"

HARNESS_MARKER = "/_harness_runner.js"

SHELL_BINARIES = {"sh", "bash", "zsh", "dash", "ash", "busybox"}
NETWORK_CLI_BINARIES = {
    "curl",
    "wget",
    "nc",
    "netcat",
    "ncat",
    "socat",
    "telnet",
    "ftp",
    "ssh",
    "scp",
    "sftp",
    "dig",
    "nslookup",
    "host",
}
RECON_CLI_BINARIES = {
    "whoami",
    "id",
    "uname",
    "hostname",
    "ifconfig",
    "ip",
    "env",
    "printenv",
    "ps",
    "cat",
    "ls",
    "find",
    "pwd",
    "lscpu",
}
ALT_INTERPRETERS = {
    "python",
    "python2",
    "python3",
    "perl",
    "ruby",
    "php",
    "awk",
    "gawk",
    "pwsh",
    "powershell",
}
PERM_BINARIES = {"chmod", "chown"}
STANDARD_NON_DNS_PORTS = {80, 443}

RE_INLINE_EVAL_OR_ENCODED = re.compile(
    r"(?:^|\s)(?:-e|--eval|-c|-enc)\b|\bbase64\b|\b(?:eval|Buffer\.from|atob)\s*\(",
    re.IGNORECASE,
)
RE_SENSITIVE_TARGET = re.compile(
    r"\.npmrc|\.ssh|\.aws|/etc/passwd|/etc/shadow|id_rsa|id_ed25519|\.netrc|\.env"
    r"|oastify|interactsh|webhook\.site|pipedream|ngrok|ipify|ifconfig\.me|icanhazip"
    r"|discord(?:app)?\.com/api/webhooks|api\.telegram\.org",
    re.IGNORECASE,
)

METADATA_COLUMNS = [
    "id",
    "reference_label",
]

RUNTIME_FEATURE_COLUMNS = [
    "rt_has_container_events",
    "rt_spawned_shell",
    "rt_ran_network_cli",
    "rt_ran_sys_recon_cmd",
    "rt_ran_alt_interpreter",
    "rt_ran_chmod_or_tmp_exec",
    "rt_cmdline_inline_eval_or_encoded",
    "rt_cmdline_sensitive_target",
    "rt_sensitive_file_open",
    "rt_dns_lookup_attempt",
    "rt_outbound_external_connect",
    "rt_outbound_non_standard_port",
    "rt_multiple_external_ips",
    "rt_process_burst_high",
    "rt_suspicious_behavior_ratio",
]

ALL_COLUMNS = METADATA_COLUMNS + RUNTIME_FEATURE_COLUMNS


def load_inventory_labels(inventory_path: Path = DEFAULT_INVENTORY) -> dict[str, str]:
    labels: dict[str, str] = {}
    if not inventory_path.is_file():
        return labels
    try:
        with inventory_path.open("r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                sid = (row.get("id") or "").strip()
                label = (row.get("reference_label") or "unknown").strip().lower()
                if sid:
                    labels[sid] = label or "unknown"
    except OSError:
        pass
    return labels


def load_expected_cid(input_path: Path, explicit_cid: str | None) -> str | None:
    if explicit_cid:
        return explicit_cid.strip()
    cid_sidecar = input_path.with_suffix(".cid")
    if cid_sidecar.is_file():
        try:
            val = cid_sidecar.read_text(encoding="utf-8").strip()
            if val:
                return val
        except OSError:
            pass
    return None


def is_target_container_process(process: dict[str, Any], expected_cid: str | None) -> bool:
    docker_id = str(process.get("docker") or "").strip()
    if not docker_id:
        return False
    if expected_cid:
        return expected_cid.startswith(docker_id) or docker_id.startswith(expected_cid[:12])
    return True


def normalize_ip(ip_str: str) -> str:
    cleaned = ip_str.strip()
    if cleaned.startswith("::ffff:"):
        cleaned = cleaned[7:]
    return cleaned


def is_non_loopback_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(normalize_ip(ip_str))
        return not (ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip.is_multicast)
    except ValueError:
        return False


def extract_from_logfile(
    input_path: Path,
    sample_id: str,
    label_map: dict[str, str] | None = None,
    expected_cid: str | None = None,
) -> dict[str, Any]:
    reference_label = (label_map or {}).get(str(sample_id), "unknown")
    target_cid = load_expected_cid(input_path, expected_cid)

    container_events = 0
    package_proc_exec_count = 0

    spawned_shell = 0
    ran_network_cli = 0
    ran_sys_recon_cmd = 0
    ran_alt_interpreter = 0
    ran_chmod_or_tmp_exec = 0
    cmdline_inline_eval = 0
    cmdline_sensitive_target = 0
    sensitive_file_open = 0
    dns_lookup_attempt = 0
    outbound_non_standard_port = 0

    external_non_dns_ips: set[str] = set()
    seen_connect_tuples: set[tuple[int, str, int]] = set()

    with input_path.open("r", encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if not isinstance(event, dict):
                continue

            # 1. Process Execution Events
            exec_block = event.get("process_exec")
            if isinstance(exec_block, dict):
                proc = exec_block.get("process") or {}
                if not is_target_container_process(proc, target_cid):
                    continue

                container_events += 1
                binary = str(proc.get("binary") or "")
                arguments = str(proc.get("arguments") or "")
                bin_name = Path(binary).name.lower() if binary else ""

                # Abaikan proses runner harness itu sendiri
                if HARNESS_MARKER in arguments or bin_name == "sleep":
                    continue

                parent = exec_block.get("parent") or {}
                parent_args = str(parent.get("arguments") or "")
                is_direct_harness_sh = (
                    bin_name in SHELL_BINARIES and HARNESS_MARKER in parent_args
                )

                package_proc_exec_count += 1
                if is_direct_harness_sh:
                    inspect_cmd = re.sub(r"^\s*-c\s+", "", arguments).strip()
                else:
                    inspect_cmd = f"{binary} {arguments}".strip()

                if bin_name in SHELL_BINARIES and not is_direct_harness_sh:
                    spawned_shell = 1
                if bin_name in NETWORK_CLI_BINARIES:
                    ran_network_cli = 1
                if bin_name in RECON_CLI_BINARIES:
                    ran_sys_recon_cmd = 1
                if bin_name in ALT_INTERPRETERS:
                    ran_alt_interpreter = 1
                if bin_name in PERM_BINARIES or binary.startswith(("/tmp/", "/dev/shm/", "/var/tmp/")):
                    ran_chmod_or_tmp_exec = 1

                if inspect_cmd and RE_INLINE_EVAL_OR_ENCODED.search(inspect_cmd):
                    cmdline_inline_eval = 1
                if inspect_cmd and RE_SENSITIVE_TARGET.search(inspect_cmd):
                    cmdline_sensitive_target = 1

            # 2. Kprobe Events (Network Connect + Sensitive File Open)
            kprobe_block = event.get("process_kprobe")
            if isinstance(kprobe_block, dict):
                proc = kprobe_block.get("process") or {}
                if not is_target_container_process(proc, target_cid):
                    continue

                container_events += 1
                fn_name = str(kprobe_block.get("function_name") or "")
                pid = int(proc.get("pid") or 0)

                if fn_name in {
                    "security_socket_connect",
                    "tcp_connect",
                    "tcp_v6_connect",
                    "udp_sendmsg",
                    "udpv6_sendmsg",
                    "sys_enter_connect",
                    "__sys_connect",
                }:
                    for arg in kprobe_block.get("args") or []:
                        if not isinstance(arg, dict):
                            continue
                        sock = arg.get("sock_arg") or {}
                        sockaddr = arg.get("sockaddr_arg") or {}

                        family = str(sockaddr.get("family") or sock.get("family") or "")
                        if family and family not in {"AF_INET", "AF_INET6", "2", "10"}:
                            continue

                        ip_val = (
                            sockaddr.get("addr")
                            or sockaddr.get("sin_addr")
                            or sockaddr.get("sin6_addr")
                            or sock.get("daddr")
                        )
                        port_val = (
                            sockaddr.get("port")
                            if sockaddr.get("port") is not None
                            else (
                                sockaddr.get("sin_port")
                                if sockaddr.get("sin_port") is not None
                                else sock.get("dport")
                            )
                        )

                        if not ip_val or port_val is None:
                            continue

                        try:
                            port_int = int(port_val)
                        except (TypeError, ValueError):
                            continue

                        if port_int <= 0:
                            continue

                        norm_ip = normalize_ip(str(ip_val))
                        conn_key = (pid, norm_ip, port_int)
                        if conn_key in seen_connect_tuples:
                            continue
                        seen_connect_tuples.add(conn_key)

                        # Port 53 menangkap resolusi DNS (termasuk Docker 127.0.0.11:53 & domain NXDOMAIN)
                        if port_int == 53:
                            dns_lookup_attempt = 1
                        elif is_non_loopback_ip(norm_ip):
                            external_non_dns_ips.add(norm_ip)
                            if port_int not in STANDARD_NON_DNS_PORTS:
                                outbound_non_standard_port = 1

                elif fn_name == "security_file_open":
                    for arg in kprobe_block.get("args") or []:
                        if not isinstance(arg, dict):
                            continue
                        file_info = arg.get("file_arg") or arg.get("path_arg") or {}
                        opened_path = str(file_info.get("path") or "")
                        if opened_path and RE_SENSITIVE_TARGET.search(opened_path):
                            sensitive_file_open = 1

    outbound_external_connect = int(len(external_non_dns_ips) > 0)
    multiple_external_ips = int(len(external_non_dns_ips) >= 2)
    process_burst_high = int(package_proc_exec_count >= 5)

    # Rata-rata indikator sinyal tinggi yang bebas dari self-contamination
    signal_components = (
        spawned_shell
        + ran_network_cli
        + ran_sys_recon_cmd
        + ran_alt_interpreter
        + ran_chmod_or_tmp_exec
        + cmdline_inline_eval
        + cmdline_sensitive_target
        + sensitive_file_open
        + dns_lookup_attempt
        + outbound_external_connect
        + outbound_non_standard_port
    )
    suspicious_behavior_ratio = round(signal_components / 11.0, 4)

    row: dict[str, Any] = {
        "id": str(sample_id),
        "reference_label": reference_label,
        "rt_has_container_events": int(container_events > 0),
        "rt_spawned_shell": spawned_shell,
        "rt_ran_network_cli": ran_network_cli,
        "rt_ran_sys_recon_cmd": ran_sys_recon_cmd,
        "rt_ran_alt_interpreter": ran_alt_interpreter,
        "rt_ran_chmod_or_tmp_exec": ran_chmod_or_tmp_exec,
        "rt_cmdline_inline_eval_or_encoded": cmdline_inline_eval,
        "rt_cmdline_sensitive_target": cmdline_sensitive_target,
        "rt_sensitive_file_open": sensitive_file_open,
        "rt_dns_lookup_attempt": dns_lookup_attempt,
        "rt_outbound_external_connect": outbound_external_connect,
        "rt_outbound_non_standard_port": outbound_non_standard_port,
        "rt_multiple_external_ips": multiple_external_ips,
        "rt_process_burst_high": process_burst_high,
        "rt_suspicious_behavior_ratio": suspicious_behavior_ratio,
    }

    return {col: row[col] for col in ALL_COLUMNS}


def save_or_update_csv(rows: list[dict[str, Any]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    rows_by_id: dict[str, dict[str, Any]] = {}

    if output_path.is_file():
        with output_path.open("r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            for r in reader:
                sid = str(r.get("id") or r.get("sample_id") or "").strip()
                if sid:
                    rows_by_id[sid] = r

    for row in rows:
        rows_by_id[str(row["id"])] = row

    sorted_keys = sorted(rows_by_id.keys(), key=lambda k: (0, int(k)) if k.isdigit() else (1, k))

    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8-sig",
        newline="",
        dir=str(output_path.parent),
        prefix=".runtime_features_",
        suffix=".tmp",
        delete=False,
    ) as tmp_file:
        tmp_path = Path(tmp_file.name)
        writer = csv.DictWriter(tmp_file, fieldnames=ALL_COLUMNS)
        writer.writeheader()
        for k in sorted_keys:
            r = rows_by_id[k]
            writer.writerow({col: r.get(col, 0) for col in ALL_COLUMNS})
        tmp_file.flush()
        os.fsync(tmp_file.fileno())

    os.replace(tmp_path, output_path)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract runtime behavioral features from Tetragon eBPF logs."
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Path file log eBPF tunggal, ID sampel, atau rentang (contoh: 1-50)",
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=None,
        help="Path ke file event eBPF tunggal",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_CSV,
        help="Path ke output CSV (default: results/runtime_features.csv)",
    )
    parser.add_argument(
        "--sample-id",
        type=str,
        default=None,
        help="ID sampel eksplisit untuk mode file tunggal",
    )
    parser.add_argument(
        "--cid",
        type=str,
        default=None,
        help="Container ID sandbox eksplisit (opsional; otomatis baca <id>.cid jika ada)",
    )
    parser.add_argument(
        "--range",
        type=str,
        default=None,
        metavar="START-END",
        help="Rentang batch ID log eBPF (contoh: 1-50)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Ekstrak semua file log yang ada di results/ebpf/*.json",
    )
    parser.add_argument(
        "--inventory",
        type=Path,
        default=DEFAULT_INVENTORY,
        help="Path ke samples/inventory.csv untuk mengambil reference_label",
    )
    args = parser.parse_args()

    output_path = args.output.expanduser().resolve()
    label_map = load_inventory_labels(args.inventory.expanduser().resolve())

    range_str = args.range or (
        args.target
        if args.target and "-" in args.target and not Path(args.target).exists()
        else None
    )
    if range_str:
        try:
            start_s, end_s = range_str.split("-")
            start_id, end_id = int(start_s), int(end_s)
        except ValueError:
            parser.error("Format range harus START-END (contoh: 1-50)")
            return

        if start_id < 1 or end_id < start_id:
            parser.error("Rentang ID harus positif dengan START <= END.")
            return

        extracted: list[dict[str, Any]] = []
        for sid in range(start_id, end_id + 1):
            log_file = DEFAULT_EBPF_DIR / f"{sid}.json"
            if log_file.is_file():
                row = extract_from_logfile(log_file, str(sid), label_map=label_map)
                extracted.append(row)
                print(
                    f"[OK] ID {sid:<4} [{row['reference_label']:<9}] "
                    f"dns={row['rt_dns_lookup_attempt']} fs={row['rt_sensitive_file_open']} "
                    f"net={row['rt_outbound_external_connect']} ratio={row['rt_suspicious_behavior_ratio']}"
                )
            else:
                print(f"[SKIP] File log eBPF ID {sid} tidak ditemukan di {DEFAULT_EBPF_DIR}.")

        if extracted:
            save_or_update_csv(extracted, output_path)
            print(f"\n[OK] Berhasil memperbarui {len(extracted)} baris di {output_path}")
        return

    if args.all or (args.target == "all"):
        json_files = sorted(
            DEFAULT_EBPF_DIR.glob("*.json"),
            key=lambda p: (0, int(p.stem)) if p.stem.isdigit() else (1, p.stem),
        )
        if not json_files:
            print(f"[ERROR] Tidak ada file .json di {DEFAULT_EBPF_DIR}")
            return

        extracted_rows = []
        for jf in json_files:
            sid = jf.stem
            row = extract_from_logfile(jf, sid, label_map=label_map)
            extracted_rows.append(row)
            print(
                f"[OK] ID {sid:<4} [{row['reference_label']:<9}] "
                f"dns={row['rt_dns_lookup_attempt']} fs={row['rt_sensitive_file_open']} "
                f"net={row['rt_outbound_external_connect']} ratio={row['rt_suspicious_behavior_ratio']}"
            )

        save_or_update_csv(extracted_rows, output_path)
        print(f"\n[OK] Berhasil memperbarui {len(extracted_rows)} baris di {output_path}")
        return

    input_path: Path | None = None
    if args.input:
        input_path = args.input.expanduser().resolve()
    elif args.target:
        p = Path(args.target).expanduser()
        if p.is_file():
            input_path = p.resolve()
        elif (DEFAULT_EBPF_DIR / f"{args.target}.json").is_file():
            input_path = (DEFAULT_EBPF_DIR / f"{args.target}.json").resolve()

    if not input_path or not input_path.is_file():
        print(f"[ERROR] File log eBPF tidak ditemukan: {input_path or args.target}")
        return

    inferred_id = args.sample_id or input_path.stem
    row = extract_from_logfile(
        input_path,
        inferred_id,
        label_map=label_map,
        expected_cid=args.cid,
    )
    save_or_update_csv([row], output_path)

    print("\n=== Hasil Ekstraksi Runtime ===")
    print(json.dumps(row, indent=2))
    print(f"\n[OK] Runtime features tersimpan di: {output_path}")


if __name__ == "__main__":
    main()
