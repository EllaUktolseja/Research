#!/usr/bin/env python3
"""Static and SBOM feature extraction for npm packages.

Extracts orthogonal, bounded behavioral and structural anomaly features
tailored for Isolation Forest without executing package code.
Supports single ID/path, range batch (e.g., 1-50), and --all modes.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import math
import os
import re
import tempfile
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_INVENTORY = ROOT_DIR / "samples" / "inventory.csv"
DEFAULT_SOURCE_DIR = ROOT_DIR / "samples" / "source"
DEFAULT_SBOM_DIR = ROOT_DIR / "results" / "sbom"
DEFAULT_OUTPUT_CSV = ROOT_DIR / "results" / "features.csv"

INSTALL_LIFECYCLE_KEYS = ("preinstall", "install", "postinstall")
PREPARE_LIFECYCLE_KEYS = ("prepare", "prepublish", "prepublishOnly", "prepack")
ALL_LIFECYCLE_KEYS = INSTALL_LIFECYCLE_KEYS + PREPARE_LIFECYCLE_KEYS

DEPENDENCY_GROUPS = (
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
)

CODE_EXTENSIONS = {".js", ".cjs", ".mjs", ".jsx", ".ts", ".cts", ".mts"}

# Regex pola serangan & kapabilitas berbahaya
RE_LIFECYCLE_NODE_OR_SHELL = re.compile(
    r"\b(?:node|nodejs|sh|bash|zsh|dash|cmd|powershell|pwsh|python|python3|perl|ruby|curl|wget|nc|netcat)\b",
    re.IGNORECASE,
)
RE_LIFECYCLE_INLINE_OR_ENCODED = re.compile(
    r"(?:^|\s)(?:-e|--eval|-c|-enc|-EncodedCommand)\b|\bbase64\b|\|\s*(?:sh|bash)\b|\$\(|`[^`]+`",
    re.IGNORECASE,
)
RE_LIFECYCLE_RECON_OR_NET = re.compile(
    r"\b(?:curl|wget|nc|netcat|whoami|hostname|uname|pwd|id|ifconfig|ipconfig)\b|https?://|oastify|interactsh|webhook\.site",
    re.IGNORECASE,
)

RE_CHILD_PROCESS = re.compile(
    r"['\"]child_process['\"]|\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*\(",
)
RE_DYNAMIC_EVAL = re.compile(
    r"\beval\s*\(|new\s+Function\s*\(|vm\.runIn(?:New|This)Context\s*\(",
)
RE_BASE64_OR_HEX_DECODE = re.compile(
    r"Buffer\.from\s*\([^)]*['\"](?:base64|hex)['\"]\s*\)|\batob\s*\(",
    re.IGNORECASE,
)
RE_OBFUSCATED_ESCAPES = re.compile(
    r"(?:\\x[0-9a-fA-F]{2}){4,}|(?:\\u00[0-9a-fA-F]{2}){4,}",
)
RE_SENSITIVE_ENV = re.compile(
    r"process\.env\.(?:[A-Z0-9_]*(?:TOKEN|SECRET|KEY|PASS|PWD|CRED|AUTH|NPM|AWS|GITHUB|GITLAB|CI|SSH|HOME|USER)[A-Z0-9_]*)\b"
    r"|process\.env\[['\"][^'\"]*(?:TOKEN|SECRET|KEY|PASS|CRED|AUTH|NPM|AWS|GITHUB|SSH|HOME|USER)[^'\"]*['\"]\]"
    r"|JSON\.stringify\s*\(\s*process\.env\s*\)|Object\.(?:keys|entries|values)\s*\(\s*process\.env\s*\)",
    re.IGNORECASE,
)
RE_SENSITIVE_PATHS = re.compile(
    r"(?:['\"`/\\]|^)(?:\.npmrc|\.ssh|\.aws|\.bashrc|\.zshrc|\.profile|\.gitconfig|id_rsa|id_ed25519|/etc/passwd|/etc/shadow)(?:['\"`/\\]|$)",
    re.IGNORECASE,
)
RE_HOST_RECON = re.compile(
    r"\bos\.(?:userInfo|homedir|hostname|networkInterfaces|platform|arch|release)\s*\(",
)
RE_NETWORK_API = re.compile(
    r"(?:require\s*\(\s*|from\s+)['\"](?:node:)?(?:http|https|http2|net|tls|dgram|axios|node-fetch|got|superagent)['\"]"
    r"|\bfetch\s*\(|\bhttps?\.request\s*\(|\baxios\.(?:get|post|put|patch|delete|request)\s*\(",
)
RE_DNS_API = re.compile(
    r"(?:require\s*\(\s*|from\s+)['\"](?:node:)?dns['\"]"
    r"|\bdns\.(?:resolve|resolve4|resolve6|resolveTxt|resolveAny|lookup|getServers)\s*\(",
)
RE_EXFIL_OR_OAST_DOMAIN = re.compile(
    r"oastify\.com|interactsh|webhook\.site|pipedream\.net|requestbin|ngrok\.io|ngrok-free\.app"
    r"|burpcollaborator|ipify\.org|ifconfig\.me|icanhazip\.com|discord(?:app)?\.com/api/webhooks|api\.telegram\.org",
    re.IGNORECASE,
)
RE_FILE_WRITE_OR_CHMOD = re.compile(
    r"\bfs\.(?:writeFile|appendFile|chmod|chown|copyFile|rename)(?:Sync)?\s*\(",
)

RE_IPV4_CANDIDATE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
RE_STRING_LITERAL = re.compile(r"""(['"`])((?:\\.|(?!\1)[^\\]){40,2048})\1""")

METADATA_COLUMNS = [
    "id",
    "name",
    "reference_label",
]

FEATURE_COLUMNS = [
    "manifest_invalid_or_missing",
    "main_entry_missing",
    "no_js_source_files",
    "has_minified_dropper",
    "has_install_lifecycle",
    "has_prepare_lifecycle",
    "lifecycle_runs_node_or_shell",
    "lifecycle_has_inline_or_encoded_cmd",
    "lifecycle_mentions_recon_or_net",
    "uses_child_process",
    "uses_dynamic_eval",
    "uses_base64_or_hex_decode",
    "has_obfuscated_escapes",
    "has_high_entropy_literal",
    "reads_sensitive_env",
    "accesses_sensitive_paths",
    "collects_host_recon",
    "uses_network_api",
    "uses_dns_api",
    "references_public_ipv4",
    "references_exfil_or_oast_domain",
    "writes_or_chmods_files",
    "sbom_scan_failed",
    "sbom_manifest_dep_mismatch",
    "has_external_dependencies",
    "obfuscation_escape_ratio",
]

ALL_COLUMNS = METADATA_COLUMNS + FEATURE_COLUMNS


def load_inventory_labels(inventory_path: Path = DEFAULT_INVENTORY) -> dict[str, str]:
    """Memuat mapping id -> reference_label dari samples/inventory.csv."""
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


def read_json(path: Path) -> tuple[Any | None, str]:
    try:
        raw = path.read_text(encoding="utf-8-sig", errors="replace")
        return json.loads(raw), "parsed"
    except FileNotFoundError:
        return None, "missing"
    except (json.JSONDecodeError, OSError):
        return None, "parse_error"


def resolve_package_root(sample_path: Path) -> Path:
    """Mengunci target ke subfolder 'package/' jika struktur standar samples/source/<id>/ dipakai."""
    pkg_sub = sample_path / "package"
    if pkg_sub.is_dir():
        return pkg_sub
    return sample_path


def resolve_entry_exists(pkg_root: Path, rel_entry: str) -> bool:
    """Memeriksa keberadaan entry point npm (mendukung implicit .js/.cjs/.mjs atau /index.js)."""
    cleaned = rel_entry.strip().lstrip("./")
    if not cleaned:
        return False

    base = (pkg_root / cleaned).resolve()
    try:
        base.relative_to(pkg_root.resolve())
    except ValueError:
        return False

    candidates = [
        base,
        base.with_suffix(".js"),
        base.with_suffix(".cjs"),
        base.with_suffix(".mjs"),
        base / "index.js",
        base / "index.cjs",
        base / "index.mjs",
    ]
    return any(p.is_file() for p in candidates)


def collect_referenced_local_files(
    pkg_root: Path, manifest: dict[str, Any]
) -> list[Path]:
    """Mengambil file lokal (termasuk tanpa ekstensi .js) yang direferensikan di scripts/bin/main."""
    referenced: set[Path] = set()
    raw_targets: list[str] = []

    main_field = manifest.get("main")
    if isinstance(main_field, str):
        raw_targets.append(main_field)

    bin_field = manifest.get("bin")
    if isinstance(bin_field, str):
        raw_targets.append(bin_field)
    elif isinstance(bin_field, dict):
        raw_targets.extend(str(v) for v in bin_field.values() if isinstance(v, str))

    scripts = manifest.get("scripts")
    if isinstance(scripts, dict):
        for cmd in scripts.values():
            if isinstance(cmd, str):
                raw_targets.extend(re.findall(r"(?:\./|\.\./)[\w./-]+", cmd))

    pkg_root_resolved = pkg_root.resolve()
    for target in raw_targets:
        candidate = (pkg_root / target).resolve()
        try:
            candidate.relative_to(pkg_root_resolved)
        except ValueError:
            continue
        if candidate.is_file():
            referenced.add(candidate)

    return sorted(referenced)


def has_public_ipv4(text: str) -> int:
    """Mendeteksi IPv4 publik yang routable (mengabaikan localhost, privat, broadcast, dan DNS publik umum)."""
    ignored_public = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9"}
    for match in RE_IPV4_CANDIDATE.findall(text):
        if match in ignored_public:
            continue
        try:
            ip = ipaddress.ip_address(match)
            if ip.version == 4 and ip.is_global:
                return 1
        except ValueError:
            continue
    return 0


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def detect_high_entropy_literal(text: str) -> int:
    """Mendeteksi string literal panjang (>= 40 karakter) dengan entropi tinggi (payload base64/terenkripsi)."""
    for _, literal in RE_STRING_LITERAL.findall(text):
        # Abaikan URL normal atau path panjang biasa
        if literal.startswith(("http://", "https://", "data:image/", "-----BEGIN ")):
            continue
        if " " in literal:
            continue
        if shannon_entropy(literal) >= 4.65:
            return 1
    return 0


def parse_sbom_signals(
    sbom_path: Path | None, declared_dep_count: int
) -> tuple[int, int]:
    """Mengembalikan (sbom_scan_failed, sbom_manifest_dep_mismatch)."""
    if sbom_path is None or not sbom_path.is_file():
        return 1, 0

    sbom, status = read_json(sbom_path)
    if (
        not isinstance(sbom, dict)
        or status != "parsed"
        or sbom.get("bomFormat") != "CycloneDX"
    ):
        return 1, 0

    components = sbom.get("components")
    comp_count = len(components) if isinstance(components, list) else 0
    mismatch = int(comp_count != declared_dep_count)
    return 0, mismatch


def extract(
    sample_path: Path,
    sbom_path: Path | None = None,
    sample_id: str | None = None,
    label_map: dict[str, str] | None = None,
) -> dict[str, Any]:
    pkg_root = resolve_package_root(sample_path)
    inferred_id = str(sample_id or sample_path.name)
    reference_label = (label_map or {}).get(inferred_id, "unknown")

    manifest_path = pkg_root / "package.json"
    manifest_raw, manifest_status = read_json(manifest_path)
    manifest_valid = isinstance(manifest_raw, dict) and manifest_status == "parsed"
    manifest: dict[str, Any] = manifest_raw if manifest_valid else {}

    pkg_name = str(manifest.get("name") or inferred_id).strip() or inferred_id

    scripts = (
        manifest.get("scripts") if isinstance(manifest.get("scripts"), dict) else {}
    )
    install_cmds = [
        str(scripts[k])
        for k in INSTALL_LIFECYCLE_KEYS
        if k in scripts and scripts[k] is not None
    ]
    prepare_cmds = [
        str(scripts[k])
        for k in PREPARE_LIFECYCLE_KEYS
        if k in scripts and scripts[k] is not None
    ]
    all_lifecycle_text = "\n".join(install_cmds + prepare_cmds)

    declared_dep_count = sum(
        len(manifest[grp])
        for grp in DEPENDENCY_GROUPS
        if isinstance(manifest.get(grp), dict)
    )

    # Kumpulkan file kode sumber JS/TS + skrip lokal yang direferensikan di package.json
    code_files_set: set[Path] = {
        p
        for p in pkg_root.rglob("*")
        if p.is_file()
        and p.suffix.lower() in CODE_EXTENSIONS
        and "node_modules" not in p.parts
        and ".git" not in p.parts
    }
    code_files_set.update(collect_referenced_local_files(pkg_root, manifest))
    code_files = sorted(code_files_set)

    source_chunks: list[str] = []
    max_line_len = 0
    for path in code_files:
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            if content.strip():
                source_chunks.append(content)
                for line in content.splitlines():
                    if len(line) > max_line_len:
                        max_line_len = len(line)
        except OSError:
            continue

    source_text = "\n".join(source_chunks)

    # Resolve SBOM dari results/sbom/<id>.json
    if sbom_path is None or not sbom_path.is_file():
        candidate_sbom = DEFAULT_SBOM_DIR / f"{inferred_id}.json"
        if candidate_sbom.is_file():
            sbom_path = candidate_sbom

    sbom_scan_failed, sbom_manifest_dep_mismatch = parse_sbom_signals(
        sbom_path, declared_dep_count
    )

    main_val = manifest.get("main")
    main_entry_missing = int(
        isinstance(main_val, str)
        and bool(main_val.strip())
        and not resolve_entry_exists(pkg_root, main_val)
    )

    # Indikator biner kapabilitas & anomali
    has_install_lifecycle = int(len(install_cmds) > 0)
    has_prepare_lifecycle = int(len(prepare_cmds) > 0)
    lifecycle_runs_node_or_shell = int(
        bool(RE_LIFECYCLE_NODE_OR_SHELL.search(all_lifecycle_text))
    )
    lifecycle_has_inline_or_encoded_cmd = int(
        bool(RE_LIFECYCLE_INLINE_OR_ENCODED.search(all_lifecycle_text))
    )
    lifecycle_mentions_recon_or_net = int(
        bool(RE_LIFECYCLE_RECON_OR_NET.search(all_lifecycle_text))
    )

    uses_child_process = int(bool(RE_CHILD_PROCESS.search(source_text)))
    uses_dynamic_eval = int(bool(RE_DYNAMIC_EVAL.search(source_text)))
    uses_base64_or_hex_decode = int(bool(RE_BASE64_OR_HEX_DECODE.search(source_text)))
    has_obfuscated_escapes = int(bool(RE_OBFUSCATED_ESCAPES.search(source_text)))
    has_high_entropy_literal = detect_high_entropy_literal(source_text)

    reads_sensitive_env = int(bool(RE_SENSITIVE_ENV.search(source_text)))
    accesses_sensitive_paths = int(bool(RE_SENSITIVE_PATHS.search(source_text)))
    collects_host_recon = int(bool(RE_HOST_RECON.search(source_text)))
    uses_network_api = int(bool(RE_NETWORK_API.search(source_text)))
    uses_dns_api = int(bool(RE_DNS_API.search(source_text)))
    references_public_ipv4 = has_public_ipv4(source_text + "\n" + all_lifecycle_text)
    references_exfil_or_oast_domain = int(
        bool(RE_EXFIL_OR_OAST_DOMAIN.search(source_text + "\n" + all_lifecycle_text))
    )
    writes_or_chmods_files = int(bool(RE_FILE_WRITE_OR_CHMOD.search(source_text)))

    # Paket kecil (<= 3 file) dengan baris kode sangat panjang (>= 1000 char) khas single-line dropper
    has_minified_dropper = int(0 < len(source_chunks) <= 3 and max_line_len >= 1000)

    # Skor kepadatan obfuscation terikat [0.0, 1.0] sebagai dimensi kontinu halus
    obf_components = (
        uses_dynamic_eval
        + uses_base64_or_hex_decode
        + has_obfuscated_escapes
        + has_high_entropy_literal
        + has_minified_dropper
    )
    obfuscation_escape_ratio = round(obf_components / 5.0, 4)

    row: dict[str, Any] = {
        "id": inferred_id,
        "name": pkg_name,
        "reference_label": reference_label,
        "manifest_invalid_or_missing": int(not manifest_valid),
        "main_entry_missing": main_entry_missing,
        "no_js_source_files": int(len(source_chunks) == 0),
        "has_minified_dropper": has_minified_dropper,
        "has_install_lifecycle": has_install_lifecycle,
        "has_prepare_lifecycle": has_prepare_lifecycle,
        "lifecycle_runs_node_or_shell": lifecycle_runs_node_or_shell,
        "lifecycle_has_inline_or_encoded_cmd": lifecycle_has_inline_or_encoded_cmd,
        "lifecycle_mentions_recon_or_net": lifecycle_mentions_recon_or_net,
        "uses_child_process": uses_child_process,
        "uses_dynamic_eval": uses_dynamic_eval,
        "uses_base64_or_hex_decode": uses_base64_or_hex_decode,
        "has_obfuscated_escapes": has_obfuscated_escapes,
        "has_high_entropy_literal": has_high_entropy_literal,
        "reads_sensitive_env": reads_sensitive_env,
        "accesses_sensitive_paths": accesses_sensitive_paths,
        "collects_host_recon": collects_host_recon,
        "uses_network_api": uses_network_api,
        "uses_dns_api": uses_dns_api,
        "references_public_ipv4": references_public_ipv4,
        "references_exfil_or_oast_domain": references_exfil_or_oast_domain,
        "writes_or_chmods_files": writes_or_chmods_files,
        "sbom_scan_failed": sbom_scan_failed,
        "sbom_manifest_dep_mismatch": sbom_manifest_dep_mismatch,
        "has_external_dependencies": int(declared_dep_count > 0),
        "obfuscation_escape_ratio": obfuscation_escape_ratio,
    }

    return {col: row[col] for col in ALL_COLUMNS}


def save_or_update_batch(rows: list[dict[str, Any]], output_csv: Path) -> None:
    """Menyimpan atau memperbarui results/features.csv secara atomic."""
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    rows_by_id: dict[str, dict[str, Any]] = {}

    if output_csv.is_file():
        with output_csv.open("r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            for r in reader:
                r_id = str(r.get("id") or "").strip()
                if r_id:
                    rows_by_id[r_id] = r

    for row in rows:
        rows_by_id[str(row["id"])] = row

    sorted_keys = sorted(
        rows_by_id.keys(), key=lambda k: (0, int(k)) if k.isdigit() else (1, k)
    )

    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8-sig",
        newline="",
        dir=str(output_csv.parent),
        prefix=".features_",
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

    os.replace(tmp_path, output_csv)


def print_batch_summary(extracted: list[dict[str, Any]], output_csv: Path) -> None:
    total = len(extracted)
    by_label: dict[str, int] = {}
    with_install = 0
    with_exec_or_obf = 0

    for r in extracted:
        lbl = str(r.get("reference_label", "unknown"))
        by_label[lbl] = by_label.get(lbl, 0) + 1
        if r.get("has_install_lifecycle") == 1:
            with_install += 1
        if (
            r.get("uses_child_process") == 1
            or r.get("uses_dynamic_eval") == 1
            or r.get("has_obfuscated_escapes") == 1
            or r.get("has_high_entropy_literal") == 1
        ):
            with_exec_or_obf += 1

    print(f"\n=== Ringkasan Ekstraksi Fitur ({total} sampel) ===")
    print(f"Distribusi label        : {by_label}")
    print(f"Dengan install lifecycle: {with_install}/{total}")
    print(f"Dengan exec/obfuscation : {with_exec_or_obf}/{total}")
    print(f"Output CSV              : {output_csv}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Path folder sampel (samples/source/1), ID tunggal (1), atau rentang (1-50)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Ekstrak fitur semua sampel di samples/source/",
    )
    parser.add_argument(
        "--range",
        type=str,
        default=None,
        metavar="START-END",
        help="Rentang batch ID sampel (contoh: 1-50)",
    )
    parser.add_argument(
        "--id", type=str, default=None, help="Sample ID eksplisit (mode single)"
    )
    parser.add_argument(
        "--sbom", type=Path, default=None, help="Optional Syft CycloneDX SBOM JSON path"
    )
    parser.add_argument(
        "--inventory",
        type=Path,
        default=DEFAULT_INVENTORY,
        help="Path ke samples/inventory.csv untuk mengambil reference_label",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_CSV,
        help="Output CSV path (default: results/features.csv)",
    )
    args = parser.parse_args()

    output_csv = args.output.expanduser().resolve()
    inventory_path = args.inventory.expanduser().resolve()
    label_map = load_inventory_labels(inventory_path)

    # Mode batch range
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
            sample_dir = DEFAULT_SOURCE_DIR / str(sid)
            if sample_dir.is_dir():
                res = extract(sample_dir, sample_id=str(sid), label_map=label_map)
                extracted.append(res)
                print(f"[OK] ID {sid:<4} [{res['reference_label']:<9}] {res['name']}")
            else:
                print(f"[SKIP] Folder sampel ID {sid} tidak ditemukan.")

        if extracted:
            save_or_update_batch(extracted, output_csv)
            print_batch_summary(extracted, output_csv)
        return

    # Mode --all
    if args.all or (args.target == "all"):
        if not DEFAULT_SOURCE_DIR.is_dir():
            parser.error(f"Direktori source tidak ditemukan: {DEFAULT_SOURCE_DIR}")
            return

        sample_dirs = sorted(
            [d for d in DEFAULT_SOURCE_DIR.iterdir() if d.is_dir()],
            key=lambda d: (0, int(d.name)) if d.name.isdigit() else (1, d.name),
        )
        extracted = []
        for d in sample_dirs:
            sid = d.name
            res = extract(d, sample_id=sid, label_map=label_map)
            extracted.append(res)
            print(f"[OK] ID {sid:<4} [{res['reference_label']:<9}] {res['name']}")

        if extracted:
            save_or_update_batch(extracted, output_csv)
            print_batch_summary(extracted, output_csv)
        return

    # Mode single
    if not args.target:
        parser.print_help()
        return

    target_path = Path(args.target).expanduser()
    if not target_path.is_dir():
        if args.target.isdigit() and (DEFAULT_SOURCE_DIR / args.target).is_dir():
            target_path = DEFAULT_SOURCE_DIR / args.target
        else:
            parser.error(f"Direktori sampel tidak ditemukan: {args.target}")
            return

    sample_id = args.id or (target_path.name if target_path.name.isdigit() else None)
    result = extract(
        target_path,
        sbom_path=args.sbom.expanduser().resolve() if args.sbom else None,
        sample_id=sample_id,
        label_map=label_map,
    )

    save_or_update_batch([result], output_csv)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"\n[OK] Fitur ID {result['id']} berhasil disimpan ke: {output_csv}")


if __name__ == "__main__":
    main()
