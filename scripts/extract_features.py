#!/usr/bin/env python3
"""Static and SBOM feature extraction for npm packages.
Does not execute package code or scripts.
Supports single sample, all samples, and range batch processing (e.g. 1-50).
"""

from __future__ import annotations
import argparse
import json
import re
import csv
from pathlib import Path
from typing import Any

SUSPICIOUS_PATTERNS = {
    "script_mentions_network_tool": r"\b(curl|wget|nc|netcat)\b",
    "script_mentions_http_url": r"https?://",
    "script_mentions_shell_identity": r"\b(whoami|hostname|pwd|uname)\b",
    "script_mentions_dns_or_oast": r"\b(dns\.|getServers|resolve\w*)\b|oastify|interactsh",
    "script_mentions_webhook": r"webhook\.site",
}
SOURCE_PATTERNS = {
    "uses_os_module": r"require\s*\(\s*['\"]os['\"]\s*\)|from\s+['\"]os['\"]",
    "uses_https_module": r"require\s*\(\s*['\"]https['\"]\s*\)|from\s+['\"]https['\"]",
    "uses_http_module": r"require\s*\(\s*['\"]http['\"]\s*\)|from\s+['\"]http['\"]",
    "uses_dns_module": r"require\s*\(\s*['\"]dns['\"]\s*\)|from\s+['\"]dns['\"]",
    "uses_child_process": r"child_process|execSync\s*\(|execFile\s*\(|spawn\s*\(",
    "references_ipify": r"ipify\.org",
    "references_oastify": r"oastify",
    "references_webhook_site": r"webhook\.site",
    "references_literal_ipv4": r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])",
    "references_process_env": r"process\.env",
    "constructs_dns_query": r"dns\.(?:resolve|lookup|resolve4|resolve6|resolveTxt|resolveAny)\s*\(",
    "uses_http_request": r"https?\.request\s*\(|fetch\s*\(|axios\.",
    "serializes_data": r"JSON\.stringify\s*\(",
    "uses_querystring": r"querystring",
    "uses_fetch_api": r"\bfetch\s*\(",
    "uses_request_method": r"\.\s*request\s*\(",
    "uses_data_encoding": r"JSON\.stringify|querystring\.stringify|encodeURIComponent",
}
LIFECYCLE_SCRIPTS = (
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "prepublish",
    "prepack",
)
DEPENDENCY_GROUPS = (
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
)

FEATURE_COLUMNS = [
    "id",
    "name",
    "version",
    "package_dir",
    "manifest_status",
    "js_file_count",
    "js_files_readable_count",
    "nonempty_js_file_count",
    "source_char_count",
    "source_missing",
    "source_empty",
    "main_file_exists",
    "script_count",
    "has_preinstall_script",
    "has_install_script",
    "has_postinstall_script",
    "has_prepare_script",
    "has_test_script",
    "script_preinstall_mentions_node",
    "manifest_dependency_count",
    "dependencies_count",
    "devdependencies_count",
    "optionaldependencies_count",
    "peerdependencies_count",
    "uses_os_module",
    "uses_https_module",
    "uses_http_module",
    "uses_dns_module",
    "uses_child_process",
    "references_ipify",
    "references_oastify",
    "references_webhook_site",
    "references_literal_ipv4",
    "references_process_env",
    "constructs_dns_query",
    "uses_http_request",
    "serializes_data",
    "uses_querystring",
    "uses_fetch_api",
    "uses_request_method",
    "uses_data_encoding",
    "script_mentions_network_tool",
    "script_mentions_http_url",
    "script_mentions_shell_identity",
    "script_mentions_dns_or_oast",
    "script_mentions_webhook",
    "sbom_component_count",
    "sbom_dependency_count",
    "sbom_has_dependencies",
    "sbom_status",
]


def read_json(path: Path) -> tuple[Any | None, str]:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace")), "parsed"
    except FileNotFoundError:
        return None, "missing"
    except (json.JSONDecodeError, OSError):
        return None, "parse_error"


def matches(pattern: str, text: str) -> int:
    return int(bool(re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE)))


def find_target_dir_and_manifest(package_dir: Path) -> tuple[Path, Path | None, dict[str, Any], str]:
    direct_json = package_dir / "package.json"
    if direct_json.is_file():
        manifest, status = read_json(direct_json)
        if isinstance(manifest, dict):
            return package_dir, direct_json, manifest, status

    candidates = [
        p for p in package_dir.rglob("package.json")
        if "node_modules" not in p.parts and ".git" not in p.parts
    ]
    if candidates:
        chosen = candidates[0]
        manifest, status = read_json(chosen)
        if isinstance(manifest, dict):
            return chosen.parent, chosen, manifest, status
        return chosen.parent, chosen, {}, status

    return package_dir, None, {}, "missing"


def parse_sbom(sbom_path: Path | None) -> tuple[int, int, int, str]:
    if sbom_path is None or not sbom_path.is_file():
        return 0, 0, 0, "not_supplied"

    sbom, status = read_json(sbom_path)
    if not isinstance(sbom, dict) or status != "parsed":
        return 0, 0, 0, "scan_failed"

    components = sbom.get("components")
    comp_count = len(components) if isinstance(components, list) else 0

    dependencies = sbom.get("dependencies")
    dep_count = len(dependencies) if isinstance(dependencies, list) else 0
    has_deps = 1 if dep_count > 0 else 0

    if comp_count > 0:
        sbom_status = "components_detected"
    elif sbom.get("bomFormat") == "CycloneDX":
        sbom_status = "no_components_detected"
    else:
        sbom_status = "parsed_no_components_field"

    return comp_count, dep_count, has_deps, sbom_status


def extract(package_dir: Path, sbom_path: Path | None = None, sample_id: str | None = None) -> dict[str, Any]:
    target_dir, manifest_path, manifest, manifest_status = find_target_dir_and_manifest(package_dir)

    scripts = (
        manifest.get("scripts") if isinstance(manifest.get("scripts"), dict) else {}
    )
    dependency_counts = {
        f"{group.lower()}_count": len(manifest.get(group, {}))
        if isinstance(manifest.get(group), dict)
        else 0
        for group in DEPENDENCY_GROUPS
    }

    js_files = sorted(
        p
        for p in package_dir.rglob("*")
        if p.is_file()
        and p.suffix.lower() in {".js", ".cjs", ".mjs", ".jsx"}
        and "node_modules" not in p.parts
        and ".git" not in p.parts
    )
    source_chunks: list[str] = []
    readable_js_count = 0
    for path in js_files:
        try:
            source_chunks.append(path.read_text(encoding="utf-8", errors="replace"))
            readable_js_count += 1
        except OSError:
            pass

    source = "\n".join(source_chunks)
    source_chars = len(source)
    nonempty_js_files = sum(1 for chunk in source_chunks if chunk.strip())
    script_text = "\n".join(str(v) for v in scripts.values())
    combined = source + "\n" + script_text

    inferred_id = sample_id or package_dir.name
    pkg_name = str(manifest.get("name", inferred_id))
    pkg_version = str(manifest.get("version", "unknown"))

    # Resolve SBOM
    if sbom_path is None or not sbom_path.is_file():
        ROOT_DIR = Path(__file__).resolve().parent.parent
        possible_sboms = [
            ROOT_DIR / "results" / "sbom" / f"{inferred_id}.json",
            ROOT_DIR / "results" / "sbom" / f"{pkg_name}-{pkg_version}-sbom.json",
        ]
        for p in possible_sboms:
            if p.is_file():
                sbom_path = p
                break

    comp_count, dep_count, has_deps, sbom_status = parse_sbom(sbom_path)

    main_val = manifest.get("main")
    main_file_exists = int(
        bool(main_val) and (target_dir / str(main_val)).is_file()
    )

    result: dict[str, Any] = {
        "id": str(inferred_id),
        "name": pkg_name,
        "version": pkg_version,
        "package_dir": str(package_dir.resolve()),
        "manifest_status": manifest_status,
        "js_file_count": len(js_files),
        "js_files_readable_count": readable_js_count,
        "nonempty_js_file_count": nonempty_js_files,
        "source_char_count": source_chars,
        "source_missing": int(len(js_files) == 0),
        "source_empty": int(len(js_files) > 0 and nonempty_js_files == 0),
        "main_file_exists": main_file_exists,
        "script_count": len(scripts),
        "has_preinstall_script": int("preinstall" in scripts),
        "has_install_script": int("install" in scripts),
        "has_postinstall_script": int("postinstall" in scripts),
        "has_prepare_script": int("prepare" in scripts),
        "has_test_script": int("test" in scripts),
        "script_preinstall_mentions_node": int(
            "node" in str(scripts.get("preinstall", "")).lower()
        ),
        "manifest_dependency_count": sum(dependency_counts.values()),
        **dependency_counts,
    }

    for key, pattern in SOURCE_PATTERNS.items():
        result[key] = matches(pattern, combined)
    for key, pattern in SUSPICIOUS_PATTERNS.items():
        result[key] = matches(pattern, script_text)

    result["sbom_component_count"] = comp_count
    result["sbom_dependency_count"] = dep_count
    result["sbom_has_dependencies"] = has_deps
    result["sbom_status"] = sbom_status

    return {col: result.get(col, 0) for col in FEATURE_COLUMNS}


def save_or_update_batch(rows: list[dict[str, Any]], output_csv: Path) -> None:
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    rows_by_id: dict[str, dict[str, Any]] = {}

    if output_csv.is_file():
        with output_csv.open("r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            for r in reader:
                r_id = str(r.get("id") or r.get("package_dir", ""))
                rows_by_id[r_id] = r

    for row in rows:
        current_id = str(row["id"])
        rows_by_id[current_id] = row

    with output_csv.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FEATURE_COLUMNS)
        writer.writeheader()
        sorted_keys = sorted(rows_by_id.keys(), key=lambda k: int(k) if k.isdigit() else k)
        for k in sorted_keys:
            r = rows_by_id[k]
            clean_r = {col: r.get(col, 0) for col in FEATURE_COLUMNS}
            writer.writerow(clean_r)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Path folder sampel (misal samples/source/1), ID sampel (1), atau rentang batch (misal 1-50)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Ekstrak fitur semua sampel yang ada di samples/source/",
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
        "--sbom", type=Path, default=None, help="Optional Syft/CycloneDX SBOM JSON path"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output CSV path (default: results/features.csv)",
    )
    args = parser.parse_args()

    ROOT_DIR = Path(__file__).resolve().parent.parent
    output_csv = args.output.expanduser().resolve() if args.output else ROOT_DIR / "results" / "features.csv"
    source_root = ROOT_DIR / "samples" / "source"

    # Batch range mode
    range_str = args.range or (args.target if args.target and "-" in args.target and not Path(args.target).is_dir() else None)
    if range_str:
        try:
            start_s, end_s = range_str.split("-")
            start_id, end_id = int(start_s), int(end_s)
        except ValueError:
            parser.error("Format range harus START-END (misal 1-50)")
            return

        extracted = []
        for sid in range(start_id, end_id + 1):
            pkg_dir = source_root / str(sid)
            if pkg_dir.is_dir():
                res = extract(pkg_dir, sample_id=str(sid))
                extracted.append(res)
                print(f"[OK] Extracted features ID {sid:<3} ({res['name']})")
            else:
                print(f"[SKIP] Folder sampel ID {sid} tidak ditemukan.")

        if extracted:
            save_or_update_batch(extracted, output_csv)
            print(f"\n[OK] Berhasil mengekstrak {len(extracted)} sampel ke: {output_csv}")
        return

    # All mode
    if args.all or (args.target == "all"):
        sample_dirs = sorted(
            [d for d in source_root.iterdir() if d.is_dir()],
            key=lambda d: int(d.name) if d.name.isdigit() else d.name,
        )
        extracted = []
        for d in sample_dirs:
            sid = d.name
            res = extract(d, sample_id=sid)
            extracted.append(res)
            print(f"[OK] Extracted features ID {sid:<3} ({res['name']})")

        if extracted:
            save_or_update_batch(extracted, output_csv)
            print(f"\n[OK] Berhasil mengekstrak {len(extracted)} sampel ke: {output_csv}")
        return

    # Single mode
    if not args.target:
        parser.print_help()
        return

    target_path = Path(args.target).expanduser()
    if not target_path.is_dir():
        # Coba periksa apakah target berupa numeric ID
        if args.target.isdigit() and (source_root / args.target).is_dir():
            target_path = source_root / args.target
        else:
            parser.error(f"Direktori sampel tidak ditemukan: {args.target}")

    sample_id = args.id or (target_path.name if target_path.name.isdigit() else None)
    result = extract(
        target_path,
        args.sbom.expanduser().resolve() if args.sbom else None,
        sample_id=sample_id,
    )

    save_or_update_batch([result], output_csv)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"\n[OK] Fitur ID {result['id']} berhasil diekstrak dan disimpan ke: {output_csv}")


if __name__ == "__main__":
    main()
