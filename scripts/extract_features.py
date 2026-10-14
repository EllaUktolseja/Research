#!/usr/bin/env python3
"""Static feature extraction for npm packages. Does not execute package code or scripts."""

from __future__ import annotations
import argparse
import json
import re
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


def read_json(path: Path) -> tuple[Any | None, str]:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace")), "parsed"
    except FileNotFoundError:
        return None, "missing"
    except (json.JSONDecodeError, OSError):
        return None, "parse_error"


def matches(pattern: str, text: str) -> int:
    return int(bool(re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE)))


def extract(package_dir: Path, sbom_path: Path | None) -> dict[str, Any]:
    package_json_path = package_dir / "package.json"
    manifest, manifest_status = read_json(package_json_path)
    if not isinstance(manifest, dict):
        manifest = {}

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
    result: dict[str, Any] = {
        "name": str(manifest.get("name", package_dir.name)),
        "version": str(manifest.get("version", "unknown")),
        "package_dir": str(package_dir.resolve()),
        "manifest_status": manifest_status,
        "js_file_count": len(js_files),
        "js_files_readable_count": readable_js_count,
        "nonempty_js_file_count": nonempty_js_files,
        "source_char_count": source_chars,
        "source_missing": int(len(js_files) == 0),
        "source_empty": int(len(js_files) > 0 and nonempty_js_files == 0),
        "main_file_exists": int(
            bool(manifest.get("main"))
            and (package_dir / str(manifest.get("main"))).is_file()
        ),
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

    if sbom_path is None:
        result["sbom_status"] = "not_supplied"
        result["sbom_component_count"] = None
    else:
        sbom, sbom_status = read_json(sbom_path)

        if not isinstance(sbom, dict) or sbom_status != "parsed":
            result["sbom_status"] = "scan_failed"
            result["sbom_component_count"] = None
        elif isinstance(sbom.get("components"), list):
            count = len(sbom["components"])
            result["sbom_component_count"] = count
            result["sbom_status"] = (
                "components_detected" if count > 0 else "no_components_detected"
            )
        elif sbom.get("bomFormat") == "CycloneDX":
            result["sbom_status"] = "no_components_detected"
            result["sbom_component_count"] = 0
        else:
            result["sbom_status"] = "parsed_no_components_field"
            result["sbom_component_count"] = None
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "package_dir", type=Path, help="Path to extracted package/ directory"
    )
    parser.add_argument(
        "--sbom", type=Path, default=None, help="Optional Syft SBOM JSON path"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output JSON path (default: results/<name>-<version>-features.json)",
    )
    args = parser.parse_args()

    package_dir = args.package_dir.expanduser().resolve()
    if not package_dir.is_dir():
        parser.error(f"package directory does not exist: {package_dir}")
    result = extract(
        package_dir, args.sbom.expanduser().resolve() if args.sbom else None
    )
    output = (
        args.output.expanduser()
        if args.output
        else Path.home()
        / "malware-research"
        / "results"
        / f"{result['name']}-{result['version']}-features.json"
    )
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"\nSaved: {output}")


if __name__ == "__main__":
    main()
