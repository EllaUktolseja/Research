#!/usr/bin/env bash
# Simpan sebagai: scripts/scan_sbom.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT="$ROOT/results/sbom"
SAMPLES_DIR="$ROOT/samples/source"
MANIFEST_LOG="$OUT/scan_manifest.tsv"
SCAN_TIMEOUT=60

FORCE=0
TARGET=""

for arg in "$@"; do
  case "$arg" in
  --force | -f)
    FORCE=1
    ;;
  --help | -h)
    echo "Usage: bash scripts/scan_sbom.sh [ID | START-END] [--force]"
    exit 0
    ;;
  *)
    if [ -z "$TARGET" ]; then
      TARGET="$arg"
    else
      echo "[ERROR] Argumen tidak dikenal: $arg" >&2
      exit 1
    fi
    ;;
  esac
done

if ! command -v syft >/dev/null 2>&1; then
  echo "[ERROR] 'syft' tidak ditemukan di PATH. Install Syft terlebih dahulu agar format SBOM seragam." >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "[ERROR] 'python3' tidak ditemukan di PATH." >&2
  exit 1
fi

mkdir -p "$OUT"

if [ ! -f "$MANIFEST_LOG" ]; then
  printf "sample_id\tpkg_name\tpkg_version\tmanifest_valid\tdeclared_deps\tsyft_components\tstatus\n" >"$MANIFEST_LOG"
fi

TOTAL_SCANNED=0
TOTAL_SKIPPED=0
TOTAL_FAILED=0

record_status() {
  local sid="$1" pname="$2" pver="$3" mvalid="$4" ddeps="$5" scomps="$6" status="$7"
  python3 - "$MANIFEST_LOG" "$sid" "$pname" "$pver" "$mvalid" "$ddeps" "$scomps" "$status" <<'PY'
import sys

log_path, sid, pname, pver, mvalid, ddeps, scomps, status = sys.argv[1:9]
header = "sample_id\tpkg_name\tpkg_version\tmanifest_valid\tdeclared_deps\tsyft_components\tstatus\n"
rows = {}

try:
    with open(log_path, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()
    for line in lines[1:]:
        if not line.strip():
            continue
        parts = line.split("\t")
        rows[parts[0]] = line
except FileNotFoundError:
    pass

rows[sid] = "\t".join([sid, pname, pver, mvalid, ddeps, scomps, status])

def sort_key(k):
    return (0, int(k)) if k.isdigit() else (1, k)

tmp_path = f"{log_path}.tmp"
with open(tmp_path, "w", encoding="utf-8") as f:
    f.write(header)
    for k in sorted(rows.keys(), key=sort_key):
        f.write(rows[k] + "\n")

import os
os.replace(tmp_path, log_path)
PY
}

scan_sample() {
  local sample_id="$1"
  local sample_dir="$SAMPLES_DIR/$sample_id"
  local pkg_dir="$sample_dir/package"
  local manifest="$pkg_dir/package.json"
  local dest_id="$OUT/${sample_id}.json"

  if [ ! -d "$sample_dir" ]; then
    echo "[SKIP] Folder sampel ID $sample_id tidak ditemukan."
    TOTAL_SKIPPED=$((TOTAL_SKIPPED + 1))
    return 0
  fi

  if [ ! -d "$pkg_dir" ]; then
    echo "[ERROR] ID $sample_id tidak memiliki folder 'package/' (jalankan ulang manage_inventory.py)." >&2
    record_status "$sample_id" "unknown" "unknown" "false" "0" "0" "missing-package-dir"
    TOTAL_FAILED=$((TOTAL_FAILED + 1))
    return 0
  fi

  if [ -s "$dest_id" ] && [ "$FORCE" -eq 0 ]; then
    echo "[SKIP] ID $sample_id sudah memiliki SBOM ($dest_id). Gunakan --force untuk timpa."
    TOTAL_SKIPPED=$((TOTAL_SKIPPED + 1))
    return 0
  fi

  if [ ! -f "$manifest" ]; then
    echo "[WARNING] ID $sample_id tidak memiliki package.json di root package/."
  fi

  local manifest_valid pkg_name pkg_version declared_deps
  IFS=$'\t' read -r manifest_valid pkg_name pkg_version declared_deps < <(
    python3 - "$manifest" <<'PY'
import json
import sys

path = sys.argv[1]
try:
    with open(path, "r", encoding="utf-8-sig") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("Root JSON bukan object")
    name = "_".join(str(data.get("name") or "unknown").split()) or "unknown"
    version = "_".join(str(data.get("version") or "unknown").split()) or "unknown"
    deps = data.get("dependencies") if isinstance(data.get("dependencies"), dict) else {}
    dev_deps = data.get("devDependencies") if isinstance(data.get("devDependencies"), dict) else {}
    print(f"true\t{name}\t{version}\t{len(deps) + len(dev_deps)}")
except Exception:
    print("false\tunknown\tunknown\t0")
PY
  )

  echo "[INFO] Scanning [ID: $sample_id] ${pkg_name}@${pkg_version} (manifest_valid=$manifest_valid, declared_deps=$declared_deps)..."

  local tmp_out="$OUT/.${sample_id}.json.tmp"
  local syft_err="$OUT/.${sample_id}.err.tmp"
  rm -f "$tmp_out" "$syft_err"

  local syft_cmd=(
    syft scan "dir:$pkg_dir"
    --source-name "$pkg_name"
    --source-version "$pkg_version"
    -o "cyclonedx-json=$tmp_out"
  )

  local cmd_status=0
  if command -v timeout >/dev/null 2>&1; then
    timeout "${SCAN_TIMEOUT}s" "${syft_cmd[@]}" >/dev/null 2>"$syft_err" || cmd_status=$?
  else
    "${syft_cmd[@]}" >/dev/null 2>"$syft_err" || cmd_status=$?
  fi

  if [ "$cmd_status" -ne 0 ] || [ ! -s "$tmp_out" ]; then
    echo "[ERROR] Syft gagal pada ID $sample_id (exit=$cmd_status): $(tr '\n' ' ' <"$syft_err" | head -c 200)" >&2
    rm -f "$tmp_out" "$syft_err"
    record_status "$sample_id" "$pkg_name" "$pkg_version" "$manifest_valid" "$declared_deps" "0" "syft-failed"
    TOTAL_FAILED=$((TOTAL_FAILED + 1))
    return 0
  fi

  local comp_count
  if ! comp_count=$(
    python3 - "$tmp_out" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        bom = json.load(f)
    if bom.get("bomFormat") != "CycloneDX":
        sys.exit(1)
    comps = bom.get("components")
    print(len(comps) if isinstance(comps, list) else 0)
except Exception:
    sys.exit(1)
PY
  ); then
    echo "[ERROR] Output SBOM ID $sample_id bukan CycloneDX JSON yang valid." >&2
    rm -f "$tmp_out" "$syft_err"
    record_status "$sample_id" "$pkg_name" "$pkg_version" "$manifest_valid" "$declared_deps" "0" "invalid-sbom"
    TOTAL_FAILED=$((TOTAL_FAILED + 1))
    return 0
  fi

  mv -f "$tmp_out" "$dest_id"
  rm -f "$syft_err"

  local scan_status="ok"
  if [ "$manifest_valid" = "false" ]; then
    scan_status="ok-malformed-manifest"
  elif [ "$declared_deps" -gt 0 ] && [ "$comp_count" -eq 0 ]; then
    scan_status="warning-empty-components"
  fi

  record_status "$sample_id" "$pkg_name" "$pkg_version" "$manifest_valid" "$declared_deps" "$comp_count" "$scan_status"
  echo "[OK] Saved: $dest_id (syft_components=$comp_count, status=$scan_status)"
  TOTAL_SCANNED=$((TOTAL_SCANNED + 1))
}

if [ -z "$TARGET" ]; then
  echo "[INFO] Memindai seluruh sampel di $SAMPLES_DIR..."
  while IFS= read -r sid; do
    [ -z "$sid" ] && continue
    scan_sample "$sid"
  done < <(find "$SAMPLES_DIR" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort -n)
elif [[ "$TARGET" =~ ^[0-9]+-[0-9]+$ ]]; then
  IFS='-' read -r start_id end_id <<<"$TARGET"
  if [ "$start_id" -lt 1 ] || [ "$end_id" -lt "$start_id" ]; then
    echo "[ERROR] Rentang ID tidak valid: $TARGET (pastikan START >= 1 dan START <= END)." >&2
    exit 1
  fi
  echo "[INFO] Memproses rentang ID: $start_id sampai $end_id..."
  for ((id = start_id; id <= end_id; id++)); do
    scan_sample "$id"
  done
elif [[ "$TARGET" =~ ^[0-9]+$ ]]; then
  scan_sample "$TARGET"
else
  echo "[ERROR] Format target tidak valid: '$TARGET'. Gunakan ID tunggal (misal: 42) atau rentang (misal: 1-50)." >&2
  exit 1
fi

echo
echo "=== Ringkasan Scan SBOM ==="
echo "Berhasil : $TOTAL_SCANNED"
echo "Dilewati : $TOTAL_SKIPPED"
echo "Gagal    : $TOTAL_FAILED"
echo "Log audit: $MANIFEST_LOG"
