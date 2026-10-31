#!/usr/bin/env bash
# Simpan sebagai: scripts/scan_sbom.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR/.."
OUT="$ROOT/results/sbom"
SAMPLES_DIR="$ROOT/samples/source"

mkdir -p "$OUT"

scan_directory() {
  local search_dir="$1"
  local target_desc="${2:-$search_dir}"

  echo "[INFO] Mencari package.json di $target_desc..."

  while IFS= read -r manifest; do
    [ -z "$manifest" ] && continue
    local pkg="${manifest%/package.json}"

    # Ambil sample_id dari path relatif samples/source/<id>/...
    local rel="${manifest#"$SAMPLES_DIR/"}"
    local sample_id="${rel%%/*}"

    # Ambil nama & versi pakai Python
    local name version
    name=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("name","unknown"))' "$manifest" 2>/dev/null || echo "unknown")
    version=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("version","unknown"))' "$manifest" 2>/dev/null || echo "unknown")

    local safe_name safe_version dest_name dest_id
    safe_name=$(printf '%s' "$name" | tr -c 'A-Za-z0-9._-' '_')
    safe_version=$(printf '%s' "$version" | tr -c 'A-Za-z0-9._-' '_')
    dest_name="$OUT/${safe_name}-${safe_version}-sbom.json"
    dest_id="$OUT/${sample_id}.json"

    echo "[INFO] Scanning [ID: $sample_id] $name@$version ($pkg)..."

    # Generate SBOM pakai Syft jika terpasang, atau fallback format CycloneDX minimal jika syft tidak ada
    if command -v syft >/dev/null 2>&1; then
      if syft scan "dir:$pkg" \
        --source-name "$name" \
        --source-version "$version" \
        -o cyclonedx-json >"$dest_name" 2>/dev/null; then
        cp -f "$dest_name" "$dest_id"
        echo "[OK] Saved: $dest_name & $dest_id"
      else
        echo "[ERROR] Gagal scanning via Syft: $name@$version"
      fi
    else
      echo "[WARNING] Syft tidak terpasang di sistem. Menghasilkan CycloneDX stub dari package.json..."
      python3 -c "
import json
from pathlib import Path
try:
    manifest = json.load(open('$manifest'))
    components = []
    deps = {**manifest.get('dependencies', {}), **manifest.get('devDependencies', {})}
    for dep, ver in deps.items():
        components.append({'name': dep, 'version': str(ver), 'type': 'library'})
    bom = {
        'bomFormat': 'CycloneDX',
        'specVersion': '1.5',
        'metadata': {'component': {'name': '$name', 'version': '$version', 'type': 'application'}},
        'components': components
    }
    with open('$dest_name', 'w') as f: json.dump(bom, f, indent=2)
    with open('$dest_id', 'w') as f: json.dump(bom, f, indent=2)
    print('[OK] Generated SBOM JSON fallback: $dest_id')
except Exception as e:
    print(f'[ERROR] Fallback gagal: {e}')
"
    fi
    echo
  done < <(
    find "$search_dir" -type f -name package.json \
      -not -path '*/node_modules/*' \
      -not -path '*/.git/*' | sort
  )
}

TARGET="${1:-}"

if [ -z "$TARGET" ]; then
  scan_directory "$SAMPLES_DIR" "seluruh folder samples/source"
elif [[ "$TARGET" =~ ^[0-9]+-[0-9]+$ ]]; then
  IFS='-' read -r start_id end_id <<< "$TARGET"
  echo "[INFO] Memproses rentang ID: $start_id sampai $end_id..."
  for (( id=start_id; id<=end_id; id++ )); do
    sample_dir="$SAMPLES_DIR/$id"
    if [ -d "$sample_dir" ]; then
      scan_directory "$sample_dir" "Sample ID: $id"
    else
      echo "[SKIP] Folder sampel ID $id tidak ditemukan."
    fi
  done
else
  sample_dir="$SAMPLES_DIR/$TARGET"
  if [ ! -d "$sample_dir" ]; then
    echo "[ERROR] Folder sampel tidak ditemukan: $sample_dir"
    exit 1
  fi
  scan_directory "$sample_dir" "Sample ID: $TARGET"
fi
