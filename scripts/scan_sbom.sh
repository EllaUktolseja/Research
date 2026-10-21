#!/usr/bin/env bash
# Simpan sebagai: scripts/scan_sbom.sh
set -euo pipefail

# Deteksi ROOT otomatis (1 level di atas folder scripts/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR/.."
OUT="$ROOT/results/sbom"
SAMPLES_DIR="$ROOT/samples/source"

mkdir -p "$OUT"

TARGET_ID="${1:-}"
if [ -n "$TARGET_ID" ]; then
  SEARCH_DIR="$SAMPLES_DIR/$TARGET_ID"
  if [ ! -d "$SEARCH_DIR" ]; then
    echo "[ERROR] Folder sampel tidak ditemukan: $SEARCH_DIR"
    exit 1
  fi
  echo "[INFO] Mencari package.json untuk Sampel ID: $TARGET_ID ($SEARCH_DIR)..."
else
  SEARCH_DIR="$SAMPLES_DIR"
  echo "[INFO] Mencari package.json di dalam seluruh $SAMPLES_DIR..."
fi

while IFS= read -r manifest; do
  PKG="${manifest%/package.json}"

  # Ambil sample_id dari path relatif samples/source/<id>/...
  REL="${manifest#"$SAMPLES_DIR/"}"
  SAMPLE_ID="${REL%%/*}"

  # Ambil nama & versi pakai Python
  NAME=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("name","unknown"))' "$manifest")
  VERSION=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("version","unknown"))' "$manifest")

  # Bersihkan nama file biar aman di OS
  SAFE_NAME=$(printf '%s' "$NAME" | tr -c 'A-Za-z0-9._-' '_')
  SAFE_VERSION=$(printf '%s' "$VERSION" | tr -c 'A-Za-z0-9._-' '_')
  DEST_NAME="$OUT/${SAFE_NAME}-${SAFE_VERSION}-sbom.json"
  DEST_ID="$OUT/${SAMPLE_ID}.json"

  echo "[INFO] Scanning [ID: $SAMPLE_ID] $NAME@$VERSION..."

  # Generate SBOM pakai Syft
  if syft scan "dir:$PKG" \
    --source-name "$NAME" \
    --source-version "$VERSION" \
    -o cyclonedx-json >"$DEST_NAME"; then
    # Salin juga ke format ID untuk konsistensi pipeline
    cp -f "$DEST_NAME" "$DEST_ID"
    echo "[OK] Saved: $DEST_NAME & $DEST_ID"
  else
    echo "[ERROR] Gagal scanning: $NAME@$VERSION"
    rm -f "$DEST_NAME" "$DEST_ID" 2>/dev/null || true
  fi
  echo
done < <(
  find "$SEARCH_DIR" -type f -name package.json \
    -not -path '*/node_modules/*' \
    -not -path '*/.git/*' | sort
)
