#!/usr/bin/env bash
# Simpan sebagai: scripts/scan_sboms.sh

# Exit kalau ada error atau variabel kosong
set -euo pipefail

# Deteksi ROOT otomatis (1 level di atas folder scripts/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR/.."
OUT="$ROOT/results/sbom"
SAMPLES_DIR="$ROOT/samples/source"

# Pastikan folder output ada
mkdir -p "$OUT"

echo "[INFO] Mencari package.json di dalam $SAMPLES_DIR..."

# Looping ke semua package.json yang ada di dalam folder source
while IFS= read -r manifest; do
  PKG="${manifest%/package.json}"

  # Ambil nama & versi pakai Python (bawaan dari script asli lo)
  NAME=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("name","unknown"))' "$manifest")
  VERSION=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("version","unknown"))' "$manifest")

  # Bersihkan nama file biar aman di OS (hindari spasi/karakter aneh)
  SAFE_NAME=$(printf '%s' "$NAME" | tr -c 'A-Za-z0-9._-' '_')
  SAFE_VERSION=$(printf '%s' "$VERSION" | tr -c 'A-Za-z0-9._-' '_')
  DEST="$OUT/${SAFE_NAME}-${SAFE_VERSION}-sbom.json"

  echo "[INFO] Scanning: $NAME@$VERSION"

  # Generate SBOM pakai Syft
  if syft scan "dir:$PKG" \
    --source-name "$NAME" \
    --source-version "$VERSION" \
    -o cyclonedx-json >"$DEST"; then
    echo "[OK] Saved: $DEST"
  else
    echo "[ERROR] Gagal scanning: $NAME@$VERSION"
    rm -f "$DEST"
  fi
  echo
done < <(
  find "$SAMPLES_DIR" -type f -name package.json \
    -not -path '*/node_modules/*' \
    -not -path '*/.git/*' | sort
)
