#!/usr/bin/env bash
set -e

SAMPLE_ID=${1:-"1"}
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

LOG_TEMP="$ROOT/logs/tetragon-node-control.jsonl"
EBPF_DEST="$ROOT/results/ebpf/${SAMPLE_ID}.json"

mkdir -p "$ROOT/results/ebpf" "$ROOT/logs"
rm -f "$LOG_TEMP"

# 1. Cek folder sampel & cari posisi package.json
SAMPLE_DIR="$ROOT/samples/source/$SAMPLE_ID"
if [ ! -d "$SAMPLE_DIR" ]; then
  echo "[ERROR] Folder $SAMPLE_DIR tidak ditemukan! Jalankan 'python scripts/manage_inventory.py --get $SAMPLE_ID' terlebih dahulu."
  exit 1
fi

TARGET_DIR=$(find "$SAMPLE_DIR" -name "package.json" -exec dirname {} \; | head -n 1)

if [ -z "$TARGET_DIR" ]; then
  echo "[WARNING] Tidak ditemukan package.json di $SAMPLE_DIR, menggunakan root sampel."
  TARGET_DIR="$SAMPLE_DIR"
fi

echo "[1/4] Starting Tetragon Sensor..."
sudo docker rm -f tetragon-sensor 2>/dev/null || true

# Menggunakan flag --export-filename menggantikan --exported-stdout-file
sudo docker run --name tetragon-sensor -d \
  --privileged --pid=host --net=host \
  -v "$ROOT/tetragon/network_egress_host.yaml:/etc/tetragon/tetragon.tp.d/network_egress_host.yaml" \
  -v "$ROOT/logs:/var/log/tetragon" \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /etc/os-release:/etc/os-release:ro \
  quay.io/cilium/tetragon:v1.2.0 \
  tetragon --export-filename /var/log/tetragon/tetragon-node-control.jsonl

sleep 3

if ! sudo docker ps | grep -q tetragon-sensor; then
  echo "[ERROR] Tetragon container crash saat startup! Berikut log error Tetragon:"
  sudo docker logs tetragon-sensor || true
  sudo docker rm -f tetragon-sensor 2>/dev/null || true
  exit 1
fi

echo "[2/4] Executing Sample ID $SAMPLE_ID (Directory: $TARGET_DIR)..."
sudo docker run --rm --net=host \
  -v "$TARGET_DIR:/app" \
  -w /app \
  node:20-slim \
  sh -c "npm install --ignore-scripts=false || node index.js || node ." || true

sleep 5

echo "[3/4] Stopping Tetragon Sensor..."
sudo docker stop tetragon-sensor 2>/dev/null || true
sudo docker rm -f tetragon-sensor 2>/dev/null || true

echo "[4/4] Moving log to results/ebpf/${SAMPLE_ID}.json..."
if [ -f "$LOG_TEMP" ]; then
  mv "$LOG_TEMP" "$EBPF_DEST"
  echo "[OK] File eBPF log disimpan di: $EBPF_DEST"
else
  echo "[ERROR] File log temporary tidak ditemukan di $LOG_TEMP!"
fi
