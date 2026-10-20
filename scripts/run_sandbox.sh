#!/usr/bin/env bash
# Simpan sebagai: scripts/run_sandbox.sh
set -e

SAMPLE_ID=${1:-"1"}
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "[1/4] Starting Tetragon Sensor..."
sudo docker run --name tetragon-sensor --rm -d \
  --privileged --pid=host --net=host \
  -v "$ROOT/tetragon/network_egress_host.yaml:/etc/tetragon/tetragon.tp.d/network_egress_host.yaml" \
  -v "$ROOT/logs:/var/log/tetragon" \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /etc/os-release:/etc/os-release:ro \
  quay.io/cilium/tetragon:v1.2.0 \
  tetragon --exported-stdout-file /var/log/tetragon/tetragon-node-control.jsonl

sleep 15

echo "[2/4] Executing Sample ID $SAMPLE_ID..."
sudo docker run --rm --net=host \
  -v "$ROOT/samples/source/$SAMPLE_ID:/app" \
  -w /app \
  node:20-slim \
  sh -c "npm install --ignore-scripts=false || node index.js" || true

sleep 5

echo "[3/4] Stopping Tetragon Sensor..."
sudo docker stop tetragon-sensor

echo "[4/4] Done! Log saved to logs/tetragon-node-control.jsonl"
