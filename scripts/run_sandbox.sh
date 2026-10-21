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

# Cleanup container lama jika masih berjalan
sudo docker rm -f tetragon-sensor 2>/dev/null || true

# PENTING: Bersihkan pin BPF filesystem sisa crash sebelumnya agar tidak memicu 'invalid argument' / 'sensor already loaded'
if [ -d "/sys/fs/bpf/tetragon" ]; then
  echo "[INFO] Membersihkan sisa pin filesystem BPF Tetragon lama..."
  sudo rm -rf /sys/fs/bpf/tetragon/* 2>/dev/null || true
fi

# Menggunakan tag v1.3.0 untuk kecocokan kernel baru dan menambahkan flag --tracing-policy-dir
# ... (bagian atas script tetap sama) ...

sudo docker run --name tetragon-sensor -d \
  --privileged --pid=host --net=host \
  -v "$ROOT/tetragon/network_egress_host.yaml:/etc/tetragon/tetragon.tp.d/network_egress_host.yaml" \
  -v "$ROOT/logs:/var/log/tetragon" \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /etc/os-release:/etc/os-release:ro \
  quay.io/cilium/tetragon:v1.3.0 \
  tetragon \
  --export-filename /var/log/tetragon/tetragon-node-control.jsonl \
  --tracing-policy-dir /etc/tetragon/tetragon.tp.d/ \
  --disable-kprobe-multi

# ... (bagian bawah script tetap sama) ...
# Berikan waktu bagi Tetragon untuk memuat program eBPF ke kernel
sleep 15

if ! sudo docker ps | grep -q tetragon-sensor; then
  echo "[ERROR] Tetragon container crash saat startup! Berikut log error Tetragon:"
  sudo docker logs tetragon-sensor || true
  sudo docker rm -f tetragon-sensor 2>/dev/null || true
  exit 1
fi

echo "[2/4] Executing Sample ID $SAMPLE_ID (Directory: $TARGET_DIR)..."

# 1. Jalankan Mock HTTP Server sederhana di background host (port 8080 & 80)
# Ini menjaga agar request HTTP/TCP dari sampel mendapat respon HTTP 200 OK
sudo docker run --name mock-sinkhole -d --net=host \
  python:3-slim python3 -c '
import http.server, socketserver
class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self): self.send_response(200); self.end_headers(); self.wfile.write(b"{}")
    def do_POST(self): self.send_response(200); self.end_headers(); self.wfile.write(b"{}")
with socketserver.TCPServer(("", 8080), Handler) as httpd:
    httpd.serve_forever()
' 2>/dev/null || true

# 2. Jalankan sampel Node.js
# Tambahkan timeout agar proses tidak menggantung jika sampel loop selamanya,
# dan pastikan log eBPF sempat menangkap syscall sebelum kontainer mati
sudo docker run --rm --net=host \
  -v "$TARGET_DIR:/app" \
  -w /app \
  node:20-slim \
  sh -c "npm install --ignore-scripts=false && timeout 10s node index.js" || true

# 3. Bersihkan mock server
sudo docker rm -f mock-sinkhole 2>/dev/null || true

# Berikan jeda waktu agar log event eBPF terakhir sempat ter-flush ke disk
sleep 10

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
