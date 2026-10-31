#!/usr/bin/env bash
set -e

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_TEMP="$ROOT/logs/tetragon-node-control.jsonl"

mkdir -p "$ROOT/results/ebpf" "$ROOT/logs"

run_single_sample() {
  local sample_id="$1"
  local ebpf_dest="$ROOT/results/ebpf/${sample_id}.json"
  local sample_dir="$ROOT/samples/source/$sample_id"

  if [ ! -d "$sample_dir" ]; then
    echo "[SKIP] Folder sampel ID $sample_id tidak ditemukan ($sample_dir)."
    return
  fi

  local target_dir
  target_dir=$(find "$sample_dir" -name "package.json" -not -path '*/node_modules/*' -not -path '*/.git/*' -exec dirname {} \; | head -n 1)
  if [ -z "$target_dir" ]; then
    echo "[WARNING] Tidak ditemukan package.json di $sample_dir, menggunakan root sampel."
    target_dir="$sample_dir"
  fi

  rm -f "$LOG_TEMP"

  echo "================================================================================"
  echo ">>> [START SANDBOX] Sample ID: $sample_id (Directory: $target_dir)"
  echo "================================================================================"

  # 1. Bersihkan sisa container dan pin BPF lama
  sudo docker rm -f tetragon-sensor mock-sinkhole 2>/dev/null || true
  if [ -d "/sys/fs/bpf/tetragon" ]; then
    sudo rm -rf /sys/fs/bpf/tetragon/* 2>/dev/null || true
  fi

  # 2. Jalankan Tetragon Sensor
  echo "[1/4] Starting Tetragon Sensor..."
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

  # Berikan jeda waktu agar sensor ter-attach ke kernel
  sleep 15

  if ! sudo docker ps | grep -q tetragon-sensor; then
    echo "[ERROR] Tetragon sensor crash saat startup untuk ID $sample_id! Menampilkan log error:"
    sudo docker logs tetragon-sensor || true
    sudo docker rm -f tetragon-sensor 2>/dev/null || true
    return
  fi

  # 3. Jalankan Mock Sinkhole Server (Port 80 & 8080)
  echo "[2/4] Executing Mock Sinkhole & Sample inside sandbox..."
  sudo docker run --name mock-sinkhole -d --net=host \
    python:3-slim python3 -c '
import http.server, socketserver, threading
class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self): self.send_response(200); self.end_headers(); self.wfile.write(b"{}")
    def do_POST(self): self.send_response(200); self.end_headers(); self.wfile.write(b"{}")
def run_port(p):
    try:
        with socketserver.TCPServer(("", p), Handler) as httpd:
            httpd.serve_forever()
    except Exception:
        pass
threading.Thread(target=run_port, args=(8080,), daemon=True).start()
threading.Thread(target=run_port, args=(80,), daemon=True).start()
import time; time.sleep(120)
' 2>/dev/null || true

  # 4. Eksekusi Node.js sampel di isolated container
  sudo docker run --rm --net=host \
    -v "$target_dir:/app" \
    -w /app \
    node:20-slim \
    sh -c "npm install --ignore-scripts=false && (if [ -f index.js ]; then timeout 10s node index.js || true; else timeout 5s node -e 'try { require(\"./\") } catch(e) {}' || true; fi)" || true

  # Bersihkan mock sinkhole
  sudo docker rm -f mock-sinkhole 2>/dev/null || true

  # Jeda flush log eBPF ke disk
  sleep 10

  # 5. Stop Tetragon Sensor
  echo "[3/4] Stopping Tetragon Sensor..."
  sudo docker stop tetragon-sensor 2>/dev/null || true
  sudo docker rm -f tetragon-sensor 2>/dev/null || true

  # 6. Pindahkan log eBPF dan otomatis ekstrak fitur runtime
  echo "[4/4] Saving and extracting runtime log..."
  if [ -f "$LOG_TEMP" ]; then
    mv "$LOG_TEMP" "$ebpf_dest"
    echo "[OK] File eBPF log disimpan di: $ebpf_dest"
    python3 "$ROOT/scripts/extract_runtime_features.py" --input "$ebpf_dest" --sample-id "$sample_id"
  else
    echo "[ERROR] File log temporary tidak ditemukan di $LOG_TEMP!"
  fi
  echo
}

TARGET="${1:-1}"

if [[ "$TARGET" =~ ^[0-9]+-[0-9]+$ ]]; then
  IFS='-' read -r start_id end_id <<< "$TARGET"
  echo "================================================================================"
  echo ">>> [BATCH EXECUTION] Menjalankan sandbox untuk rentang ID: $start_id sampai $end_id"
  echo "================================================================================"
  for (( id=start_id; id<=end_id; id++ )); do
    run_single_sample "$id"
  done
else
  run_single_sample "$TARGET"
fi
