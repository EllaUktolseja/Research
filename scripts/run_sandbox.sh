#!/usr/bin/env bash
# Simpan sebagai: scripts/run_sandbox.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SAMPLES_DIR="$ROOT/samples/source"
EBPF_DIR="$ROOT/results/ebpf"
LOG_DIR="$ROOT/logs"
LOG_TEMP="$LOG_DIR/tetragon-node-control.jsonl"
POLICY_FILE="$ROOT/tetragon/network_egress_host.yaml"

FORCE=0
TARGET=""

for arg in "$@"; do
  case "$arg" in
  --force | -f)
    FORCE=1
    ;;
  --help | -h)
    echo "Usage: sudo ./scripts/run_sandbox.sh [ID | START-END] [--force]"
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

if [ ! -f "$POLICY_FILE" ]; then
  echo "[ERROR] TracingPolicy tidak ditemukan: $POLICY_FILE" >&2
  exit 1
fi

mkdir -p "$EBPF_DIR" "$LOG_DIR"

cleanup_tetragon() {
  echo "[INFO] Menghentikan Tetragon sensor..."
  docker stop tetragon-sensor >/dev/null 2>&1 || true
  docker rm -f tetragon-sensor >/dev/null 2>&1 || true
}
trap cleanup_tetragon EXIT

start_tetragon() {
  docker rm -f tetragon-sensor >/dev/null 2>&1 || true
  if [ -d "/sys/fs/bpf/tetragon" ]; then
    rm -rf /sys/fs/bpf/tetragon/* 2>/dev/null || true
  fi

  rm -f "$LOG_TEMP"
  touch "$LOG_TEMP"

  echo "[INFO] Menjalankan Tetragon sensor untuk batch..."
  docker run --name tetragon-sensor -d \
    --privileged --pid=host --net=host \
    -v "$POLICY_FILE:/etc/tetragon/tetragon.tp.d/network_egress_host.yaml:ro" \
    -v "$LOG_DIR:/var/log/tetragon" \
    -v /sys/kernel/debug:/sys/kernel/debug \
    -v /sys/fs/bpf:/sys/fs/bpf \
    -v /etc/os-release:/etc/os-release:ro \
    quay.io/cilium/tetragon:v1.3.0 \
    tetragon \
    --export-filename /var/log/tetragon/tetragon-node-control.jsonl \
    --tracing-policy-dir /etc/tetragon/tetragon.tp.d/ \
    --disable-kprobe-multi >/dev/null

  sleep 6

  if ! docker ps --format '{{.Names}}' | grep -qx 'tetragon-sensor'; then
    echo "[ERROR] Tetragon sensor gagal berjalan. Log:" >&2
    docker logs tetragon-sensor || true
    exit 1
  fi
  echo "[OK] Tetragon sensor aktif."
}

run_single_sample() {
  local sample_id="$1"
  local ebpf_dest="$EBPF_DIR/${sample_id}.json"
  local cid_dest="$EBPF_DIR/${sample_id}.cid"
  local sample_dir="$SAMPLES_DIR/$sample_id"
  local pkg_dir="$sample_dir/package"

  if [ ! -d "$sample_dir" ]; then
    echo "[SKIP] Folder sampel ID $sample_id tidak ditemukan."
    return 0
  fi

  if [ ! -d "$pkg_dir" ]; then
    pkg_dir="$sample_dir"
  fi

  if [ -s "$ebpf_dest" ] && [ "$FORCE" -eq 0 ]; then
    echo "[SKIP] Log eBPF ID $sample_id sudah ada ($ebpf_dest). Gunakan --force untuk ulang."
    return 0
  fi

  local work_dir="/tmp/sandbox_pkg_${sample_id}_$$"
  local cid_file="/tmp/sandbox_cid_${sample_id}_$$"
  rm -rf "$work_dir" "$cid_file"
  cp -a "$pkg_dir" "$work_dir"

  local offset_before
  offset_before=$(stat -c%s "$LOG_TEMP" 2>/dev/null || echo 0)

  echo "================================================================================"
  echo ">>> [SANDBOX] Sample ID: $sample_id (Source: $pkg_dir)"
  echo "================================================================================"

  # Jalankan npm install (termasuk lifecycle scripts) + entry point main/bin/index.js
  docker run --rm \
    --cidfile "$cid_file" \
    -v "$work_dir:/app" \
    -w /app \
    node:20-slim \
    sh -c '
      timeout 25s npm install --ignore-scripts=false --no-audit --no-fund >/dev/null 2>&1 || true
      timeout 10s node -e "
        const fs = require(\"fs\");
        const path = require(\"path\");
        const { spawnSync } = require(\"child_process\");
        try {
          const pkg = JSON.parse(fs.readFileSync(\"package.json\", \"utf8\"));
          if (typeof pkg.main === \"string\" && pkg.main.trim()) {
            try { require(path.resolve(pkg.main)); } catch (_) {}
          }
          if (typeof pkg.bin === \"string\") {
            spawnSync(\"node\", [path.resolve(pkg.bin)], { timeout: 3000 });
          } else if (pkg.bin && typeof pkg.bin === \"object\") {
            for (const rel of Object.values(pkg.bin)) {
              if (typeof rel === \"string\") {
                spawnSync(\"node\", [path.resolve(rel)], { timeout: 3000 });
              }
            }
          }
        } catch (_) {}
        if (fs.existsSync(\"index.js\")) {
          try { require(path.resolve(\"index.js\")); } catch (_) {}
        }
      " >/dev/null 2>&1 || true
    ' >/dev/null 2>&1 || true

  # Tunggu flush ring buffer eBPF ke file JSONL
  sleep 2

  local offset_after
  offset_after=$(stat -c%s "$LOG_TEMP" 2>/dev/null || echo 0)

  local cid_val=""
  if [ -f "$cid_file" ]; then
    cid_val=$(tr -d '[:space:]' <"$cid_file")
    printf '%s\n' "$cid_val" >"$cid_dest"
  fi

  if [ "$offset_after" -gt "$offset_before" ]; then
    tail -c +"$((offset_before + 1))" "$LOG_TEMP" >"$ebpf_dest"
  else
    : >"$ebpf_dest"
  fi

  chmod 666 "$ebpf_dest" "$cid_dest" 2>/dev/null || true
  rm -rf "$work_dir" "$cid_file"

  echo "[OK] Saved eBPF log: $ebpf_dest (bytes: $((offset_after - offset_before)), cid: ${cid_val:0:12})"
  python3 "$ROOT/scripts/extract_runtime_features.py" \
    --input "$ebpf_dest" \
    --sample-id "$sample_id" || echo "[WARNING] Ekstraksi fitur runtime gagal untuk ID $sample_id"
}

if [ -z "$TARGET" ]; then
  echo "Usage: sudo ./scripts/run_sandbox.sh [ID | START-END] [--force]" >&2
  exit 1
fi

start_tetragon

if [[ "$TARGET" =~ ^[0-9]+-[0-9]+$ ]]; then
  IFS='-' read -r start_id end_id <<<"$TARGET"
  if [ "$start_id" -lt 1 ] || [ "$end_id" -lt "$start_id" ]; then
    echo "[ERROR] Rentang ID tidak valid: $TARGET" >&2
    exit 1
  fi
  for ((id = start_id; id <= end_id; id++)); do
    run_single_sample "$id"
  done
elif [[ "$TARGET" =~ ^[0-9]+$ ]]; then
  run_single_sample "$TARGET"
else
  echo "[ERROR] Format target tidak valid: $TARGET" >&2
  exit 1
fi
