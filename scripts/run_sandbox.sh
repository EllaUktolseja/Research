#!/usr/bin/env bash
# Simpan sebagai: scripts/run_sandbox.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SAMPLES_DIR="$ROOT/samples/source"
EBPF_DIR="$ROOT/results/ebpf"
LOG_DIR="$ROOT/logs"
LOG_TEMP="$LOG_DIR/tetragon-node-control.jsonl"
POLICY_FILE="$ROOT/tetragon/network_egress_host.yaml"
HARNESS_JS="/tmp/tetragon_harness_runner_$$.js"

FORCE=0
TARGET=""

for arg in "$@"; do
  case "$arg" in
    --force|-f)
      FORCE=1
      ;;
    --help|-h)
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

cat <<'EOF' > "$HARNESS_JS"
const fs = require("fs");
const path = require("path");
const { pathToFileURL } = require("url");
const { spawnSync } = require("child_process");

const LIFECYCLE_KEYS = [
  "preinstall",
  "install",
  "postinstall",
  "prepare",
  "prepublish",
  "prepublishOnly",
  "prepack",
];

async function tryImportOrRequire(relTarget) {
  if (typeof relTarget !== "string" || !relTarget.trim()) return;
  const resolved = path.resolve("/app", relTarget.trim());
  if (!resolved.startsWith("/app")) return;

  try {
    require(resolved);
    return;
  } catch (err) {
    if (err && err.code === "ERR_REQUIRE_ESM") {
      try {
        await import(pathToFileURL(resolved).href);
      } catch (_) {}
    }
  }
}

async function main() {
  let pkg = {};
  try {
    pkg = JSON.parse(fs.readFileSync("/app/package.json", "utf8"));
  } catch (_) {}

  // 1. Jalankan lifecycle scripts milik paket root
  const scripts = pkg && typeof pkg.scripts === "object" ? pkg.scripts : {};
  for (const key of LIFECYCLE_KEYS) {
    const cmd = scripts[key];
    if (typeof cmd === "string" && cmd.trim()) {
      try {
        spawnSync("/bin/sh", ["-c", cmd], {
          cwd: "/app",
          timeout: 4000,
          stdio: "ignore",
        });
      } catch (_) {}
    }
  }

  // 2. Import / require entry points paket
  if (typeof pkg.main === "string") {
    await tryImportOrRequire(pkg.main);
  }
  if (typeof pkg.module === "string") {
    await tryImportOrRequire(pkg.module);
  }
  if (fs.existsSync("/app/index.js")) {
    await tryImportOrRequire("index.js");
  }

  // 3. Jalankan bin scripts jika ada
  if (typeof pkg.bin === "string") {
    const binPath = path.resolve("/app", pkg.bin);
    if (binPath.startsWith("/app") && fs.existsSync(binPath)) {
      try {
        spawnSync("node", [binPath], { cwd: "/app", timeout: 2500, stdio: "ignore" });
      } catch (_) {}
    }
  } else if (pkg.bin && typeof pkg.bin === "object") {
    for (const rel of Object.values(pkg.bin)) {
      if (typeof rel === "string") {
        const binPath = path.resolve("/app", rel);
        if (binPath.startsWith("/app") && fs.existsSync(binPath)) {
          try {
            spawnSync("node", [binPath], { cwd: "/app", timeout: 2500, stdio: "ignore" });
          } catch (_) {}
        }
      }
    }
  }

  // Jeda 2 detik agar callback async (DNS/HTTP/FS) selesai tereksekusi
  setTimeout(() => process.exit(0), 2000);
}

main().catch(() => process.exit(0));
EOF

cleanup_all() {
  echo "[INFO] Menghentikan Tetragon sensor & membersihkan file sementara..."
  docker stop tetragon-sensor >/dev/null 2>&1 || true
  docker rm -f tetragon-sensor >/dev/null 2>&1 || true
  rm -f "$HARNESS_JS"
}
trap cleanup_all EXIT

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
  local container_name="sandbox_eval_${sample_id}_$$"
  rm -rf "$work_dir" "$cid_file"
  docker rm -f "$container_name" >/dev/null 2>&1 || true
  cp -a "$pkg_dir" "$work_dir"

  echo "================================================================================"
  echo ">>> [SANDBOX] Sample ID: $sample_id (Source: $pkg_dir)"
  echo "================================================================================"

  # Start container sandbox
  docker run -d \
    --name "$container_name" \
    --cidfile "$cid_file" \
    -v "$work_dir:/app" \
    -v "$HARNESS_JS:/_harness_runner.js:ro" \
    -w /app \
    node:20-slim \
    sleep 120 >/dev/null

  local cid_val=""
  if [ -f "$cid_file" ]; then
    cid_val=$(tr -d '[:space:]' < "$cid_file")
    printf '%s\n' "$cid_val" > "$cid_dest"
  fi

  # PHASE 1 (Untraced): Hydrate dependencies tanpa mengeksekusi lifecycle scripts
  docker exec "$container_name" \
    timeout 25s npm install --ignore-scripts --no-audit --no-fund >/dev/null 2>&1 || true
  sleep 1

  # Catat offset log tepat sebelum kode/lifecycle paket dieksekusi
  local offset_before
  offset_before=$(stat -c%s "$LOG_TEMP" 2>/dev/null || echo 0)

  # PHASE 2 (Traced): Jalankan lifecycle scripts + entry point paket
  docker exec "$container_name" \
    timeout 15s node /_harness_runner.js >/dev/null 2>&1 || true

  # Tunggu flush ring buffer eBPF ke disk
  sleep 1

  local offset_after
  offset_after=$(stat -c%s "$LOG_TEMP" 2>/dev/null || echo 0)

  docker rm -f "$container_name" >/dev/null 2>&1 || true

  if [ "$offset_after" -gt "$offset_before" ]; then
    tail -c +"$((offset_before + 1))" "$LOG_TEMP" > "$ebpf_dest"
  else
    : > "$ebpf_dest"
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
  IFS='-' read -r start_id end_id <<< "$TARGET"
  if [ "$start_id" -lt 1 ] || [ "$end_id" -lt "$start_id" ]; then
    echo "[ERROR] Rentang ID tidak valid: $TARGET" >&2
    exit 1
  fi
  for (( id=start_id; id<=end_id; id++ )); do
    run_single_sample "$id"
  done
elif [[ "$TARGET" =~ ^[0-9]+$ ]]; then
  run_single_sample "$TARGET"
else
  echo "[ERROR] Format target tidak valid: $TARGET" >&2
  exit 1
fi
