#!/usr/bin/env bash
set -euo pipefail

spool_root="/var/lib/open-creel/data/spool/gondolin"
bronze_root="/var/lib/open-creel/data/bronze"

openclaw_streams=(
  runtime
  audit
  messages
  tool_calls
  approvals
  skills
  auth
)

ebpf_streams=(
  exec
  fileaccess
  connect
)

mkdir -p "${spool_root}/openclaw" "${spool_root}/ebpf"
mkdir -p "${bronze_root}/openclaw" "${bronze_root}/ebpf"

for name in "${openclaw_streams[@]}"; do
  touch "${spool_root}/openclaw/${name}.log"
  touch "${bronze_root}/openclaw/${name}.log"
done

for name in "${ebpf_streams[@]}"; do
  touch "${spool_root}/ebpf/${name}.log"
  touch "${bronze_root}/ebpf/${name}.log"
done

pids=()

start_tail() {
  local src="$1"
  local dst="$2"
  tail -n 0 -F "$src" >> "$dst" &
  pids+=("$!")
}

for name in "${openclaw_streams[@]}"; do
  start_tail "${spool_root}/openclaw/${name}.log" "${bronze_root}/openclaw/${name}.log"
done

for name in "${ebpf_streams[@]}"; do
  start_tail "${spool_root}/ebpf/${name}.log" "${bronze_root}/ebpf/${name}.log"
done

cleanup() {
  local pid
  for pid in "${pids[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait || true
}

trap cleanup EXIT INT TERM

wait
