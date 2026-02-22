#!/usr/bin/env bash
set -euo pipefail

open_creel_repo="${OPEN_CREEL_REPO:?OPEN_CREEL_REPO must be set}"
gondolin_host_dir="${open_creel_repo}/vendor/gondolin/host"

spool_root="/var/lib/open-creel/data/spool/gondolin"
mkdir -p "${spool_root}/openclaw" "${spool_root}/ebpf"

gateway_listen_host="${OPENCLAW_GATEWAY_HOST:-127.0.0.1}"
gateway_listen_port="${OPENCLAW_GATEWAY_PORT:-38080}"

read -r -d '' guest_bootstrap <<'GUEST_BOOTSTRAP' || true
set -euo pipefail

mkdir -p /spool/openclaw /spool/ebpf /tmp/openclaw-gateway
for name in runtime audit messages tool_calls approvals skills auth; do
  touch "/spool/openclaw/${name}.log"
done
for name in exec fileaccess connect; do
  touch "/spool/ebpf/${name}.log"
done

cat > /tmp/openclaw-gateway/run.sh <<'GATEWAY_SCRIPT'
#!/bin/sh
set -eu

mkdir -p /tmp/openclaw-gateway/www
printf '{"status":"ok","service":"openclaw-gateway"}\n' > /tmp/openclaw-gateway/www/index.html
exec python -m http.server 18080 --bind 127.0.0.1 --directory /tmp/openclaw-gateway/www
GATEWAY_SCRIPT
chmod +x /tmp/openclaw-gateway/run.sh

echo "/ :18080" > /etc/gondolin/listeners
/tmp/openclaw-gateway/run.sh &
gateway_pid="$!"

(
  while :; do
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '{"source":"gondolin-guest","ts":"%s","event":"runtime","service":"openclaw-gateway"}\n' "${ts}" >> /spool/openclaw/runtime.log
    printf '{"source":"gondolin-guest","ts":"%s","event":"audit","action":"gateway_heartbeat"}\n' "${ts}" >> /spool/openclaw/audit.log
    printf '{"source":"gondolin-guest","ts":"%s","event":"message","content":"gateway alive"}\n' "${ts}" >> /spool/openclaw/messages.log
    printf '{"source":"gondolin-guest","ts":"%s","event":"tool_call","tool":"health_check","status":"ok"}\n' "${ts}" >> /spool/openclaw/tool_calls.log
    printf '{"source":"gondolin-guest","ts":"%s","event":"approval","status":"granted"}\n' "${ts}" >> /spool/openclaw/approvals.log
    printf '{"source":"gondolin-guest","ts":"%s","event":"skill","name":"baseline"}\n' "${ts}" >> /spool/openclaw/skills.log
    printf '{"source":"gondolin-guest","ts":"%s","event":"auth","status":"paired"}\n' "${ts}" >> /spool/openclaw/auth.log
    sleep 2
  done
) &
openclaw_stream_pid="$!"

(
  while :; do
    ts_ns="$(( $(date +%s) * 1000000000 ))"
    printf '{"source":"gondolin-guest","time_ns":%s,"pid":1200,"ppid":1,"uid":0,"comm":"openclaw-worker","binary":"/usr/bin/openclaw-worker","argv":["openclaw-worker","--run"],"cwd":"/workspace"}\n' "${ts_ns}" >> /spool/ebpf/exec.log
    printf '{"source":"gondolin-guest","time_ns":%s,"pid":1200,"ppid":1,"uid":0,"comm":"openclaw-worker","operation":"open","path":"/workspace/task.txt","flags":0,"read":true,"write":false,"create":false,"truncate":false}\n' "${ts_ns}" >> /spool/ebpf/fileaccess.log
    printf '{"source":"gondolin-guest","time_ns":%s,"pid":1200,"ppid":1,"uid":0,"comm":"openclaw-gateway","dst_ip":"127.0.0.1","dst_port":18080}\n' "${ts_ns}" >> /spool/ebpf/connect.log
    sleep 3
  done
) &
ebpf_stream_pid="$!"

cleanup() {
  kill "${openclaw_stream_pid}" "${ebpf_stream_pid}" "${gateway_pid}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

wait "${gateway_pid}"
GUEST_BOOTSTRAP

cd "${gondolin_host_dir}"
exec npm run gondolin -- bash \
  --listen "${gateway_listen_host}:${gateway_listen_port}" \
  --mount-hostfs "${spool_root}:/spool" \
  --mount-hostfs "${open_creel_repo}:/workspace" \
  -- /bin/sh -lc "${guest_bootstrap}"
