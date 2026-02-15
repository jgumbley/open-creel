OpenClaw Host Monitoring

Local security data lake for a single Ubuntu machine running OpenClaw.
Provisioning in this repo installs OpenCreel (the monitor), not OpenClaw itself.

Thin slice:
- Bronze:
  - Zeek JSON logs under `/var/lib/open-creel/data/bronze/zeek`.
    - `conn.log`, `dns.log`, `http.log`, `ssl.log`, and `notice.log`.
  - eBPF JSONL logs under `/var/lib/open-creel/data/bronze/ebpf`:
    - `exec.log` from `tracepoint/syscalls/sys_enter_execve*` (OpenClaw-scoped process tree, with argv preview up to 8 elements).
    - `fileaccess.log` from `tracepoint/syscalls/sys_enter_openat`, `sys_enter_unlink*`, and `sys_enter_rename*` (OpenClaw-scoped process tree).
      - Includes an explicit `truncate` boolean derived from `openat` flags.
    - `connect.log` from `tracepoint/syscalls/sys_enter_connect` (IPv4 + IPv6) and inbound socket lifecycle telemetry (`bind`, `listen`, `accept`) host-wide.
  - OpenClaw JSONL streams under `/var/lib/open-creel/data/bronze/openclaw`:
    - `runtime.log` (journald + file-backed session/cron JSONL tails).
    - `audit.log`, `messages.log`, `tool_calls.log`, `approvals.log`, `skills.log`, and `auth.log` from OpenClaw audit-file tails when present.
  - If no scoped OpenClaw process tree is active, `exec.log` and `fileaccess.log` can remain empty by design.
- Silver:
  - OCSF `network_activity` (`class_uid=4001`) from Zeek `conn.log`, enriched by Zeek `dns.log`, `http.log`, `ssl.log`, and eBPF `connect.log` actor attribution.
  - OCSF `process_activity` (`class_uid=1007`) from eBPF `exec.log` with process lineage.
  - OCSF `file_activity` (`class_uid=1001`) from eBPF `fileaccess.log` (`open`, `delete`, and `rename` activity names).
- Gold: OCSF findings (`class_uid=2004`) for DNS coverage drift, unexpected child processes in the agent tree, and sensitive file reads by unexpected processes.
- Run Silver: `make silver` (inspect latest record with `make silver-show-latest`).
- Run Gold: `make gold` (inspect latest record with `make gold-show-latest`).
