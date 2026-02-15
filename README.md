OpenClaw Host Monitoring

Local security data lake for a single Ubuntu machine running OpenClaw.
Provisioning in this repo installs OpenCreel (the monitor), not OpenClaw itself.

Thin slice:
- Bronze:
  - Zeek JSON logs under `/var/lib/open-creel/data/bronze/zeek`.
  - eBPF JSONL logs under `/var/lib/open-creel/data/bronze/ebpf`, scoped to `openclaw` seed process names and their descendants:
    - `exec.log` from `tracepoint/sched/sched_process_exec`
    - `fileaccess.log` from `tracepoint/syscalls/sys_enter_openat`
    - `connect.log` from `tracepoint/syscalls/sys_enter_connect`
  - If no scoped OpenClaw process tree is active, eBPF logs can remain empty by design.
- Silver:
  - OCSF `network_activity` (`class_uid=4001`) from Zeek `conn.log`, enriched by Zeek `dns.log` and eBPF `connect.log` actor attribution.
  - OCSF `process_activity` (`class_uid=1007`) from eBPF `exec.log` with process lineage.
  - OCSF `file_activity` (`class_uid=1001`) from eBPF `fileaccess.log`.
- Gold: OCSF findings (`class_uid=2004`) for DNS coverage drift, unexpected child processes in the agent tree, and sensitive file reads by unexpected processes.
- Run Silver: `make silver` (inspect latest record with `make silver-proof`).
- Run Gold: `make gold` (inspect latest record with `make gold-proof`).
