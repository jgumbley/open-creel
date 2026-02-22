OpenClaw Host Monitoring

Sandbox and Local security data lake for openclaw.
The purpose is developing an approach to the control of permission hungry agents.
Provisioning in this repo installs OpenCreel (the monitor), and a sandbox with OpenClaw itself.

Host prerequisites (assumed, not managed by Ansible in this repo):
- Node.js
- npm

Current topology after running `make claw`:

```text
host-machine (ubuntu)
├── host changes from make infra
│   ├── apt/repo
│   │   ├── Zeek signing key installed
│   │   ├── Zeek apt repository added
│   │   └── Zeek installed
│   ├── directories created
│   │   ├── /var/lib/open-creel/data/bronze/{zeek,ebpf,openclaw}
│   │   ├── /var/lib/open-creel/data/{silver,gold}
│   │   └── /etc/open-creel/{zeek,ebpf}
│   ├── systemd units/scripts installed
│   │   ├── open-creel-zeek.service
│   │   ├── open-creel-ebpf-{exec,fileaccess,connect}.service
│   │   ├── open-creel-openclaw-journal.service
│   │   ├── open-creel-claw-bronze-merge.service
│   │   └── open-creel-gondolin-openclaw.service
│   └── services enabled + started + restarted
│       └── active checks passed; proof showed zeek/ebpf/openclaw data being written
└── gondolin-vm
    ├── Gondolin source is vendored at `vendor/gondolin` (pinned revision)
    ├── OpenClaw gateway runs in guest with ingress on `http://127.0.0.1:38080/`
    └── guest telemetry spools to `/var/lib/open-creel/data/spool/gondolin/*` and merges into bronze
```

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
