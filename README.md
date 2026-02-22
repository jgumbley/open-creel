OpenClaw Host Monitoring

Sandbox and local security data lake for OpenClaw.
The purpose is developing an approach to controlling permission-hungry agents.

Host prerequisites (assumed, not managed by Ansible in this repo):
- Node.js
- npm

Provisioning layers:
- Layer 1 (`make sandbox`): Gondolin VM lifecycle and ingress proof.
- Layer 2 (`make openclaw`): OpenClaw runtime and gateway inside Gondolin.
- Layer 3 (`make telemetry`): Zeek, eBPF, OpenClaw journal collector, and Gondolin spool-to-bronze merge services.
- Layer 4 (`make silver`, `make gold`): Python bronze -> silver/gold transforms.

Playbooks:
- `provision/sandbox.yml`
- `provision/openclaw.yml`
- `provision/telemetry.yml`
- Legacy wrappers: `provision/claw.yml` and `provision/creel.yml`

Current topology after running `make provision`:

```text
host-machine (ubuntu)
├── layer 1 sandbox
│   ├── Gondolin source in `vendor/gondolin`
│   └── open-creel-gondolin-sandbox.service
├── layer 2 openclaw
│   └── open-creel-gondolin-openclaw.service
└── layer 3 telemetry
    ├── open-creel-zeek.service
    ├── open-creel-ebpf-{exec,fileaccess,connect}.service
    ├── open-creel-openclaw-journal.service
    └── open-creel-claw-merge-*.service (gondolin spool -> bronze)
```

Thin slice:
- Bronze:
  - Zeek JSON logs under `/var/lib/open-creel/data/bronze/zeek`.
    - `conn.log`, `dns.log`, `http.log`, `ssl.log`, `notice.log`.
  - eBPF JSONL logs under `/var/lib/open-creel/data/bronze/ebpf`.
    - `exec.log` from `tracepoint/syscalls/sys_enter_execve*`.
    - `fileaccess.log` from `sys_enter_openat`, `sys_enter_unlink*`, `sys_enter_rename*`.
    - `connect.log` from `sys_enter_connect` plus inbound lifecycle telemetry.
  - OpenClaw JSONL streams under `/var/lib/open-creel/data/bronze/openclaw`.
    - `runtime.log`, `audit.log`, `messages.log`, `tool_calls.log`, `approvals.log`, `skills.log`, `auth.log`.
- Silver:
  - OCSF `network_activity` (`class_uid=4001`) from Zeek `conn.log`, enriched by Zeek `dns.log`, `http.log`, `ssl.log`, and eBPF `connect.log` actor attribution.
  - OCSF `process_activity` (`class_uid=1007`) from eBPF `exec.log` with process lineage.
  - OCSF `file_activity` (`class_uid=1001`) from eBPF `fileaccess.log` (`open`, `delete`, `rename`).
- Gold:
  - OCSF findings (`class_uid=2004`) for DNS coverage drift, unexpected child processes in the agent tree, and sensitive file reads by unexpected processes.

Run transforms:
- `make silver` (inspect latest with `make silver-show-latest`)
- `make gold` (inspect latest with `make gold-show-latest`)
