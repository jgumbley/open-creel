# NEXT STEP: `make claw` entrypoint

## Goal
From a fresh `open-creel` checkout, the operator should run:

```bash
make claw
```

After sudo/become prompts (Ansible), the system should end with:
- Gondolin available from vendored source.
- A running OpenClaw Gateway inside Gondolin, or a ready-to-configure OpenClaw state.
- Bronze telemetry flowing to host-visible paths, with Silver/Gold runnable from existing targets (ok if need to update folder locations)

## Scope
- Use `open-creel` as the single orchestration repo and entrypoint.
- Vendor `gondolin` into this repo at `vendor/gondolin`.
- have openclaw going inside a provisioned microvm
- use ansible, nicely factored i.e. perhaps a claw role etc

## Proposed repository shape
- `vendor/gondolin/` (vendored checkout, pinned revision).
- New Gondolin/OpenClaw automation task file
  - `gondolin_prereq.yml`
  - `gondolin_openclaw.yml`
- New helper scripts
  - Gondolin launcher script.
  - Guest telemetry spool-to-bronze automation of guest 

## Runtime model
2.  starts and launches Gondolin.
3. OpenClaw runs inside guest with host-mounted state/workspace.
4. Guest telemetry writes to host-mounted spool paths.
5. Host merger appends normalized records into canonical bronze files:
   - `/var/lib/open-creel/data/bronze/openclaw/*.log`
   - `/var/lib/open-creel/data/bronze/ebpf/*.log` (guest-attributed stream)

## `make` interface changes
- Add `make claw` target:
  - Declares baseline dependency at the Make layer (`make claw` invokes/depends on `make infra` first).
  - Runs the Ansible path that provisions/updates Gondolin + OpenClaw-in-Gondolin units.
  - Ensures services are enabled and started.
  - Prints health/proof summary.
- Keep `make infra` standalone for baseline sensor provisioning (operator can run it independently).
- Keep dependency wiring in Makefile, not as an Ansible playbook-to-playbook dependency.
- Keep `make bronze|silver|gold` unchanged for later development (STAY IN YOUR LANE)

## Acceptance criteria
1. Fresh clone to running system:
   - `make claw` completes with no manual file edits.
   - `make claw` succeeds from clean state by running baseline infra before claw-specific orchestration.
2. OpenClaw in Gondolin:
   - OpenClaw gateway process is running in guest and reachable via configured ingress.
3. Bronze proof:
   - `make bronze` shows fresh runtime/audit/tool/auth lines.
   - Host network telemetry and guest-attributed process/file telemetry both appear.
