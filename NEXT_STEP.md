# NEXT STEP: `make claw` entrypoint

## Status handoff (2026-02-22)

### Implemented so far
- `make claw` now uses a single Ansible call: `ansible-playbook provision/claw.yml -c local -K ...`.
- Provisioning assets are now grouped under `provision/`:
  - `provision/creel.yml`
  - `provision/claw.yml`
  - `provision/roles/collectors/tasks/main.yml`
  - `provision/roles/claw/tasks/main.yml`
  - `provision/scripts/claw_gondolin_launcher.sh`
  - `provision/scripts/claw_bronze_merge.sh`
- `make lint` now performs the Ansible syntax check for `provision/claw.yml` and Python linting.
- `make test` passes.

### Latest runtime result
- No evidence yet that `./pane.sh claw make claw` was re-run after the prerequisite fix to validate the full flow end-to-end.
- Current state: end-to-end validation is still pending.

### Acceptance criteria status
1. Fresh clone to running system:
   - `make claw` end-to-end: `PENDING VALIDATION` (re-run evidence not yet captured).
   - baseline infra before claw-specific orchestration: `IMPLEMENTED` (wired inside `provision/claw.yml`; requires final run confirmation).
2. OpenClaw in Gondolin:
   - `PENDING VALIDATION` (no fresh end-to-end proof captured yet).
3. Bronze proof (guest-attributed streams):
   - `PENDING VALIDATION` (no fresh end-to-end proof captured yet).

### Next agent actions
1. Re-run full flow via pane and capture output:
   - `./pane.sh claw make claw`
2. After success, verify:
   - `systemctl is-active open-creel-claw-bronze-merge.service`
   - `systemctl is-active open-creel-gondolin-openclaw.service`
   - `curl -fsS http://127.0.0.1:38080/`
   - `make bronze` shows guest-tagged lines (`"source":"gondolin-guest"`) in openclaw and ebpf logs.
3. Update README/NEXT_STEP acceptance notes with concrete pass/fail evidence from the new run.

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
- `provision/`
  - `provision/creel.yml` and `provision/claw.yml` playbooks.
  - `provision/roles/` with `collectors` and `claw`.
  - `provision/scripts/` with Gondolin launcher and bronze merge helpers.

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
