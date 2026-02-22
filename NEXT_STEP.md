# NEXT STEP: `make claw` entrypoint

## Status handoff (2026-02-22)

### Implemented so far
- `make claw` now uses a single Ansible call: `ansible-playbook claw.yml -c local -K ...`.
- `claw.yml` was added to orchestrate:
  - `creel.yml`
  - `gondolin_prereq.yml`
  - `gondolin_openclaw.yml`
- New claw automation assets were added:
  - `gondolin_prereq.yml`
  - `gondolin_openclaw.yml`
  - `scripts/claw_gondolin_launcher.sh`
  - `scripts/claw_bronze_merge.sh`
- `make claw-check` passes syntax check for `claw.yml`.
- `make test` passes.

### Latest runtime result
- Command run: `./pane.sh claw make claw`
- Result: failed during `gondolin_prereq.yml`.
- Failing task: `Install Gondolin host runtime dependencies`
- Failure text:
  - `apt-get ... install 'npm=9.2.0~ds1-2' failed`
  - `E: Unable to correct problems, you have held broken packages.`
  - `npm` dependency chain had multiple unmet `node-*` package requirements.

### Acceptance criteria status
1. Fresh clone to running system:
   - `make claw` end-to-end: `FAILED` (blocked by apt/npm package state).
   - baseline infra before claw-specific orchestration: `PASS` (infra ran first inside `claw.yml`).
2. OpenClaw in Gondolin:
   - `NOT REACHED` (play failed before Gondolin/OpenClaw service startup).
3. Bronze proof (guest-attributed streams):
   - `NOT REACHED` (guest spool/merge verification is in `gondolin_openclaw.yml`, not executed yet).

### Next agent actions
1. Fix prerequisite package installation in `gondolin_prereq.yml`:
   - remove or replace `apt` install of `npm` with a provisioning path that works on this host,
   - keep `make claw` as single-call orchestration.
2. Re-run full flow via pane:
   - `./pane.sh claw make claw`
3. After success, verify:
   - `systemctl is-active open-creel-claw-bronze-merge.service`
   - `systemctl is-active open-creel-gondolin-openclaw.service`
   - `curl -fsS http://127.0.0.1:38080/`
   - `make bronze` shows guest-tagged lines (`"source":"gondolin-guest"`) in openclaw and ebpf logs.
4. If needed, update README/NEXT_STEP acceptance notes after end-to-end pass.

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
