# Continuity Handoff

## Scope
User asked to run `make openclaw` and, if npm failed, change the npm repair step to:
`curl -qL https://npmjs.org/install.sh | sh`.

## What Was Changed
- Updated `provision/roles/openclaw/tasks/main.yml`:
  - `Self-update npm inside Gondolin guest` now runs:
    - `curl -qL https://npmjs.org/install.sh | sh`
  - Added `Ensure git is present inside Gondolin guest`:
    - `ansible.builtin.package: name=git state=present`
- Existing spool-based OpenClaw install/runtime structure remains:
  - `/spool/openclaw`, `/spool/openclaw/npm-global`, `/spool/openclaw/npm-cache`, `/spool/openclaw/home`
  - install command remains:
    - `npm install -g --prefix /spool/openclaw/npm-global openclaw@latest`

## Current Repository State
- Modified files:
  - `provision/roles/openclaw/tasks/main.yml`
  - `continuity.md`
- `git status --short` at handoff:
  - `M provision/roles/openclaw/tasks/main.yml`
  - `?? continuity.md`

## Latest Execution Result
Latest clean run used:
- `make openclaw`

Result:
- `Self-update npm inside Gondolin guest` succeeded (`changed`).
- `Ensure git is present inside Gondolin guest` succeeded (`ok`).
- `Install OpenClaw CLI into spool-backed npm prefix inside Gondolin guest` failed with `rc=1`.

Concrete failure details from Ansible/npm:
- Run window: start `2026-02-22 18:46:05`, end `2026-02-22 19:17:22`.
- npm failure path:
  - `/spool/openclaw/npm-global/lib/node_modules/openclaw/node_modules/@discordjs/opus`
- `node-pre-gyp` prebuilt binary fetch returned 404 for:
  - `opus-v0.10.0-node-v137-napi-v3-linux-x64-musl-1.2.5.tar.gz`
- Fallback source build via `node-gyp` then failed with:
  - `Error: not found: make`
- Full log:
  - `/spool/openclaw/npm-cache/_logs/2026-02-22T18_46_05_497Z-debug-0.log`

## What Is Now Confirmed
- Prior `spawn git ENOENT` blocker is resolved by installing `git`.
- `openclaw@latest` currently pulls very large dependency graph (includes `node-llama-cpp`).
- Current hard failure is toolchain-related for native module fallback build (`make` missing).

## Recommended Next Steps For Next Agent
1. Add guest build prerequisites before OpenClaw npm install (likely via `ansible.builtin.package`):
   - at minimum: `make` (required by observed failure)
   - likely also compiler toolchain packages if `node-gyp` continues (e.g. `g++`, libc dev headers)
2. Re-run:
   - `make openclaw`
3. If native build continues to fail after toolchain install:
   - inspect whether Node `v24.13.0` + musl guest is unsupported for `@discordjs/opus` prebuild,
   - then consider pinning Node/OpenClaw versions compatible with available prebuilds or guaranteed source-build support.

## Notes
- During investigation, pane reuse caused overlapping scrollback; final result above comes from a clean non-pane `make openclaw` run.
- OpenClaw install can take a long time due dependency size; long silent periods were observed while npm downloaded artifacts.
