#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 2 ]; then
  echo "Usage: pane.sh <pane-label> <command ...>" >&2
  exit 1
fi

pane_label="$1"
shift

cmd_display="$(printf ' %q' "$@")"
cmd_display="${cmd_display:1}"

if ! command -v tmux >/dev/null 2>&1; then
  echo "tmux is required to start an agent pane." >&2
  exit 1
fi

if [ -z "${TMUX:-}" ]; then
  echo "agent panes must be started from inside an existing tmux session." >&2
  exit 1
fi

repo_root="$(pwd)"
pane_height="${AGENT_PANE_PERCENT:-45}"
current_height="$(tmux display-message -p '#{pane_height}' 2>/dev/null || true)"
pane_lines="$pane_height"
if [ -n "$current_height" ] && [ "$current_height" -gt 0 ] 2>/dev/null; then
  pane_lines=$(( current_height * pane_height / 100 ))
  [ "$pane_lines" -lt 3 ] && pane_lines=3
fi

session_id="$(tmux display-message -p '#{session_id}')"
existing_pane="$(
  tmux list-panes -t "$session_id" -F '#{pane_id}::#{pane_title}' |
    awk -F '::' -v label="$pane_label" '$2 == label { print $1; exit }'
)"

if [ -n "$existing_pane" ]; then
  cat <<EOF
Pane "$existing_pane" for "$pane_label" already exists in this session.
No new pane was created.
To rerun in that pane: tmux send-keys -t $existing_pane C-m
To capture output: tmux capture-pane -pt $existing_pane
Reminder: close used panes when finished (Ctrl-b x or tmux kill-pane -t $existing_pane).
EOF
  exit 0
fi

runner_script="$(mktemp)"
cat > "$runner_script" <<'RUNNER_EOF'
#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 2 ]; then
  echo "Usage: tmux-agent-pane <pane-label> <command ...>" >&2
  exit 1
fi

pane_label="$1"
shift

cmd_display="$(printf ' %q' "$@")"
cmd_display="${cmd_display:1}"

printf '\033]2;%s\007' "$pane_label"

cat <<EOF
[agent:${pane_label}] Running ${cmd_display}

If you are prompted for sudo/BECOME credentials, type them directly in this pane.
Secrets typed here are not echoed, so they will not appear in captured output.

When the command finishes, reuse this same pane to rerun it:
- press Enter in this pane, or
- from the main terminal run: tmux send-keys -t "$TMUX_PANE" C-m
Do not create a new pane unless you want another concurrent run.
The main terminal/agent can read progress via tmux capture-pane.

EOF

status=0
while :; do
  if "$@"; then
    status=0
  else
    status=$?
  fi

  cat <<EOF

[agent:${pane_label}] Command exited with status ${status}.
Reuse this same pane to run again: press Enter.
From the main terminal you can also run: tmux send-keys -t "$TMUX_PANE" C-m
Reminder: close used panes when finished.
Close this pane with Ctrl-b x, or from the main terminal: tmux kill-pane -t "$TMUX_PANE"

EOF

  if [ ! -t 0 ]; then
    break
  fi
  read -r _ || break
done

exit "$status"
RUNNER_EOF

pane_id="$(tmux split-window -b -v -l "$pane_lines" -c "$repo_root" -P -F '#{pane_id}' \
  bash "$runner_script" "$pane_label" "$@")"
rm -f "$runner_script"

cat <<EOF
Started tmux pane "$pane_id" for "$pane_label".
Command: $cmd_display
Watch the pane above for prompts. Type any sudo/BECOME passwords there, not here.
To capture its output later: tmux capture-pane -pt $pane_id
To rerun in the same pane (no new pane needed): tmux send-keys -t $pane_id C-m
The pane stays open after each run; press Enter in that pane to rerun, or close it to stop.
Reminder: close used panes when finished (Ctrl-b x or tmux kill-pane -t $pane_id).
EOF
