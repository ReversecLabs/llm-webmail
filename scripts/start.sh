#!/usr/bin/env bash
set -euo pipefail
app_dir="${1:-/home/azureuser/llm-webmail}"
pane="${2:-%1}"
mode="${3:-start}"
if [[ ! "$app_dir" =~ ^/[A-Za-z0-9._/-]+$ || ! "$pane" =~ ^%[0-9]+$ ]]; then
    echo "Invalid application path or pane ID." >&2
    exit 1
fi
if [[ "$mode" != start && "$mode" != --stop-only ]]; then
    echo "Expected start or --stop-only." >&2
    exit 1
fi
actual_dir="$(tmux display-message -p -t "$pane" '#{pane_current_path}')"
if [[ "$actual_dir" != "$app_dir" ]]; then
    echo "Refusing to touch a pane outside the webmail directory." >&2
    exit 1
fi
command="$(tmux display-message -p -t "$pane" '#{pane_current_command}')"
case "$command" in
    python|python3|python3.*) tmux send-keys -t "$pane" C-c ;;
    bash|zsh|sh) ;;
    *) echo "Unexpected command in webmail pane; refusing to interrupt it." >&2; exit 1 ;;
esac
stopped=false
for ((attempt=0; attempt<60; attempt++)); do
    command="$(tmux display-message -p -t "$pane" '#{pane_current_command}')"
    if [[ "$command" =~ ^(bash|zsh|sh)$ ]] && ! curl --max-time 2 -fsS -o /dev/null http://127.0.0.1:5001/ 2>/dev/null; then
        stopped=true
        break
    fi
    sleep 1
done
if [[ "$stopped" != true ]]; then
    echo "Webmail did not stop; no pane or session will be killed." >&2
    exit 1
fi
if [[ "$mode" == --stop-only ]]; then
    exit 0
fi
test -x "$app_dir/venv/bin/python"
test -x "$app_dir/scripts/run_app.sh"
tmux send-keys -t "$pane" -l "$app_dir/scripts/run_app.sh"
tmux send-keys -t "$pane" Enter
for ((attempt=0; attempt<180; attempt++)); do
    if curl --max-time 2 -fsS -o /dev/null http://127.0.0.1:5001/ 2>/dev/null; then
        echo "Webmail is healthy on port 5001 (pane $pane)."
        exit 0
    fi
    sleep 1
done
echo "Webmail did not become healthy; inspect $app_dir/webmail.log." >&2
exit 1
