#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "$script_dir/.." && pwd)"
host="${DEPLOY_HOST:-azureuser@llmbank.fs-playground.com}"
app_dir="${DEPLOY_DIR:-/home/azureuser/llm-webmail}"
pane="${DEPLOY_PANE:-%1}"
update_models="${DEPLOY_UPDATE_MODELS:-0}"
ssh_config="${DEPLOY_SSH_CONFIG:-/home/kyuz0/.ssh/config}"
if [[ ! "$app_dir" =~ ^/[A-Za-z0-9._/-]+$ || ! "$pane" =~ ^%[0-9]+$ || ! "$update_models" =~ ^[01]$ ]]; then
    echo "Invalid deployment path or pane ID." >&2
    exit 1
fi
cd "$repo_dir"
if [[ -n "$(git status --porcelain)" ]]; then
    echo "Commit all source changes before deploying." >&2
    exit 1
fi
revision="$(git rev-parse HEAD)"
archive="$(mktemp /tmp/llmwebmail-deploy.XXXXXX.tar.gz)"
trap 'rm -f -- "$archive"' EXIT
git ls-files -z | python3 -c '
import sys
paths = [p for p in sys.stdin.buffer.read().split(b"\0") if p and p != b"config.toml"]
sys.stdout.buffer.write(b"\0".join(paths) + b"\0")
' | tar --null -czf "$archive" --files-from=-
if tar -tzf "$archive" | python3 -c '
import re, sys
names = sys.stdin.read().splitlines()
pattern = r"(^|/)(config\.toml|\.env|\.session_secret|venv|data\.db[^/]*|token_stats\.json)(/|$)"
sys.exit(0 if any(re.search(pattern, name) for name in names) else 1)
'; then
    echo "Refusing to deploy server configuration or runtime state." >&2
    exit 1
fi
ssh_args=(-F "$ssh_config" -o BatchMode=yes)
remote_archive="/tmp/$(basename "$archive")"
scp "${ssh_args[@]}" "$archive" "$host:$remote_archive"
ssh "${ssh_args[@]}" "$host" \
    "bash -s -- '$remote_archive' '$app_dir' '$pane' '$revision' '$update_models'" < "$script_dir/install_remote.sh"
echo "Deployed webmail revision $revision."
