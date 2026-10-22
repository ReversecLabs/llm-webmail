#!/usr/bin/env bash
set -euo pipefail
archive="${1:?archive is required}"
app_dir="${2:?app directory is required}"
pane="${3:?pane is required}"
revision="${4:?revision is required}"
update_models="${5:-0}"
if [[ ! "$update_models" =~ ^[01]$ ]]; then
    echo "Invalid model-update flag." >&2
    exit 1
fi
if [[ ! "$archive" =~ ^/tmp/llmwebmail-deploy\.[A-Za-z0-9]+\.tar\.gz$ || ! "$app_dir" =~ ^/[A-Za-z0-9._/-]+$ || "$app_dir" == / || ! "$pane" =~ ^%[0-9]+$ || ! "$revision" =~ ^[a-f0-9]{40}$ ]]; then
    echo "Invalid deployment arguments." >&2
    exit 1
fi
test -f "$app_dir/config.toml"
test -f "$app_dir/.env"
test -x "$app_dir/venv/bin/python"
stage="$(mktemp -d /tmp/llmwebmail-release.XXXXXX)"
trap 'rm -rf -- "$stage"; rm -f -- "$archive"' EXIT
tar -xzf "$archive" -C "$stage"
test -f "$stage/app.py"
test -x "$stage/scripts/start.sh"
if ! cmp -s "$stage/requirements.txt" "$app_dir/requirements.txt"; then
    echo "Dependencies differ; review and install that change before deployment." >&2
    exit 1
fi
"$stage/scripts/start.sh" "$app_dir" "$pane" --stop-only
umask 077
backup_root="$(dirname "$app_dir")/llmwebmail-backups"
mkdir -p "$backup_root"
chmod 700 "$backup_root"
backup="$backup_root/llmwebmail-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
tar -czf "$backup" --exclude='./venv' --exclude='./.git' --exclude='./__pycache__' -C "$app_dir" .
echo "Source and persistent-state backup: $backup"
rsync -a \
    --exclude='.git/' --exclude='config.toml' --exclude='.env' \
    --exclude='.session_secret' --exclude='venv/' --exclude='data.db*' \
    --exclude='token_stats.json' --exclude='webmail.log' \
    "$stage/" "$app_dir/"
printf '%s\n' "$revision" > "$app_dir/.deployed-revision"
if [[ "$update_models" == 1 ]]; then
    "$app_dir/venv/bin/python" "$app_dir/scripts/update_models.py"
fi
"$app_dir/scripts/start.sh" "$app_dir" "$pane"
