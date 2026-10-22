#!/usr/bin/env bash
set -euo pipefail
app_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$app_dir"
source venv/bin/activate
export PYTHONUNBUFFERED=1
exec > >(tee -a "$app_dir/webmail.log") 2>&1
exec python app.py
