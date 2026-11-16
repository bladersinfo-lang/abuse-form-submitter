#!/usr/bin/env sh
# One-command start on macOS/Linux: creates .venv on first run, installs deps and Chromium, starts the app.
set -e
cd "$(dirname "$0")"
if [ ! -x .venv/bin/python ]; then
  python3 -m venv .venv
  .venv/bin/python -m pip install -q -r requirements.txt
  .venv/bin/python -m playwright install chromium
fi
exec .venv/bin/python app.py
