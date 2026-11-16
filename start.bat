@echo off
rem One-command start on Windows: creates .venv on first run, installs deps and Chromium, starts the app.
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (
  python -m venv .venv || exit /b 1
  .venv\Scripts\python -m pip install -q -r requirements.txt || exit /b 1
  .venv\Scripts\python -m playwright install chromium || exit /b 1
)
.venv\Scripts\python app.py
