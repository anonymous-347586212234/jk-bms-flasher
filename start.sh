#!/usr/bin/env sh
set -eu

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$PROJECT_DIR"

if [ ! -x ".venv/bin/python" ] && [ ! -x ".venv/Scripts/python.exe" ]; then
    if command -v python3.14 >/dev/null 2>&1; then
        python3.14 -m venv .venv
    elif command -v python3 >/dev/null 2>&1; then
        python3 -m venv .venv
    else
        echo "Python 3.14 is required but was not found." >&2
        exit 1
    fi
fi

if [ -x ".venv/bin/python" ]; then
    VENV_PYTHON=".venv/bin/python"
else
    VENV_PYTHON=".venv/Scripts/python.exe"
fi

"$VENV_PYTHON" -m pip install -e .
exec "$VENV_PYTHON" main.py
