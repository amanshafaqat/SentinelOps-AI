#!/bin/bash
set -e

WORKSPACE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="$WORKSPACE_DIR/.venv"

# If .venv/bin/uvicorn already exists and functions, skip setup
if [ -f "$VENV_DIR/bin/uvicorn" ] && "$VENV_DIR/bin/python" -c "import uvicorn, fastapi, sqlalchemy" >/dev/null 2>&1; then
    echo "[setup-python] Virtual environment is intact and verified."
    exit 0
fi

echo "[setup-python] Initializing Python virtual environment in $VENV_DIR..."
rm -rf "$VENV_DIR"
python3 -m venv --without-pip "$VENV_DIR"

echo "[setup-python] Installing pip into virtual environment..."
curl -sSL https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py
"$VENV_DIR/bin/python" /tmp/get-pip.py --quiet

echo "[setup-python] Installing requirements.txt into virtual environment..."
"$VENV_DIR/bin/pip" install --quiet -r "$WORKSPACE_DIR/backend/requirements.txt"

echo "[setup-python] Verifying Python backend installation..."
"$VENV_DIR/bin/python" -c "import uvicorn, fastapi, sqlalchemy; print('Verified: uvicorn', uvicorn.__version__, 'fastapi', fastapi.__version__)"
echo "[setup-python] Setup completed successfully."
