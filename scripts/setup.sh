#!/bin/bash
# PicoShogun Enterprise Setup Script
# Initializes database, installs dependencies, and configures the platform

set -e

BASE="/home/kirk/.picoclaw/workspace/PicoShogun"
PYTHON="python3"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     PicoShogun Enterprise Setup                            ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

cd "$BASE"

# Check Python version
echo "[1/6] Checking Python..."
PYTHON_VERSION=$($PYTHON --version 2>&1 | cut -d' ' -f2)
echo "  Python $PYTHON_VERSION"

# Create virtual environment if not exists
if [[ ! -d "$BASE/venv" ]]; then
    echo "[2/6] Creating virtual environment..."
    $PYTHON -m venv "$BASE/venv"
fi

source "$BASE/venv/bin/activate"

# Install dependencies
echo "[3/6] Installing dependencies..."
pip install --upgrade pip
pip install -r "$BASE/requirements.txt"

# Initialize database
echo "[4/6] Initializing database..."
$PYTHON -c "
import sys
sys.path.insert(0, '$BASE')
from database.manager import db
from services.orchestrator import EnhancedOrchestrator
orch = EnhancedOrchestrator()
print(f'  Database initialized')
print(f'  {len(orch.registry)} projects registered')
"

# Create necessary directories
echo "[5/6] Creating directories..."
mkdir -p "$BASE/logs"
mkdir -p "$BASE/backups"
mkdir -p "$BASE/temp"

# Check configuration
echo "[6/6] Validating configuration..."
$PYTHON -c "
import sys
sys.path.insert(0, '$BASE')
from config.settings import settings
issues = settings.validate()
if issues:
    print('  Warnings:')
    for issue in issues:
        print(f'    - {issue}')
else:
    print('  Configuration valid')
"

echo ""
echo "=== Setup Complete ==="
echo ""
echo "To start the API server:"
echo "  cd $BASE"
echo "  source venv/bin/activate"
echo "  python -m uvicorn api.server:app --reload"
echo ""
echo "To run a batch:"
echo "  ./scripts/run_category.sh monitoring --verbose"
echo ""
echo "To install as systemd service:"
echo "  sudo cp shogun.service /etc/systemd/system/"
echo "  sudo systemctl enable shogun"
echo "  sudo systemctl start shogun"
