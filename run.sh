#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== ThreatIQ Platform ==="

# Create virtualenv if missing
if [ ! -d ".venv" ]; then
  echo "→ Creating virtual environment..."
  python3 -m venv .venv
fi

source .venv/bin/activate

echo "→ Installing dependencies..."
pip install -q -r requirements.txt

echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║   ThreatIQ Platform is starting...   ║"
echo "  ║                                      ║"
echo "  ║   Open: http://localhost:8000         ║"
echo "  ║   API:  http://localhost:8000/api/docs║"
echo "  ║                                      ║"
echo "  ║   Press Ctrl+C to stop               ║"
echo "  ╚══════════════════════════════════════╝"
echo ""

# Use port 8001 if 8000 is occupied
PORT=8001
if ! lsof -ti:8001 > /dev/null 2>&1; then PORT=8001; fi

echo "  Starting on port $PORT..."
uvicorn main:app --host 0.0.0.0 --port $PORT
