#!/bin/bash
#
# PurpleSploit Web Dashboard Launcher
# Starts the web interface
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_DIR="$SCRIPT_DIR/../python"

cd "$PYTHON_DIR"

# Check if Python package is installed
if ! python3 -c "import purplesploit" 2>/dev/null; then
    echo "Installing PurpleSploit Python package..."
    pip3 install -e . || {
        echo "Failed to install package. Install manually with:"
        echo "  cd python && pip3 install -e ."
        exit 1
    }
fi

echo "Starting PurpleSploit Web Dashboard..."
echo "Dashboard: http://localhost:8000"
echo "Press Ctrl+C to stop"
echo ""

python3 -m purplesploit.web.dashboard
