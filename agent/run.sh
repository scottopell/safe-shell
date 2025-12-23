#!/bin/bash
# Run the Linux triage agent
# This script builds safe-shell and runs the agent

set -e

# Source .env if it exists (for API key)
if [ -f /workspace/.env ]; then
    set -a  # auto-export variables
    source /workspace/.env
    set +a
fi

# Check for API key
if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo "Error: ANTHROPIC_API_KEY not set"
    echo "Export your API key: export ANTHROPIC_API_KEY='sk-...'"
    exit 1
fi

# Build safe-shell if needed
SAFE_SHELL="/workspace/sandbox/target/release/safe-shell"
if [ ! -f "$SAFE_SHELL" ]; then
    echo "Building safe-shell..."
    cd /workspace/sandbox
    cargo build --release
fi

# Install Python dependencies if needed
cd /workspace/agent
if ! python3 -c "import anthropic" 2>/dev/null; then
    echo "Installing Python dependencies..."
    pip3 install -r requirements.txt
fi

# Run the agent
exec python3 -m src.main "$@"
