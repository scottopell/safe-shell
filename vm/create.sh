#!/bin/bash
# Create the safe-shell development VM
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VM_NAME="safe-shell-vm"

echo "Creating Lima VM: $VM_NAME"
echo "This will take a few minutes on first run (downloading image, installing Rust)..."

# Check if VM already exists
if limactl list --json | grep -q "\"name\":\"$VM_NAME\""; then
    echo "VM '$VM_NAME' already exists."
    echo "Run './destroy.sh' first if you want a fresh VM."
    exit 1
fi

# Create and start the VM
limactl create --name="$VM_NAME" "$SCRIPT_DIR/safe-shell-vm.yaml"
limactl start "$VM_NAME"

echo ""
echo "=== VM Ready ==="
echo "To enter the VM:  limactl shell $VM_NAME"
echo "Or use:           lima $VM_NAME"
echo ""
echo "Workspace is at:  /workspace"
