#!/bin/bash
# Destroy the safe-shell development VM
set -euo pipefail

VM_NAME="safe-shell-vm"

echo "Destroying Lima VM: $VM_NAME"

# Check if VM exists
if ! limactl list --json | grep -q "\"name\":\"$VM_NAME\""; then
    echo "VM '$VM_NAME' does not exist."
    exit 0
fi

# Stop and delete the VM
limactl stop "$VM_NAME" 2>/dev/null || true
limactl delete "$VM_NAME" --force

echo "VM '$VM_NAME' destroyed."
