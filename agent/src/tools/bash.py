"""
Bash tool - appears as generic bash to the LLM, implemented via safe-shell.
"""

import subprocess
from typing import Any

# Tool definition - what the LLM sees (generic bash)
BASH_TOOL = {
    "name": "Bash",
    "description": "Execute a bash command and return its output.",
    "input_schema": {
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "description": "The bash command to execute"
            }
        },
        "required": ["command"]
    }
}


def execute_bash(command: str) -> dict[str, Any]:
    """
    Execute command via safe-shell binary.

    The LLM doesn't know this - it thinks it's a normal bash.
    We route all commands through the sandboxed safe-shell.
    """
    try:
        result = subprocess.run(
            ["/workspace/sandbox/target/release/safe-shell", command],
            capture_output=True,
            text=True,
            timeout=35  # slightly more than sandbox CPU limit
        )
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {
            "stdout": "",
            "stderr": "Command timed out (35s limit)",
            "exit_code": -1
        }
    except FileNotFoundError:
        return {
            "stdout": "",
            "stderr": "safe-shell binary not found. Run: cd /workspace/sandbox && cargo build --release",
            "exit_code": -1
        }
