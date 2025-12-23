#!/usr/bin/env python3
"""
Linux Triage Agent - Entry point

Usage:
    python -m src.main [--verbose]

Requires:
    - ANTHROPIC_API_KEY environment variable
    - safe-shell binary at /workspace/sandbox/target/release/safe-shell
"""

import argparse
import os
import sys


def main():
    parser = argparse.ArgumentParser(description="Linux Triage Agent")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    # Check for API key
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("Error: ANTHROPIC_API_KEY environment variable not set", file=sys.stderr)
        print("Export your API key: export ANTHROPIC_API_KEY='sk-...'", file=sys.stderr)
        sys.exit(1)

    # Check for safe-shell binary
    safe_shell_path = "/workspace/sandbox/target/release/safe-shell"
    if not os.path.exists(safe_shell_path):
        print(f"Error: safe-shell binary not found at {safe_shell_path}", file=sys.stderr)
        print("Build it first: cd /workspace/sandbox && cargo build --release", file=sys.stderr)
        sys.exit(1)

    from .agent import run_agent
    run_agent(verbose=args.verbose)


if __name__ == "__main__":
    main()
