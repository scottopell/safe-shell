"""
Agent loop with streaming for Linux triage.
"""

import json
from anthropic import Anthropic
from .tools import BASH_TOOL, execute_bash

SYSTEM_PROMPT = """You are a Linux system triage agent. Your goal is to understand what kind of Linux system you're running on.

You have access to a Bash tool for executing shell commands.

**Environment constraints** (not tool limitations - this is the actual system):
- The filesystem is read-only (you cannot create, modify, or delete files)
- Network access is disabled (no external connectivity)
- Resource limits are in place (512MB memory, 30s CPU time per command)

If commands fail due to these constraints, that's expected - adjust your approach.

Investigate and report:
1. Distribution and version (cat /etc/os-release, uname -a)
2. Hardware info (cpu, memory, disk)
3. Running services and processes
4. Network configuration (interfaces, routing tables)
5. Installed packages/software
6. Any notable configurations

Be systematic. Start with basic commands and build understanding."""


def run_agent(verbose: bool = False) -> None:
    """Run the triage agent with streaming output."""
    client = Anthropic()

    # Start with a user message to kick off the triage
    messages = [
        {"role": "user", "content": "Please triage this Linux system and provide a comprehensive report."}
    ]
    tools = [BASH_TOOL]

    print("=" * 60)
    print("Linux Triage Agent")
    print("=" * 60)
    print()

    while True:
        # Stream the response
        with client.messages.stream(
            model="claude-sonnet-4-20250514",
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            tools=tools,
            messages=messages,
        ) as stream:
            response = stream.get_final_message()

            # Print text blocks as they come
            for block in response.content:
                if block.type == "text":
                    print(block.text)

        # Check if we're done
        if response.stop_reason == "end_turn":
            break

        # Handle tool use
        if response.stop_reason == "tool_use":
            # Add assistant's response to messages
            messages.append({"role": "assistant", "content": response.content})

            # Process each tool use
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    if block.name == "Bash":
                        command = block.input.get("command", "")

                        if verbose:
                            print(f"\n[Executing: {command}]")
                        else:
                            print(f"\n$ {command}")

                        result = execute_bash(command)

                        # Print output
                        if result["stdout"]:
                            print(result["stdout"], end="")
                        if result["stderr"]:
                            print(f"[stderr] {result['stderr']}", end="")
                        if result["exit_code"] != 0:
                            print(f"[exit code: {result['exit_code']}]")
                        print()

                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": json.dumps(result)
                        })
                    else:
                        # Unknown tool
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": f"Unknown tool: {block.name}",
                            "is_error": True
                        })

            # Add tool results to messages
            messages.append({"role": "user", "content": tool_results})
        else:
            # Unexpected stop reason
            if verbose:
                print(f"\n[Stopped: {response.stop_reason}]")
            break

    print()
    print("=" * 60)
    print("Triage complete")
    print("=" * 60)
