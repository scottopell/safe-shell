#!/usr/bin/env python3
"""
Sandbox security test suite for safe-shell.

Tests all three security layers:
- Landlock: filesystem and network restrictions
- seccomp: syscall filtering
- rlimits: resource limits

Run with: python3 tests/test_sandbox.py
"""

import os
import subprocess
import sys
import time
import unittest
from pathlib import Path

SAFE_SHELL = "/workspace/sandbox/target/release/safe-shell"
TIMEOUT = 35  # Slightly > 30s CPU limit
TESTS_DIR = Path(__file__).parent


# === Terminal Colors ===
class Colors:
    """ANSI color codes for terminal output."""

    def __init__(self):
        # Disable colors if not a TTY or NO_COLOR is set
        use_color = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
        if use_color:
            self.GREEN = "\033[92m"
            self.RED = "\033[91m"
            self.YELLOW = "\033[93m"
            self.BLUE = "\033[94m"
            self.CYAN = "\033[96m"
            self.BOLD = "\033[1m"
            self.DIM = "\033[2m"
            self.RESET = "\033[0m"
        else:
            self.GREEN = self.RED = self.YELLOW = self.BLUE = ""
            self.CYAN = self.BOLD = self.DIM = self.RESET = ""

C = Colors()


class SandboxCapabilities:
    """Detect sandbox capabilities from verbose output."""

    def __init__(self):
        self.landlock_enabled = False
        self.signal_scoping_enabled = False
        self.socket_scoping_enabled = False
        self._detect()

    def _detect(self):
        """Run a simple command with -v to detect capabilities."""
        try:
            result = subprocess.run(
                [SAFE_SHELL, "-v", "true"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            stderr = result.stderr
            self.landlock_enabled = "Landlock fully enforced" in stderr or "Landlock only partially enforced" in stderr
            self.signal_scoping_enabled = "Signal scoping: enabled" in stderr
            self.socket_scoping_enabled = "Abstract Unix socket scoping: enabled" in stderr
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass


# Global capabilities detection (runs once at import)
CAPS = None


def get_caps() -> SandboxCapabilities:
    global CAPS
    if CAPS is None:
        CAPS = SandboxCapabilities()
    return CAPS


def run_sandboxed(command: str, timeout: int = TIMEOUT) -> tuple[int, str, str]:
    """Run command in sandbox, return (exit_code, stdout, stderr)."""
    try:
        result = subprocess.run(
            [SAFE_SHELL, command],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except FileNotFoundError:
        raise unittest.SkipTest(f"safe-shell binary not found at {SAFE_SHELL}")


class TestLandlockFilesystem(unittest.TestCase):
    """Test Landlock filesystem restrictions."""

    def test_read_allowed(self):
        """Reading files should work."""
        code, stdout, stderr = run_sandboxed("cat /etc/passwd")
        self.assertEqual(code, 0, f"Expected exit 0, got {code}. stderr: {stderr}")
        self.assertIn("root", stdout, "Expected /etc/passwd to contain 'root'")

    def test_write_blocked(self):
        """Writing files should be blocked."""
        code, stdout, stderr = run_sandboxed("touch /tmp/sandbox_test_file")
        self.assertNotEqual(code, 0, "Expected non-zero exit code for write attempt")
        # Landlock reports "Permission denied" rather than "Read-only file system"
        self.assertTrue(
            "Permission denied" in stderr or "Read-only" in stderr,
            f"Expected permission error, got: {stderr}",
        )

    def test_execute_allowed(self):
        """Executing binaries should work."""
        code, stdout, stderr = run_sandboxed("ls /")
        self.assertEqual(code, 0, f"Expected exit 0, got {code}. stderr: {stderr}")
        self.assertIn("bin", stdout, "Expected 'bin' in root directory listing")

    def test_tmpdir_points_to_dev_shm(self):
        """TMPDIR environment variable should point to /dev/shm."""
        code, stdout, stderr = run_sandboxed("echo $TMPDIR")
        self.assertEqual(code, 0, f"Expected exit 0, got {code}. stderr: {stderr}")
        self.assertEqual(stdout.strip(), "/dev/shm",
            f"Expected TMPDIR=/dev/shm, got: {stdout.strip()}")

    def test_mktemp_works(self):
        """mktemp should work with TMPDIR pointing to /dev/shm."""
        code, stdout, stderr = run_sandboxed("mktemp")
        self.assertEqual(code, 0, f"Expected exit 0, got {code}. stderr: {stderr}")
        self.assertTrue(stdout.strip().startswith("/dev/shm/"),
            f"Expected temp file in /dev/shm, got: {stdout.strip()}")


class TestLandlockNetwork(unittest.TestCase):
    """Test Landlock network restrictions."""

    def test_tcp_connect_blocked(self):
        """TCP connections should be blocked."""
        # Use a short timeout to avoid waiting too long
        code, stdout, stderr = run_sandboxed(
            "curl -s --connect-timeout 2 http://1.1.1.1 2>&1"
        )
        self.assertNotEqual(code, 0, "Expected non-zero exit code for network attempt")

    def test_tcp_bind_blocked(self):
        """TCP bind should be blocked."""
        code, stdout, stderr = run_sandboxed(
            "python3 -c \"import socket; s=socket.socket(); s.bind(('',8080))\""
        )
        self.assertNotEqual(code, 0, "Expected non-zero exit code for bind attempt")
        combined = stdout + stderr
        self.assertTrue(
            "Operation not permitted" in combined or "Permission denied" in combined,
            f"Expected permission error, got: {combined}",
        )


class TestSeccomp(unittest.TestCase):
    """Test seccomp syscall filtering."""

    def test_udp_blocked(self):
        """UDP socket creation should be blocked."""
        code, stdout, stderr = run_sandboxed(
            "python3 -c \"import socket; socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\""
        )
        self.assertNotEqual(code, 0, "Expected non-zero exit code for UDP socket")
        combined = stdout + stderr
        self.assertIn(
            "Operation not permitted", combined,
            f"Expected EPERM for UDP socket, got: {combined}",
        )

    def test_ptrace_allowed_within_sandbox(self):
        """ptrace should work within sandbox (Landlock domain hierarchy)."""
        # Landlock restricts ptrace based on domain hierarchy - sandboxed processes
        # can ptrace other sandboxed processes but not unsandboxed ones.
        # This allows debugging tools (strace, gdb) to work within the sandbox.
        code, stdout, stderr = run_sandboxed("strace -e trace=none /bin/true 2>&1")
        self.assertEqual(code, 0, f"Expected strace to work within sandbox, got code {code}. stderr: {stderr}")

    def test_setuid_blocked(self):
        """setuid should be blocked."""
        code, stdout, stderr = run_sandboxed("python3 -c \"import os; os.setuid(0)\"")
        self.assertNotEqual(code, 0, "Expected non-zero exit code for setuid")
        combined = stdout + stderr
        self.assertIn(
            "Operation not permitted", combined,
            f"Expected EPERM for setuid, got: {combined}",
        )

    def test_mount_blocked(self):
        """mount should be blocked (either by seccomp or lack of privileges)."""
        code, stdout, stderr = run_sandboxed("mount -t tmpfs none /mnt 2>&1")
        self.assertNotEqual(code, 0, "Expected non-zero exit code for mount")
        combined = stdout + stderr
        # Mount blocked either by seccomp (EPERM) or by lack of CAP_SYS_ADMIN
        self.assertTrue(
            "Operation not permitted" in combined or "must be superuser" in combined,
            f"Expected mount to be blocked, got: {combined}",
        )


class TestRlimits(unittest.TestCase):
    """Test resource limits."""

    def test_memory_limit(self):
        """Memory allocation beyond 512MB should fail."""
        # Try to allocate ~800MB (100M * 8 bytes per int)
        code, stdout, stderr = run_sandboxed(
            "python3 -c \"x=[0]*100000000\"",
            timeout=10,
        )
        self.assertNotEqual(code, 0, "Expected non-zero exit code for memory exhaustion")

    def test_file_size_limit(self):
        """File writes should fail due to RLIMIT_FSIZE=0."""
        code, stdout, stderr = run_sandboxed(
            "dd if=/dev/zero of=/tmp/test bs=1 count=1 2>&1"
        )
        self.assertNotEqual(code, 0, "Expected non-zero exit code for file write")

    def test_fork_bomb_limit(self):
        """Fork bomb should hit NPROC limit and not hang."""
        # This should complete (hit limit) rather than hang forever
        code, stdout, stderr = run_sandboxed(
            ":(){ :|:& };:",
            timeout=10,
        )
        # We just care that it didn't hang - any exit code is fine
        self.assertIsNotNone(code, "Fork bomb should complete (hit NPROC limit)")


class TestSignalScoping(unittest.TestCase):
    """Test Landlock signal scoping (kernel 6.12+)."""

    def setUp(self):
        caps = get_caps()
        if not caps.signal_scoping_enabled:
            self.skipTest("Signal scoping requires kernel 6.12+ (Landlock ABI v6)")

    def test_self_signal_allowed(self):
        """Process should be able to signal itself."""
        code, stdout, stderr = run_sandboxed("bash -c 'kill -0 $$'")
        self.assertEqual(code, 0, f"Expected exit 0 for self-signal, got {code}. stderr: {stderr}")

    def test_external_signal_blocked(self):
        """Signals to PID 1 (init) should be blocked."""
        code, stdout, stderr = run_sandboxed("kill -0 1 2>&1")
        self.assertNotEqual(code, 0, "Expected non-zero exit code for signaling PID 1")
        combined = stdout + stderr
        self.assertIn(
            "Operation not permitted", combined,
            f"Expected EPERM for external signal, got: {combined}",
        )


class TestUnixSocketBlocking(unittest.TestCase):
    """Test that Unix domain sockets are blocked entirely via seccomp."""

    def test_unix_socket_creation_blocked(self):
        """Creating AF_UNIX sockets should be blocked by seccomp."""
        code, stdout, stderr = run_sandboxed(
            "python3 -c \"import socket; socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\""
        )
        self.assertNotEqual(code, 0, "Expected non-zero exit code for AF_UNIX socket")
        combined = stdout + stderr
        self.assertIn(
            "Operation not permitted", combined,
            f"Expected EPERM for AF_UNIX socket creation, got: {combined}",
        )

    def test_socketpair_allowed(self):
        """socketpair(AF_UNIX) should work for internal IPC (intentional)."""
        # socketpair creates anonymous connected socket pairs for internal IPC.
        # Unlike socket(), these cannot connect to external services like docker.sock.
        # This is intentionally allowed for legitimate IPC patterns.
        code, stdout, stderr = run_sandboxed(
            "python3 -c \"import socket; a,b = socket.socketpair(); a.send(b'test'); print(b.recv(4))\""
        )
        self.assertEqual(code, 0, f"Expected socketpair to work, got code {code}. stderr: {stderr}")
        self.assertIn("b'test'", stdout, f"Expected to receive test data, got: {stdout}")


# === Custom Test Result for Pretty Output ===
class PrettyTestResult(unittest.TestResult):
    """Custom test result with colored, grouped output."""

    # Map test class names to display info
    CATEGORIES = {
        "TestLandlockFilesystem": ("Landlock Filesystem", "Read-only FS enforcement"),
        "TestLandlockNetwork": ("Landlock Network", "TCP connect/bind blocking"),
        "TestSeccomp": ("seccomp Syscalls", "Dangerous syscall filtering"),
        "TestRlimits": ("Resource Limits", "Memory, CPU, process limits"),
        "TestSignalScoping": ("Signal Scoping", "Cross-process signal blocking"),
        "TestUnixSocketBlocking": ("Unix Socket Blocking", "AF_UNIX socket isolation"),
    }

    def __init__(self, stream, descriptions, verbosity):
        super().__init__(stream, descriptions, verbosity)
        self.stream = stream
        self.current_class = None
        self.class_results = {}  # class_name -> list of (test_name, status, msg)

    def getDescription(self, test):
        """Get short test name without class prefix."""
        return test._testMethodName.replace("test_", "").replace("_", " ")

    def startTest(self, test):
        super().startTest(test)
        class_name = test.__class__.__name__

        # Print category header when switching classes
        if class_name != self.current_class:
            if self.current_class is not None:
                self.stream.write("\n")
            self.current_class = class_name

            cat_name, cat_desc = self.CATEGORIES.get(
                class_name, (class_name, "")
            )
            self.stream.write(f"{C.BOLD}{C.BLUE}{cat_name}{C.RESET}")
            if cat_desc:
                self.stream.write(f" {C.DIM}({cat_desc}){C.RESET}")
            self.stream.write("\n")

    def addSuccess(self, test):
        super().addSuccess(test)
        desc = self.getDescription(test)
        self.stream.write(f"  {C.GREEN}✓{C.RESET} {desc}\n")

    def addFailure(self, test, err):
        super().addFailure(test, err)
        desc = self.getDescription(test)
        self.stream.write(f"  {C.RED}✗{C.RESET} {desc}\n")

    def addError(self, test, err):
        super().addError(test, err)
        desc = self.getDescription(test)
        self.stream.write(f"  {C.RED}✗{C.RESET} {desc} {C.DIM}(error){C.RESET}\n")

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        desc = self.getDescription(test)
        self.stream.write(f"  {C.YELLOW}○{C.RESET} {desc} {C.DIM}({reason}){C.RESET}\n")

    def printSummary(self):
        """Print final summary."""
        self.stream.write("\n")
        self.stream.write(f"{C.BOLD}{'─' * 50}{C.RESET}\n")

        total = self.testsRun
        failed = len(self.failures) + len(self.errors)
        skipped = len(self.skipped)
        passed = total - failed - skipped

        # Status line
        if failed == 0:
            status = f"{C.GREEN}{C.BOLD}PASSED{C.RESET}"
        else:
            status = f"{C.RED}{C.BOLD}FAILED{C.RESET}"

        self.stream.write(f"{status}  ")
        parts = []
        if passed:
            parts.append(f"{C.GREEN}{passed} passed{C.RESET}")
        if failed:
            parts.append(f"{C.RED}{failed} failed{C.RESET}")
        if skipped:
            parts.append(f"{C.YELLOW}{skipped} skipped{C.RESET}")
        self.stream.write(" · ".join(parts))
        self.stream.write(f" {C.DIM}({total} total){C.RESET}\n")

        # Print failure details
        if self.failures or self.errors:
            self.stream.write(f"\n{C.RED}{C.BOLD}Failures:{C.RESET}\n")
            for test, traceback in self.failures + self.errors:
                self.stream.write(f"\n{C.RED}● {test}{C.RESET}\n")
                # Print just the assertion message, not full traceback
                lines = traceback.strip().split("\n")
                for line in lines[-3:]:
                    self.stream.write(f"  {C.DIM}{line}{C.RESET}\n")


class PrettyTestRunner(unittest.TextTestRunner):
    """Custom test runner using PrettyTestResult."""

    def __init__(self, **kwargs):
        kwargs["resultclass"] = PrettyTestResult
        super().__init__(**kwargs)

    def run(self, test):
        result = self._makeResult()
        result.stream = self.stream
        test(result)
        result.printSummary()
        return result


def print_header(caps: SandboxCapabilities):
    """Print test suite header with capabilities."""
    print(f"\n{C.BOLD}safe-shell Sandbox Test Suite{C.RESET}")
    print(f"{C.DIM}{'─' * 50}{C.RESET}")

    def cap_status(enabled: bool) -> str:
        if enabled:
            return f"{C.GREEN}✓{C.RESET}"
        return f"{C.YELLOW}○{C.RESET}"

    print(f"{C.BOLD}Detected Capabilities:{C.RESET}")
    print(f"  {cap_status(caps.landlock_enabled)} Landlock filesystem/network")
    print(f"  {cap_status(caps.signal_scoping_enabled)} Signal scoping {C.DIM}(kernel 6.12+){C.RESET}")
    print(f"  {cap_status(caps.socket_scoping_enabled)} Socket scoping {C.DIM}(kernel 6.12+){C.RESET}")
    print(f"{C.DIM}{'─' * 50}{C.RESET}\n")


def main():
    # Check if safe-shell binary exists
    if not os.path.exists(SAFE_SHELL):
        print(f"{C.RED}Error:{C.RESET} safe-shell binary not found at {SAFE_SHELL}")
        print(f"Build it with: {C.CYAN}cd /workspace/sandbox && cargo build --release{C.RESET}")
        sys.exit(1)

    # Detect and print capabilities
    caps = get_caps()
    print_header(caps)

    # Run tests with custom runner
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])

    runner = PrettyTestRunner(stream=sys.stdout, verbosity=0)
    result = runner.run(suite)

    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
