#!/usr/bin/env python3
"""
Python runtime compatibility test for safe-shell sandbox.

Run under sandbox: safe-shell 'python3 /workspace/tests/python_compat.py'
"""

import os
import sys
import socket
import threading
import resource
import ctypes
from multiprocessing import Pool, Queue, Value, Array, shared_memory

print("=" * 75)
print("PYTHON RUNTIME SANDBOX COMPATIBILITY TEST")
print("=" * 75)

results = []

def test(category, name, func):
    try:
        result = func()
        results.append((category, name, "PASS", str(result)[:25]))
    except Exception as e:
        results.append((category, name, "BLOCKED", type(e).__name__))

# FILESYSTEM
test("Filesystem", "Read files", lambda: open("/etc/passwd").read()[:10])
test("Filesystem", "List directories", lambda: len(os.listdir("/usr")))
test("Filesystem", "Write to /tmp", lambda: open("/tmp/x", "w").write("x"))
test("Filesystem", "Write to /dev/shm", lambda: (open("/dev/shm/x", "w").write("x"), os.unlink("/dev/shm/x"))[0])

# NETWORK
test("Network", "TCP socket create", lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM))
test("Network", "TCP connect", lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("8.8.8.8", 53)))
test("Network", "UDP socket", lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
test("Network", "Unix socket", lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))

# PROCESSES
test("Process", "subprocess.run", lambda: __import__("subprocess").run(["echo", "hi"], capture_output=True).returncode)
test("Process", "os.setuid(0)", lambda: os.setuid(0))
test("Process", "os.kill(pid=1)", lambda: os.kill(1, 0))

# THREADING
test("Threading", "Thread create/join", lambda: (t:=threading.Thread(target=lambda:None), t.start(), t.join()))

# MULTIPROCESSING
def double(x): return x*2
test("Multiprocessing", "Pool.map", lambda: Pool(2).__enter__().map(double, [1,2]))
test("Multiprocessing", "Queue", lambda: (q:=Queue(), q.put(1), q.get()))
test("Multiprocessing", "Value", lambda: Value("i", 42).value)
test("Multiprocessing", "Array", lambda: list(Array("d", [1.0, 2.0])))
test("Multiprocessing", "SharedMemory", lambda: (s:=shared_memory.SharedMemory(create=True, size=64), s.close(), s.unlink()))

# RESOURCES
test("Resources", "getrlimit", lambda: resource.getrlimit(resource.RLIMIT_NPROC))
test("Resources", "Raise rlimit", lambda: resource.setrlimit(resource.RLIMIT_NPROC, (9999, 9999)))

# SYSCALLS (architecture-specific)
libc = ctypes.CDLL(None, use_errno=True)
arch = os.uname().machine

def try_prctl():
    ret = libc.prctl(15, b"test", 0, 0, 0)  # PR_SET_NAME
    if ret != 0:
        raise OSError(ctypes.get_errno(), "prctl failed")
    return ret

def try_memfd():
    NR_memfd_create = 279 if arch == "aarch64" else 319
    fd = libc.syscall(NR_memfd_create, b"test", 0)
    if fd == -1:
        raise OSError(ctypes.get_errno(), "memfd_create failed")
    os.close(fd)
    return "created"

def try_mount():
    NR_mount = 40 if arch == "aarch64" else 165
    ret = libc.syscall(NR_mount, b"none", b"/tmp", b"tmpfs", 0, 0)
    if ret == -1:
        raise OSError(ctypes.get_errno(), "mount failed")
    return ret

test("Syscalls", "prctl", try_prctl)
test("Syscalls", "memfd_create", try_memfd)
test("Syscalls", "mount", try_mount)

# Print results
print("")
current_cat = ""
for cat, name, status, details in results:
    if cat != current_cat:
        print("")
        print("[" + cat + "]")
        current_cat = cat
    symbol = "+" if status == "PASS" else "-"
    print("  " + symbol + " " + name.ljust(25) + status.ljust(10) + details)

passed = sum(1 for r in results if r[2] == "PASS")
blocked = sum(1 for r in results if r[2] == "BLOCKED")
print("")
print("=" * 75)
print("SUMMARY: " + str(passed) + " allowed, " + str(blocked) + " blocked")
print("=" * 75)

# Exit with error if unexpected results
# Expected: 13 allowed, 9 blocked
if passed < 13:
    print("WARNING: Fewer features working than expected!")
    sys.exit(1)
