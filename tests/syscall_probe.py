#!/usr/bin/env python3
"""
Advanced syscall probe for safe-shell sandbox.

Tests kernel exploitation primitives, namespace escapes, and privilege escalation paths.
Useful for security auditing and verifying sandbox restrictions.

Run under sandbox: safe-shell 'python3 /workspace/tests/syscall_probe.py'
"""

import os
import ctypes
import platform

results = []
libc = ctypes.CDLL(None, use_errno=True)

def test(name, func):
    try:
        result = func()
        results.append((name, "ALLOWED", str(result)[:40]))
    except Exception as e:
        results.append((name, "BLOCKED", str(type(e).__name__) + ": " + str(e)[:30]))

# Architecture-specific syscall numbers
arch = platform.machine()
if arch == "aarch64":
    NR_memfd_create = 279
    NR_io_uring_setup = 425
    NR_userfaultfd = 282
    NR_perf_event_open = 241
    NR_add_key = 217
    NR_keyctl = 219
    NR_clone3 = 435
    NR_mount = 40
    NR_unshare = 97
    NR_setns = 268
    NR_capset = 91
else:  # x86_64
    NR_memfd_create = 319
    NR_io_uring_setup = 425
    NR_userfaultfd = 323
    NR_perf_event_open = 298
    NR_add_key = 248
    NR_keyctl = 250
    NR_clone3 = 435
    NR_mount = 165
    NR_unshare = 272
    NR_setns = 308
    NR_capset = 126

print("=" * 80)
print("ADVANCED SYSCALL PROBE - Security Audit")
print("=" * 80)

# === KERNEL EXPLOITATION PRIMITIVES ===
print("\n[Kernel Exploitation Primitives]")

def try_memfd():
    fd = libc.syscall(NR_memfd_create, b"test", 1)  # MFD_CLOEXEC=1
    if fd == -1:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    os.close(fd)
    return "fd created"

test("memfd_create", try_memfd)

def try_io_uring():
    ret = libc.syscall(NR_io_uring_setup, 8, 0)
    if ret == -1:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    return ret

test("io_uring_setup", try_io_uring)

def try_userfaultfd():
    fd = libc.syscall(NR_userfaultfd, 0)
    if fd == -1:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    os.close(fd)
    return fd

test("userfaultfd", try_userfaultfd)

def try_add_key():
    ret = libc.syscall(NR_add_key, b"user", b"test", b"data", 4, -4)
    if ret == -1:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    return ret

test("add_key", try_add_key)

def try_keyctl():
    KEYCTL_GET_KEYRING_ID = 0
    ret = libc.syscall(NR_keyctl, KEYCTL_GET_KEYRING_ID, -4, 0)
    if ret == -1:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    return ret

test("keyctl", try_keyctl)

# === NAMESPACE/CONTAINER ESCAPE ===
print("\n[Namespace/Container Escape]")

def try_unshare():
    CLONE_NEWUSER = 0x10000000
    ret = libc.syscall(NR_unshare, CLONE_NEWUSER)
    if ret == -1:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    return ret

test("unshare(CLONE_NEWUSER)", try_unshare)

def try_setns():
    try:
        with open("/proc/1/ns/mnt", "r") as f:
            fd = f.fileno()
            ret = libc.syscall(NR_setns, fd, 0)
            if ret == -1:
                raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
            return ret
    except PermissionError as e:
        raise e

test("setns(/proc/1/ns/mnt)", try_setns)

def try_mount():
    ret = libc.syscall(NR_mount, b"none", b"/tmp", b"tmpfs", 0, 0)
    if ret == -1:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    return ret

test("mount(tmpfs)", try_mount)

# User namespace exploitation
def try_uid_map():
    pid = os.fork()
    if pid == 0:
        libc.syscall(NR_unshare, 0x10000000)  # CLONE_NEWUSER
        try:
            with open("/proc/self/uid_map", "w") as f:
                f.write("0 {} 1\n".format(os.getuid()))
            os._exit(0)
        except:
            os._exit(1)
    else:
        _, status = os.waitpid(pid, 0)
        if os.WEXITSTATUS(status) == 0:
            return "uid_map write succeeded"
        else:
            raise Exception("uid_map write blocked")

test("write uid_map after unshare", try_uid_map)

# === DEVICE ACCESS ===
print("\n[Device Access]")

test("open(/dev/mem)", lambda: open("/dev/mem", "rb"))
test("open(/dev/kmem)", lambda: open("/dev/kmem", "rb"))
test("open(/dev/port)", lambda: open("/dev/port", "rb"))

def try_tiocsti():
    import fcntl
    fd = os.open("/dev/ptmx", os.O_RDWR)
    try:
        TIOCSTI = 0x5412
        fcntl.ioctl(fd, TIOCSTI, b"x")
    finally:
        os.close(fd)
    return "injected"

test("ioctl(TIOCSTI)", try_tiocsti)

# === PRIVILEGE ESCALATION ===
print("\n[Privilege Escalation]")

test("os.setuid(0)", lambda: os.setuid(0))
test("os.setgid(0)", lambda: os.setgid(0))

def try_capset():
    import struct
    hdr = struct.pack("II", 0x20080522, 0)
    data = struct.pack("III" * 2, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
                       0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF)
    hdr_buf = ctypes.create_string_buffer(hdr)
    data_buf = ctypes.create_string_buffer(data)
    ret = libc.syscall(NR_capset, ctypes.addressof(hdr_buf), ctypes.addressof(data_buf))
    if ret == -1:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    return ret

test("capset(all caps)", try_capset)

# === PTRACE ===
print("\n[Ptrace]")

def try_ptrace_init():
    PTRACE_ATTACH = 16
    ret = libc.ptrace(PTRACE_ATTACH, 1, 0, 0)
    if ret == -1:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    return ret

test("ptrace(ATTACH, pid=1)", try_ptrace_init)

def try_ptrace_self():
    # Can we ptrace our own child? (should work within sandbox domain)
    pid = os.fork()
    if pid == 0:
        import time
        time.sleep(10)
        os._exit(0)
    else:
        import time
        time.sleep(0.1)  # Let child start
        PTRACE_ATTACH = 16
        ret = libc.ptrace(PTRACE_ATTACH, pid, 0, 0)
        os.kill(pid, 9)
        os.waitpid(pid, 0)
        if ret == -1:
            raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
        return "attached to child"

test("ptrace(ATTACH, child)", try_ptrace_self)

# === /PROC INFORMATION ===
print("\n[/proc Information Disclosure]")

test("read /proc/kallsyms", lambda: open("/proc/kallsyms").readline()[:30])
test("read /proc/self/maps", lambda: str(len(open("/proc/self/maps").readlines())) + " mappings")
test("read /proc/self/environ", lambda: str(len(open("/proc/self/environ").read())) + " bytes")

# Print summary
print("\n" + "=" * 80)
print("RESULTS SUMMARY")
print("=" * 80)

allowed = [r for r in results if r[1] == "ALLOWED"]
blocked = [r for r in results if r[1] == "BLOCKED"]

print(f"\nALLOWED ({len(allowed)}):")
for name, status, details in allowed:
    print(f"  + {name}: {details}")

print(f"\nBLOCKED ({len(blocked)}):")
for name, status, details in blocked:
    print(f"  - {name}: {details}")

print("\n" + "=" * 80)
print(f"TOTAL: {len(allowed)} allowed, {len(blocked)} blocked")
print("=" * 80)
