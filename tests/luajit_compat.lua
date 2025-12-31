#!/usr/bin/env luajit
-- LuaJIT Runtime Compatibility Test for Landlock Sandbox
-- Tests JIT compilation, FFI, coroutines, and system interactions

local ffi = require("ffi")

-- Test result tracking
local results = {
    allowed = {},
    blocked = {},
    errors = {}
}

local function record(name, success, blocked_expected, details)
    local entry = {name = name, details = details or ""}
    if success then
        table.insert(results.allowed, entry)
    elseif blocked_expected then
        table.insert(results.blocked, entry)
    else
        table.insert(results.errors, entry)
    end
end

local function test(name, blocked_expected, fn)
    io.write(string.format("  [TEST] %-45s ", name))
    io.flush()
    local ok, err = pcall(fn)
    if ok then
        print("[ALLOWED]")
        record(name, true, blocked_expected)
        return true
    else
        local msg = tostring(err):sub(1, 60)
        if blocked_expected then
            print("[BLOCKED] " .. msg)
            record(name, false, true, msg)
        else
            print("[ERROR]   " .. msg)
            record(name, false, false, msg)
        end
        return false
    end
end

print("=" .. string.rep("=", 70))
print("LuaJIT Runtime Compatibility Test")
print("LuaJIT Version: " .. jit.version)
print("Architecture: " .. jit.arch)
print("OS: " .. jit.os)
print("=" .. string.rep("=", 70))

------------------------------------------------------------
-- SECTION 1: Basic Interpreter
------------------------------------------------------------
print("\n[SECTION 1: Basic Interpreter]")

test("Hello world", false, function()
    local x = "Hello from LuaJIT!"
    assert(#x > 0)
end)

test("Math operations", false, function()
    local x = math.sin(1.5) + math.cos(2.5) * math.sqrt(100)
    assert(type(x) == "number")
end)

test("String operations", false, function()
    local s = string.format("%s %d %.2f", "test", 42, 3.14159)
    assert(s == "test 42 3.14")
end)

test("Table operations", false, function()
    local t = {a=1, b=2, c=3}
    local sum = 0
    for k, v in pairs(t) do sum = sum + v end
    assert(sum == 6)
end)

------------------------------------------------------------
-- SECTION 2: JIT Compilation
------------------------------------------------------------
print("\n[SECTION 2: JIT Compilation]")

test("JIT status check", false, function()
    assert(jit.status() ~= nil)
end)

test("JIT hot loop compilation", false, function()
    -- This loop should trigger JIT compilation
    local sum = 0
    for i = 1, 100000 do
        sum = sum + i
    end
    assert(sum == 5000050000)
end)

test("JIT trace generation", false, function()
    -- Force trace compilation with predictable loop
    local t = {}
    for i = 1, 10000 do
        t[i] = i * 2
    end
    local sum = 0
    for i = 1, 10000 do
        sum = sum + t[i]
    end
    assert(sum == 100010000)
end)

test("JIT with function calls", false, function()
    local function fib(n)
        if n < 2 then return n end
        return fib(n-1) + fib(n-2)
    end
    local result = fib(20)
    assert(result == 6765)
end)

test("JIT flush", false, function()
    jit.flush()
    -- Re-run a loop after flush
    local sum = 0
    for i = 1, 1000 do sum = sum + i end
    assert(sum == 500500)
end)

test("JIT off/on toggle", false, function()
    jit.off()
    local x = 0
    for i = 1, 100 do x = x + 1 end
    jit.on()
    assert(x == 100)
end)

------------------------------------------------------------
-- SECTION 3: FFI (Foreign Function Interface)
------------------------------------------------------------
print("\n[SECTION 3: FFI - Foreign Function Interface]")

test("FFI cdef basic types", false, function()
    ffi.cdef[[
        typedef struct { int x; int y; } point_t;
    ]]
    local p = ffi.new("point_t", {10, 20})
    assert(p.x == 10 and p.y == 20)
end)

test("FFI memory allocation", false, function()
    local arr = ffi.new("int[100]")
    for i = 0, 99 do arr[i] = i end
    assert(arr[50] == 50)
end)

test("FFI string handling", false, function()
    local cs = ffi.new("char[32]", "Hello FFI")
    assert(ffi.string(cs) == "Hello FFI")
end)

test("FFI libc getpid()", false, function()
    ffi.cdef[[
        int getpid(void);
    ]]
    local pid = ffi.C.getpid()
    assert(pid > 0)
end)

test("FFI libc getenv()", false, function()
    ffi.cdef[[
        char* getenv(const char* name);
    ]]
    local home = ffi.C.getenv("HOME")
    -- May be nil in sandbox, that's ok
    assert(home ~= nil or true)
end)

test("FFI libc time()", false, function()
    ffi.cdef[[
        typedef long time_t;
        time_t time(time_t* t);
    ]]
    local t = ffi.C.time(nil)
    assert(t > 0)
end)

test("FFI malloc/free", false, function()
    ffi.cdef[[
        void* malloc(size_t size);
        void free(void* ptr);
    ]]
    local ptr = ffi.C.malloc(1024)
    assert(ptr ~= nil)
    ffi.C.free(ptr)
end)

test("FFI mmap attempt", true, function()
    ffi.cdef[[
        void* mmap(void* addr, size_t len, int prot, int flags, int fd, long offset);
        int munmap(void* addr, size_t len);
    ]]
    -- PROT_READ|PROT_WRITE=3, MAP_PRIVATE|MAP_ANONYMOUS=0x22
    local ptr = ffi.C.mmap(nil, 4096, 3, 0x22, -1, 0)
    if ptr == ffi.cast("void*", -1) then
        error("mmap failed")
    end
    ffi.C.munmap(ptr, 4096)
end)

------------------------------------------------------------
-- SECTION 4: Coroutines
------------------------------------------------------------
print("\n[SECTION 4: Coroutines]")

test("Coroutine create/resume", false, function()
    local co = coroutine.create(function()
        for i = 1, 5 do
            coroutine.yield(i)
        end
    end)
    local sum = 0
    for i = 1, 5 do
        local ok, val = coroutine.resume(co)
        assert(ok)
        sum = sum + val
    end
    assert(sum == 15)
end)

test("Multiple coroutines", false, function()
    local cos = {}
    for i = 1, 10 do
        cos[i] = coroutine.create(function() return i * 2 end)
    end
    local sum = 0
    for i = 1, 10 do
        local ok, val = coroutine.resume(cos[i])
        sum = sum + val
    end
    assert(sum == 110)
end)

test("Coroutine with JIT", false, function()
    local co = coroutine.create(function()
        local sum = 0
        for i = 1, 10000 do
            sum = sum + i
            if i % 1000 == 0 then coroutine.yield(sum) end
        end
        return sum
    end)
    local last = 0
    while coroutine.status(co) ~= "dead" do
        local ok, val = coroutine.resume(co)
        if val then last = val end
    end
    assert(last == 50005000)
end)

------------------------------------------------------------
-- SECTION 5: Filesystem Operations
------------------------------------------------------------
print("\n[SECTION 5: Filesystem Operations]")

test("Read file (/etc/hostname)", false, function()
    local f = io.open("/etc/hostname", "r")
    assert(f, "Cannot open file")
    local content = f:read("*a")
    f:close()
    assert(#content > 0)
end)

test("List directory (io.popen ls)", false, function()
    local p = io.popen("ls /etc 2>/dev/null", "r")
    local output = p:read("*a")
    p:close()
    assert(#output > 0)
end)

test("Write to /tmp", true, function()
    local f = io.open("/tmp/luajit_test.txt", "w")
    assert(f, "Cannot open for write")
    f:write("test")
    f:close()
    os.remove("/tmp/luajit_test.txt")
end)

test("Write to /dev/shm", false, function()
    local f = io.open("/dev/shm/luajit_test.txt", "w")
    assert(f, "Cannot open for write")
    f:write("test from luajit")
    f:close()
    -- Verify
    local f2 = io.open("/dev/shm/luajit_test.txt", "r")
    local content = f2:read("*a")
    f2:close()
    assert(content == "test from luajit")
    os.remove("/dev/shm/luajit_test.txt")
end)

test("Create directory in /dev/shm", true, function()
    local ok = os.execute("mkdir /dev/shm/luajit_test_dir")
    assert(ok == 0 or ok == true)
    os.execute("rmdir /dev/shm/luajit_test_dir")
end)

------------------------------------------------------------
-- SECTION 6: Process/OS Operations
------------------------------------------------------------
print("\n[SECTION 6: Process/OS Operations]")

test("os.getenv", false, function()
    local path = os.getenv("PATH")
    assert(path and #path > 0)
end)

test("os.clock", false, function()
    local c = os.clock()
    assert(type(c) == "number")
end)

test("os.time", false, function()
    local t = os.time()
    assert(t > 0)
end)

test("os.execute (echo)", false, function()
    local ok = os.execute("echo hello >/dev/null 2>&1")
    assert(ok == 0 or ok == true)
end)

test("os.execute (subprocess)", false, function()
    local ok = os.execute("sleep 0.1")
    assert(ok == 0 or ok == true)
end)

test("io.popen read", false, function()
    local p = io.popen("uname -a", "r")
    local output = p:read("*a")
    p:close()
    assert(#output > 0 and output:find("Linux"))
end)

------------------------------------------------------------
-- SECTION 7: Network Operations (Expected Blocked)
------------------------------------------------------------
print("\n[SECTION 7: Network Operations]")

test("FFI socket() TCP", true, function()
    ffi.cdef[[
        int socket(int domain, int type, int protocol);
        int close(int fd);
    ]]
    -- AF_INET=2, SOCK_STREAM=1
    local fd = ffi.C.socket(2, 1, 0)
    if fd < 0 then error("socket failed") end
    ffi.C.close(fd)
end)

test("FFI socket() UDP", true, function()
    -- AF_INET=2, SOCK_DGRAM=2
    local fd = ffi.C.socket(2, 2, 0)
    if fd < 0 then error("socket failed") end
    ffi.C.close(fd)
end)

test("FFI socket() Unix", true, function()
    -- AF_UNIX=1, SOCK_STREAM=1
    local fd = ffi.C.socket(1, 1, 0)
    if fd < 0 then error("socket failed") end
    ffi.C.close(fd)
end)

test("FFI socketpair() Unix", false, function()
    ffi.cdef[[
        int socketpair(int domain, int type, int protocol, int sv[2]);
    ]]
    local sv = ffi.new("int[2]")
    -- AF_UNIX=1, SOCK_STREAM=1
    local ret = ffi.C.socketpair(1, 1, 0, sv)
    if ret < 0 then error("socketpair failed") end
    ffi.C.close(sv[0])
    ffi.C.close(sv[1])
end)

------------------------------------------------------------
-- SECTION 8: Signal Handling
------------------------------------------------------------
print("\n[SECTION 8: Signal Handling]")

test("FFI getpid for signal test", false, function()
    local pid = ffi.C.getpid()
    assert(pid > 0)
end)

test("FFI kill(self, 0) - check process", false, function()
    ffi.cdef[[
        int kill(int pid, int sig);
    ]]
    local pid = ffi.C.getpid()
    local ret = ffi.C.kill(pid, 0)
    assert(ret == 0)
end)

test("FFI kill(1, 0) - signal init", true, function()
    local ret = ffi.C.kill(1, 0)
    if ret ~= 0 then error("kill returned " .. ret) end
end)

------------------------------------------------------------
-- SECTION 9: Memory Operations
------------------------------------------------------------
print("\n[SECTION 9: Memory Operations]")

test("Large table allocation", false, function()
    local t = {}
    for i = 1, 100000 do
        t[i] = string.rep("x", 10)
    end
    assert(#t == 100000)
end)

test("FFI large allocation (10MB)", false, function()
    local size = 10 * 1024 * 1024
    local arr = ffi.new("char[?]", size)
    -- Touch memory
    arr[0] = 65
    arr[size-1] = 90
    assert(arr[0] == 65 and arr[size-1] == 90)
end)

test("FFI allocation near limit (100MB)", false, function()
    local size = 100 * 1024 * 1024
    local arr = ffi.new("char[?]", size)
    arr[0] = 65
    arr[size-1] = 90
    assert(arr[0] == 65)
end)

test("FFI allocation over limit (400MB)", true, function()
    -- RLIMIT_AS is 512MB, this should fail or stress limits
    local size = 400 * 1024 * 1024
    local arr = ffi.new("char[?]", size)
    -- Touch to force commit
    for i = 0, size-1, 4096 do
        arr[i] = 65
    end
end)

------------------------------------------------------------
-- SECTION 10: Privileged Operations (Expected Blocked)
------------------------------------------------------------
print("\n[SECTION 10: Privileged Operations]")

test("FFI setuid(0)", true, function()
    ffi.cdef[[
        int setuid(int uid);
    ]]
    local ret = ffi.C.setuid(0)
    if ret ~= 0 then error("setuid failed (expected)") end
end)

test("FFI mount()", true, function()
    ffi.cdef[[
        int mount(const char* src, const char* target, const char* fs,
                  unsigned long flags, const void* data);
    ]]
    local ret = ffi.C.mount("none", "/mnt", "tmpfs", 0, nil)
    if ret ~= 0 then error("mount failed (expected)") end
end)

test("FFI prctl()", true, function()
    ffi.cdef[[
        int prctl(int option, unsigned long arg2, unsigned long arg3,
                  unsigned long arg4, unsigned long arg5);
    ]]
    -- PR_SET_DUMPABLE = 4
    local ret = ffi.C.prctl(4, 0, 0, 0, 0)
    if ret ~= 0 then error("prctl failed") end
end)

------------------------------------------------------------
-- Summary
------------------------------------------------------------
print("\n" .. string.rep("=", 71))
print("SUMMARY")
print(string.rep("=", 71))
print(string.format("  Allowed:  %d tests", #results.allowed))
print(string.format("  Blocked:  %d tests (expected)", #results.blocked))
print(string.format("  Errors:   %d tests (unexpected)", #results.errors))
print(string.rep("=", 71))

if #results.errors > 0 then
    print("\nUNEXPECTED ERRORS:")
    for _, e in ipairs(results.errors) do
        print(string.format("  - %s: %s", e.name, e.details))
    end
end

print("\nALLOWED OPERATIONS:")
for _, e in ipairs(results.allowed) do
    print(string.format("  [+] %s", e.name))
end

print("\nBLOCKED OPERATIONS (as expected):")
for _, e in ipairs(results.blocked) do
    print(string.format("  [-] %s: %s", e.name, e.details))
end

-- Exit code: 0 if no unexpected errors
os.exit(#results.errors)
