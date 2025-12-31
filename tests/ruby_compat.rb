#!/usr/bin/env ruby
# Ruby Runtime Compatibility Test for Landlock Sandbox
# Tests process control, FFI, sockets, signals, and system interactions

require 'socket'
require 'tempfile'
require 'fileutils'
require 'timeout'

# Test result tracking
$results = {
  allowed: [],
  blocked: [],
  errors: []
}

def record(name, success, blocked_expected, details = "")
  entry = { name: name, details: details }
  if success
    $results[:allowed] << entry
  elsif blocked_expected
    $results[:blocked] << entry
  else
    $results[:errors] << entry
  end
end

def test(name, blocked_expected: false)
  print "  [TEST] #{name.ljust(45)} "
  $stdout.flush
  begin
    yield
    puts "[ALLOWED]"
    record(name, true, blocked_expected)
    true
  rescue => e
    msg = e.message[0..59]
    if blocked_expected
      puts "[BLOCKED] #{msg}"
      record(name, false, true, msg)
    else
      puts "[ERROR]   #{msg}"
      record(name, false, false, msg)
    end
    false
  end
end

puts "=" * 71
puts "Ruby Runtime Compatibility Test"
puts "Ruby Version: #{RUBY_VERSION} (#{RUBY_PLATFORM})"
puts "Ruby Engine: #{RUBY_ENGINE}"
puts "=" * 71

# ============================================================
# SECTION 1: Basic Interpreter
# ============================================================
puts "\n[SECTION 1: Basic Interpreter]"

test("Hello world") do
  x = "Hello from Ruby!"
  raise "Failed" unless x.length > 0
end

test("Math operations") do
  x = Math.sin(1.5) + Math.cos(2.5) * Math.sqrt(100)
  raise "Failed" unless x.is_a?(Float)
end

test("String operations") do
  s = sprintf("%s %d %.2f", "test", 42, 3.14159)
  raise "Failed" unless s == "test 42 3.14"
end

test("Array/Hash operations") do
  arr = [1, 2, 3, 4, 5]
  hash = { a: 1, b: 2, c: 3 }
  raise "Failed" unless arr.sum == 15 && hash.values.sum == 6
end

test("Block/Proc/Lambda") do
  doubled = [1, 2, 3].map { |x| x * 2 }
  proc_obj = Proc.new { |x| x * 3 }
  lambda_obj = ->(x) { x * 4 }
  raise "Failed" unless doubled == [2, 4, 6] && proc_obj.call(2) == 6 && lambda_obj.call(2) == 8
end

# ============================================================
# SECTION 2: Standard Library Loading
# ============================================================
puts "\n[SECTION 2: Standard Library Loading]"

test("require 'json'") do
  require 'json'
  data = JSON.parse('{"key": "value"}')
  raise "Failed" unless data["key"] == "value"
end

test("require 'yaml'") do
  require 'yaml'
  data = YAML.safe_load("key: value")
  raise "Failed" unless data["key"] == "value"
end

test("require 'digest'") do
  require 'digest'
  hash = Digest::SHA256.hexdigest("test")
  raise "Failed" unless hash.length == 64
end

test("require 'base64'") do
  require 'base64'
  encoded = Base64.encode64("hello")
  decoded = Base64.decode64(encoded)
  raise "Failed" unless decoded == "hello"
end

test("require 'erb'") do
  require 'erb'
  template = ERB.new("Hello <%= name %>")
  result = template.result_with_hash(name: "World")
  raise "Failed" unless result == "Hello World"
end

test("require 'open3'") do
  require 'open3'
  # Just test the require, not execution
  raise "Failed" unless defined?(Open3)
end

# ============================================================
# SECTION 3: Filesystem Operations
# ============================================================
puts "\n[SECTION 3: Filesystem Operations]"

test("Read file (/etc/hostname)") do
  content = File.read("/etc/hostname")
  raise "Failed" unless content.length > 0
end

test("List directory (/etc)") do
  entries = Dir.entries("/etc")
  raise "Failed" unless entries.length > 0
end

test("File.exist? check") do
  raise "Failed" unless File.exist?("/etc/passwd")
end

test("Write to /tmp", blocked_expected: true) do
  File.write("/tmp/ruby_test.txt", "test")
  File.delete("/tmp/ruby_test.txt")
end

test("Write to /dev/shm") do
  path = "/dev/shm/ruby_test_#{$$}.txt"
  File.write(path, "test from ruby")
  content = File.read(path)
  File.delete(path)
  raise "Failed" unless content == "test from ruby"
end

test("Create directory in /dev/shm", blocked_expected: true) do
  path = "/dev/shm/ruby_test_dir_#{$$}"
  Dir.mkdir(path)
  Dir.rmdir(path)
end

test("Tempfile (default location)", blocked_expected: true) do
  # Default tempfile goes to /tmp which should be blocked
  tf = Tempfile.new('ruby_test')
  tf.write("test")
  tf.close
  tf.unlink
end

test("Tempfile in /dev/shm") do
  tf = Tempfile.new('ruby_test', '/dev/shm')
  tf.write("test data")
  tf.rewind
  content = tf.read
  tf.close
  tf.unlink
  raise "Failed" unless content == "test data"
end

# ============================================================
# SECTION 4: Process Operations
# ============================================================
puts "\n[SECTION 4: Process Operations]"

test("Process.pid") do
  raise "Failed" unless Process.pid > 0
end

test("Process.ppid") do
  raise "Failed" unless Process.ppid > 0
end

test("ENV access") do
  raise "Failed" unless ENV['PATH'] && ENV['PATH'].length > 0
end

test("system() command") do
  result = system("true")
  raise "Failed" unless result == true
end

test("backticks command") do
  output = `echo hello`.chomp
  raise "Failed" unless output == "hello"
end

test("Open3.capture3") do
  require 'open3'
  stdout, stderr, status = Open3.capture3("echo", "test")
  raise "Failed" unless stdout.chomp == "test" && status.success?
end

test("Process.spawn") do
  pid = Process.spawn("sleep 0.1")
  _, status = Process.wait2(pid)
  raise "Failed" unless status.success?
end

test("Process.fork", blocked_expected: false) do
  # Fork should work, child inherits sandbox
  rd, wr = IO.pipe
  pid = Process.fork do
    rd.close
    wr.write("child")
    wr.close
    exit!(0)
  end
  wr.close
  result = rd.read
  rd.close
  Process.wait(pid)
  raise "Failed" unless result == "child"
end

test("Process.exec in fork") do
  rd, wr = IO.pipe
  pid = Process.fork do
    rd.close
    $stdout.reopen(wr)
    exec("echo", "execed")
  end
  wr.close
  result = rd.read
  rd.close
  Process.wait(pid)
  raise "Failed" unless result.chomp == "execed"
end

# ============================================================
# SECTION 5: Signal Handling
# ============================================================
puts "\n[SECTION 5: Signal Handling]"

test("Signal.trap setup") do
  old_handler = Signal.trap("USR1") { }
  Signal.trap("USR1", old_handler || "DEFAULT")
end

test("Process.kill(0, $$) - self check") do
  result = Process.kill(0, $$)
  raise "Failed" unless result == 1
end

test("Process.kill(0, 1) - check init", blocked_expected: true) do
  Process.kill(0, 1)
end

test("Signal delivery to self") do
  received = false
  old_handler = Signal.trap("USR1") { received = true }
  Process.kill("USR1", $$)
  sleep 0.1
  Signal.trap("USR1", old_handler || "DEFAULT")
  raise "Failed" unless received
end

# ============================================================
# SECTION 6: Threading
# ============================================================
puts "\n[SECTION 6: Threading]"

test("Thread.new") do
  result = nil
  t = Thread.new { result = 42 }
  t.join
  raise "Failed" unless result == 42
end

test("Multiple threads") do
  results = []
  mutex = Mutex.new
  threads = 10.times.map do |i|
    Thread.new do
      sleep(rand * 0.01)
      mutex.synchronize { results << i }
    end
  end
  threads.each(&:join)
  raise "Failed" unless results.sort == (0..9).to_a
end

test("Thread with Queue") do
  require 'thread'
  queue = Queue.new
  producer = Thread.new do
    5.times { |i| queue << i }
  end
  sum = 0
  consumer = Thread.new do
    5.times { sum += queue.pop }
  end
  producer.join
  consumer.join
  raise "Failed" unless sum == 10
end

test("Mutex synchronization") do
  mutex = Mutex.new
  counter = 0
  threads = 10.times.map do
    Thread.new do
      100.times do
        mutex.synchronize { counter += 1 }
      end
    end
  end
  threads.each(&:join)
  raise "Failed" unless counter == 1000
end

# ============================================================
# SECTION 7: Network Operations
# ============================================================
puts "\n[SECTION 7: Network Operations]"

test("TCPSocket.new", blocked_expected: true) do
  # Should fail on connect due to Landlock
  socket = TCPSocket.new('127.0.0.1', 80)
  socket.close
end

test("Socket.new (TCP)", blocked_expected: false) do
  # Socket creation may work, connect should fail
  socket = Socket.new(:INET, :STREAM)
  socket.close
end

test("Socket.new (UDP)", blocked_expected: true) do
  socket = Socket.new(:INET, :DGRAM)
  socket.close
end

test("Socket.new (Unix)", blocked_expected: true) do
  socket = Socket.new(:UNIX, :STREAM)
  socket.close
end

test("Socket.pair (Unix)") do
  # socketpair should work for internal IPC
  s1, s2 = Socket.pair(:UNIX, :STREAM)
  s1.write("hello")
  s1.close_write
  result = s2.read
  s1.close rescue nil
  s2.close
  raise "Failed" unless result == "hello"
end

test("UNIXSocket.pair") do
  s1, s2 = UNIXSocket.pair
  s1.send("test", 0)
  result = s2.recv(10)
  s1.close
  s2.close
  raise "Failed" unless result == "test"
end

test("TCPServer.new", blocked_expected: true) do
  server = TCPServer.new('127.0.0.1', 0)
  server.close
end

# ============================================================
# SECTION 8: FFI / Fiddle
# ============================================================
puts "\n[SECTION 8: FFI / Fiddle]"

test("require 'fiddle'") do
  require 'fiddle'
  raise "Failed" unless defined?(Fiddle)
end

test("Fiddle dlopen libc") do
  require 'fiddle'
  libc = Fiddle.dlopen(nil)  # Current process (includes libc)
  raise "Failed" unless libc
end

test("Fiddle call getpid()") do
  require 'fiddle'
  libc = Fiddle.dlopen(nil)
  getpid = Fiddle::Function.new(
    libc['getpid'],
    [],
    Fiddle::TYPE_INT
  )
  pid = getpid.call
  raise "Failed" unless pid == $$
end

test("Fiddle call time()") do
  require 'fiddle'
  libc = Fiddle.dlopen(nil)
  time_func = Fiddle::Function.new(
    libc['time'],
    [Fiddle::TYPE_VOIDP],
    Fiddle::TYPE_LONG
  )
  t = time_func.call(0)
  raise "Failed" unless t > 0
end

test("Fiddle malloc/free") do
  require 'fiddle'
  ptr = Fiddle::Pointer.malloc(1024)
  raise "Failed" unless ptr.to_i > 0
  Fiddle.free(ptr)
end

# ============================================================
# SECTION 9: Privileged Operations (Expected Blocked)
# ============================================================
puts "\n[SECTION 9: Privileged Operations]"

test("Process::Sys.setuid(0)", blocked_expected: true) do
  Process::Sys.setuid(0)
end

test("File.chown", blocked_expected: true) do
  # Even if we could write, chown should fail
  File.chown(0, 0, "/dev/shm/nonexistent")
end

# ============================================================
# SECTION 10: Memory / Resource Operations
# ============================================================
puts "\n[SECTION 10: Memory / Resource Operations]"

test("Large string allocation (10MB)") do
  s = "x" * (10 * 1024 * 1024)
  raise "Failed" unless s.length == 10 * 1024 * 1024
end

test("Large array allocation") do
  arr = Array.new(1_000_000) { |i| i }
  raise "Failed" unless arr.length == 1_000_000
end

test("Process.getrlimit") do
  soft, hard = Process.getrlimit(:AS)
  raise "Failed" unless soft > 0
end

test("Process.setrlimit", blocked_expected: true) do
  # Try to raise our own limits - should fail
  Process.setrlimit(:AS, 1024 * 1024 * 1024)
end

# ============================================================
# Summary
# ============================================================
puts "\n" + "=" * 71
puts "SUMMARY"
puts "=" * 71
puts "  Allowed:  #{$results[:allowed].length} tests"
puts "  Blocked:  #{$results[:blocked].length} tests (expected)"
puts "  Errors:   #{$results[:errors].length} tests (unexpected)"
puts "=" * 71

if $results[:errors].length > 0
  puts "\nUNEXPECTED ERRORS:"
  $results[:errors].each do |e|
    puts "  - #{e[:name]}: #{e[:details]}"
  end
end

puts "\nALLOWED OPERATIONS:"
$results[:allowed].each do |e|
  puts "  [+] #{e[:name]}"
end

puts "\nBLOCKED OPERATIONS (as expected):"
$results[:blocked].each do |e|
  puts "  [-] #{e[:name]}: #{e[:details]}"
end

# Exit code: 0 if no unexpected errors
exit($results[:errors].length)
