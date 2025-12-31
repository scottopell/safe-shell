#!/usr/bin/env node
// Node.js Runtime Compatibility Test for Landlock Sandbox
// Tests V8 JIT, async I/O, child processes, networking, and system interactions

const fs = require('fs');
const path = require('path');
const { spawn, fork, execSync } = require('child_process');
const net = require('net');
const dgram = require('dgram');
const os = require('os');
const crypto = require('crypto');

// Test result tracking
const results = {
  allowed: [],
  blocked: [],
  errors: []
};

function record(name, success, blockedExpected, details = '') {
  const entry = { name, details };
  if (success) {
    results.allowed.push(entry);
  } else if (blockedExpected) {
    results.blocked.push(entry);
  } else {
    results.errors.push(entry);
  }
}

async function test(name, blockedExpected, fn) {
  process.stdout.write(`  [TEST] ${name.padEnd(45)} `);
  try {
    await fn();
    console.log('[ALLOWED]');
    record(name, true, blockedExpected);
    return true;
  } catch (e) {
    const msg = (e.message || String(e)).substring(0, 60);
    if (blockedExpected) {
      console.log(`[BLOCKED] ${msg}`);
      record(name, false, true, msg);
    } else {
      console.log(`[ERROR]   ${msg}`);
      record(name, false, false, msg);
    }
    return false;
  }
}

async function main() {
  console.log('='.repeat(71));
  console.log('Node.js Runtime Compatibility Test');
  console.log(`Node.js Version: ${process.version}`);
  console.log(`V8 Version: ${process.versions.v8}`);
  console.log(`Platform: ${process.platform} ${process.arch}`);
  console.log('='.repeat(71));

  // ============================================================
  // SECTION 1: Basic Interpreter & V8
  // ============================================================
  console.log('\n[SECTION 1: Basic Interpreter & V8]');

  await test('Hello world', false, async () => {
    const x = 'Hello from Node.js!';
    if (x.length === 0) throw new Error('Failed');
  });

  await test('Math operations', false, async () => {
    const x = Math.sin(1.5) + Math.cos(2.5) * Math.sqrt(100);
    if (typeof x !== 'number') throw new Error('Failed');
  });

  await test('JSON parse/stringify', false, async () => {
    const obj = { key: 'value', num: 42 };
    const str = JSON.stringify(obj);
    const parsed = JSON.parse(str);
    if (parsed.key !== 'value') throw new Error('Failed');
  });

  await test('Array operations', false, async () => {
    const arr = [1, 2, 3, 4, 5];
    const sum = arr.reduce((a, b) => a + b, 0);
    if (sum !== 15) throw new Error('Failed');
  });

  await test('V8 JIT hot loop', false, async () => {
    // Trigger JIT compilation with hot loop
    let sum = 0;
    for (let i = 0; i < 1000000; i++) {
      sum += i;
    }
    if (sum !== 499999500000) throw new Error('Failed');
  });

  await test('V8 optimized function', false, async () => {
    function fib(n) {
      if (n < 2) return n;
      return fib(n - 1) + fib(n - 2);
    }
    const result = fib(20);
    if (result !== 6765) throw new Error('Failed');
  });

  // ============================================================
  // SECTION 2: Async & Promises
  // ============================================================
  console.log('\n[SECTION 2: Async & Promises]');

  await test('Promise.resolve', false, async () => {
    const result = await Promise.resolve(42);
    if (result !== 42) throw new Error('Failed');
  });

  await test('Promise.all', false, async () => {
    const results = await Promise.all([
      Promise.resolve(1),
      Promise.resolve(2),
      Promise.resolve(3)
    ]);
    if (results.reduce((a, b) => a + b) !== 6) throw new Error('Failed');
  });

  await test('setTimeout/setImmediate', false, async () => {
    await new Promise(resolve => setTimeout(resolve, 10));
    await new Promise(resolve => setImmediate(resolve));
  });

  await test('async/await chain', false, async () => {
    const delay = (ms) => new Promise(r => setTimeout(r, ms));
    await delay(5);
    await delay(5);
  });

  // ============================================================
  // SECTION 3: Module Loading
  // ============================================================
  console.log('\n[SECTION 3: Module Loading]');

  await test('require built-in (crypto)', false, async () => {
    const hash = crypto.createHash('sha256').update('test').digest('hex');
    if (hash.length !== 64) throw new Error('Failed');
  });

  await test('require built-in (zlib)', false, async () => {
    const zlib = require('zlib');
    const compressed = zlib.gzipSync(Buffer.from('hello'));
    const decompressed = zlib.gunzipSync(compressed);
    if (decompressed.toString() !== 'hello') throw new Error('Failed');
  });

  await test('require built-in (url)', false, async () => {
    const { URL } = require('url');
    const u = new URL('https://example.com/path?query=1');
    if (u.hostname !== 'example.com') throw new Error('Failed');
  });

  await test('require built-in (stream)', false, async () => {
    const { Readable } = require('stream');
    const readable = Readable.from(['hello']);
    if (!readable) throw new Error('Failed');
  });

  // ============================================================
  // SECTION 4: Filesystem Operations
  // ============================================================
  console.log('\n[SECTION 4: Filesystem Operations]');

  await test('fs.readFileSync (/etc/hostname)', false, async () => {
    const content = fs.readFileSync('/etc/hostname', 'utf8');
    if (content.length === 0) throw new Error('Failed');
  });

  await test('fs.readdirSync (/etc)', false, async () => {
    const entries = fs.readdirSync('/etc');
    if (entries.length === 0) throw new Error('Failed');
  });

  await test('fs.existsSync', false, async () => {
    if (!fs.existsSync('/etc/passwd')) throw new Error('Failed');
  });

  await test('fs.statSync', false, async () => {
    const stat = fs.statSync('/etc/passwd');
    if (!stat.isFile()) throw new Error('Failed');
  });

  await test('fs.writeFileSync to /tmp', true, async () => {
    fs.writeFileSync('/tmp/nodejs_test.txt', 'test');
    fs.unlinkSync('/tmp/nodejs_test.txt');
  });

  await test('fs.writeFileSync to /dev/shm', false, async () => {
    const testPath = `/dev/shm/nodejs_test_${process.pid}.txt`;
    fs.writeFileSync(testPath, 'test from nodejs');
    const content = fs.readFileSync(testPath, 'utf8');
    fs.unlinkSync(testPath);
    if (content !== 'test from nodejs') throw new Error('Failed');
  });

  await test('fs.mkdirSync in /dev/shm', true, async () => {
    const dirPath = `/dev/shm/nodejs_test_dir_${process.pid}`;
    fs.mkdirSync(dirPath);
    fs.rmdirSync(dirPath);
  });

  await test('fs.promises API', false, async () => {
    const content = await fs.promises.readFile('/etc/hostname', 'utf8');
    if (content.length === 0) throw new Error('Failed');
  });

  // ============================================================
  // SECTION 5: Process Operations
  // ============================================================
  console.log('\n[SECTION 5: Process Operations]');

  await test('process.pid', false, async () => {
    if (process.pid <= 0) throw new Error('Failed');
  });

  await test('process.env', false, async () => {
    if (!process.env.PATH || process.env.PATH.length === 0) throw new Error('Failed');
  });

  await test('process.cwd()', false, async () => {
    const cwd = process.cwd();
    if (cwd.length === 0) throw new Error('Failed');
  });

  await test('execSync (echo)', false, async () => {
    const output = execSync('echo hello', { encoding: 'utf8' });
    if (output.trim() !== 'hello') throw new Error('Failed');
  });

  await test('spawn with stdout', false, async () => {
    await new Promise((resolve, reject) => {
      const child = spawn('echo', ['test']);
      let output = '';
      child.stdout.on('data', (data) => { output += data; });
      child.on('close', (code) => {
        if (code === 0 && output.trim() === 'test') resolve();
        else reject(new Error(`code=${code} output=${output}`));
      });
      child.on('error', reject);
    });
  });

  await test('spawn with pipe', false, async () => {
    await new Promise((resolve, reject) => {
      const child = spawn('cat', [], { stdio: ['pipe', 'pipe', 'pipe'] });
      let output = '';
      child.stdout.on('data', (data) => { output += data; });
      child.stdin.write('piped data');
      child.stdin.end();
      child.on('close', (code) => {
        if (code === 0 && output === 'piped data') resolve();
        else reject(new Error(`code=${code} output=${output}`));
      });
      child.on('error', reject);
    });
  });

  // ============================================================
  // SECTION 6: Signal Handling
  // ============================================================
  console.log('\n[SECTION 6: Signal Handling]');

  await test('process.on SIGUSR1', false, async () => {
    let received = false;
    const handler = () => { received = true; };
    process.on('SIGUSR1', handler);
    process.kill(process.pid, 'SIGUSR1');
    await new Promise(r => setTimeout(r, 50));
    process.removeListener('SIGUSR1', handler);
    if (!received) throw new Error('Signal not received');
  });

  await test('process.kill(pid, 0) - self', false, async () => {
    process.kill(process.pid, 0);
  });

  await test('process.kill(1, 0) - init', true, async () => {
    process.kill(1, 0);
  });

  // ============================================================
  // SECTION 7: Network Operations
  // ============================================================
  console.log('\n[SECTION 7: Network Operations]');

  await test('net.Socket TCP create', false, async () => {
    const socket = new net.Socket();
    socket.destroy();
  });

  await test('net.Socket TCP connect', true, async () => {
    await new Promise((resolve, reject) => {
      const socket = new net.Socket();
      socket.setTimeout(1000);
      socket.on('error', (e) => {
        socket.destroy();
        reject(e);
      });
      socket.on('timeout', () => {
        socket.destroy();
        reject(new Error('timeout'));
      });
      socket.connect(80, '127.0.0.1', () => {
        socket.destroy();
        resolve();
      });
    });
  });

  await test('net.createServer', false, async () => {
    const server = net.createServer();
    server.close();
  });

  await test('net.createServer listen', true, async () => {
    await new Promise((resolve, reject) => {
      const server = net.createServer();
      server.on('error', (e) => {
        server.close();
        reject(e);
      });
      server.listen(0, '127.0.0.1', () => {
        server.close();
        resolve();
      });
    });
  });

  await test('dgram UDP socket', true, async () => {
    const socket = dgram.createSocket('udp4');
    socket.close();
  });

  // Unix socket via net module - this uses socket() not socketpair()
  await test('net.Socket Unix connect', true, async () => {
    await new Promise((resolve, reject) => {
      const socket = new net.Socket();
      socket.on('error', (e) => {
        socket.destroy();
        reject(e);
      });
      socket.connect('/var/run/test.sock', () => {
        socket.destroy();
        resolve();
      });
    });
  });

  // ============================================================
  // SECTION 8: Worker Threads
  // ============================================================
  console.log('\n[SECTION 8: Worker Threads]');

  await test('Worker thread creation', false, async () => {
    const { Worker, isMainThread } = require('worker_threads');
    if (!isMainThread) throw new Error('Not main thread');

    await new Promise((resolve, reject) => {
      const worker = new Worker(`
        const { parentPort } = require('worker_threads');
        parentPort.postMessage({ result: 42 });
      `, { eval: true });

      worker.on('message', (msg) => {
        if (msg.result === 42) resolve();
        else reject(new Error('Wrong result'));
      });
      worker.on('error', reject);
      worker.on('exit', (code) => {
        if (code !== 0) reject(new Error(`Worker exited with code ${code}`));
      });
    });
  });

  await test('Multiple workers', false, async () => {
    const { Worker } = require('worker_threads');

    const workerPromises = Array(4).fill(null).map((_, i) => {
      return new Promise((resolve, reject) => {
        const worker = new Worker(`
          const { parentPort, workerData } = require('worker_threads');
          parentPort.postMessage({ id: workerData.id, result: workerData.id * 2 });
        `, { eval: true, workerData: { id: i } });

        worker.on('message', resolve);
        worker.on('error', reject);
      });
    });

    const results = await Promise.all(workerPromises);
    const sum = results.reduce((a, b) => a + b.result, 0);
    if (sum !== 12) throw new Error('Failed'); // 0*2 + 1*2 + 2*2 + 3*2 = 12
  });

  // ============================================================
  // SECTION 9: Memory Operations
  // ============================================================
  console.log('\n[SECTION 9: Memory Operations]');

  await test('Buffer allocation (10MB)', false, async () => {
    const buf = Buffer.alloc(10 * 1024 * 1024);
    buf[0] = 65;
    buf[buf.length - 1] = 90;
    if (buf[0] !== 65 || buf[buf.length - 1] !== 90) throw new Error('Failed');
  });

  await test('Large array allocation', false, async () => {
    const arr = new Array(1000000).fill(0).map((_, i) => i);
    if (arr.length !== 1000000) throw new Error('Failed');
  });

  await test('ArrayBuffer (10MB)', false, async () => {
    const ab = new ArrayBuffer(10 * 1024 * 1024);
    const view = new Uint8Array(ab);
    view[0] = 255;
    if (view[0] !== 255) throw new Error('Failed');
  });

  await test('process.memoryUsage()', false, async () => {
    const mem = process.memoryUsage();
    if (mem.heapUsed <= 0) throw new Error('Failed');
  });

  // ============================================================
  // SECTION 10: OS Operations
  // ============================================================
  console.log('\n[SECTION 10: OS Operations]');

  await test('os.hostname()', false, async () => {
    const hostname = os.hostname();
    if (hostname.length === 0) throw new Error('Failed');
  });

  await test('os.platform()', false, async () => {
    if (os.platform() !== 'linux') throw new Error('Failed');
  });

  await test('os.cpus()', false, async () => {
    const cpus = os.cpus();
    if (cpus.length === 0) throw new Error('Failed');
  });

  await test('os.totalmem()', false, async () => {
    if (os.totalmem() <= 0) throw new Error('Failed');
  });

  await test('os.tmpdir()', false, async () => {
    const tmp = os.tmpdir();
    if (tmp.length === 0) throw new Error('Failed');
  });

  // ============================================================
  // Summary
  // ============================================================
  console.log('\n' + '='.repeat(71));
  console.log('SUMMARY');
  console.log('='.repeat(71));
  console.log(`  Allowed:  ${results.allowed.length} tests`);
  console.log(`  Blocked:  ${results.blocked.length} tests (expected)`);
  console.log(`  Errors:   ${results.errors.length} tests (unexpected)`);
  console.log('='.repeat(71));

  if (results.errors.length > 0) {
    console.log('\nUNEXPECTED ERRORS:');
    results.errors.forEach(e => {
      console.log(`  - ${e.name}: ${e.details}`);
    });
  }

  console.log('\nALLOWED OPERATIONS:');
  results.allowed.forEach(e => {
    console.log(`  [+] ${e.name}`);
  });

  console.log('\nBLOCKED OPERATIONS (as expected):');
  results.blocked.forEach(e => {
    console.log(`  [-] ${e.name}: ${e.details}`);
  });

  process.exit(results.errors.length);
}

main().catch(e => {
  console.error('Fatal error:', e);
  process.exit(1);
});
