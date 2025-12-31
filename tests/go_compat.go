// Go runtime compatibility test for safe-shell sandbox.
//
// Build: go build -o go_compat go_compat.go
// Run under sandbox: safe-shell './go_compat'

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Result struct {
	Category string
	Name     string
	Status   string
	Details  string
}

var results []Result

func test(category, name string, fn func() (string, error)) {
	result, err := fn()
	if err != nil {
		errStr := err.Error()
		if len(errStr) > 25 {
			errStr = errStr[:25]
		}
		results = append(results, Result{category, name, "BLOCKED", errStr})
	} else {
		if len(result) > 25 {
			result = result[:25]
		}
		results = append(results, Result{category, name, "PASS", result})
	}
}

func main() {
	fmt.Println(strings.Repeat("=", 75))
	fmt.Println("GO RUNTIME SANDBOX COMPATIBILITY TEST")
	fmt.Println(strings.Repeat("=", 75))

	// FILESYSTEM
	test("Filesystem", "Read files", func() (string, error) {
		data, err := os.ReadFile("/etc/passwd")
		if err != nil {
			return "", err
		}
		return string(data[:10]), nil
	})

	test("Filesystem", "List directories", func() (string, error) {
		entries, err := os.ReadDir("/usr")
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%d entries", len(entries)), nil
	})

	test("Filesystem", "Write to /tmp", func() (string, error) {
		err := os.WriteFile("/tmp/go_test", []byte("x"), 0644)
		if err != nil {
			return "", err
		}
		os.Remove("/tmp/go_test")
		return "1", nil
	})

	test("Filesystem", "Write to /dev/shm", func() (string, error) {
		err := os.WriteFile("/dev/shm/go_test", []byte("x"), 0644)
		if err != nil {
			return "", err
		}
		os.Remove("/dev/shm/go_test")
		return "1", nil
	})

	test("Filesystem", "os.CreateTemp", func() (string, error) {
		tmpdir := os.Getenv("TMPDIR")
		if tmpdir == "" {
			tmpdir = "/tmp"
		}
		f, err := os.CreateTemp(tmpdir, "go_test_*")
		if err != nil {
			return "", err
		}
		name := f.Name()
		f.Close()
		os.Remove(name)
		return name, nil
	})

	test("Filesystem", "os.MkdirTemp", func() (string, error) {
		tmpdir := os.Getenv("TMPDIR")
		if tmpdir == "" {
			tmpdir = "/tmp"
		}
		dir, err := os.MkdirTemp(tmpdir, "go_test_*")
		if err != nil {
			return "", err
		}
		os.RemoveAll(dir)
		return dir, nil
	})

	// NETWORK
	test("Network", "TCP dial", func() (string, error) {
		conn, err := net.DialTimeout("tcp", "8.8.8.8:53", 2*time.Second)
		if err != nil {
			return "", err
		}
		conn.Close()
		return "connected", nil
	})

	test("Network", "TCP listen", func() (string, error) {
		ln, err := net.Listen("tcp", ":0")
		if err != nil {
			return "", err
		}
		ln.Close()
		return "listening", nil
	})

	test("Network", "UDP dial", func() (string, error) {
		conn, err := net.Dial("udp", "8.8.8.8:53")
		if err != nil {
			return "", err
		}
		conn.Close()
		return "connected", nil
	})

	test("Network", "Unix socket dial", func() (string, error) {
		conn, err := net.Dial("unix", "/var/run/test.sock")
		if err != nil {
			return "", err
		}
		conn.Close()
		return "connected", nil
	})

	// PROCESSES
	test("Process", "exec.Command", func() (string, error) {
		cmd := exec.Command("echo", "hello")
		output, err := cmd.Output()
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(output)), nil
	})

	test("Process", "syscall.Kill self", func() (string, error) {
		err := syscall.Kill(os.Getpid(), 0)
		if err != nil {
			return "", err
		}
		return "allowed", nil
	})

	test("Process", "syscall.Kill pid 1", func() (string, error) {
		err := syscall.Kill(1, 0)
		if err != nil {
			return "", err
		}
		return "allowed", nil
	})

	test("Process", "syscall.Setuid(0)", func() (string, error) {
		err := syscall.Setuid(0)
		if err != nil {
			return "", err
		}
		return "set", nil
	})

	// GOROUTINES
	test("Goroutines", "spawn goroutine", func() (string, error) {
		var wg sync.WaitGroup
		result := ""
		wg.Add(1)
		go func() {
			defer wg.Done()
			result = "completed"
		}()
		wg.Wait()
		return result, nil
	})

	test("Goroutines", "channel comm", func() (string, error) {
		ch := make(chan string, 1)
		go func() {
			ch <- "hello"
		}()
		msg := <-ch
		return msg, nil
	})

	test("Goroutines", "GOMAXPROCS", func() (string, error) {
		n := runtime.GOMAXPROCS(0)
		return fmt.Sprintf("%d", n), nil
	})

	// SYSCALLS
	test("Syscalls", "syscall.Getrlimit", func() (string, error) {
		var rlim syscall.Rlimit
		err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlim)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("(%d, %d)", rlim.Cur, rlim.Max), nil
	})

	test("Syscalls", "syscall.Setrlimit", func() (string, error) {
		rlim := syscall.Rlimit{Cur: 9999, Max: 9999}
		err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rlim)
		if err != nil {
			return "", err
		}
		return "set", nil
	})

	test("Syscalls", "syscall.Mount", func() (string, error) {
		err := syscall.Mount("none", "/mnt", "tmpfs", 0, "")
		if err != nil {
			return "", err
		}
		return "mounted", nil
	})

	// IPC
	test("IPC", "os.Pipe", func() (string, error) {
		r, w, err := os.Pipe()
		if err != nil {
			return "", err
		}
		go func() {
			w.WriteString("test")
			w.Close()
		}()
		buf := make([]byte, 10)
		n, _ := r.Read(buf)
		r.Close()
		return string(buf[:n]), nil
	})

	test("IPC", "net.Socketpair", func() (string, error) {
		// Go doesn't have direct socketpair, use syscall
		fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
		if err != nil {
			return "", err
		}
		syscall.Close(fds[0])
		syscall.Close(fds[1])
		return "created", nil
	})

	// Print results
	fmt.Println()
	currentCat := ""
	for _, r := range results {
		if r.Category != currentCat {
			fmt.Printf("\n[%s]\n", r.Category)
			currentCat = r.Category
		}
		symbol := "+"
		if r.Status == "BLOCKED" {
			symbol = "-"
		}
		fmt.Printf("  %s %-25s %-10s %s\n", symbol, r.Name, r.Status, r.Details)
	}

	passed := 0
	blocked := 0
	for _, r := range results {
		if r.Status == "PASS" {
			passed++
		} else {
			blocked++
		}
	}

	fmt.Println()
	fmt.Println(strings.Repeat("=", 75))
	fmt.Printf("SUMMARY: %d allowed, %d blocked\n", passed, blocked)
	fmt.Println(strings.Repeat("=", 75))

	// Expected: ~10 allowed, ~10 blocked
	if passed < 8 {
		fmt.Println("WARNING: Fewer features working than expected!")
		os.Exit(1)
	}
}

// Ensure tmpdir from env is used
func init() {
	tmpdir := os.Getenv("TMPDIR")
	if tmpdir != "" {
		os.Setenv("TMPDIR", tmpdir)
	}
}
