// Command loadtest stress-tests a running omni-sag gateway with many
// concurrent SSH connections, each opening one -L-style tunnel (a
// direct-tcpip channel, the same mechanism `ssh -L` uses) and holding it
// open for a measurement window. Not part of the shipped binaries or CI —
// a manual dev tool, run against a real gateway (e.g. the docker-compose
// lab) pointed at scripts/loadtest/config.yaml.
package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:2222", "gateway SSH address")
	user := flag.String("user", "alice", "AD username to authenticate as (reused across all connections)")
	password := flag.String("password", "Passw0rd!", "password for -user")
	target := flag.String("target", "127.0.0.1:17001", "tunnel destination; this tool also starts its own echo listener here — must match a policy allow rule")
	n := flag.Int("n", 1000, "number of concurrent connections/tunnels")
	hold := flag.Duration("hold", 15*time.Second, "how long each tunnel stays open once established")
	rampBatch := flag.Int("ramp-batch", 200, "connections started per ramp interval")
	rampEvery := flag.Duration("ramp-every", 250*time.Millisecond, "interval between ramp batches")
	dialTimeout := flag.Duration("dial-timeout", 10*time.Second, "SSH handshake timeout per connection")
	flag.Parse()

	raiseFileLimit()

	echoAddr := startEchoListener(*target)
	log.Printf("loadtest: echo target listening on %s", echoAddr)
	log.Printf("loadtest: ramping %d connections as %q against %s, ramp-batch=%d every %s", *n, *user, *addr, *rampBatch, *rampEvery)

	var (
		attempted int64
		succeeded int64
		failed    int64
		mu        sync.Mutex
		latencies []time.Duration
		errCounts = map[string]int{}
	)

	var wg sync.WaitGroup
	start := time.Now()

	for i := 0; i < *n; i++ {
		if i > 0 && i%*rampBatch == 0 {
			time.Sleep(*rampEvery)
		}
		wg.Add(1)
		atomic.AddInt64(&attempted, 1)
		go func() {
			defer wg.Done()
			t0 := time.Now()
			err := runOne(*addr, *user, *password, *target, *dialTimeout, *hold)
			elapsed := time.Since(t0)
			if err != nil {
				atomic.AddInt64(&failed, 1)
				mu.Lock()
				errCounts[err.Error()]++
				mu.Unlock()
				return
			}
			atomic.AddInt64(&succeeded, 1)
			mu.Lock()
			latencies = append(latencies, elapsed)
			mu.Unlock()
		}()
	}

	wg.Wait()
	total := time.Since(start)

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	pct := func(p float64) time.Duration {
		if len(latencies) == 0 {
			return 0
		}
		idx := int(float64(len(latencies)-1) * p)
		return latencies[idx]
	}

	fmt.Printf("\n=== loadtest results ===\n")
	fmt.Printf("attempted: %d  succeeded: %d  failed: %d\n", attempted, succeeded, failed)
	fmt.Printf("wall time: %s\n", total)
	if len(latencies) > 0 {
		fmt.Printf("handshake+tunnel latency: p50=%s p95=%s p99=%s max=%s\n",
			pct(0.50), pct(0.95), pct(0.99), latencies[len(latencies)-1])
	}
	if len(errCounts) > 0 {
		fmt.Println("errors:")
		for e, c := range errCounts {
			fmt.Printf("  %5d x %s\n", c, e)
		}
	}
}

// runOne opens one SSH connection as user, opens one direct-tcpip channel to
// target, verifies an echo round-trip, holds the tunnel open for hold, then
// closes both.
func runOne(addr, user, password, target string, dialTimeout, hold time.Duration) error {
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         dialTimeout,
	})
	if err != nil {
		return fmt.Errorf("ssh dial: %w", err)
	}
	defer client.Close()

	conn, err := client.Dial("tcp", target)
	if err != nil {
		return fmt.Errorf("tunnel dial: %w", err)
	}
	defer conn.Close()

	payload := make([]byte, 32)
	_, _ = rand.Read(payload)
	if _, err := conn.Write(payload); err != nil {
		return fmt.Errorf("tunnel write: %w", err)
	}
	echoed := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, echoed); err != nil {
		return fmt.Errorf("tunnel read: %w", err)
	}
	for i := range payload {
		if payload[i] != echoed[i] {
			return fmt.Errorf("echo mismatch")
		}
	}

	time.Sleep(hold)
	return nil
}

// startEchoListener starts a TCP echo server on addr and returns its actual
// listen address.
func startEchoListener(addr string) string {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("loadtest: echo listener: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// raiseFileLimit raises this process's open-file soft limit to its hard
// limit, best-effort. The gateway process needs the same treatment
// separately, in its own shell, before it's started — this only affects the
// loadtest process itself.
func raiseFileLimit() {
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &rl); err != nil {
		log.Printf("loadtest: getrlimit: %v", err)
		return
	}
	if rl.Cur >= rl.Max {
		return
	}
	want := rl.Cur
	rl.Cur = rl.Max
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &rl); err != nil {
		log.Printf("loadtest: setrlimit to %d: %v (continuing with current limit %d)", rl.Max, err, want)
		return
	}
	log.Printf("loadtest: raised open-file limit to %d", rl.Max)
}
