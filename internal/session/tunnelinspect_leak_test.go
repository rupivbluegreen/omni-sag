package session

import (
	"io"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
)

// denyProbeConn is a hand-scripted io.ReadWriteCloser standing in for one
// side of an enforced tunnel. Read #0 delivers classifying bytes (a JDWP
// handshake) that alone make holdAndClassify return. Read #1 sleeps just
// long enough for enforceTunnel to consume that classification, decide
// deny, and reach its Close calls — then delivers a second chunk that
// nobody ever asked for or will drain. Read #2+ blocks until Close, like a
// real conn whose Read unblocks with an error once closed.
type denyProbeConn struct {
	mu     sync.Mutex
	reads  int
	closed chan struct{}
	once   sync.Once
}

func newDenyProbeConn() *denyProbeConn {
	return &denyProbeConn{closed: make(chan struct{})}
}

func (c *denyProbeConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	i := c.reads
	c.reads++
	c.mu.Unlock()

	switch i {
	case 0:
		return copy(p, []byte("JDWP-Handshake")), nil
	case 1:
		time.Sleep(5 * time.Millisecond)
		return copy(p, []byte("more-bytes-nobody-drains")), nil
	default:
		<-c.closed
		return 0, io.ErrClosedPipe
	}
}

func (c *denyProbeConn) Write(p []byte) (int, error) { return len(p), nil }

func (c *denyProbeConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

// settleGoroutines gives background goroutines a chance to actually exit
// (or, pre-fix, to actually reach and block on their leaking channel send)
// before NumGoroutine is sampled.
func settleGoroutines() {
	for i := 0; i < 5; i++ {
		runtime.Gosched()
	}
	time.Sleep(50 * time.Millisecond)
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
}

// TestEnforceTunnel_DenyPathDoesNotLeakAsyncReaderGoroutines reproduces the
// enforce-deny goroutine leak: when holdAndClassify classifies (and
// returns) off only the first chunk of a side that goes on to deliver a
// second chunk, enforceTunnel's deny path used to close ch/conn and return
// without ever draining the asyncReaders, so their background goroutines
// blocked forever trying to hand off a chunk into a cap-1 channel nobody
// would ever read again. Must fail before the fix and pass after.
func TestEnforceTunnel_DenyPathDoesNotLeakAsyncReaderGoroutines(t *testing.T) {
	srv := &Server{
		sink: evidence.NewMemSink(),
		tunnelInspect: TunnelInspectConfig{
			Enabled: true, MaxPrefixBytes: 512, ClassifyTimeout: 2 * time.Second, Enforce: true,
		},
	}
	pr := policy.Principal{User: "alice"}

	run := func() {
		ch := newDenyProbeConn()
		conn := newDenyProbeConn()
		srv.enforceTunnel(ch, conn, pr, "127.0.0.1", "target:1", []string{"postgres"})
	}

	for i := 0; i < 3; i++ { // warm-up
		run()
	}
	settleGoroutines()
	base := runtime.NumGoroutine()

	const iterations = 100
	for i := 0; i < iterations; i++ {
		run()
	}
	settleGoroutines()
	after := runtime.NumGoroutine()

	if after > base+5 {
		t.Fatalf("goroutine leak: base=%d after %d iterations=%d (want no growth)", base, iterations, after)
	}
}
