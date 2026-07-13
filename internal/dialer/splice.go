package dialer

import (
	"io"
	"sync"
)

// Splice copies bytes bidirectionally between two endpoints (an SSH channel and
// a target connection) until either side closes, then closes both. It returns
// the total bytes copied a->b and b->a. This is the data-plane core and lives
// in the dialer because the dialer owns the outbound path.
func Splice(a, b io.ReadWriteCloser) (aToB, bToA int64) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		aToB, _ = io.Copy(b, a)
		closeWrite(b)
	}()
	go func() {
		defer wg.Done()
		bToA, _ = io.Copy(a, b)
		closeWrite(a)
	}()

	wg.Wait()
	_ = a.Close()
	_ = b.Close()
	return aToB, bToA
}

// closeWrite performs a half-close on the write side if supported (e.g.
// *net.TCPConn.CloseWrite), so the peer sees EOF; otherwise it is a no-op and
// the final Close in Splice tears the connection down.
func closeWrite(c io.ReadWriteCloser) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}
