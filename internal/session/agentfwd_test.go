package session

import (
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"
)

// fakeConn implements the tiny slice of ssh.Conn that forwardedAgentSigners
// needs, so the test never touches a real network connection.
type fakeConn struct {
	ssh.Conn // embed to satisfy the full interface; only OpenChannel is overridden
	openErr  error
}

func (f *fakeConn) OpenChannel(name string, data []byte) (ssh.Channel, <-chan *ssh.Request, error) {
	if name != "auth-agent@openssh.com" {
		return nil, nil, errors.New("unexpected channel type: " + name)
	}
	if f.openErr != nil {
		return nil, nil, f.openErr
	}
	return nil, nil, errors.New("no forwarded agent") // real success path is covered by the docker-lab integration test (Task 13); a real ssh.Channel needs a live connection to construct
}

func TestForwardedAgentSigners_NoForwardingFailsClosed(t *testing.T) {
	s := &Server{}
	_, closer, err := s.forwardedAgentSigners(&fakeConn{openErr: errors.New("channel open failed")})
	if err == nil {
		t.Fatal("want an error when the client never forwarded an agent, got nil")
	}
	if closer != nil {
		t.Fatal("want a nil closer on failure; a non-nil closer would leak/mislead the caller")
	}
}
