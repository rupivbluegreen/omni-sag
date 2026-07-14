package session

import (
	"fmt"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// agentForwardChannelType is OpenSSH's well-known channel type for a
// forwarded ssh-agent. golang.org/x/crypto/ssh/agent.ForwardToAgent uses the
// same string internally but does not export it, so it is restated here.
const agentForwardChannelType = "auth-agent@openssh.com"

// forwardedAgentSigners opens a new auth-agent@openssh.com channel back to
// the connected client (which must have sent an auth-agent-req@openssh.com
// channel request first — see interactive.go's handleSession) and returns
// the signers offered by the client's local agent. This is how passthrough
// mode authenticates the gateway's second SSH leg AS the human user, not as
// the gateway: the target sees the client's own key.
//
// Failure (no forwarding requested, agent has no keys, channel rejected)
// returns an error and never falls back to another credential mode — the
// caller (dialTarget, Task 7) must fail closed.
func (s *Server) forwardedAgentSigners(sconn ssh.Conn) ([]ssh.Signer, error) {
	ch, reqs, err := sconn.OpenChannel(agentForwardChannelType, nil)
	if err != nil {
		return nil, fmt.Errorf("session: no forwarded agent available (client must connect with ssh -A): %w", err)
	}
	go ssh.DiscardRequests(reqs)
	defer ch.Close()

	client := agent.NewClient(ch)
	signers, err := client.Signers()
	if err != nil {
		return nil, fmt.Errorf("session: forwarded agent has no usable keys: %w", err)
	}
	if len(signers) == 0 {
		return nil, fmt.Errorf("session: forwarded agent returned no signers")
	}
	return signers, nil
}
