package dialer

import (
	"net"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

// tracer is the package's global-API tracer handle. It is a no-op when no
// TracerProvider has been installed (OTel disabled), so every instrumented
// call site below costs nothing unless internal/otelexport.Setup ran.
var tracer = otel.Tracer("github.com/rupivbluegreen/omni-sag/internal/dialer")

func omnisagEvidenceID(id string) attribute.KeyValue {
	return attribute.String("omnisag.evidence.id", id)
}

func omnisagPolicyMatchedRole(r string) attribute.KeyValue {
	return attribute.String("omnisag.policy.matched_role", r)
}

func omnisagCredentialMode(m string) attribute.KeyValue {
	return attribute.String("omnisag.credential.mode", m)
}

func omnisagApprovalOutcome(o string) attribute.KeyValue {
	return attribute.String("omnisag.approval.outcome", o)
}

// peerAddress extracts the bare IP/host from addr, dropping the port, for
// the network.peer.address span attribute. Falls back to the full string
// when addr has no host:port shape.
func peerAddress(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	if h, _, err := net.SplitHostPort(addr.String()); err == nil {
		return h
	}
	return addr.String()
}
