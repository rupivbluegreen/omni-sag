package metrics

import (
	"testing"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
)

// The non-terminal "requested" approval event must not be counted as a refusal;
// only terminal granted/refused outcomes count.
func TestApprovalBucketing(t *testing.T) {
	m := New()
	b := func(v bool) *bool { return &v }

	m.record(evidence.Event{Type: evidence.TypeApproval, Outcome: "requested", Allow: b(false)})
	if m.approvalRefused.get() != 0 || m.approvalGranted.get() != 0 {
		t.Fatalf("a pending 'requested' event must not increment either counter (granted=%d refused=%d)",
			m.approvalGranted.get(), m.approvalRefused.get())
	}

	m.record(evidence.Event{Type: evidence.TypeApproval, Outcome: "granted", Allow: b(true)})
	m.record(evidence.Event{Type: evidence.TypeApproval, Outcome: "refused", Allow: b(false)})
	if m.approvalGranted.get() != 1 {
		t.Fatalf("granted=%d, want 1", m.approvalGranted.get())
	}
	if m.approvalRefused.get() != 1 {
		t.Fatalf("refused=%d, want 1", m.approvalRefused.get())
	}
}
