package evidence

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEvent_TunnelProtocolJSON(t *testing.T) {
	e := Event{Type: TypeTunnelProtocol, Target: "db:5432", Protocol: "jdwp", Allow: BoolPtr(false), Reason: "protocol jdwp not permitted"}
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"protocol":"jdwp"`) {
		t.Fatalf("marshaled event missing protocol field: %s", data)
	}
	var back Event
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back.Protocol != "jdwp" || back.Type != TypeTunnelProtocol {
		t.Fatalf("round-trip mismatch: %+v", back)
	}
}

func TestEvent_TargetUserJSON(t *testing.T) {
	data, err := json.Marshal(Event{Type: TypeCredential, User: "alice", TargetUser: "user01"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"target_user":"user01"`) {
		t.Fatalf("marshaled event missing target_user field: %s", data)
	}
	data, err = json.Marshal(Event{Type: TypeCredential, User: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "target_user") {
		t.Fatalf("target_user must be omitted when empty: %s", data)
	}
}
