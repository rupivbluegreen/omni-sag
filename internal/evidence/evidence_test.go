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
