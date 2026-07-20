package eventexport

import (
	"encoding/json"
	"net"
	"strconv"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
)

type ecsFormatter struct{}

func (ecsFormatter) ContentType() string { return "application/json" }

func (ecsFormatter) Format(e evidence.Event) ([]byte, error) {
	m := map[string]any{
		"@timestamp": e.Time.UTC().Format(time.RFC3339),
		"event": map[string]any{
			"action":  string(e.Type),
			"outcome": outcomeString(e.Allow),
		},
	}

	if e.User != "" {
		m["user"] = map[string]any{"name": e.User}
	}
	if e.SourceIP != "" {
		m["source"] = map[string]any{"ip": e.SourceIP}
	}
	if e.Target != "" {
		dest := map[string]any{"address": e.Target}
		if host, port, err := net.SplitHostPort(e.Target); err == nil {
			dest["address"] = host
			if p, err := strconv.Atoi(port); err == nil {
				dest["port"] = p
			}
		}
		m["destination"] = dest
	}

	msg := e.Reason
	if msg == "" {
		msg = e.Detail
	}
	if msg != "" {
		m["message"] = msg
	}

	// Object/transfer fields (recording, transfer, inspection events).
	file := map[string]any{}
	if e.Path != "" {
		file["path"] = e.Path
	} else if e.ObjectKey != "" {
		file["path"] = e.ObjectKey
	}
	if e.SHA256 != "" {
		file["hash"] = map[string]any{"sha256": e.SHA256}
	}
	if e.Bytes != 0 {
		file["size"] = e.Bytes
	}
	if len(file) > 0 {
		m["file"] = file
	}

	return json.Marshal(m)
}
