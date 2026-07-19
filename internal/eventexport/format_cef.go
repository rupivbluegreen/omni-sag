package eventexport

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
)

// cefVersion is the CEF header's device-version field. Fixed rather than
// sourced from build info: the event schema, not the binary, is what a SIEM
// parser cares about.
const cefVersion = "1.0"

type cefFormatter struct{}

func (cefFormatter) ContentType() string { return "text/plain" }

// cefHeaderEscaper escapes the two characters CEF requires escaped in
// header fields: backslash and pipe (the header field separator).
var cefHeaderEscaper = strings.NewReplacer(`\`, `\\`, `|`, `\|`)

// cefExtensionEscaper escapes the characters CEF requires escaped in
// extension values: backslash, equals (the key=value separator), and
// newlines (which would otherwise break single-line framing).
var cefExtensionEscaper = strings.NewReplacer(`\`, `\\`, `=`, `\=`, "\n", `\n`, "\r", `\n`)

func (cefFormatter) Format(e evidence.Event) ([]byte, error) {
	sig := cefHeaderEscaper.Replace(string(e.Type))
	header := fmt.Sprintf("CEF:0|omni-sag|gateway|%s|%s|%s|%d|", cefVersion, sig, sig, cefSeverity(e))

	var ext []string
	add := func(key, val string) {
		if val == "" {
			return
		}
		ext = append(ext, key+"="+cefExtensionEscaper.Replace(val))
	}

	add("rt", strconv.FormatInt(e.Time.UnixMilli(), 10))
	add("suser", e.User)
	add("src", e.SourceIP)
	if e.Target != "" {
		if host, port, err := net.SplitHostPort(e.Target); err == nil {
			add("dst", host)
			add("dpt", port)
		} else {
			add("dst", e.Target)
		}
	}
	add("cat", string(e.Type))
	add("outcome", outcomeString(e.Allow))
	add("msg", cefMessage(e))

	// Object/transfer fields (recording, transfer, inspection events).
	if e.Path != "" {
		add("fname", e.Path)
	} else if e.ObjectKey != "" {
		add("fname", e.ObjectKey)
	}
	if e.Bytes != 0 {
		add("fsize", strconv.FormatInt(e.Bytes, 10))
	}
	add("fileHash", e.SHA256)

	return []byte(header + strings.Join(ext, " ")), nil
}

func cefMessage(e evidence.Event) string {
	if e.Reason != "" {
		return e.Reason
	}
	return e.Detail
}

// cefSeverity maps a denial (Allow explicitly false) or a blocked
// content-inspection verdict to a high severity; everything else is low.
func cefSeverity(e evidence.Event) int {
	denied := e.Allow != nil && !*e.Allow
	blocked := e.Verdict == "blocked"
	if denied || blocked {
		return 8
	}
	return 3
}
