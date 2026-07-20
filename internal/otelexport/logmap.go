// EXPERIMENTAL: this file is the only place go.opentelemetry.io/otel/log
// types are referenced (besides otlplog.go), so a breaking 0.x bump of that
// pre-GA module touches only these two files — see the design doc's
// stability caveat. EventToLogRecord is pure (no I/O), mapping an
// evidence.Event onto an OTel log.Record for the experimental `otlp`
// eventexport transport.
package otelexport

import (
	"fmt"

	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/trace"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
)

// EventToLogRecord maps e onto a log.Record: Timestamp = e.Time,
// SeverityNumber derived from type/verdict/allow, Body a short human
// string, and Attributes the same promoted field set the #19 ECS formatter
// maps (user, source_ip, target, type, verdict, evidence id, ...). sc's
// TraceId/SpanId are added as attributes only when sc.IsValid() — the log
// API's Record has no trace-correlation field of its own; a real Logger
// additionally derives the wire-level OTLP trace_id/span_id from the ctx
// passed to Emit (see otlplog.go), so this is belt-and-suspenders, not the
// only correlation path.
func EventToLogRecord(e evidence.Event, sc trace.SpanContext) log.Record {
	var r log.Record
	r.SetTimestamp(e.Time)
	r.SetSeverity(severityFor(e))
	r.SetBody(log.StringValue(bodyFor(e)))
	r.AddAttributes(attributesFor(e, sc)...)
	return r
}

// severityFor derives SeverityNumber from the event's outcome: a blocked or
// error content-inspection verdict is ERROR, any other explicit deny (Allow
// == false) is WARN, everything else (allow, or an event with no tri-state
// outcome, e.g. a transfer manifest) is INFO.
func severityFor(e evidence.Event) log.Severity {
	if e.Type == evidence.TypeInspection && (e.Verdict == "blocked" || e.Verdict == "error") {
		return log.SeverityError
	}
	if e.Allow != nil && !*e.Allow {
		return log.SeverityWarn
	}
	return log.SeverityInfo
}

// bodyFor renders a short human-readable summary line.
func bodyFor(e evidence.Event) string {
	msg := e.Reason
	if msg == "" {
		msg = e.Detail
	}
	if msg == "" {
		return string(e.Type)
	}
	return fmt.Sprintf("%s: %s", e.Type, msg)
}

// attributesFor promotes the non-empty evidence.Event fields to log
// attributes, flat-named (not ECS's nested dotted structure — this is a
// separate, simpler mapping for the otlp transport).
func attributesFor(e evidence.Event, sc trace.SpanContext) []log.KeyValue {
	attrs := []log.KeyValue{
		log.String("evidence_id", e.ID),
		log.String("type", string(e.Type)),
	}
	add := func(k, v string) {
		if v != "" {
			attrs = append(attrs, log.String(k, v))
		}
	}
	add("user", e.User)
	add("source_ip", e.SourceIP)
	add("target", e.Target)
	if e.Allow != nil {
		attrs = append(attrs, log.Bool("allow", *e.Allow))
	}
	add("reason", e.Reason)
	add("matched_role", e.MatchedRole)
	add("record_mode", e.RecordMode)
	add("path", e.Path)
	add("direction", e.Direction)
	add("verdict", e.Verdict)
	add("credential_mode", e.CredentialMode)
	add("outcome", e.Outcome)
	add("object_key", e.ObjectKey)
	add("sha256", e.SHA256)
	if e.Bytes != 0 {
		attrs = append(attrs, log.Int64("bytes", e.Bytes))
	}
	add("detail", e.Detail)
	if sc.IsValid() {
		attrs = append(attrs, log.String("trace_id", sc.TraceID().String()), log.String("span_id", sc.SpanID().String()))
	}
	return attrs
}
