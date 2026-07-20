package session

import (
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

// tracer is the package's global-API tracer handle. It is a no-op when no
// TracerProvider has been installed (OTel disabled), so every instrumented
// call site below costs nothing unless internal/otelexport.Setup ran.
var tracer = otel.Tracer("github.com/rupivbluegreen/omni-sag/internal/session")

// omnisagUser is the stable custom user-identity attribute. The enduser.*
// semconv has churned across spec versions, so this is an intentional
// custom namespace rather than a moving convention — see the design doc.
func omnisagUser(user string) attribute.KeyValue { return attribute.String("omnisag.user", user) }

func omnisagGroupsCount(n int) attribute.KeyValue { return attribute.Int("omnisag.groups.count", n) }

func omnisagChannelType(t string) attribute.KeyValue {
	return attribute.String("omnisag.channel.type", t)
}

func omnisagTargetHost(h string) attribute.KeyValue {
	return attribute.String("omnisag.target.host", h)
}

func omnisagEvidenceID(id string) attribute.KeyValue {
	return attribute.String("omnisag.evidence.id", id)
}

func omnisagTransferBytes(n int64) attribute.KeyValue {
	return attribute.Int64("omnisag.transfer.bytes", n)
}

func omnisagTransferDirection(d string) attribute.KeyValue {
	return attribute.String("omnisag.transfer.direction", d)
}

func omnisagInspectionVerdict(v string) attribute.KeyValue {
	return attribute.String("omnisag.inspection.verdict", v)
}

func omnisagPath(p string) attribute.KeyValue { return attribute.String("omnisag.path", p) }
