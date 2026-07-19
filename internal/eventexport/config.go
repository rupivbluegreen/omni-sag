package eventexport

import "time"

// defaultBufferSize is used when an ExporterConfig doesn't set BufferSize
// (or sets a non-positive value).
const defaultBufferSize = 10000

// defaultSinkFlushInterval is the async exporter's periodic Flush interval
// for transports that don't have their own notion of a flush interval
// (file, syslog). http uses its own FlushIntervalSeconds when set.
const defaultSinkFlushInterval = time.Second

// Config is the package-level configuration a ForwardingSink is built from.
// It mirrors the spec's `export:` yaml block; mapping from internal/config
// is a later task.
type Config struct {
	Enabled   bool
	Exporters []ExporterConfig
}

// ExporterConfig describes one export destination: a Formatter + Transport
// pair. Exactly the sub-config matching Transport must be set (e.g.
// Transport: "syslog" requires Syslog != nil) — New validates this.
type ExporterConfig struct {
	Name       string
	Format     string
	Transport  string
	BufferSize int

	File   *fileConfig
	Syslog *syslogConfig
	HTTP   *httpConfig
}

// bufferSize returns the configured buffer size, defaulting to
// defaultBufferSize when unset or non-positive.
func (ec ExporterConfig) bufferSize() int {
	if ec.BufferSize <= 0 {
		return defaultBufferSize
	}
	return ec.BufferSize
}

// flushInterval derives the async exporter's periodic-flush interval: the
// http transport's own flush_interval_seconds when configured, else a sane
// default.
func (ec ExporterConfig) flushInterval() time.Duration {
	if ec.Transport == "http" && ec.HTTP != nil && ec.HTTP.FlushIntervalSeconds > 0 {
		return time.Duration(ec.HTTP.FlushIntervalSeconds) * time.Second
	}
	return defaultSinkFlushInterval
}
