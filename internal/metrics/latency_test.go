package metrics

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

// scrape renders m and returns the exposition lines, keyed by everything left
// of the value, so a test can assert one series without depending on ordering.
func scrape(t *testing.T, m *Metrics) map[string]string {
	t.Helper()
	var buf bytes.Buffer
	m.WriteText(&buf)
	out := make(map[string]string)
	for _, line := range strings.Split(buf.String(), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.LastIndex(line, " ")
		if i < 0 {
			t.Fatalf("malformed exposition line %q", line)
		}
		out[line[:i]] = line[i+1:]
	}
	return out
}

func TestHistogramBucketBoundaries(t *testing.T) {
	m := New()
	// One observation per side of the 0.025 boundary, one exactly on it, and
	// one past the largest bound so only +Inf catches it.
	for _, d := range []time.Duration{
		10 * time.Millisecond, // <= 0.01
		25 * time.Millisecond, // exactly 0.025: le is inclusive, so this bucket
		26 * time.Millisecond, // > 0.025, <= 0.05
		120 * time.Second,     // > 60, +Inf only
	} {
		m.ObserveAuth(d, true)
	}

	got := scrape(t, m)
	const name = "omnisag_auth_duration_seconds"
	want := map[string]string{
		name + `_bucket{result="success",le="0.005"}`: "0",
		name + `_bucket{result="success",le="0.01"}`:  "1",
		name + `_bucket{result="success",le="0.025"}`: "2", // cumulative: includes the 0.01 one
		name + `_bucket{result="success",le="0.05"}`:  "3",
		name + `_bucket{result="success",le="60"}`:    "3", // the 120s sample is above every bound
		name + `_bucket{result="success",le="+Inf"}`:  "4",
		name + `_count{result="success"}`:             "4",
	}
	for series, v := range want {
		if got[series] != v {
			t.Errorf("%s = %q, want %q", series, got[series], v)
		}
	}
	sum, err := strconv.ParseFloat(got[name+`_sum{result="success"}`], 64)
	if err != nil {
		t.Fatalf("_sum is not a number: %v", err)
	}
	if wantSum := 0.010 + 0.025 + 0.026 + 120.0; sum != wantSum {
		t.Errorf("_sum = %v, want %v", sum, wantSum)
	}
}

func TestObservationsAreSplitByOutcome(t *testing.T) {
	m := New()
	m.ObserveAuth(time.Second, true)
	m.ObserveSessionSetup(time.Second, false)
	m.ObserveSessionSetup(2*time.Second, false)

	got := scrape(t, m)
	for series, want := range map[string]string{
		`omnisag_auth_duration_seconds_count{result="success"}`:          "1",
		`omnisag_auth_duration_seconds_count{result="failure"}`:          "0",
		`omnisag_session_setup_duration_seconds_count{result="success"}`: "0",
		`omnisag_session_setup_duration_seconds_count{result="failure"}`: "2",
	} {
		if got[series] != want {
			t.Errorf("%s = %q, want %q", series, got[series], want)
		}
	}
}

// A histogram must expose its full series set before it has ever been
// observed, or a fresh gateway looks to Prometheus like it has no such metric
// at all and an SLO query silently returns nothing.
func TestUntouchedScrapeIsValidAndZero(t *testing.T) {
	got := scrape(t, New())

	families := map[string][]string{
		"omnisag_auth_duration_seconds":          {`result="success"`, `result="failure"`},
		"omnisag_session_setup_duration_seconds": {`result="success"`, `result="failure"`},
		"omnisag_session_duration_seconds":       {""},
	}
	buckets := map[string][]float64{
		"omnisag_auth_duration_seconds":          SetupBuckets,
		"omnisag_session_setup_duration_seconds": SetupBuckets,
		"omnisag_session_duration_seconds":       LifetimeBuckets,
	}
	for name, labelSets := range families {
		for _, labels := range labelSets {
			suffix, le := "", func(v string) string { return fmt.Sprintf("{le=%q}", v) }
			if labels != "" {
				suffix = "{" + labels + "}"
				le = func(v string) string { return fmt.Sprintf("{%s,le=%q}", labels, v) }
			}
			for _, b := range buckets[name] {
				series := name + "_bucket" + le(formatFloat(b))
				if got[series] != "0" {
					t.Errorf("%s = %q, want 0", series, got[series])
				}
			}
			for series, want := range map[string]string{
				name + "_bucket" + le("+Inf"): "0",
				name + "_sum" + suffix:        "0",
				name + "_count" + suffix:      "0",
			} {
				if got[series] != want {
					t.Errorf("%s = %q, want %q", series, got[series], want)
				}
			}
		}
	}
}

func TestHistogramTypeAndHelpDeclared(t *testing.T) {
	var buf bytes.Buffer
	New().WriteText(&buf)
	text := buf.String()
	for _, name := range []string{
		"omnisag_auth_duration_seconds",
		"omnisag_session_setup_duration_seconds",
		"omnisag_session_duration_seconds",
	} {
		if !strings.Contains(text, "# TYPE "+name+" histogram\n") {
			t.Errorf("missing '# TYPE %s histogram'", name)
		}
		if !strings.Contains(text, "# HELP "+name+" ") {
			t.Errorf("missing '# HELP %s'", name)
		}
		// HELP/TYPE are declared once for the whole family, not per series.
		if n := strings.Count(text, "# TYPE "+name+" histogram"); n != 1 {
			t.Errorf("'# TYPE %s' declared %d times, want 1", name, n)
		}
	}
}

// Cumulative buckets must never exceed _count, whatever the interleaving.
func TestConcurrentObservationsStayConsistent(t *testing.T) {
	m := New()
	done := make(chan struct{})
	go func() {
		for i := 0; i < 2000; i++ {
			m.ObserveSessionLifetime(time.Duration(i) * time.Millisecond)
		}
		close(done)
	}()
	for i := 0; i < 200; i++ {
		got := scrape(t, m)
		count := got["omnisag_session_duration_seconds_count"]
		inf := got[`omnisag_session_duration_seconds_bucket{le="+Inf"}`]
		if count != inf {
			t.Fatalf("+Inf bucket %q != _count %q", inf, count)
		}
		for _, b := range LifetimeBuckets {
			v, _ := strconv.ParseInt(got[`omnisag_session_duration_seconds_bucket{le="`+formatFloat(b)+`"}`], 10, 64)
			c, _ := strconv.ParseInt(count, 10, 64)
			if v > c {
				t.Fatalf("bucket le=%v is %d, above _count %d", b, v, c)
			}
		}
	}
	<-done
}
