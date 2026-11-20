package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/c77cc/mongosniffer/model"
)

func TestCollectorReportAndMetrics(t *testing.T) {
	c := NewCollector(10, false)
	t0 := time.Unix(100, 0)
	c.Add(model.OperationEvent{Command: "find", Database: "shop", Collection: "orders", Fingerprint: "find shop.orders", Acknowledged: true, Duration: 10 * time.Millisecond, FirstResponseAt: t0, FirstResponse: 8 * time.Millisecond, ResponseTransfer: 2 * time.Millisecond, RequestBytes: 100, Metadata: model.ConnectionMetadata{ClientAddress: "127.0.0.1", ServerAddress: "127.0.0.1:27017", HandshakeObserved: true}, Result: model.ResultSummary{ReturnedDocuments: 2, ResponseBytes: 200}})
	c.Add(model.OperationEvent{Command: "find", Database: "shop", Collection: "orders", Fingerprint: "find shop.orders", Acknowledged: true, Incomplete: true, IncompleteReason: "connection_closed", Duration: 20 * time.Millisecond, Metadata: model.ConnectionMetadata{ClientAddress: "127.0.0.1", ServerAddress: "127.0.0.1:27017", HandshakeObserved: true}})
	r := c.Snapshot(BuildInfo{Version: "test"}, 0)
	if r.SchemaVersion != 1 || len(r.Operations) != 1 || r.Operations[0].LatencyMS.Observations != 1 || r.Operations[0].ReturnedDocuments != 2 {
		t.Fatalf("report = %+v", r)
	}
	op := r.Operations[0]
	if op.FingerprintID == "" {
		t.Fatal("fingerprint_id is empty")
	}
	if op.Dimensions.ServerAddress != "127.0.0.1:27017" {
		t.Fatalf("server dimension = %q", op.Dimensions.ServerAddress)
	}
	if op.LatencyMS.FirstResponse.Observations != 1 || op.LatencyMS.FirstResponse.Total != 8 || op.LatencyMS.ResponseTransfer.Total != 2 {
		t.Fatalf("phase latency = %+v", op.LatencyMS)
	}
	if op.LatencyMS.P95 < op.LatencyMS.Min || op.LatencyMS.P95 > op.LatencyMS.Max || op.LatencyMS.FirstResponse.P95 < op.LatencyMS.FirstResponse.Min || op.LatencyMS.FirstResponse.P95 > op.LatencyMS.FirstResponse.Max {
		t.Fatalf("quantiles are outside observed bounds: %+v", op.LatencyMS)
	}
	if op.IncompleteObservedMS == nil || op.IncompleteObservedMS.Observations != 1 || op.IncompleteObservedMS.Total != 20 {
		t.Fatalf("incomplete observed duration = %+v", op.IncompleteObservedMS)
	}
	var out bytes.Buffer
	if err := WritePrometheus(&out, r); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"# HELP mongosniffer_operation_calls_total",
		"# TYPE mongosniffer_operation_calls_total counter",
		"# HELP mongosniffer_operation_first_response_seconds",
		"# TYPE mongosniffer_operation_first_response_seconds gauge",
		"mongosniffer_operation_incomplete_observed_duration_observations_total",
		`server="127.0.0.1:27017"`,
		`fingerprint_id="`,
		"mongosniffer_completed_operations_total 1",
		"mongosniffer_excluded_operations_total 1",
	} {
		if !strings.Contains(out.String(), expected) {
			t.Fatalf("metrics missing %q:\n%s", expected, out.String())
		}
	}
}

func TestCollectorSeparatesServerEndpoints(t *testing.T) {
	c := NewCollector(10, false)
	base := model.OperationEvent{
		Command:      "find",
		Database:     "shop",
		Collection:   "orders",
		Fingerprint:  "find shop.orders",
		Acknowledged: true,
		Duration:     time.Millisecond,
		Metadata:     model.ConnectionMetadata{ClientAddress: "127.0.0.1"},
	}
	first := base
	first.Metadata.ServerAddress = "10.0.0.8:27017"
	second := base
	second.Metadata.ServerAddress = "10.0.0.9:27017"
	c.Add(first)
	c.Add(second)

	r := c.Snapshot(BuildInfo{Version: "test"}, 0)
	if len(r.Operations) != 2 {
		t.Fatalf("operations = %d, want 2: %+v", len(r.Operations), r.Operations)
	}
	servers := map[string]bool{}
	for _, operation := range r.Operations {
		servers[operation.Dimensions.ServerAddress] = true
	}
	if !servers["10.0.0.8:27017"] || !servers["10.0.0.9:27017"] {
		t.Fatalf("server dimensions = %v", servers)
	}
}
