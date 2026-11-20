package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

func WriteJSON(w io.Writer, report Report) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(report)
}
func WriteJSONLine(w io.Writer, report Report) error {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(report)
}

type metricDescription struct{ name, kind, help string }

var metricDescriptions = []metricDescription{
	{"mongosniffer_operation_calls_total", "counter", "Observed MongoDB operation executions."},
	{"mongosniffer_operation_errors_total", "counter", "MongoDB operations with command, write, or write concern errors."},
	{"mongosniffer_operation_incomplete_total", "counter", "MongoDB operations without a complete terminal response."},
	{"mongosniffer_operation_unacknowledged_total", "counter", "Observed unacknowledged MongoDB operations."},
	{"mongosniffer_operation_duration_observations_total", "counter", "Completed acknowledged operations included in latency metrics."},
	{"mongosniffer_operation_duration_seconds_total", "counter", "Cumulative observed duration of completed acknowledged operations."},
	{"mongosniffer_operation_duration_seconds", "gauge", "Cumulative operation duration quantile since process start."},
	{"mongosniffer_operation_duration_max_seconds", "gauge", "Maximum completed operation duration since process start."},
	{"mongosniffer_operation_first_response_observations_total", "counter", "Completed operations with an observed first response boundary."},
	{"mongosniffer_operation_first_response_seconds_total", "counter", "Cumulative time from request completion to first response."},
	{"mongosniffer_operation_first_response_seconds", "gauge", "Cumulative first response duration quantile since process start."},
	{"mongosniffer_operation_first_response_max_seconds", "gauge", "Maximum first response duration since process start."},
	{"mongosniffer_operation_response_transfer_observations_total", "counter", "Completed operations with an observed response transfer phase."},
	{"mongosniffer_operation_response_transfer_seconds_total", "counter", "Cumulative time from first response to terminal response."},
	{"mongosniffer_operation_response_transfer_seconds", "gauge", "Cumulative response transfer duration quantile since process start."},
	{"mongosniffer_operation_response_transfer_max_seconds", "gauge", "Maximum response transfer duration since process start."},
	{"mongosniffer_operation_incomplete_observed_duration_observations_total", "counter", "Incomplete operations with an observed diagnostic duration."},
	{"mongosniffer_operation_incomplete_observed_duration_seconds_total", "counter", "Cumulative observed duration of incomplete operations."},
	{"mongosniffer_operation_incomplete_observed_duration_seconds", "gauge", "Cumulative incomplete observed duration quantile since process start."},
	{"mongosniffer_operation_incomplete_observed_duration_max_seconds", "gauge", "Maximum observed duration of an incomplete operation since process start."},
	{"mongosniffer_returned_documents_total", "counter", "Documents returned by observed MongoDB operations."},
	{"mongosniffer_affected_documents_total", "counter", "Documents affected by observed MongoDB operations."},
	{"mongosniffer_request_protocol_bytes_total", "counter", "MongoDB request protocol bytes observed."},
	{"mongosniffer_response_protocol_bytes_total", "counter", "MongoDB response protocol bytes observed."},
	{"mongosniffer_capture_packets_total", "counter", "Packets delivered by the capture source."},
	{"mongosniffer_capture_matched_packets_total", "counter", "Packets matching the configured MongoDB endpoint."},
	{"mongosniffer_capture_kernel_drops_total", "counter", "Packets dropped by the capture kernel buffer."},
	{"mongosniffer_capture_interface_drops_total", "counter", "Packets dropped by the interface or capture backend."},
	{"mongosniffer_tcp_gap_events_total", "counter", "TCP reassembly gap events."},
	{"mongosniffer_tcp_skipped_bytes_total", "counter", "Bytes skipped because of bounded TCP gaps."},
	{"mongosniffer_tcp_sequence_discontinuities_total", "counter", "Unsafe TCP sequence discontinuities."},
	{"mongosniffer_connections_observed_total", "counter", "TCP connections observed."},
	{"mongosniffer_connections_handshake_observed_total", "counter", "Connections with an observed MongoDB handshake."},
	{"mongosniffer_connections_midstream_total", "counter", "Connections first observed after their initial client SYN."},
	{"mongosniffer_connections_protocol_state_loss_total", "counter", "Connections disabled after protocol state loss."},
	{"mongosniffer_completed_operations_total", "counter", "Completed acknowledged operations included in latency statistics."},
	{"mongosniffer_unacknowledged_operations_total", "counter", "Unacknowledged operations excluded from latency statistics."},
	{"mongosniffer_excluded_operations_total", "counter", "Incomplete acknowledged operations excluded from latency statistics."},
	{"mongosniffer_metadata_missing_operations_total", "counter", "Operations whose connection handshake metadata was not observed."},
	{"mongosniffer_encrypted_sessions_total", "counter", "MongoDB TLS sessions identified but not decrypted."},
	{"mongosniffer_decode_errors_total", "counter", "Packet, stream, or MongoDB protocol decode errors."},
	{"mongosniffer_fingerprint_truncations_total", "counter", "Fingerprints truncated at configured safety limits."},
	{"mongosniffer_dropped_operation_keys_total", "counter", "Operations dropped because the bounded aggregation key capacity was full."},
	{"mongosniffer_protocol_issues_total", "counter", "MongoDB protocol issues by bounded reason."},
}

func WritePrometheus(w io.Writer, r Report) error {
	write := func(format string, args ...any) error { _, err := fmt.Fprintf(w, format, args...); return err }
	for _, metric := range metricDescriptions {
		if err := write("# HELP %s %s\n# TYPE %s %s\n", metric.name, metric.help, metric.name, metric.kind); err != nil {
			return err
		}
	}
	for _, op := range r.Operations {
		labels := metricLabels(op.Dimensions, op.FingerprintID, op.Fingerprint)
		metrics := []struct {
			name  string
			value any
		}{
			{"mongosniffer_operation_calls_total", op.Calls}, {"mongosniffer_operation_errors_total", op.Errors},
			{"mongosniffer_operation_incomplete_total", op.Incomplete}, {"mongosniffer_operation_unacknowledged_total", op.Unacknowledged},
			{"mongosniffer_operation_duration_observations_total", op.LatencyMS.Observations},
			{"mongosniffer_operation_duration_seconds_total", op.LatencyMS.Total / 1000},
			{"mongosniffer_operation_duration_max_seconds", op.LatencyMS.Max / 1000},
			{"mongosniffer_returned_documents_total", op.ReturnedDocuments}, {"mongosniffer_affected_documents_total", op.AffectedDocuments},
			{"mongosniffer_request_protocol_bytes_total", op.RequestProtocolBytes}, {"mongosniffer_response_protocol_bytes_total", op.ResponseProtocolBytes},
		}
		for _, metric := range metrics {
			if err := write("%s{%s} %v\n", metric.name, labels, metric.value); err != nil {
				return err
			}
		}
		if err := writeQuantiles(write, "mongosniffer_operation_duration", labels, op.LatencyMS.P95, op.LatencyMS.P99); err != nil {
			return err
		}
		if err := writePhaseMetrics(write, "first_response", labels, op.LatencyMS.FirstResponse); err != nil {
			return err
		}
		if err := writePhaseMetrics(write, "response_transfer", labels, op.LatencyMS.ResponseTransfer); err != nil {
			return err
		}
		incomplete := PhaseSummary{}
		if op.IncompleteObservedMS != nil {
			incomplete = *op.IncompleteObservedMS
		}
		if err := writePhaseMetrics(write, "incomplete_observed_duration", labels, incomplete); err != nil {
			return err
		}
	}
	globals := []struct {
		name  string
		value uint64
	}{
		{"mongosniffer_capture_packets_total", r.Capture.PacketsSeen}, {"mongosniffer_capture_matched_packets_total", r.Capture.PacketsMatched},
		{"mongosniffer_capture_kernel_drops_total", r.Capture.KernelPacketsDropped}, {"mongosniffer_capture_interface_drops_total", r.Capture.InterfacePacketsDropped},
		{"mongosniffer_tcp_gap_events_total", r.Capture.TCPGapEvents}, {"mongosniffer_tcp_skipped_bytes_total", r.Capture.TCPBytesSkipped},
		{"mongosniffer_tcp_sequence_discontinuities_total", r.Capture.TCPSequenceDiscontinuities}, {"mongosniffer_connections_observed_total", r.Capture.ConnectionsObserved},
		{"mongosniffer_connections_handshake_observed_total", r.Capture.HandshakeObservedConnections}, {"mongosniffer_connections_midstream_total", r.Capture.MidstreamConnections},
		{"mongosniffer_connections_protocol_state_loss_total", r.Capture.ProtocolStateLossConnections}, {"mongosniffer_completed_operations_total", r.DataQuality.CompletedOperations},
		{"mongosniffer_unacknowledged_operations_total", r.DataQuality.UnacknowledgedOperations}, {"mongosniffer_excluded_operations_total", r.DataQuality.ExcludedOperations},
		{"mongosniffer_metadata_missing_operations_total", r.DataQuality.MetadataMissingOperations}, {"mongosniffer_encrypted_sessions_total", r.EncryptedSessions},
		{"mongosniffer_decode_errors_total", r.DecodeErrors}, {"mongosniffer_fingerprint_truncations_total", r.FingerprintTruncations},
		{"mongosniffer_dropped_operation_keys_total", r.DroppedOperationKeys},
	}
	for _, metric := range globals {
		if err := write("%s %d\n", metric.name, metric.value); err != nil {
			return err
		}
	}
	issues := make([]string, 0, len(r.ProtocolIssues))
	for issue := range r.ProtocolIssues {
		issues = append(issues, issue)
	}
	sort.Strings(issues)
	for _, issue := range issues {
		if err := write("mongosniffer_protocol_issues_total{issue=\"%s\"} %d\n", labelValue(issue), r.ProtocolIssues[issue]); err != nil {
			return err
		}
	}
	return nil
}

func writeQuantiles(write func(string, ...any) error, prefix, labels string, p95, p99 float64) error {
	if err := write("%s_seconds{%s,quantile=\"0.95\"} %g\n", prefix, labels, p95/1000); err != nil {
		return err
	}
	return write("%s_seconds{%s,quantile=\"0.99\"} %g\n", prefix, labels, p99/1000)
}

func writePhaseMetrics(write func(string, ...any) error, phase, labels string, value PhaseSummary) error {
	prefix := "mongosniffer_operation_" + phase
	if err := write("%s_observations_total{%s} %d\n", prefix, labels, value.Observations); err != nil {
		return err
	}
	if err := write("%s_seconds_total{%s} %g\n", prefix, labels, value.Total/1000); err != nil {
		return err
	}
	if err := write("%s_max_seconds{%s} %g\n", prefix, labels, value.Max/1000); err != nil {
		return err
	}
	return writeQuantiles(write, prefix, labels, value.P95, value.P99)
}
