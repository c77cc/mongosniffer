package report

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/c77cc/mongosniffer/bsonshape"
	"github.com/c77cc/mongosniffer/model"
)

type BuildInfo struct {
	Version  string `json:"version"`
	Revision string `json:"revision,omitempty"`
}

type Dimensions struct {
	Command         string `json:"command"`
	Database        string `json:"database,omitempty"`
	Collection      string `json:"collection,omitempty"`
	ApplicationName string `json:"application_name,omitempty"`
	DriverName      string `json:"driver_name,omitempty"`
	ClientAddress   string `json:"client_address,omitempty"`
	ServerAddress   string `json:"server_address,omitempty"`
	Transactional   bool   `json:"transactional"`
	RetryableWrite  bool   `json:"retryable_write"`
	CursorKind      string `json:"cursor_kind,omitempty"`
}

type DimensionStatus struct {
	HandshakeObserved bool     `json:"handshake_observed"`
	Missing           []string `json:"missing,omitempty"`
}
type PhaseSummary struct {
	Observations uint64  `json:"observations"`
	Average      float64 `json:"average"`
	Min          float64 `json:"min"`
	P95          float64 `json:"p95"`
	P99          float64 `json:"p99"`
	Max          float64 `json:"max"`
	Total        float64 `json:"total"`
}
type LatencySummary struct {
	Observations     uint64       `json:"observations"`
	Average          float64      `json:"average"`
	Min              float64      `json:"min"`
	P95              float64      `json:"p95"`
	P99              float64      `json:"p99"`
	Max              float64      `json:"max"`
	Total            float64      `json:"total"`
	FirstResponse    PhaseSummary `json:"first_response"`
	ResponseTransfer PhaseSummary `json:"response_transfer"`
}

type OperationSummary struct {
	FingerprintID         string            `json:"fingerprint_id"`
	Fingerprint           string            `json:"fingerprint"`
	Dimensions            Dimensions        `json:"dimensions"`
	DimensionStatus       DimensionStatus   `json:"dimension_status"`
	Calls                 uint64            `json:"calls"`
	Acknowledged          uint64            `json:"acknowledged"`
	Unacknowledged        uint64            `json:"unacknowledged"`
	Errors                uint64            `json:"errors"`
	Incomplete            uint64            `json:"incomplete"`
	ReturnedDocuments     int64             `json:"returned_documents"`
	AffectedDocuments     int64             `json:"affected_documents"`
	ModifiedDocuments     int64             `json:"modified_documents"`
	Upserts               int64             `json:"upserts"`
	WriteErrors           int64             `json:"write_errors"`
	WriteConcernErrors    int64             `json:"write_concern_errors"`
	RequestProtocolBytes  int64             `json:"request_protocol_bytes"`
	ResponseProtocolBytes int64             `json:"response_protocol_bytes"`
	ErrorCodes            map[string]uint64 `json:"error_codes,omitempty"`
	ErrorCodeNames        map[string]uint64 `json:"error_code_names,omitempty"`
	WriteErrorCodes       map[string]uint64 `json:"write_error_codes,omitempty"`
	WriteConcernCodes     map[string]uint64 `json:"write_concern_error_codes,omitempty"`
	ErrorLabels           map[string]uint64 `json:"error_labels,omitempty"`
	IncompleteReasons     map[string]uint64 `json:"incomplete_reasons,omitempty"`
	Compression           map[string]uint64 `json:"compression,omitempty"`
	LatencyMS             LatencySummary    `json:"latency_ms"`
	IncompleteObservedMS  *PhaseSummary     `json:"incomplete_observed_duration_ms,omitempty"`
}

type DataQuality struct {
	CompletedOperations       uint64  `json:"completed_operations"`
	UnacknowledgedOperations  uint64  `json:"unacknowledged_operations"`
	ExcludedOperations        uint64  `json:"excluded_operations"`
	ExcludedPercentage        float64 `json:"excluded_percentage"`
	MetadataMissingOperations uint64  `json:"metadata_missing_operations"`
}

type Report struct {
	SchemaVersion          int                `json:"schema_version"`
	Build                  BuildInfo          `json:"build"`
	GeneratedAt            time.Time          `json:"generated_at"`
	Operations             []OperationSummary `json:"operations"`
	ControlCounters        map[string]uint64  `json:"control_counters,omitempty"`
	Capture                model.CaptureStats `json:"capture"`
	DataQuality            DataQuality        `json:"data_quality"`
	EncryptedSessions      uint64             `json:"encrypted_sessions"`
	DecodeErrors           uint64             `json:"decode_errors"`
	ProtocolIssues         map[string]uint64  `json:"protocol_issues"`
	FingerprintTruncations uint64             `json:"fingerprint_truncations"`
	DroppedOperationKeys   uint64             `json:"dropped_operation_keys"`
}

type key struct {
	fingerprintKey, fingerprintID, fingerprint, command, database, collection, application, driver, client, server, cursorKind string
	transactional, retryable                                                                                                   bool
}

type group struct {
	key                                                                    key
	calls, acknowledged, unacknowledged, errors, incomplete                uint64
	returned, affected, modified, upserts, writeErrors, writeConcernErrors int64
	requestBytes, responseBytes                                            int64
	errorCodes, errorCodeNames, writeErrorCodes, writeConcernCodes         map[string]uint64
	errorLabels, incompleteReasons, compression                            map[string]uint64
	handshakeObserved                                                      bool
	metadataMissing                                                        uint64
	latency, firstResponse, responseTransfer, incompleteObserved           histogram
}

type Collector struct {
	mu                                            sync.RWMutex
	maxGroups                                     int
	includeSystem                                 bool
	groups                                        map[key]*group
	control                                       map[string]uint64
	capture                                       model.CaptureStats
	quality                                       DataQuality
	encrypted, decodeErrors, dropped, truncations uint64
	issues                                        map[string]uint64
}

func NewCollector(maxGroups int, includeSystem bool) *Collector {
	if maxGroups <= 0 {
	}
	return &Collector{maxGroups: maxGroups, includeSystem: includeSystem, groups: make(map[key]*group), control: make(map[string]uint64), issues: make(map[string]uint64)}
}

func (c *Collector) Add(e model.OperationEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if bsonshape.IsControl(e.Command) {
		c.control[e.Command]++
		if !c.includeSystem {
			return
		}
	}
	if e.FingerprintTruncated {
		c.truncations++
	}
	fingerprintKey := e.FingerprintKey
	if fingerprintKey == "" {
		fingerprintKey = e.Fingerprint
	}
	fingerprintID := e.FingerprintID
	if fingerprintID == "" {
		fingerprintID = bsonshape.FingerprintHash(fingerprintKey)
	}
	k := key{fingerprintKey: fingerprintKey, fingerprintID: fingerprintID, fingerprint: e.Fingerprint, command: e.Command, database: e.Database, collection: e.Collection, application: e.Metadata.ApplicationName, driver: e.Metadata.DriverName, client: e.Metadata.ClientAddress, server: e.Metadata.ServerAddress, cursorKind: e.CursorKind, transactional: e.Transactional, retryable: e.RetryableWrite}
	g := c.groups[k]
	if g == nil {
		if len(c.groups) >= c.maxGroups {
			c.dropped++
			c.updateQuality(e, false)
			return
		}
		g = &group{key: k, errorCodes: map[string]uint64{}, errorCodeNames: map[string]uint64{}, writeErrorCodes: map[string]uint64{}, writeConcernCodes: map[string]uint64{}, errorLabels: map[string]uint64{}, incompleteReasons: map[string]uint64{}, compression: map[string]uint64{}}
		c.groups[k] = g
	}
	g.calls++
	if e.Acknowledged {
		g.acknowledged++
	} else {
		g.unacknowledged++
	}
	if e.Incomplete {
		g.incomplete++
		g.incompleteReasons[e.IncompleteReason]++
		g.incompleteObserved.Add(e.Duration)
	}
	if e.Result.Error {
		g.errors++
	}
	if e.Result.ErrorCode != 0 {
		g.errorCodes[strconv.FormatInt(e.Result.ErrorCode, 10)]++
	}
	if e.Result.ErrorCodeName != "" {
		g.errorCodeNames[e.Result.ErrorCodeName]++
	}
	for code, count := range e.Result.WriteErrorCodes {
		g.writeErrorCodes[strconv.FormatInt(code, 10)] += uint64(count)
	}
	for code, count := range e.Result.WriteConcernCodes {
		g.writeConcernCodes[strconv.FormatInt(code, 10)] += uint64(count)
	}
	for _, label := range e.Result.ErrorLabels {
		g.errorLabels[label]++
	}
	g.returned += e.Result.ReturnedDocuments
	g.affected += e.Result.AffectedDocuments
	g.modified += e.Result.ModifiedDocuments
	g.upserts += e.Result.Upserts
	g.writeErrors += e.Result.WriteErrors
	g.writeConcernErrors += e.Result.WriteConcernErrors
	g.requestBytes += e.RequestBytes
	g.responseBytes += e.Result.ResponseBytes
	g.compression[e.Compression]++
	g.handshakeObserved = g.handshakeObserved || e.Metadata.HandshakeObserved
	if !e.Metadata.HandshakeObserved {
		g.metadataMissing++
		c.quality.MetadataMissingOperations++
	}
	if e.Acknowledged && !e.Incomplete {
		g.latency.Add(e.Duration)
		if !e.FirstResponseAt.IsZero() {
			g.firstResponse.Add(e.FirstResponse)
			g.responseTransfer.Add(e.ResponseTransfer)
		}
		c.quality.CompletedOperations++
	} else if !e.Acknowledged {
		c.quality.UnacknowledgedOperations++
	} else {
		c.quality.ExcludedOperations++
	}
}

func (c *Collector) updateQuality(e model.OperationEvent, excluded bool) {
	if !e.Metadata.HandshakeObserved {
		c.quality.MetadataMissingOperations++
	}
	if excluded {
		c.quality.ExcludedOperations++
		return
	}
	if !e.Acknowledged {
		c.quality.UnacknowledgedOperations++
	} else if e.Incomplete {
		c.quality.ExcludedOperations++
	} else {
		c.quality.CompletedOperations++
	}
}

func (c *Collector) AddIssue(issue string)     { c.mu.Lock(); c.issues[issue]++; c.mu.Unlock() }
func (c *Collector) AddDecodeError()           { c.mu.Lock(); c.decodeErrors++; c.mu.Unlock() }
func (c *Collector) AddEncryptedSession()      { c.mu.Lock(); c.encrypted++; c.mu.Unlock() }
func (c *Collector) AddFingerprintTruncation() { c.mu.Lock(); c.truncations++; c.mu.Unlock() }
func (c *Collector) AddPacket(seenBytes int, matched, truncated bool) {
	c.mu.Lock()
	c.capture.PacketsSeen++
	c.capture.BytesCaptured += uint64(max(seenBytes, 0))
	if matched {
		c.capture.PacketsMatched++
	}
	if truncated {
		c.capture.TruncatedPackets++
	}
	c.mu.Unlock()
}
func (c *Collector) AddConnection(midstream bool) {
	c.mu.Lock()
	c.capture.ConnectionsObserved++
	if midstream {
		c.capture.MidstreamConnections++
	}
	c.mu.Unlock()
}
func (c *Collector) AddHandshakeConnection() {
	c.mu.Lock()
	c.capture.HandshakeObservedConnections++
	c.mu.Unlock()
}
func (c *Collector) AddProtocolStateLoss() {
	c.mu.Lock()
	c.capture.ProtocolStateLossConnections++
	c.mu.Unlock()
}
func (c *Collector) AddTCPGap(skipped int) {
	c.mu.Lock()
	c.capture.TCPGapEvents++
	c.capture.TCPBytesSkipped += uint64(max(skipped, 0))
	c.mu.Unlock()
}
func (c *Collector) AddTCPSequenceDiscontinuity() {
	c.mu.Lock()
	c.capture.TCPSequenceDiscontinuities++
	c.mu.Unlock()
}
func (c *Collector) SetCaptureDrops(kernel, iface uint64) {
	c.mu.Lock()
	c.capture.KernelPacketsDropped = kernel
	c.capture.InterfacePacketsDropped = iface
	c.mu.Unlock()
}

func (c *Collector) Snapshot(build BuildInfo, limit int) Report {
	c.mu.RLock()
	defer c.mu.RUnlock()
	operations := make([]OperationSummary, 0, len(c.groups))
	for _, g := range c.groups {
		operations = append(operations, summarize(g))
	}
	sort.Slice(operations, func(i, j int) bool {
		if operations[i].LatencyMS.Max == operations[j].LatencyMS.Max {
			if operations[i].Fingerprint == operations[j].Fingerprint {
				return operations[i].FingerprintID < operations[j].FingerprintID
			}
			return operations[i].Fingerprint < operations[j].Fingerprint
		}
		return operations[i].LatencyMS.Max > operations[j].LatencyMS.Max
	})
	if limit > 0 && len(operations) > limit {
		operations = operations[:limit]
	}
	quality := c.quality
	total := quality.CompletedOperations + quality.UnacknowledgedOperations + quality.ExcludedOperations
	if total > 0 {
		quality.ExcludedPercentage = float64(quality.ExcludedOperations) * 100 / float64(total)
	}
	return Report{SchemaVersion: 1, Build: build, GeneratedAt: time.Now(), Operations: operations, ControlCounters: cloneMap(c.control), Capture: c.capture, DataQuality: quality, EncryptedSessions: c.encrypted, DecodeErrors: c.decodeErrors, ProtocolIssues: cloneMap(c.issues), FingerprintTruncations: c.truncations, DroppedOperationKeys: c.dropped}
}

func summarize(g *group) OperationSummary {
	missing := []string{}
	if !g.handshakeObserved {
		missing = []string{"application_name", "driver_name"}
	}
	var incompleteObserved *PhaseSummary
	if g.incompleteObserved.count > 0 {
		value := summarizePhase(g.incompleteObserved)
		incompleteObserved = &value
	}
	return OperationSummary{FingerprintID: g.key.fingerprintID, Fingerprint: g.key.fingerprint, Dimensions: Dimensions{Command: g.key.command, Database: g.key.database, Collection: g.key.collection, ApplicationName: g.key.application, DriverName: g.key.driver, ClientAddress: g.key.client, ServerAddress: g.key.server, Transactional: g.key.transactional, RetryableWrite: g.key.retryable, CursorKind: g.key.cursorKind}, DimensionStatus: DimensionStatus{HandshakeObserved: g.handshakeObserved, Missing: missing}, Calls: g.calls, Acknowledged: g.acknowledged, Unacknowledged: g.unacknowledged, Errors: g.errors, Incomplete: g.incomplete, ReturnedDocuments: g.returned, AffectedDocuments: g.affected, ModifiedDocuments: g.modified, Upserts: g.upserts, WriteErrors: g.writeErrors, WriteConcernErrors: g.writeConcernErrors, RequestProtocolBytes: g.requestBytes, ResponseProtocolBytes: g.responseBytes, ErrorCodes: cloneMap(g.errorCodes), ErrorCodeNames: cloneMap(g.errorCodeNames), WriteErrorCodes: cloneMap(g.writeErrorCodes), WriteConcernCodes: cloneMap(g.writeConcernCodes), ErrorLabels: cloneMap(g.errorLabels), IncompleteReasons: cloneMap(g.incompleteReasons), Compression: cloneMap(g.compression), LatencyMS: LatencySummary{Observations: g.latency.count, Average: g.latency.AverageMS(), Min: g.latency.MinMS(), P95: g.latency.QuantileMS(.95), P99: g.latency.QuantileMS(.99), Max: g.latency.MaxMS(), Total: g.latency.TotalMS(), FirstResponse: summarizePhase(g.firstResponse), ResponseTransfer: summarizePhase(g.responseTransfer)}, IncompleteObservedMS: incompleteObserved}
}

func summarizePhase(h histogram) PhaseSummary {
	return PhaseSummary{Observations: h.count, Average: h.AverageMS(), Min: h.MinMS(), P95: h.QuantileMS(.95), P99: h.QuantileMS(.99), Max: h.MaxMS(), Total: h.TotalMS()}
}

func cloneMap[K comparable](in map[K]uint64) map[K]uint64 {
	if len(in) == 0 {
		return nil
	}
	out := make(map[K]uint64, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

const histogramBins = 384

type histogram struct {
	count           uint64
	total, min, max time.Duration
	bins            [histogramBins]uint64
}

func (h *histogram) Add(v time.Duration) {
	if v < 0 {
		v = 0
	}
	h.count++
	h.total += v
	if h.count == 1 || v < h.min {
		h.min = v
	}
	if v > h.max {
		h.max = v
	}
	h.bins[durationBin(v)]++
}
func durationBin(v time.Duration) int {
	if v <= 0 {
		return 0
	}
	idx := int(math.Log(float64(v)+1) / math.Log(1.08))
	if idx >= histogramBins {
		return histogramBins - 1
	}
	return idx
}
func binDuration(i int) time.Duration {
	if i <= 0 {
		return 0
	}
	return time.Duration(math.Pow(1.08, float64(i)) - 1)
}
func (h histogram) QuantileMS(q float64) float64 {
	if h.count == 0 {
		return 0
	}
	target := uint64(math.Ceil(float64(h.count) * q))
	var n uint64
	for i, count := range h.bins {
		n += count
		if n >= target {
			v := binDuration(i)
			if v < h.min {
				v = h.min
			}
			if v > h.max {
				v = h.max
			}
			return ms(v)
		}
	}
	return ms(h.max)
}
func (h histogram) AverageMS() float64 {
	if h.count == 0 {
		return 0
	}
	return float64(h.total) / float64(h.count) / float64(time.Millisecond)
}
func (h histogram) MinMS() float64   { return ms(h.min) }
func (h histogram) MaxMS() float64   { return ms(h.max) }
func (h histogram) TotalMS() float64 { return ms(h.total) }
func ms(v time.Duration) float64     { return math.Round(float64(v)/float64(time.Millisecond)*1000) / 1000 }

func labelValue(v string) string {
	return strings.NewReplacer("\\", "\\\\", "\n", "\\n", `"`, `\"`).Replace(v)
}
func metricLabels(d Dimensions, fingerprintID, fingerprint string) string {
	return fmt.Sprintf(`fingerprint_id="%s",fingerprint="%s",command="%s",database="%s",collection="%s",application="%s",driver="%s",client="%s",server="%s",transactional="%t",retryable_write="%t"`, labelValue(fingerprintID), labelValue(fingerprint), labelValue(d.Command), labelValue(d.Database), labelValue(d.Collection), labelValue(d.ApplicationName), labelValue(d.DriverName), labelValue(d.ClientAddress), labelValue(d.ServerAddress), d.Transactional, d.RetryableWrite)
}
