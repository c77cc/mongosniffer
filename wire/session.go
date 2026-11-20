package wire

import (
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/c77cc/mongosniffer/bsonshape"
	"github.com/c77cc/mongosniffer/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
)

type SessionConfig struct {
	Decode           DecodeLimits
	Fingerprint      bsonshape.Limits
	MaxPending       int
	MaxResponseChain int
	MaxCursors       int
	Metadata         model.ConnectionMetadata
	OnEvent          func(model.OperationEvent)
	OnIssue          func(string)
	OnEncrypted      func()
	RawCommand       bool
	GroupByRaw       bool
	CursorBudget     *CursorBudget
}

type CursorBudget struct{ max, used atomic.Int64 }

func NewCursorBudget(maximum int64) *CursorBudget {
	budget := &CursorBudget{}
	budget.max.Store(maximum)
	return budget
}
func (b *CursorBudget) acquire() bool {
	if b == nil {
		return true
	}
	for {
		used := b.used.Load()
		if used >= b.max.Load() {
			return false
		}
		if b.used.CompareAndSwap(used, used+1) {
			return true
		}
	}
}
func (b *CursorBudget) release(count int) {
	if b != nil && count > 0 {
		b.used.Add(-int64(count))
	}
}

type pendingRequest struct {
	id                 uint32
	command            bsonshape.Command
	startedAt          time.Time
	requestCompletedAt time.Time
	firstResponseAt    time.Time
	requestBytes       int64
	compression        string
	responseCount      int
	result             model.ResultSummary
	cursorID           int64
	killCursorIDs      []int64
}

type cursorOrigin struct {
	namespace, command, fingerprintHash, kind string
	lastSeen                                  time.Time
}

type directionState struct {
	framer *Framer
	probe  []byte
	probed bool
}

type Session struct {
	cfg                         SessionConfig
	directions                  [2]directionState
	pending                     map[uint32]*pendingRequest
	chains                      map[uint32]uint32
	cursors                     map[int64]cursorOrigin
	metadata                    model.ConnectionMetadata
	encrypted, disabled, closed bool
}

func NewSession(cfg SessionConfig) *Session {
	if cfg.Decode.FrameLimit == 0 {
		cfg.Decode = DefaultDecodeLimits()
	}
	if cfg.Fingerprint.MaxDepth == 0 {
		cfg.Fingerprint = bsonshape.DefaultLimits()
	}
	if cfg.MaxPending <= 0 {
		cfg.MaxPending = 4096
	}
	if cfg.MaxResponseChain <= 0 {
		cfg.MaxResponseChain = 4096
	}
	if cfg.MaxCursors <= 0 {
		cfg.MaxCursors = 4096
	}
	s := &Session{cfg: cfg, metadata: cfg.Metadata, pending: make(map[uint32]*pendingRequest), chains: make(map[uint32]uint32), cursors: make(map[int64]cursorOrigin)}
	s.directions[0].framer = NewFramer(cfg.Decode.FrameLimit)
	s.directions[1].framer = NewFramer(cfg.Decode.FrameLimit)
	return s
}

func (s *Session) Metadata() model.ConnectionMetadata { return s.metadata }
func (s *Session) Encrypted() bool                    { return s.encrypted }
func (s *Session) Disabled() bool                     { return s.disabled }

func (s *Session) FeedSpan(direction model.Direction, data []byte, startedAt, completedAt time.Time) error {
	if s.closed {
		return errors.New("session is closed")
	}
	if s.disabled || s.encrypted || len(data) == 0 {
		return nil
	}
	if direction != model.ClientToServer && direction != model.ServerToClient {
		return errors.New("invalid direction")
	}
	d := &s.directions[int(direction)]
	if !d.probed {
		d.probe = append(d.probe, data...)
		if len(d.probe) < 5 {
			return nil
		}
		d.probed = true
		if looksLikeTLS(d.probe[:5]) {
			s.encrypted = true
			if s.cfg.OnEncrypted != nil {
				s.cfg.OnEncrypted()
			}
			return nil
		}
		data = d.probe
		d.probe = nil
	}
	err := d.framer.Feed(data, startedAt, completedAt, func(frame Frame) error { return s.handleFrame(direction, frame) })
	if err != nil {
		reason := issueReason(err)
		s.issue(reason)
		s.finishPending(completedAt, reason)
		s.disabled = true
	}
	return err
}

func (s *Session) handleFrame(direction model.Direction, frame Frame) error {
	msg, err := ParseMessage(frame.Bytes, s.cfg.Decode)
	if err != nil {
		if strings.Contains(err.Error(), "legacy_or_unsupported_opcode") {
			s.issue("legacy_or_unsupported_opcode")
			return nil
		}
		return err
	}
	if msg.UnknownOptionalFlags != 0 {
		s.issue("unknown_optional_flag")
	}
	cmd, err := bsonshape.ParseCommand(msg.Body, msg.Sequences, s.cfg.Fingerprint)
	if err != nil {
		return fmt.Errorf("invalid_bson: %w", err)
	}
	if s.cfg.RawCommand {
		raw, rawErr := bsonshape.RedactedRawCommandWithSequences(msg.Body, msg.Sequences)
		if rawErr != nil {
			return fmt.Errorf("invalid_bson: %w", rawErr)
		}
		cmd.RawCommand = raw
		if s.cfg.GroupByRaw {
			cmd.Fingerprint = raw
			cmd.GroupKey = raw
			cmd.FingerprintID = bsonshape.FingerprintHash(raw)
		}
	}
	if msg.Compression != "" && forbiddenCompressed(cmd.Name) {
		s.issue("forbidden_compressed_command")
	}
	if direction == model.ClientToServer {
		return s.handleRequest(frame, msg, cmd)
	}
	return s.handleResponse(frame, msg)
}

func (s *Session) handleRequest(frame Frame, msg Message, cmd bsonshape.Command) error {
	s.observeClientMetadata(cmd.Name, msg.Body)
	if cmd.Name == "getmore" {
		doc := bson.Raw(msg.Body)
		cmd.Collection = stringValue(doc.Lookup("collection"))
		cmd.Database = stringValue(doc.Lookup("$db"))
		if cmd.Database != "" && cmd.Collection != "" {
			cmd.Namespace = cmd.Database + "." + cmd.Collection
			cmd.Fingerprint = "getmore " + cmd.Namespace
			cmd.GroupKey += " namespace " + cmd.Namespace
		}
		cursorID := integer(doc.Lookup("getMore"))
		if origin, ok := s.cursors[cursorID]; ok {
			cmd.Fingerprint += " origin " + origin.fingerprintHash
			cmd.GroupKey += " origin " + origin.fingerprintHash
			cmd.FingerprintID = bsonshape.FingerprintHash(cmd.GroupKey)
			cmd.CursorKind = origin.kind
		}
		cmd.FingerprintID = bsonshape.FingerprintHash(cmd.GroupKey)
	}
	var killCursorIDs []int64
	if cmd.Name == "killcursors" {
		killCursorIDs = int64Array(bson.Raw(msg.Body).Lookup("cursors"), s.cfg.MaxCursors)
	}
	if _, exists := s.pending[msg.Header.RequestID]; exists {
		return errors.New("duplicate_request_id")
	}
	p := &pendingRequest{id: msg.Header.RequestID, command: cmd, startedAt: frame.StartedAt, requestCompletedAt: frame.CompletedAt, requestBytes: msg.ProtocolBytes, compression: defaultCompression(msg.Compression), killCursorIDs: killCursorIDs}
	if cmd.Name == "getmore" {
		p.cursorID = integer(bson.Raw(msg.Body).Lookup("getMore"))
	}
	if msg.Flags&FlagMoreToCome != 0 {
		s.emit(s.eventFor(p, frame.CompletedAt, false, ""))
		return nil
	}
	if len(s.pending) >= s.cfg.MaxPending {
		return errors.New("pending_limit")
	}
	s.pending[p.id] = p
	return nil
}

func (s *Session) handleResponse(frame Frame, msg Message) error {
	root := msg.Header.ResponseTo
	p, ok := s.pending[root]
	if !ok {
		if chainedRoot, chainOK := s.chains[root]; chainOK {
			root = chainedRoot
			p, ok = s.pending[root]
			delete(s.chains, msg.Header.ResponseTo)
		}
	}
	if !ok {
		s.issue("unknown_response_to")
		return nil
	}
	if p.firstResponseAt.IsZero() {
		p.firstResponseAt = frame.StartedAt
	}
	p.responseCount++
	if p.responseCount > s.cfg.MaxResponseChain {
		return errors.New("response_chain_limit")
	}
	mergeResult(&p.result, parseResult(msg.Body, msg.ProtocolBytes))
	if isHello(p.command.Name) {
		s.observeServerMetadata(msg.Body)
	}
	if msg.Flags&FlagMoreToCome != 0 {
		s.chains[msg.Header.RequestID] = root
		return nil
	}
	delete(s.pending, root)
	for responseID, chainRoot := range s.chains {
		if chainRoot == root {
			delete(s.chains, responseID)
		}
	}
	if p.result.CursorNonZero && !p.result.Error {
		s.rememberCursor(p, frame.CompletedAt)
	}
	if p.command.Name == "killcursors" && !p.result.Error {
		for _, id := range p.killCursorIDs {
			s.deleteCursor(id)
		}
	}
	if p.cursorID != 0 && !p.result.CursorNonZero {
		s.deleteCursor(p.cursorID)
	}
	s.emit(s.eventFor(p, frame.CompletedAt, true, ""))
	return nil
}

func (s *Session) rememberCursor(p *pendingRequest, at time.Time) {
	if p.result.CursorID == 0 {
		return
	}
	if p.command.Name == "getmore" {
		if origin, ok := s.cursors[p.cursorID]; ok {
			delete(s.cursors, p.cursorID)
			origin.lastSeen = at
			s.cursors[p.result.CursorID] = origin
			return
		}
	}
	if len(s.cursors) >= s.cfg.MaxCursors {
		s.issue("cursor_limit")
		return
	}
	if _, exists := s.cursors[p.result.CursorID]; !exists && !s.cfg.CursorBudget.acquire() {
		s.issue("cursor_limit")
		return
	}
	ns := p.result.CursorNamespace
	if ns == "" {
		ns = p.command.Namespace
	}
	s.cursors[p.result.CursorID] = cursorOrigin{namespace: ns, command: p.command.Name, fingerprintHash: p.command.FingerprintID, kind: p.command.CursorKind, lastSeen: at}
}

func (s *Session) deleteCursor(id int64) {
	if _, exists := s.cursors[id]; exists {
		delete(s.cursors, id)
		s.cfg.CursorBudget.release(1)
	}
}
func (s *Session) clearCursors() {
	s.cfg.CursorBudget.release(len(s.cursors))
	s.cursors = make(map[int64]cursorOrigin)
}

func (s *Session) eventFor(p *pendingRequest, finishedAt time.Time, acknowledged bool, incompleteReason string) model.OperationEvent {
	e := model.OperationEvent{
		Command: p.command.Name, Database: p.command.Database, Collection: p.command.Collection,
		Fingerprint: p.command.Fingerprint, FingerprintID: p.command.FingerprintID, FingerprintKey: p.command.GroupKey, RawCommand: p.command.RawCommand, FingerprintTruncated: p.command.Truncated, StartedAt: p.requestCompletedAt, FinishedAt: finishedAt,
		Acknowledged: acknowledged, Incomplete: incompleteReason != "", IncompleteReason: incompleteReason,
		Transactional: p.command.Transactional, RetryableWrite: p.command.RetryableWrite, CursorKind: p.command.CursorKind,
		RequestBytes: p.requestBytes, Compression: p.compression, Metadata: s.metadata, Result: p.result,
	}
	if acknowledged {
		e.Duration = finishedAt.Sub(p.requestCompletedAt)
		if e.Duration < 0 {
			e.Duration = 0
		}
		if incompleteReason == "" && !p.firstResponseAt.IsZero() {
			e.FirstResponseAt = p.firstResponseAt
			e.FirstResponse = p.firstResponseAt.Sub(p.requestCompletedAt)
			e.ResponseTransfer = finishedAt.Sub(p.firstResponseAt)
		}
	}
	return e
}

func (s *Session) emit(e model.OperationEvent) {
	if s.cfg.OnEvent != nil {
		s.cfg.OnEvent(e)
	}
}
func (s *Session) issue(issue string) {
	if s.cfg.OnIssue != nil {
		s.cfg.OnIssue(issue)
	}
}

func (s *Session) Gap(at time.Time, skipped int) {
	if s.disabled || s.closed {
		return
	}
	s.issue("tcp_gap")
	s.finishPending(at, "tcp_gap")
	s.clearCursors()
	s.disabled = true
}

func (s *Session) Close(at time.Time, reason string) {
	if s.closed {
		return
	}
	s.closed = true
	if reason == "" {
		reason = "connection_closed"
	}
	s.finishPending(at, reason)
	s.cfg.CursorBudget.release(len(s.cursors))
	s.cursors = nil
}

func (s *Session) finishPending(at time.Time, reason string) {
	for _, p := range s.pending {
		s.emit(s.eventFor(p, at, true, reason))
	}
	s.pending = make(map[uint32]*pendingRequest)
	s.chains = make(map[uint32]uint32)
}

func (s *Session) observeClientMetadata(name string, body []byte) {
	if !isHello(name) {
		return
	}
	doc := bson.Raw(body)
	s.metadata.HandshakeObserved = true
	if client := doc.Lookup("client"); client.Type == bsontype.EmbeddedDocument {
		c := client.Document()
		if app := c.Lookup("application"); app.Type == bsontype.EmbeddedDocument {
			s.metadata.ApplicationName = limitedString(app.Document().Lookup("name"), 128)
		}
		if driver := c.Lookup("driver"); driver.Type == bsontype.EmbeddedDocument {
			s.metadata.DriverName = limitedString(driver.Document().Lookup("name"), 128)
			s.metadata.DriverVersion = limitedString(driver.Document().Lookup("version"), 64)
		}
		if osdoc := c.Lookup("os"); osdoc.Type == bsontype.EmbeddedDocument {
			s.metadata.OS = limitedString(osdoc.Document().Lookup("type"), 64)
		}
		s.metadata.Platform = limitedString(c.Lookup("platform"), 256)
	}
	s.metadata.CompressionOffered = stringArray(doc.Lookup("compression"), 16)
	s.metadata.LoadBalanced = boolValue(doc.Lookup("loadBalanced"))
	s.metadata.APIVersion = limitedString(doc.Lookup("apiVersion"), 32)
}

func (s *Session) observeServerMetadata(body []byte) {
	doc := bson.Raw(body)
	s.metadata.CompressionAccepted = stringArray(doc.Lookup("compression"), 16)
	s.metadata.MaxWireVersion = integer(doc.Lookup("maxWireVersion"))
	s.metadata.MaxMessageSizeBytes = integer(doc.Lookup("maxMessageSizeBytes"))
	s.metadata.MaxBSONObjectSize = integer(doc.Lookup("maxBsonObjectSize"))
	s.metadata.MaxWriteBatchSize = integer(doc.Lookup("maxWriteBatchSize"))
	s.metadata.ServiceIDPresent = doc.Lookup("serviceId").Type != 0
	max := integer(doc.Lookup("maxMessageSizeBytes"))
	if max >= HeaderSize {
		if max > AbsoluteFrameLimit {
			max = AbsoluteFrameLimit
		}
		for i := range s.directions {
			s.directions[i].framer.SetLimit(int(max))
		}
	}
}

func stringArray(v bson.RawValue, limit int) []string {
	if v.Type != bsontype.Array {
		return nil
	}
	vals, err := v.Array().Values()
	if err != nil {
		return nil
	}
	if len(vals) > limit {
		vals = vals[:limit]
	}
	out := make([]string, 0, len(vals))
	for _, value := range vals {
		if value.Type == bsontype.String {
			out = append(out, limitedString(value, 64))
		}
	}
	return out
}

func int64Array(v bson.RawValue, limit int) []int64 {
	if v.Type != bsontype.Array {
		return nil
	}
	values, err := v.Array().Values()
	if err != nil {
		return nil
	}
	if len(values) > limit {
		values = values[:limit]
	}
	out := make([]int64, 0, len(values))
	for _, value := range values {
		out = append(out, integer(value))
	}
	return out
}

func limitedString(v bson.RawValue, limit int) string {
	if v.Type != bsontype.String {
		return ""
	}
	value := v.StringValue()
	if len(value) > limit {
		return value[:limit]
	}
	return value
}
func defaultCompression(v string) string {
	if v == "" {
		return "uncompressed"
	}
	return v
}
func isHello(v string) bool { return v == "hello" || v == "ismaster" }
func forbiddenCompressed(v string) bool {
	return isHello(v) || isAuthCommand(v) || v == "createuser" || v == "updateuser"
}
func isAuthCommand(v string) bool {
	return v == "saslstart" || v == "saslcontinue" || v == "authenticate" || v == "getnonce"
}

func looksLikeTLS(v []byte) bool {
	if len(v) < 5 || v[0] < 20 || v[0] > 23 || v[1] != 3 || v[2] > 4 {
		return false
	}
	length := int(v[3])<<8 | int(v[4])
	return length > 0 && length <= 18432
}

func issueReason(err error) string {
	v := err.Error()
	for _, reason := range []string{"invalid_message_length", "checksum_mismatch", "decompression_failed", "unsupported_compressor", "unknown_required_flag", "unsupported_optional_section", "legacy_or_unsupported_opcode", "invalid_bson", "duplicate_request_id", "pending_limit", "response_chain_limit", "cursor_limit"} {
		if strings.Contains(v, reason) {
			return reason
		}
	}
	return "protocol_error"
}
