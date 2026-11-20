package wire

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"hash/crc32"
	"testing"
	"time"

	"github.com/c77cc/mongosniffer/model"
	"github.com/golang/snappy"
	"github.com/klauspost/compress/zstd"
	"go.mongodb.org/mongo-driver/bson"
)

func bsonDoc(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := bson.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func opmsg(t *testing.T, req, response uint32, flags uint32, body []byte) []byte {
	t.Helper()
	size := HeaderSize + 4 + 1 + len(body)
	if flags&FlagChecksumPresent != 0 {
		size += 4
	}
	out := make([]byte, size)
	binary.LittleEndian.PutUint32(out[:4], uint32(size))
	binary.LittleEndian.PutUint32(out[4:8], req)
	binary.LittleEndian.PutUint32(out[8:12], response)
	binary.LittleEndian.PutUint32(out[12:16], uint32(OpMsg))
	binary.LittleEndian.PutUint32(out[16:20], flags)
	out[20] = 0
	copy(out[21:], body)
	if flags&FlagChecksumPresent != 0 {
		binary.LittleEndian.PutUint32(out[len(out)-4:], crc32.Checksum(out[:len(out)-4], crc32.MakeTable(crc32.Castagnoli)))
	}
	return out
}
func compressedFrame(t *testing.T, original []byte, id byte) []byte {
	t.Helper()
	body := original[16:]
	var payload []byte
	switch id {
	case 0:
		payload = append([]byte(nil), body...)
	case 1:
		payload = snappy.Encode(nil, body)
	case 2:
		var b bytes.Buffer
		w := zlib.NewWriter(&b)
		_, _ = w.Write(body)
		_ = w.Close()
		payload = b.Bytes()
	case 3:
		enc, err := zstd.NewWriter(nil)
		if err != nil {
			t.Fatal(err)
		}
		payload = enc.EncodeAll(body, nil)
		enc.Close()
	}
	out := make([]byte, HeaderSize+9+len(payload))
	binary.LittleEndian.PutUint32(out[:4], uint32(len(out)))
	copy(out[4:12], original[4:12])
	binary.LittleEndian.PutUint32(out[12:16], uint32(OpCompressed))
	binary.LittleEndian.PutUint32(out[16:20], uint32(OpMsg))
	binary.LittleEndian.PutUint32(out[20:24], uint32(len(body)))
	out[24] = id
	copy(out[25:], payload)
	return out
}

func TestFramerSplitAndCoalesced(t *testing.T) {
	one := opmsg(t, 1, 0, 0, bsonDoc(t, bson.D{{Key: "ping", Value: 1}, {Key: "$db", Value: "admin"}}))
	two := opmsg(t, 2, 0, 0, bsonDoc(t, bson.D{{Key: "ping", Value: 1}, {Key: "$db", Value: "admin"}}))
	joined := append(one, two...)
	f := NewFramer(DefaultFrameLimit)
	var frames []Frame
	now := time.Now()
	if err := f.Feed(joined[:7], now, now, func(frame Frame) error { frames = append(frames, frame); return nil }); err != nil {
		t.Fatal(err)
	}
	if err := f.Feed(joined[7:], now, now, func(frame Frame) error { frames = append(frames, frame); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(frames) != 2 {
		t.Fatalf("frames = %d", len(frames))
	}
}

func TestOPMsgChecksumAndCompression(t *testing.T) {
	original := opmsg(t, 42, 0, FlagChecksumPresent, bsonDoc(t, bson.D{{Key: "find", Value: "orders"}, {Key: "$db", Value: "shop"}}))
	for _, id := range []byte{0, 1, 2, 3} {
		t.Run(string(rune('0'+id)), func(t *testing.T) {
			msg, err := ParseMessage(compressedFrame(t, original, id), DefaultDecodeLimits())
			if err != nil {
				t.Fatal(err)
			}
			if msg.Header.RequestID != 42 || msg.Compression == "" {
				t.Fatalf("message = %+v", msg)
			}
		})
	}
	broken := append([]byte(nil), original...)
	broken[len(broken)-1] ^= 1
	if _, err := ParseMessage(broken, DefaultDecodeLimits()); err == nil {
		t.Fatal("bad checksum accepted")
	}
}

func TestOPMsgSequenceBeforeBody(t *testing.T) {
	document := bsonDoc(t, bson.D{{Key: "x", Value: 1}})
	name := append([]byte("documents"), 0)
	sectionSize := 4 + len(name) + len(document)
	body := bsonDoc(t, bson.D{{Key: "insert", Value: "orders"}, {Key: "$db", Value: "shop"}})
	payload := make([]byte, 4)
	payload = append(payload, 1)
	payload = binary.LittleEndian.AppendUint32(payload, uint32(sectionSize))
	payload = append(payload, name...)
	payload = append(payload, document...)
	payload = append(payload, 0)
	payload = append(payload, body...)
	frame := make([]byte, 16+len(payload))
	binary.LittleEndian.PutUint32(frame[:4], uint32(len(frame)))
	binary.LittleEndian.PutUint32(frame[4:8], 7)
	binary.LittleEndian.PutUint32(frame[12:16], uint32(OpMsg))
	copy(frame[16:], payload)
	msg, err := ParseMessage(frame, DefaultDecodeLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(msg.Sequences) != 1 || msg.Sequences[0].Count != 1 {
		t.Fatalf("sequences = %+v", msg.Sequences)
	}
}

func TestSessionCorrelationExhaustUnacknowledgedAndTLS(t *testing.T) {
	var events []model.OperationEvent
	var issues []string
	session := NewSession(SessionConfig{OnEvent: func(e model.OperationEvent) { events = append(events, e) }, OnIssue: func(v string) { issues = append(issues, v) }})
	t0 := time.Unix(100, 0)
	request := opmsg(t, 10, 0, 0, bsonDoc(t, bson.D{{Key: "find", Value: "orders"}, {Key: "filter", Value: bson.D{{Key: "x", Value: 1}}}, {Key: "$db", Value: "shop"}}))
	first := opmsg(t, 20, 10, FlagMoreToCome, bsonDoc(t, bson.D{{Key: "ok", Value: 1}, {Key: "cursor", Value: bson.D{{Key: "id", Value: int64(9)}, {Key: "ns", Value: "shop.orders"}, {Key: "firstBatch", Value: bson.A{bson.D{{Key: "x", Value: 1}}}}}}}))
	last := opmsg(t, 21, 20, 0, bsonDoc(t, bson.D{{Key: "ok", Value: 1}, {Key: "cursor", Value: bson.D{{Key: "id", Value: int64(0)}, {Key: "ns", Value: "shop.orders"}, {Key: "nextBatch", Value: bson.A{}}}}}))
	if err := session.FeedSpan(model.ClientToServer, request, t0, t0.Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err := session.FeedSpan(model.ServerToClient, first, t0.Add(5*time.Millisecond), t0.Add(6*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err := session.FeedSpan(model.ServerToClient, last, t0.Add(8*time.Millisecond), t0.Add(9*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Result.ReturnedDocuments != 1 || events[0].Duration != 8*time.Millisecond {
		t.Fatalf("events = %+v, issues=%v", events, issues)
	}
	w0 := opmsg(t, 11, 0, FlagMoreToCome, bsonDoc(t, bson.D{{Key: "insert", Value: "orders"}, {Key: "$db", Value: "shop"}}))
	if err := session.FeedSpan(model.ClientToServer, w0, t0, t0); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].Acknowledged {
		t.Fatalf("w:0 event = %+v", events)
	}
	encrypted := false
	tls := NewSession(SessionConfig{OnEncrypted: func() { encrypted = true }})
	if err := tls.FeedSpan(model.ClientToServer, []byte{22, 3}, t0, t0); err != nil {
		t.Fatal(err)
	}
	if err := tls.FeedSpan(model.ClientToServer, []byte{3, 0, 10}, t0, t0); err != nil {
		t.Fatal(err)
	}
	if !encrypted || !tls.Encrypted() {
		t.Fatal("TLS was not detected across spans")
	}
}

func TestSessionCloseMarksPendingIncomplete(t *testing.T) {
	var events []model.OperationEvent
	session := NewSession(SessionConfig{OnEvent: func(e model.OperationEvent) { events = append(events, e) }})
	t0 := time.Unix(200, 0)
	request := opmsg(t, 99, 0, 0, bsonDoc(t, bson.D{{Key: "find", Value: "orders"}, {Key: "$db", Value: "shop"}}))
	if err := session.FeedSpan(model.ClientToServer, request, t0, t0.Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	session.Close(t0.Add(time.Second), "connection_closed")
	if len(events) != 1 || !events[0].Incomplete || events[0].IncompleteReason != "connection_closed" || events[0].Duration != 999*time.Millisecond {
		t.Fatalf("event = %+v", events)
	}
}

func TestResponseWriteErrors(t *testing.T) {
	body := bsonDoc(t, bson.D{{Key: "ok", Value: 1}, {Key: "writeErrors", Value: bson.A{bson.D{{Key: "index", Value: 0}, {Key: "code", Value: 11000}, {Key: "errmsg", Value: "secret detail"}}}}, {Key: "writeConcernError", Value: bson.D{{Key: "code", Value: 64}}}, {Key: "errorLabels", Value: bson.A{"RetryableWriteError", "unbounded-user-label"}}})
	result := parseResult(body, 100)
	if !result.Error || result.WriteErrorCodes[11000] != 1 || result.WriteConcernCodes[64] != 1 || len(result.ErrorLabels) != 1 {
		t.Fatalf("result = %+v", result)
	}
}

func FuzzParseMessage(f *testing.F) {
	body, _ := bson.Marshal(bson.D{{Key: "ping", Value: 1}, {Key: "$db", Value: "admin"}})
	size := HeaderSize + 4 + 1 + len(body)
	seed := make([]byte, size)
	binary.LittleEndian.PutUint32(seed[:4], uint32(size))
	binary.LittleEndian.PutUint32(seed[12:16], uint32(OpMsg))
	seed[20] = 0
	copy(seed[21:], body)
	f.Add(seed)
	f.Add([]byte{1, 2, 3})
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = ParseMessage(data, DefaultDecodeLimits()) })
}
