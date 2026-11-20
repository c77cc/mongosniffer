package bsonshape

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
)

type Limits struct {
	MaxDepth          int
	MaxElements       int
	MaxOutputBytes    int
	MaxSequenceShapes int
}

func DefaultLimits() Limits {
	return Limits{MaxDepth: 64, MaxElements: 4096, MaxOutputBytes: 64 << 10, MaxSequenceShapes: 32}
}

type Sequence struct {
	Identifier string
	Documents  [][]byte
	Count      int
	BSONBytes  int64
}

type Command struct {
	Name, Database, Collection, Namespace string
	Fingerprint, FingerprintID, GroupKey  string
	Transactional, RetryableWrite         bool
	CursorKind                            string
	HasSession                            bool
	ChangeStream                          bool
	Truncated                             bool
	RawCommand                            string
}

var controlCommands = map[string]bool{
	"hello": true, "ismaster": true, "saslstart": true, "saslcontinue": true,
	"authenticate": true, "getnonce": true, "endsessions": true,
	"refreshsessions": true, "ping": true,
}

func IsControl(name string) bool { return controlCommands[strings.ToLower(name)] }

func ParseCommand(raw []byte, sequences []Sequence, limits Limits) (Command, error) {
	if limits.MaxDepth <= 0 {
		limits = DefaultLimits()
	}
	doc := bson.Raw(raw)
	if err := validateRaw(doc); err != nil {
		return Command{}, fmt.Errorf("invalid BSON: %w", err)
	}
	elems, err := doc.Elements()
	if err != nil || len(elems) == 0 {
		return Command{}, errors.New("command BSON has no elements")
	}
	name := strings.ToLower(elems[0].Key())
	cmd := Command{Name: name, CursorKind: "normal"}
	cmd.Database = stringValue(doc.Lookup("$db"))
	cmd.Collection = collectionFor(name, elems[0].Value())
	if cmd.Database != "" && cmd.Collection != "" {
		cmd.Namespace = cmd.Database + "." + cmd.Collection
	}
	cmd.HasSession = doc.Lookup("lsid").Type != 0
	cmd.Transactional = doc.Lookup("autocommit").Type != 0 || doc.Lookup("startTransaction").Type != 0 || name == "committransaction" || name == "aborttransaction"
	cmd.RetryableWrite = cmd.HasSession && doc.Lookup("txnNumber").Type != 0 && !cmd.Transactional
	if boolValue(doc.Lookup("tailable")) {
		cmd.CursorKind = "tailable"
	}
	if boolValue(doc.Lookup("awaitData")) {
		cmd.CursorKind = "awaitData"
	}

	b := &shapeBuilder{limits: limits}
	b.write(name)
	if cmd.Namespace != "" {
		b.write(" " + cmd.Namespace)
	} else if cmd.Database != "" {
		b.write(" " + cmd.Database)
	}
	if isAuthCommand(name) {
		b.write(" <redacted-auth>")
		cmd.GroupKey, cmd.Truncated = b.String(), b.truncated
		cmd.Fingerprint = cmd.GroupKey
		cmd.FingerprintID = FingerprintHash(cmd.GroupKey)
		return cmd, nil
	}
	b.write(" ")
	b.document(doc, 0, "")
	for _, seq := range sequences {
		b.write(" " + safeIdentifier(seq.Identifier) + ":[")
		seen := min(len(seq.Documents), limits.MaxSequenceShapes)
		var first string
		mixed := false
		for i := 0; i < seen; i++ {
			sb := &shapeBuilder{limits: limits}
			d := bson.Raw(seq.Documents[i])
			if validateRaw(d) != nil {
				return Command{}, fmt.Errorf("invalid BSON in sequence %q", seq.Identifier)
			}
			sb.document(d, 0, seq.Identifier)
			if i == 0 {
				first = sb.String()
			} else if sb.String() != first {
				mixed = true
			}
		}
		if first != "" {
			b.write(first)
		}
		if mixed {
			b.write(",...mixed")
		}
		if seq.Count > seen || len(seq.Documents) > seen {
			b.write(",...[truncated]")
		}
		b.write("]")
	}
	cmd.GroupKey = b.String()
	cmd.ChangeStream = strings.Contains(cmd.GroupKey, `"$changeStream"`)
	if cmd.ChangeStream {
		cmd.CursorKind = "changeStream"
	}
	readable, readableTruncated := readableFingerprint(doc, sequences, cmd, limits)
	cmd.Fingerprint = readable
	cmd.FingerprintID = FingerprintHash(cmd.GroupKey)
	cmd.Truncated = b.truncated || readableTruncated
	return cmd, nil
}

func FingerprintHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:8])
}

func collectionFor(name string, v bson.RawValue) string {
	switch name {
	case "find", "aggregate", "count", "distinct", "insert", "update", "delete", "findandmodify", "killcursors":
		return stringValue(v)
	}
	return ""
}

func isAuthCommand(name string) bool {
	return name == "saslstart" || name == "saslcontinue" || name == "authenticate" || name == "getnonce"
}

func stringValue(v bson.RawValue) string {
	if v.Type == bsontype.String {
		return v.StringValue()
	}
	return ""
}

func boolValue(v bson.RawValue) bool {
	return v.Type == bsontype.Boolean && v.Boolean()
}

type shapeBuilder struct {
	b         strings.Builder
	limits    Limits
	elements  int
	truncated bool
}

func (s *shapeBuilder) String() string { return s.b.String() }

func (s *shapeBuilder) write(v string) {
	if s.truncated {
		return
	}
	left := s.limits.MaxOutputBytes - s.b.Len()
	if left <= 0 {
		s.truncated = true
		return
	}
	if len(v) > left {
		token := "...[truncated]"
		if left >= len(token) {
			s.b.WriteString(v[:left-len(token)])
			s.b.WriteString(token)
		}
		s.truncated = true
		return
	}
	s.b.WriteString(v)
}

func (s *shapeBuilder) document(doc bson.Raw, depth int, context string) {
	if depth >= s.limits.MaxDepth {
		s.write(`"...[depth]"`)
		s.truncated = true
		return
	}
	elems, err := doc.Elements()
	if err != nil {
		s.write(`"...[invalid]"`)
		return
	}
	s.write("{")
	for i, e := range elems {
		if s.elements >= s.limits.MaxElements {
			if i > 0 {
				s.write(",")
			}
			s.write(`"...[elements]":"?"`)
			s.truncated = true
			break
		}
		key := e.Key()
		if sensitiveKey(key) {
			continue
		}
		if i > 0 && s.b.Len() > 0 && s.b.String()[s.b.Len()-1] != '{' {
			s.write(",")
		}
		s.elements++
		s.write(strconv.Quote(key) + ":")
		s.value(e.Value(), depth+1, key)
	}
	s.write("}")
}

func (s *shapeBuilder) value(v bson.RawValue, depth int, key string) {
	switch v.Type {
	case bsontype.EmbeddedDocument:
		s.document(v.Document(), depth, key)
	case bsontype.Array:
		s.array(v.Array(), depth, key)
	case bsontype.Regex:
		_, opts := v.Regex()
		chars := strings.Split(opts, "")
		sort.Strings(chars)
		s.write(strconv.Quote("?" + strings.Join(chars, "")))
	case bsontype.JavaScript, bsontype.CodeWithScope:
		s.write(strconv.Quote("?"))
	default:
		s.write(strconv.Quote("?"))
	}
}

func (s *shapeBuilder) array(arr bson.Raw, depth int, key string) {
	if depth >= s.limits.MaxDepth {
		s.write(`["...[depth]"]`)
		s.truncated = true
		return
	}
	vals, err := arr.Values()
	if err != nil {
		s.write(`["...[invalid]"]`)
		return
	}
	s.write("[")
	if key == "$and" || key == "$or" || key == "$nor" {
		shapes := make([]string, 0, len(vals))
		for _, value := range vals {
			shapes = append(shapes, valueShape(value, depth+1, key, s.limits))
		}
		sort.Strings(shapes)
		for i, shape := range shapes {
			if i > 0 {
				s.write(",")
			}
			s.write(shape)
		}
		s.write("]")
		return
	}
	if (key == "$in" || key == "$nin" || key == "$all") && allScalar(vals) {
		if len(vals) > 0 {
			s.write(strconv.Quote("?"))
		}
		s.write("]")
		return
	}
	limit := min(len(vals), s.limits.MaxSequenceShapes)
	if key == "pipeline" {
		for i := 0; i < limit; i++ {
			if i > 0 {
				s.write(",")
			}
			s.value(vals[i], depth+1, key)
		}
		if len(vals) > limit {
			if limit > 0 {
				s.write(",")
			}
			s.write(`"...[truncated]"`)
			s.truncated = true
		}
		s.write("]")
		return
	}
	if limit > 0 {
		first := valueShape(vals[0], depth+1, key, s.limits)
		s.write(first)
		mixed := false
		for i := 1; i < limit; i++ {
			if valueShape(vals[i], depth+1, key, s.limits) != first {
				mixed = true
				break
			}
		}
		if mixed {
			s.write(`,"...mixed"`)
		}
	}
	if len(vals) > limit {
		s.write(`,"...[truncated]"`)
		s.truncated = true
	}
	s.write("]")
}

func valueShape(value bson.RawValue, depth int, key string, limits Limits) string {
	scratch := &shapeBuilder{limits: limits}
	scratch.value(value, depth, key)
	return scratch.String()
}

func allScalar(vs []bson.RawValue) bool {
	for _, v := range vs {
		if v.Type == bsontype.EmbeddedDocument || v.Type == bsontype.Array {
			return false
		}
	}
	return true
}

func sensitiveKey(k string) bool {
	switch strings.ToLower(k) {
	case "lsid", "txnnumber", "$clustertime", "signature", "speculativeauthenticate", "saslsupportedmechs", "payload", "securitytoken":
		return true
	}
	return false
}

func safeIdentifier(s string) string {
	if len(s) > 128 {
		return "sequence"
	}
	for _, r := range s {
		if !(r == '_' || r == '$' || r == '.' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return "sequence"
		}
	}
	return s
}
