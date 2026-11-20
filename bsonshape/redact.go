package bsonshape

import (
	"fmt"
	"strings"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
)

// RedactedRawCommand creates bounded Extended JSON for the explicitly
// sensitive raw-command mode. Authentication and session material remains
// redacted even when the caller opted into values.
func RedactedRawCommand(raw []byte) (string, error) {
	return RedactedRawCommandWithSequences(raw, nil)
}

func RedactedRawCommandWithSequences(raw []byte, sequences []Sequence) (string, error) {
	doc := bson.Raw(raw)
	if err := validateRaw(doc); err != nil {
		return "", err
	}
	elems, err := doc.Elements()
	if err != nil || len(elems) == 0 {
		return "", fmt.Errorf("empty command")
	}
	if isAuthCommand(strings.ToLower(elems[0].Key())) {
		return fmt.Sprintf(`{"%s":"<redacted-auth>"}`, elems[0].Key()), nil
	}
	value, err := redactDocument(doc, 0)
	if err != nil {
		return "", err
	}
	for _, sequence := range sequences {
		items := make(bson.A, 0, len(sequence.Documents)+1)
		for _, rawDocument := range sequence.Documents {
			item, itemErr := redactDocument(bson.Raw(rawDocument), 0)
			if itemErr != nil {
				return "", itemErr
			}
			items = append(items, item)
		}
		if sequence.Count > len(sequence.Documents) {
			items = append(items, "...[truncated]")
		}
		value = append(value, bson.E{Key: safeIdentifier(sequence.Identifier), Value: items})
	}
	encoded, err := bson.MarshalExtJSON(value, false, false)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func redactDocument(raw bson.Raw, depth int) (bson.D, error) {
	if depth > 64 {
		return bson.D{{Key: "...[depth]", Value: "<truncated>"}}, nil
	}
	elems, err := raw.Elements()
	if err != nil {
		return nil, err
	}
	out := make(bson.D, 0, len(elems))
	for _, elem := range elems {
		if rawSensitiveKey(elem.Key()) {
			continue
		}
		value, valueErr := redactValue(elem.Value(), depth+1)
		if valueErr != nil {
			return nil, valueErr
		}
		out = append(out, bson.E{Key: elem.Key(), Value: value})
	}
	return out, nil
}

func redactValue(v bson.RawValue, depth int) (any, error) {
	switch v.Type {
	case bsontype.EmbeddedDocument:
		return redactDocument(v.Document(), depth)
	case bsontype.Array:
		values, err := v.Array().Values()
		if err != nil {
			return nil, err
		}
		truncated := len(values) > 256
		if truncated {
			values = values[:256]
		}
		out := make(bson.A, 0, len(values)+1)
		for _, value := range values {
			item, itemErr := redactValue(value, depth+1)
			if itemErr != nil {
				return nil, itemErr
			}
			out = append(out, item)
		}
		if truncated {
			out = append(out, "...[truncated]")
		}
		return out, nil
	case bsontype.Binary:
		_, data := v.Binary()
		return fmt.Sprintf("<binary %d bytes>", len(data)), nil
	case bsontype.String:
		value := v.StringValue()
		if len(value) > 1024 {
			value = value[:1024] + "...[truncated]"
		}
		return value, nil
	case bsontype.JavaScript, bsontype.CodeWithScope:
		return "<redacted-javascript>", nil
	default:
		var value any
		if err := v.Unmarshal(&value); err != nil {
			return "<unsupported>", nil
		}
		return value, nil
	}
}

func rawSensitiveKey(key string) bool {
	if sensitiveKey(key) {
		return true
	}
	switch strings.ToLower(key) {
	case "password", "pwd", "authtoken", "accesstoken", "keymaterial":
		return true
	}
	return false
}
