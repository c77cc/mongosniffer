package wire

import (
	"strings"

	"github.com/c77cc/mongosniffer/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
)

func parseResult(body []byte, responseBytes int64) model.ResultSummary {
	r := model.ResultSummary{ResponseBytes: responseBytes}
	doc := bson.Raw(body)
	if !numericTruthy(doc.Lookup("ok")) {
		r.Error = true
	}
	r.ErrorCode = integer(doc.Lookup("code"))
	r.ErrorCodeName = safeCodeName(stringValue(doc.Lookup("codeName")))
	r.AffectedDocuments = integer(doc.Lookup("n"))
	r.ModifiedDocuments = integer(doc.Lookup("nModified"))
	r.PartialResults = boolValue(doc.Lookup("partialResultsReturned"))
	if v := doc.Lookup("upserted"); v.Type == bsontype.Array {
		r.Upserts = int64(arrayCount(v.Array()))
	}
	if v := doc.Lookup("writeErrors"); v.Type == bsontype.Array {
		r.WriteErrors = int64(arrayCount(v.Array()))
		r.Error = r.Error || r.WriteErrors > 0
		r.WriteErrorCodes = codesFromDocumentArray(v.Array())
	}
	if v := doc.Lookup("writeConcernError"); v.Type == bsontype.EmbeddedDocument {
		r.WriteConcernErrors = 1
		r.Error = true
		code := integer(v.Document().Lookup("code"))
		if code != 0 {
			r.WriteConcernCodes = map[int64]int64{code: 1}
		}
	}
	r.ErrorLabels = safeErrorLabels(doc.Lookup("errorLabels"))
	if v := doc.Lookup("cursor"); v.Type == bsontype.EmbeddedDocument {
		cursor := v.Document()
		r.CursorID = integer(cursor.Lookup("id"))
		r.CursorNonZero = r.CursorID != 0
		r.CursorNamespace = stringValue(cursor.Lookup("ns"))
		if batch := cursor.Lookup("firstBatch"); batch.Type == bsontype.Array {
			r.ReturnedDocuments += int64(arrayCount(batch.Array()))
		}
		if batch := cursor.Lookup("nextBatch"); batch.Type == bsontype.Array {
			r.ReturnedDocuments += int64(arrayCount(batch.Array()))
		}
	}
	return r
}

func mergeResult(dst *model.ResultSummary, src model.ResultSummary) {
	dst.ReturnedDocuments += src.ReturnedDocuments
	dst.AffectedDocuments += src.AffectedDocuments
	dst.ModifiedDocuments += src.ModifiedDocuments
	dst.Upserts += src.Upserts
	dst.WriteErrors += src.WriteErrors
	dst.WriteConcernErrors += src.WriteConcernErrors
	mergeCodeCounts(&dst.WriteErrorCodes, src.WriteErrorCodes)
	mergeCodeCounts(&dst.WriteConcernCodes, src.WriteConcernCodes)
	if len(src.ErrorLabels) > 0 {
		dst.ErrorLabels = append(dst.ErrorLabels, src.ErrorLabels...)
	}
	dst.ResponseBytes += src.ResponseBytes
	dst.Error = dst.Error || src.Error
	if src.ErrorCode != 0 {
		dst.ErrorCode = src.ErrorCode
	}
	if src.ErrorCodeName != "" {
		dst.ErrorCodeName = src.ErrorCodeName
	}
	dst.PartialResults = dst.PartialResults || src.PartialResults
	dst.CursorID, dst.CursorNamespace, dst.CursorNonZero = src.CursorID, src.CursorNamespace, src.CursorNonZero
}

func integer(v bson.RawValue) int64 {
	switch v.Type {
	case bsontype.Int32:
		return int64(v.Int32())
	case bsontype.Int64:
		return v.Int64()
	case bsontype.Double:
		return int64(v.Double())
	}
	return 0
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

func numericTruthy(v bson.RawValue) bool {
	if v.Type == 0 {
		return true
	}
	switch v.Type {
	case bsontype.Int32:
		return v.Int32() != 0
	case bsontype.Int64:
		return v.Int64() != 0
	case bsontype.Double:
		return v.Double() != 0
	case bsontype.Boolean:
		return v.Boolean()
	}
	return true
}

func arrayCount(raw bson.Raw) int {
	values, err := raw.Values()
	if err != nil {
		return 0
	}
	return len(values)
}

func codesFromDocumentArray(raw bson.Raw) map[int64]int64 {
	values, err := raw.Values()
	if err != nil {
		return nil
	}
	result := map[int64]int64{}
	for _, value := range values {
		if value.Type == bsontype.EmbeddedDocument {
			if code := integer(value.Document().Lookup("code")); code != 0 {
				result[code]++
			}
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func mergeCodeCounts(dst *map[int64]int64, src map[int64]int64) {
	if len(src) == 0 {
		return
	}
	if *dst == nil {
		*dst = map[int64]int64{}
	}
	for code, count := range src {
		(*dst)[code] += count
	}
}

func safeErrorLabels(v bson.RawValue) []string {
	if v.Type != bsontype.Array {
		return nil
	}
	values, err := v.Array().Values()
	if err != nil {
		return nil
	}
	allowed := map[string]bool{"RetryableWriteError": true, "TransientTransactionError": true, "UnknownTransactionCommitResult": true, "NoWritesPerformed": true, "ResumableChangeStreamError": true}
	result := make([]string, 0, min(len(values), 16))
	for _, value := range values {
		label := stringValue(value)
		if allowed[label] {
			result = append(result, label)
		}
		if len(result) == 16 {
			break
		}
	}
	return result
}

func safeCodeName(s string) string {
	if len(s) > 128 {
		return ""
	}
	for _, r := range s {
		if !(r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return ""
		}
	}
	return strings.TrimSpace(s)
}
