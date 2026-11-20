package bsonshape

import (
	"strings"
	"testing"

	"go.mongodb.org/mongo-driver/bson"
)

func mustBSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := bson.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestFingerprintStableAndRedacted(t *testing.T) {
	a := mustBSON(t, bson.D{{Key: "find", Value: "orders"}, {Key: "filter", Value: bson.D{{Key: "status", Value: "paid"}, {Key: "user", Value: 42}}}, {Key: "$db", Value: "shop"}, {Key: "lsid", Value: bson.D{{Key: "id", Value: "secret"}}}})
	b := mustBSON(t, bson.D{{Key: "find", Value: "orders"}, {Key: "filter", Value: bson.D{{Key: "status", Value: "open"}, {Key: "user", Value: 99}}}, {Key: "$db", Value: "shop"}, {Key: "lsid", Value: bson.D{{Key: "id", Value: "different"}}}})
	one, err := ParseCommand(a, nil, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	two, err := ParseCommand(b, nil, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if one.Fingerprint != two.Fingerprint {
		t.Fatalf("fingerprints differ:\n%s\n%s", one.Fingerprint, two.Fingerprint)
	}
	for _, secret := range []string{"paid", "open", "secret", "different", "42", "99"} {
		if strings.Contains(one.Fingerprint+two.Fingerprint, secret) {
			t.Fatalf("fingerprint leaked %q", secret)
		}
	}
}

func TestFingerprintArraysIgnoreBusinessLengthButPreservePipelineOrder(t *testing.T) {
	command := func(ids bson.A) []byte {
		return mustBSON(t, bson.D{{Key: "find", Value: "orders"}, {Key: "filter", Value: bson.D{{Key: "id", Value: bson.D{{Key: "$in", Value: ids}}}}}, {Key: "$db", Value: "shop"}})
	}
	a, _ := ParseCommand(command(bson.A{1}), nil, DefaultLimits())
	b, _ := ParseCommand(command(bson.A{2, 3, 4}), nil, DefaultLimits())
	if a.Fingerprint != b.Fingerprint {
		t.Fatalf("array length changed fingerprint:\n%s\n%s", a.Fingerprint, b.Fingerprint)
	}
	pipeline := func(stages bson.A) string {
		raw := mustBSON(t, bson.D{{Key: "aggregate", Value: "orders"}, {Key: "pipeline", Value: stages}, {Key: "$db", Value: "shop"}})
		cmd, err := ParseCommand(raw, nil, DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		return cmd.Fingerprint
	}
	first := pipeline(bson.A{bson.D{{Key: "$match", Value: bson.D{{Key: "a", Value: 1}}}}, bson.D{{Key: "$limit", Value: 1}}})
	second := pipeline(bson.A{bson.D{{Key: "$limit", Value: 1}}, bson.D{{Key: "$match", Value: bson.D{{Key: "a", Value: 1}}}}})
	if first == second {
		t.Fatal("pipeline stage order was discarded")
	}
}

func TestReadableFingerprintShowsCompleteWhereAndProjection(t *testing.T) {
	filter := bson.D{{Key: "$and", Value: bson.A{
		bson.D{{Key: "$and", Value: bson.A{
			bson.D{{Key: "online_offline_change_time", Value: bson.D{{Key: "$lte", Value: 123}}}},
			bson.D{{Key: "delete_at", Value: bson.D{{Key: "$eq", Value: 0}}}},
		}}},
		bson.D{{Key: "asset_id", Value: bson.D{{Key: "$in", Value: bson.A{1001, 1002}}}}},
		bson.D{{Key: "$or", Value: bson.A{
			bson.D{{Key: "is_online", Value: true}},
			bson.D{{Key: "last_time", Value: bson.D{{Key: "$gte", Value: 456}}}},
		}}},
	}}}
	projection := bson.D{
		{Key: "_id", Value: 1}, {Key: "client_id", Value: 1}, {Key: "is_online", Value: 1},
		{Key: "asset_id", Value: 1}, {Key: "asset_oid", Value: 1}, {Key: "last_time", Value: 1},
		{Key: "online_offline_change_time", Value: 1}, {Key: "event_time", Value: 1},
		{Key: "create_time", Value: 1}, {Key: "update_time", Value: 1}, {Key: "delete_at", Value: 1},
	}
	raw := mustBSON(t, bson.D{
		{Key: "find", Value: "client_online_info_v5"}, {Key: "batchSize", Value: 100},
		{Key: "filter", Value: filter}, {Key: "limit", Value: 10}, {Key: "projection", Value: projection},
		{Key: "skip", Value: 0}, {Key: "sort", Value: bson.D{{Key: "_id", Value: 1}}},
		{Key: "$db", Value: "da_skylar_client"}, {Key: "$readPreference", Value: bson.D{{Key: "mode", Value: "secondaryPreferred"}}},
	})
	cmd, err := ParseCommand(raw, nil, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	want := "find da_skylar_client.client_online_info_v5 where asset_id in [?] and delete_at = ? and (is_online = ? or last_time >= ?) and online_offline_change_time <= ? sort(_id: ?) limit ? skip ? project(_id, client_id, is_online, asset_id, asset_oid, last_time, online_offline_change_time, event_time, create_time, update_time, delete_at)"
	if cmd.Fingerprint != want {
		t.Fatalf("fingerprint:\n%s\nwant:\n%s", cmd.Fingerprint, want)
	}
	if strings.Contains(cmd.Fingerprint, "mixed") || strings.Contains(cmd.Fingerprint, "batchSize") || strings.Contains(cmd.Fingerprint, "$readPreference") {
		t.Fatalf("fingerprint contains implementation noise: %s", cmd.Fingerprint)
	}
	if len(cmd.FingerprintID) != 16 || cmd.GroupKey == "" {
		t.Fatalf("fingerprint identity = %q, group key empty=%t", cmd.FingerprintID, cmd.GroupKey == "")
	}
}

func TestLogicalClauseOrderDoesNotChangeFingerprintIdentity(t *testing.T) {
	command := func(clauses bson.A) Command {
		raw := mustBSON(t, bson.D{{Key: "find", Value: "orders"}, {Key: "filter", Value: bson.D{{Key: "$and", Value: clauses}}}, {Key: "$db", Value: "shop"}})
		cmd, err := ParseCommand(raw, nil, DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		return cmd
	}
	a := bson.D{{Key: "status", Value: "paid"}}
	b := bson.D{{Key: "created_at", Value: bson.D{{Key: "$gte", Value: 1}}}}
	one := command(bson.A{a, b})
	two := command(bson.A{b, a})
	if one.Fingerprint != two.Fingerprint || one.FingerprintID != two.FingerprintID || one.GroupKey != two.GroupKey {
		t.Fatalf("logical order changed fingerprint:\n%+v\n%+v", one, two)
	}
}

func TestReadableDeleteSequenceFingerprint(t *testing.T) {
	raw := mustBSON(t, bson.D{{Key: "delete", Value: "orders"}, {Key: "ordered", Value: true}, {Key: "$db", Value: "shop"}})
	request := mustBSON(t, bson.D{
		{Key: "q", Value: bson.D{{Key: "$and", Value: bson.A{
			bson.D{{Key: "delete_at", Value: bson.D{{Key: "$lte", Value: 123}}}},
			bson.D{{Key: "status", Value: bson.D{{Key: "$eq", Value: "expired"}}}},
		}}}},
		{Key: "limit", Value: 1},
	})
	cmd, err := ParseCommand(raw, []Sequence{{Identifier: "deletes", Documents: [][]byte{request}, Count: 1}}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	want := "delete shop.orders where delete_at <= ? and status = ? limit ?"
	if cmd.Fingerprint != want {
		t.Fatalf("fingerprint = %q, want %q", cmd.Fingerprint, want)
	}
	if strings.Contains(cmd.Fingerprint, "expired") || strings.Contains(cmd.Fingerprint, "123") {
		t.Fatalf("fingerprint leaked values: %s", cmd.Fingerprint)
	}
}

func TestReadableInsertAndUpdateFingerprints(t *testing.T) {
	insertBody := mustBSON(t, bson.D{{Key: "insert", Value: "orders"}, {Key: "ordered", Value: true}, {Key: "$db", Value: "shop"}})
	document := mustBSON(t, bson.D{{Key: "_id", Value: 1}, {Key: "status", Value: "new"}, {Key: "amount", Value: 42}})
	insert, err := ParseCommand(insertBody, []Sequence{{Identifier: "documents", Documents: [][]byte{document}, Count: 1}}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if want := "insert shop.orders documents(_id, status, amount)"; insert.Fingerprint != want {
		t.Fatalf("insert fingerprint = %q, want %q", insert.Fingerprint, want)
	}

	updateBody := mustBSON(t, bson.D{{Key: "update", Value: "orders"}, {Key: "ordered", Value: true}, {Key: "$db", Value: "shop"}})
	request := mustBSON(t, bson.D{
		{Key: "q", Value: bson.D{{Key: "status", Value: "new"}}},
		{Key: "u", Value: bson.D{{Key: "$set", Value: bson.D{{Key: "status", Value: "paid"}, {Key: "updated_at", Value: 123}}}}},
	})
	update, err := ParseCommand(updateBody, []Sequence{{Identifier: "updates", Documents: [][]byte{request}, Count: 1}}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if want := "update shop.orders where status = ? update $set(status, updated_at)"; update.Fingerprint != want {
		t.Fatalf("update fingerprint = %q, want %q", update.Fingerprint, want)
	}
}

func TestRedactedRawCommand(t *testing.T) {
	raw := mustBSON(t, bson.D{{Key: "find", Value: "orders"}, {Key: "filter", Value: bson.D{{Key: "email", Value: "a@example.com"}}}, {Key: "lsid", Value: bson.D{{Key: "id", Value: "session-secret"}}}, {Key: "password", Value: "credential"}})
	value, err := RedactedRawCommand(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(value, "a@example.com") {
		t.Fatalf("raw mode lost business value: %s", value)
	}
	if strings.Contains(value, "session-secret") || strings.Contains(value, "credential") || strings.Contains(value, "lsid") {
		t.Fatalf("raw mode leaked mandatory-redacted data: %s", value)
	}
	auth := mustBSON(t, bson.D{{Key: "saslStart", Value: 1}, {Key: "payload", Value: []byte("credential")}})
	value, err = RedactedRawCommand(auth)
	if err != nil || strings.Contains(value, "credential") {
		t.Fatalf("auth redaction = %q, %v", value, err)
	}
}

func FuzzParseCommand(f *testing.F) {
	seed, err := bson.Marshal(bson.D{
		{Key: "find", Value: "orders"},
		{Key: "filter", Value: bson.D{{Key: "$and", Value: bson.A{
			bson.D{{Key: "status", Value: bson.D{{Key: "$in", Value: bson.A{"paid", "open"}}}}},
			bson.D{{Key: "$or", Value: bson.A{bson.D{{Key: "amount", Value: bson.D{{Key: "$gte", Value: 10}}}}, bson.D{{Key: "priority", Value: true}}}}},
		}}}},
		{Key: "$db", Value: "shop"},
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = ParseCommand(raw, nil, DefaultLimits())
	})
}
