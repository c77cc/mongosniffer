//go:build e2e

package e2e

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readconcern"
	"go.mongodb.org/mongo-driver/mongo/writeconcern"
)

func (h *harness) testStandaloneAndReplay(t *testing.T) {
	container, port, _ := h.startMongo(t, "plain", false)
	h.prepareCollection(t, port, "plain-setup", nil)
	cap := h.startCapture(t, "plain", port)
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	client, err := connectMongo(ctx, mongoURI(port, "mongosniffer-e2e-go", ""), nil)
	if err != nil {
		t.Fatal(err)
	}
	collection := client.Database("e2e").Collection("orders")
	docs := []any{bson.D{{"_id", 1}, {"status", "super-secret-e2e"}, {"amount", 10}}, bson.D{{"_id", 2}, {"status", "open"}, {"amount", 20}}, bson.D{{"_id", 3}, {"status", "open"}, {"amount", 30}}, bson.D{{"_id", 4}, {"status", "closed"}, {"amount", 40}}, bson.D{{"_id", 5}, {"status", "open"}, {"amount", 50}}}
	if _, err := collection.InsertMany(ctx, docs); err != nil {
		t.Fatal(err)
	}
	cursor, err := collection.Find(ctx, bson.D{{"status", bson.D{{"$in", bson.A{"open", "closed"}}}}}, options.Find().SetBatchSize(2).SetSort(bson.D{{"_id", 1}}))
	if err != nil {
		t.Fatal(err)
	}
	var found []bson.D
	if err := cursor.All(ctx, &found); err != nil {
		t.Fatal(err)
	}
	if len(found) != 4 {
		t.Fatalf("find returned %d", len(found))
	}
	aggregate, err := collection.Aggregate(ctx, mongo.Pipeline{{{"$match", bson.D{{"status", "open"}}}}, {{"$group", bson.D{{"_id", "$status"}, {"total", bson.D{{"$sum", "$amount"}}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	_ = aggregate.Close(ctx)
	if _, err := collection.UpdateMany(ctx, bson.D{{"status", "open"}}, bson.D{{"$inc", bson.D{{"amount", 1}}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := collection.DeleteOne(ctx, bson.D{{"_id", 5}}); err != nil {
		t.Fatal(err)
	}
	result := collection.FindOneAndUpdate(ctx, bson.D{{"_id", 2}}, bson.D{{"$set", bson.D{{"status", "processed"}}}})
	if result.Err() != nil {
		t.Fatal(result.Err())
	}
	models := []mongo.WriteModel{mongo.NewUpdateOneModel().SetFilter(bson.D{{"_id", 3}}).SetUpdate(bson.D{{"$set", bson.D{{"bulk", true}}}}), mongo.NewDeleteOneModel().SetFilter(bson.D{{"_id", 4}})}
	if _, err := collection.BulkWrite(ctx, models); err != nil {
		t.Fatal(err)
	}
	if _, err := collection.InsertOne(ctx, bson.D{{"_id", 1}, {"status", "duplicate-secret"}}); err == nil {
		t.Fatal("duplicate key insert succeeded")
	}
	_ = client.Disconnect(ctx)
	unackClient, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI(port, "mongosniffer-e2e-w0", "")).SetWriteConcern(writeconcern.Unacknowledged()))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = unackClient.Database("e2e").Collection("orders").InsertOne(ctx, bson.D{{"_id", 99}, {"status", "w0-secret"}})
	_ = unackClient.Disconnect(ctx)
	live := h.stopCapture(t, cap)
	h.assertHealthy(t, live)
	for _, command := range []string{"insert", "find", "getmore", "aggregate", "update", "delete", "findandmodify"} {
		requireCommand(t, live, command)
	}
	_, insertErrors, _, insertUnack := sumCommand(live, "insert")
	if insertErrors < 1 || insertUnack < 1 {
		t.Fatalf("insert errors=%d unack=%d operations=%+v", insertErrors, insertUnack, operationsFor(live, "insert"))
	}
	if strings.Contains(cap.stdout.String(), "super-secret-e2e") || strings.Contains(cap.stdout.String(), "duplicate-secret") || strings.Contains(cap.stdout.String(), "w0-secret") {
		t.Fatal("default report leaked BSON business values")
	}
	replay := h.replay(t, cap, port, "plain")
	h.assertReplayEqual(t, live, replay)
	h.docker(t, "stop", "--time", "2", container)
}

func (h *harness) prepareCollection(t *testing.T, port int, app string, tlsConfig *tls.Config) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	client, err := connectMongo(ctx, mongoURI(port, app, ""), tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	_ = client.Database("e2e").Collection("orders").Drop(ctx)
	_ = client.Disconnect(ctx)
}

func (h *harness) testCompression(t *testing.T) {
	container, port, _ := h.startMongo(t, "compression", false)
	h.prepareCollection(t, port, "compression-setup", nil)
	cap := h.startCapture(t, "compression", port)
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	for index, compressor := range []string{"snappy", "zlib", "zstd"} {
		opts := options.Client().ApplyURI(mongoURI(port, "mongosniffer-e2e-"+compressor, "")).SetCompressors([]string{compressor})
		client, err := mongo.Connect(ctx, opts)
		if err != nil {
			t.Fatal(err)
		}
		if err := client.Ping(ctx, nil); err != nil {
			t.Fatalf("%s ping: %v", compressor, err)
		}
		collection := client.Database("e2e").Collection("compressed")
		payload := deterministicPayload(int64(index+1), 64<<10)
		if _, err := collection.InsertOne(ctx, bson.D{{"_id", index}, {"payload", payload}}); err != nil {
			t.Fatalf("%s insert: %v", compressor, err)
		}
		var result bson.D
		if err := collection.FindOne(ctx, bson.D{{"_id", index}}).Decode(&result); err != nil {
			t.Fatalf("%s find: %v", compressor, err)
		}
		_ = client.Disconnect(ctx)
	}
	live := h.stopCapture(t, cap)
	h.assertHealthy(t, live)
	for _, compressor := range []string{"snappy", "zlib", "zstd"} {
		found := false
		for _, op := range live.Operations {
			if op.Compression[compressor] > 0 {
				found = true
			}
		}
		if !found {
			t.Fatalf("no %s operation: %+v", compressor, live.Operations)
		}
	}
	replay := h.replay(t, cap, port, "compression")
	h.assertReplayEqual(t, live, replay)
	h.docker(t, "stop", "--time", "2", container)
}

func deterministicPayload(seed int64, length int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	random := rand.New(rand.NewSource(seed))
	data := make([]byte, length)
	for i := range data {
		data[i] = alphabet[random.Intn(len(alphabet))]
	}
	return string(data)
}

func (h *harness) testTLS(t *testing.T) {
	container, port, tlsConfig := h.startMongo(t, "tls", true)
	cap := h.startCapture(t, "tls", port)
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
		client, err := connectMongo(ctx, mongoURI(port, fmt.Sprintf("tls-%d", i), ""), tlsConfig)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		_ = client.Disconnect(ctx)
		cancel()
	}
	live := h.stopCapture(t, cap)
	if live.EncryptedSessions < 3 || len(live.Operations) != 0 || live.DecodeErrors != 0 {
		t.Fatalf("TLS report=%+v", live)
	}
	replay := h.replay(t, cap, port, "tls")
	h.assertReplayEqual(t, live, replay)
	h.docker(t, "stop", "--time", "2", container)
}

func (h *harness) testInterruption(t *testing.T) {
	container, port, _ := h.startMongo(t, "interruption", false)
	cap := h.startCapture(t, "interruption", port)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client, err := connectMongo(ctx, mongoURI(port, "interruption", ""), nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- client.Database("admin").RunCommand(ctx, bson.D{{"sleep", 1}, {"secs", 10}, {"lock", "none"}}).Err()
	}()
	time.Sleep(500 * time.Millisecond)
	h.docker(t, "kill", container)
	<-done
	_ = client.Disconnect(context.Background())
	live := h.stopCapture(t, cap)
	calls, _, incomplete, _ := sumCommand(live, "sleep")
	if calls != 1 || incomplete != 1 {
		t.Fatalf("interrupted sleep calls=%d incomplete=%d report=%+v", calls, incomplete, live)
	}
	replay := h.replay(t, cap, port, "interruption")
	h.assertReplayEqual(t, live, replay)
}

func (h *harness) testReplicaSet(t *testing.T) {
	container, port := h.startReplica(t)
	uri := mongoURI(port, "replica-setup", "") + "&replicaSet=rs0"
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	client, err := connectMongo(ctx, uri, nil)
	if err != nil {
		t.Fatal(err)
	}
	collection := client.Database("e2e").Collection("transactions")
	_ = collection.Drop(ctx)
	_ = client.Disconnect(ctx)
	cap := h.startCapture(t, "replica", port)
	client, err = connectMongo(ctx, mongoURI(port, "mongosniffer-e2e-replica", "")+"&replicaSet=rs0", nil)
	if err != nil {
		t.Fatal(err)
	}
	collection = client.Database("e2e").Collection("transactions")
	session, err := client.StartSession()
	if err != nil {
		t.Fatal(err)
	}
	_, err = session.WithTransaction(ctx, func(sc mongo.SessionContext) (any, error) {
		if _, e := collection.InsertOne(sc, bson.D{{"_id", 1}, {"state", "new"}}); e != nil {
			return nil, e
		}
		_, e := collection.UpdateOne(sc, bson.D{{"_id", 1}}, bson.D{{"$set", bson.D{{"state", "committed"}}}})
		return nil, e
	}, options.Transaction().SetReadConcern(readconcern.Snapshot()).SetWriteConcern(writeconcern.Majority()))
	session.EndSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := collection.Watch(ctx, mongo.Pipeline{}, options.ChangeStream().SetMaxAwaitTime(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := collection.InsertOne(ctx, bson.D{{"_id", 2}, {"state", "change-stream"}}); err != nil {
		t.Fatal(err)
	}
	if !stream.Next(ctx) {
		t.Fatalf("change stream: %v", stream.Err())
	}
	_ = stream.Close(ctx)
	_ = client.Disconnect(ctx)
	live := h.stopCapture(t, cap)
	h.assertHealthy(t, live)
	requireCommand(t, live, "committransaction")
	aggregate := requireCommand(t, live, "aggregate")
	if aggregate.Dimensions.CursorKind != "changeStream" {
		t.Fatalf("change stream cursor kind=%q", aggregate.Dimensions.CursorKind)
	}
	requireCommand(t, live, "getmore")
	replay := h.replay(t, cap, port, "replica")
	h.assertReplayEqual(t, live, replay)
	h.docker(t, "stop", "--time", "2", container)
}

func (h *harness) testRealClients(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("host-network client containers require Linux")
	}
	container, port, _ := h.startMongo(t, "clients", false)
	h.prepareCollection(t, port, "clients-setup", nil)
	cap := h.startCapture(t, "clients", port)
	uri := mongoURI(port, "external-client", "")
	h.dockerClient(t, "python:3.13-slim", uri, "sh", "-ceu", `pip install -q pymongo; python - <<'PY'
import os
from pymongo import MongoClient
c=MongoClient(os.environ['MONGO_URI'],appname='mongosniffer-e2e-pymongo'); x=c.e2e.clients; x.insert_one({'client':'python'}); list(x.find({'client':'python'})); c.close()
PY`)
	h.dockerClient(t, "node:22-alpine", uri, "sh", "-ceu", `cd /tmp; npm install --silent mongodb@6; node - <<'JS'
const {MongoClient}=require('mongodb'); (async()=>{const c=new MongoClient(process.env.MONGO_URI,{appName:'mongosniffer-e2e-node'});await c.connect();const x=c.db('e2e').collection('clients');await x.insertOne({client:'node'});await x.findOne({client:'node'});await c.close()})().catch(e=>{console.error(e);process.exit(1)})
JS`)
	javaDir := filepath.Join(h.repo, "tests", "e2e", "clients", "java")
	h.dockerClientMount(t, "maven:3.9-eclipse-temurin-21", uri, javaDir, "sh", "-ceu", "cp -r /client /tmp/client; cd /tmp/client; mvn -q compile exec:java")
	dotnetDir := filepath.Join(h.repo, "tests", "e2e", "clients", "dotnet")
	h.dockerClientMount(t, "mcr.microsoft.com/dotnet/sdk:9.0", uri, dotnetDir, "sh", "-ceu", "cp -r /client /tmp/client; cd /tmp/client; dotnet run --configuration Release")
	live := h.stopCapture(t, cap)
	h.assertHealthy(t, live)
	inserts, _, _, _ := sumCommand(live, "insert")
	finds, _, _, _ := sumCommand(live, "find")
	if inserts < 4 || finds < 4 {
		t.Fatalf("multi-client inserts=%d finds=%d operations=%+v", inserts, finds, live.Operations)
	}
	replay := h.replay(t, cap, port, "clients")
	h.assertReplayEqual(t, live, replay)
	h.docker(t, "stop", "--time", "2", container)
}
func (h *harness) dockerClient(t *testing.T, image, uri string, args ...string) {
	all := []string{"run", "--rm", "--network", "host", "-e", "MONGO_URI=" + uri, image}
	all = append(all, args...)
	h.runWithTimeout(t, clientTimeout, h.repo, "docker", all...)
}
func (h *harness) dockerClientMount(t *testing.T, image, uri, source string, args ...string) {
	all := []string{"run", "--rm", "--network", "host", "-e", "MONGO_URI=" + uri, "-v", source + ":/client:ro", image}
	all = append(all, args...)
	h.runWithTimeout(t, clientTimeout, h.repo, "docker", all...)
}
