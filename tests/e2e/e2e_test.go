//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	commandTimeout = 3 * time.Minute
	clientTimeout  = 8 * time.Minute
)

type harness struct {
	t                                                      *testing.T
	repo, artifacts, binary, tcpdump, image, iface, prefix string
	retain                                                 bool
	resources                                              []dockerResource
}
type dockerResource struct{ kind, name string }
type captureRun struct {
	cmd, packetCmd                             *exec.Cmd
	cmdDone, packetDone                        chan error
	stdout, stderr, packetStdout, packetStderr bytes.Buffer
	reportPath, pcapPath                       string
}

type reportJSON struct {
	SchemaVersion          int                                `json:"schema_version"`
	Build                  struct{ Version, Revision string } `json:"build"`
	GeneratedAt            time.Time                          `json:"generated_at"`
	Operations             []operationJSON                    `json:"operations"`
	ControlCounters        map[string]uint64                  `json:"control_counters"`
	Capture                captureJSON                        `json:"capture"`
	DataQuality            dataQualityJSON                    `json:"data_quality"`
	EncryptedSessions      uint64                             `json:"encrypted_sessions"`
	DecodeErrors           uint64                             `json:"decode_errors"`
	FingerprintTruncations uint64                             `json:"fingerprint_truncations"`
	DroppedOperationKeys   uint64                             `json:"dropped_operation_keys"`
	ProtocolIssues         map[string]uint64                  `json:"protocol_issues"`
}
type dimensionsJSON struct {
	Command         string `json:"command"`
	Database        string `json:"database"`
	Collection      string `json:"collection"`
	ApplicationName string `json:"application_name"`
	DriverName      string `json:"driver_name"`
	ClientAddress   string `json:"client_address"`
	ServerAddress   string `json:"server_address"`
	CursorKind      string `json:"cursor_kind"`
	Transactional   bool   `json:"transactional"`
	RetryableWrite  bool   `json:"retryable_write"`
}
type phaseJSON struct {
	Observations                       uint64 `json:"observations"`
	Average, Min, P95, P99, Max, Total float64
}
type latencyJSON struct {
	Observations                       uint64 `json:"observations"`
	Average, Min, P95, P99, Max, Total float64
	FirstResponse                      phaseJSON `json:"first_response"`
	ResponseTransfer                   phaseJSON `json:"response_transfer"`
}
type operationJSON struct {
	FingerprintID         string            `json:"fingerprint_id"`
	Fingerprint           string            `json:"fingerprint"`
	Dimensions            dimensionsJSON    `json:"dimensions"`
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
	ErrorCodes            map[string]uint64 `json:"error_codes"`
	WriteErrorCodes       map[string]uint64 `json:"write_error_codes"`
	WriteConcernCodes     map[string]uint64 `json:"write_concern_error_codes"`
	IncompleteReasons     map[string]uint64 `json:"incomplete_reasons"`
	Compression           map[string]uint64 `json:"compression"`
	Latency               latencyJSON       `json:"latency_ms"`
	IncompleteObserved    *phaseJSON        `json:"incomplete_observed_duration_ms"`
}
type captureJSON struct {
	PacketsSeen                  uint64 `json:"packets_seen"`
	PacketsMatched               uint64 `json:"packets_matched"`
	TruncatedPackets             uint64 `json:"truncated_packets"`
	KernelPacketsDropped         uint64 `json:"kernel_packets_dropped"`
	InterfacePacketsDropped      uint64 `json:"interface_packets_dropped"`
	TCPGapEvents                 uint64 `json:"tcp_gap_events"`
	TCPBytesSkipped              uint64 `json:"tcp_bytes_skipped"`
	TCPSequenceDiscontinuities   uint64 `json:"tcp_sequence_discontinuities"`
	ConnectionsObserved          uint64 `json:"connections_observed"`
	HandshakeObservedConnections uint64 `json:"handshake_observed_connections"`
	MidstreamConnections         uint64 `json:"midstream_connections"`
	ProtocolStateLossConnections uint64 `json:"protocol_state_loss_connections"`
}
type dataQualityJSON struct {
	CompletedOperations       uint64  `json:"completed_operations"`
	UnacknowledgedOperations  uint64  `json:"unacknowledged_operations"`
	ExcludedOperations        uint64  `json:"excluded_operations"`
	MetadataMissingOperations uint64  `json:"metadata_missing_operations"`
	ExcludedPercentage        float64 `json:"excluded_percentage"`
}

func TestDockerEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("Docker E2E disabled by -short")
	}
	h := newHarness(t)
	defer h.cleanup()
	h.requireDocker()
	h.build()
	t.Run("standalone_driver_and_replay", h.testStandaloneAndReplay)
	t.Run("compression", h.testCompression)
	t.Run("tls_detection_and_replay", h.testTLS)
	t.Run("server_interruption", h.testInterruption)
	if os.Getenv("MONGOSNIFFER_E2E_REPLICA") == "1" {
		t.Run("replica_transaction_and_change_stream", h.testReplicaSet)
	}
	if os.Getenv("MONGOSNIFFER_E2E_REAL_CLIENTS") == "1" {
		t.Run("real_client_compatibility", h.testRealClients)
	}
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	configured := os.Getenv("MONGOSNIFFER_E2E_ARTIFACTS")
	base := artifactBase(repo, configured)
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	artifacts, err := os.MkdirTemp(base, "run-")
	if err != nil {
		t.Fatal(err)
	}
	iface := os.Getenv("MONGOSNIFFER_E2E_INTERFACE")
	if iface == "" {
		iface = "lo"
		if runtime.GOOS == "darwin" {
			iface = "lo0"
		}
	}
	image := os.Getenv("MONGOSNIFFER_MONGO_IMAGE")
	if image == "" {
		image = "mongo:7.0"
	}
	return &harness{t: t, repo: repo, artifacts: artifacts, binary: filepath.Join(artifacts, "mongosniffer"), image: image, iface: iface, prefix: fmt.Sprintf("mongosniffer-e2e-%d-%d", os.Getpid(), time.Now().UnixNano()), retain: configured != ""}
}

func (h *harness) requireDocker() {
	if _, err := exec.LookPath("docker"); err != nil {
		h.dockerUnavailable("docker is not installed")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, "docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput(); err != nil || strings.TrimSpace(string(output)) == "" || bytes.Contains(output, []byte("Cannot connect")) {
		h.dockerUnavailable(fmt.Sprintf("docker daemon unavailable: %v: %s", err, output))
	}
}
func (h *harness) dockerUnavailable(message string) {
	if os.Getenv("MONGOSNIFFER_E2E_REQUIRED") == "1" {
		h.t.Fatal(message)
	}
	h.t.Skip(message)
}
func (h *harness) build() {
	h.run(h.t, h.repo, "go", "build", "-trimpath", "-o", h.binary, "./cmd/mongosniffer")
	path, err := exec.LookPath("tcpdump")
	if err != nil {
		h.t.Fatalf("tcpdump is required: %v", err)
	}
	h.tcpdump = path
	if os.Getenv("MONGOSNIFFER_E2E_SETCAP") == "1" {
		h.run(h.t, h.repo, "sudo", "-n", "setcap", "cap_net_raw,cap_net_admin=eip", h.binary)
		h.run(h.t, h.repo, "sudo", "-n", "setcap", "cap_net_raw,cap_net_admin=eip", h.tcpdump)
	}
	if list := h.runOutput(h.t, h.repo, h.binary, "--list-interfaces"); !strings.Contains(list, h.iface) {
		h.t.Fatalf("interface %q missing:\n%s", h.iface, list)
	}
}

func (h *harness) startMongo(t *testing.T, label string, tlsEnabled bool) (string, int, *tls.Config) {
	t.Helper()
	name := h.prefix + "-" + label
	args := []string{"run", "-d", "--name", name, "-p", "127.0.0.1::27017"}
	var tlsConfig *tls.Config
	if tlsEnabled {
		certDir, config := h.generateTLS(t, label)
		tlsConfig = config
		args = append(args, "-v", certDir+":/certs:ro")
	}
	args = append(args, h.image, "mongod", "--bind_ip_all", "--setParameter", "enableTestCommands=1")
	if tlsEnabled {
		args = append(args, "--tlsMode", "requireTLS", "--tlsCertificateKeyFile", "/certs/server.pem", "--tlsCAFile", "/certs/ca.pem", "--tlsAllowConnectionsWithoutCertificates")
	}
	h.docker(t, args...)
	h.resources = append(h.resources, dockerResource{"container", name})
	port := h.publishedPort(t, name)
	h.waitMongo(t, port, tlsConfig, name, "")
	return name, port, tlsConfig
}

func (h *harness) startReplica(t *testing.T) (string, int) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("replica-set host-network E2E currently requires Linux")
	}
	port := freePort(t)
	name := h.prefix + "-replica"
	h.docker(t, "run", "-d", "--name", name, "--network", "host", h.image, "mongod", "--port", strconv.Itoa(port), "--bind_ip", "127.0.0.1", "--replSet", "rs0", "--setParameter", "enableTestCommands=1")
	h.resources = append(h.resources, dockerResource{"container", name})
	deadline := time.Now().Add(45 * time.Second)
	var output string
	for time.Now().Before(deadline) {
		output, _ = h.dockerOutput(t, "exec", name, "mongosh", "--quiet", "--port", strconv.Itoa(port), "--eval", fmt.Sprintf(`try { rs.initiate({_id:"rs0",members:[{_id:0,host:"127.0.0.1:%d"}]}) } catch (e) { print(e) }`, port))
		if strings.Contains(output, "ok: 1") || strings.Contains(output, "already initialized") {
			break
		}
		time.Sleep(time.Second)
	}
	uri := mongoURI(port, "replica-init", "") + "&replicaSet=rs0"
	h.waitMongo(t, port, nil, name, uri)
	return name, port
}

func (h *harness) publishedPort(t *testing.T, name string) int {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		output, err := h.dockerOutput(t, "port", name, "27017/tcp")
		if err == nil {
			line := strings.Split(strings.TrimSpace(output), "\n")[0]
			if _, text, e := net.SplitHostPort(line); e == nil {
				if port, e := strconv.Atoi(text); e == nil {
					return port
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("MongoDB port not published for %s", name)
	return 0
}
func (h *harness) waitMongo(t *testing.T, port int, tlsConfig *tls.Config, container, overrideURI string) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		uri := overrideURI
		if uri == "" {
			uri = mongoURI(port, "readiness", "")
		}
		client, err := connectMongo(context.Background(), uri, tlsConfig)
		if err == nil {
			_ = client.Disconnect(context.Background())
			return
		}
		last = err
		time.Sleep(300 * time.Millisecond)
	}
	logs, _ := h.dockerOutput(t, "logs", container)
	t.Fatalf("MongoDB not ready: %v\n%s", last, logs)
}

func connectMongo(ctx context.Context, uri string, tlsConfig *tls.Config) (*mongo.Client, error) {
	opts := options.Client().ApplyURI(uri)
	if tlsConfig != nil {
		opts.SetTLSConfig(tlsConfig)
	}
	connectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	client, err := mongo.Connect(connectCtx, opts)
	if err != nil {
		return nil, err
	}
	if err = client.Ping(connectCtx, nil); err != nil {
		_ = client.Disconnect(context.Background())
		return nil, err
	}
	return client, nil
}
func mongoURI(port int, app, extra string) string {
	uri := fmt.Sprintf("mongodb://127.0.0.1:%d/?directConnection=true&appName=%s", port, app)
	if extra != "" {
		uri += "&" + extra
	}
	return uri
}

func (h *harness) startCapture(t *testing.T, label string, port int) *captureRun {
	t.Helper()
	cap := &captureRun{reportPath: filepath.Join(h.artifacts, label+"-live.json"), pcapPath: filepath.Join(h.artifacts, label+".pcap")}
	packetArgs := []string{h.tcpdump, "-i", h.iface, "-U", "-s", "0", "-w", cap.pcapPath, fmt.Sprintf("tcp port %d", port)}
	if os.Getenv("MONGOSNIFFER_E2E_SUDO") == "1" {
		packetArgs = append([]string{"sudo", "-n"}, packetArgs...)
	}
	cap.packetCmd = exec.Command(packetArgs[0], packetArgs[1:]...)
	cap.packetCmd.Dir = h.repo
	cap.packetCmd.Stdout = &cap.packetStdout
	cap.packetCmd.Stderr = &cap.packetStderr
	if err := cap.packetCmd.Start(); err != nil {
		t.Fatal(err)
	}
	cap.packetDone = make(chan error, 1)
	go func() { cap.packetDone <- cap.packetCmd.Wait() }()
	args := []string{h.binary, "--interface", h.iface, "--server", e2eServerSpec(port), "--max-groups", "0"}
	if os.Getenv("MONGOSNIFFER_E2E_SUDO") == "1" {
		args = append([]string{"sudo", "-n"}, args...)
	}
	cap.cmd = exec.Command(args[0], args[1:]...)
	cap.cmd.Dir = h.repo
	cap.cmd.Stdout = &cap.stdout
	cap.cmd.Stderr = &cap.stderr
	if err := cap.cmd.Start(); err != nil {
		stopProcess(cap.packetCmd, cap.packetDone)
		t.Fatal(err)
	}
	cap.cmdDone = make(chan error, 1)
	go func() { cap.cmdDone <- cap.cmd.Wait() }()
	h.waitCapture(t, cap, port)
	return cap
}
func (h *harness) waitCapture(t *testing.T, cap *captureRun, port int) {
	t.Helper()
	deadline := time.NewTimer(10 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()
	for {
		select {
		case err := <-cap.cmdDone:
			stopProcess(cap.packetCmd, cap.packetDone)
			t.Fatalf("mongosniffer startup: %v stderr=%s", err, cap.stderr.String())
		case err := <-cap.packetDone:
			stopProcess(cap.cmd, cap.cmdDone)
			t.Fatalf("tcpdump startup: %v stderr=%s", err, cap.packetStderr.String())
		case <-ticker.C:
			if info, err := os.Stat(cap.pcapPath); err == nil && info.Size() >= 24 {
				return
			}
			conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 100*time.Millisecond)
			if err == nil {
				_ = conn.Close()
			}
		case <-deadline.C:
			t.Fatalf("capture startup timeout: sniffer=%s tcpdump=%s", cap.stderr.String(), cap.packetStderr.String())
		}
	}
}
func (h *harness) stopCapture(t *testing.T, cap *captureRun) reportJSON {
	t.Helper()
	time.Sleep(1500 * time.Millisecond)
	if err := cap.cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-cap.cmdDone:
		if err != nil {
			t.Fatalf("mongosniffer exit: %v\nstdout=%s\nstderr=%s", err, cap.stdout.String(), cap.stderr.String())
		}
	case <-time.After(10 * time.Second):
		_ = cap.cmd.Process.Kill()
		t.Fatal("mongosniffer stop timeout")
	}
	stopProcess(cap.packetCmd, cap.packetDone)
	_ = os.WriteFile(cap.reportPath, cap.stdout.Bytes(), 0o600)
	_ = os.WriteFile(cap.pcapPath+".tcpdump.log", cap.packetStderr.Bytes(), 0o600)
	if info, err := os.Stat(cap.pcapPath); err != nil || info.Size() <= 24 {
		t.Fatalf("empty PCAP: %v %v", info, err)
	}
	return decodeReport(t, cap.stdout.Bytes(), cap.reportPath)
}
func (h *harness) replay(t *testing.T, cap *captureRun, port int, label string) reportJSON {
	t.Helper()
	data := []byte(h.runOutput(t, h.repo, h.binary, "--read-pcap", cap.pcapPath, "--server", e2eServerSpec(port), "--max-groups", "0"))
	path := filepath.Join(h.artifacts, label+"-replay.json")
	_ = os.WriteFile(path, data, 0o600)
	return decodeReport(t, data, path)
}

func e2eServerSpec(port int) string {
	value := strconv.Itoa(port)
	return net.JoinHostPort("127.0.0.1", value) + "," + net.JoinHostPort("127.0.0.2", value)
}

func stopProcess(cmd *exec.Cmd, done <-chan error) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(os.Interrupt)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		<-done
	}
}
func decodeReport(t *testing.T, data []byte, path string) reportJSON {
	t.Helper()
	var result reportJSON
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode %s: %v\n%s", path, err, data)
	}
	return result
}
func (h *harness) assertHealthy(t *testing.T, r reportJSON) {
	t.Helper()
	if r.SchemaVersion != 1 || r.Build.Version == "" {
		t.Fatalf("report identity: %+v", r)
	}
	if r.DecodeErrors != 0 || r.DroppedOperationKeys != 0 || r.Capture.TCPGapEvents != 0 || r.Capture.ProtocolStateLossConnections != 0 {
		t.Fatalf("unhealthy report: %+v", r)
	}
	if r.Capture.PacketsMatched == 0 || r.Capture.ConnectionsObserved == 0 {
		t.Fatalf("empty capture: %+v", r.Capture)
	}
	for _, operation := range r.Operations {
		if operation.FingerprintID == "" {
			t.Fatalf("operation missing fingerprint_id: %+v", operation)
		}
		if operation.Dimensions.ServerAddress == "" {
			t.Fatalf("operation missing server_address: %+v", operation)
		}
	}
}
func operationsFor(r reportJSON, command string) []operationJSON {
	var out []operationJSON
	for _, op := range r.Operations {
		if op.Dimensions.Command == command {
			out = append(out, op)
		}
	}
	return out
}
func sumCommand(r reportJSON, command string) (calls, errorsCount, incomplete, unack uint64) {
	for _, op := range operationsFor(r, command) {
		calls += op.Calls
		errorsCount += op.Errors
		incomplete += op.Incomplete
		unack += op.Unacknowledged
	}
	return
}
func requireCommand(t *testing.T, r reportJSON, command string) operationJSON {
	t.Helper()
	ops := operationsFor(r, command)
	if len(ops) == 0 {
		t.Fatalf("command %q missing: %+v", command, r.Operations)
	}
	return ops[0]
}
func (h *harness) assertReplayEqual(t *testing.T, live, replay reportJSON) {
	t.Helper()
	live.GeneratedAt = time.Time{}
	replay.GeneratedAt = time.Time{}
	live.Capture = captureJSON{}
	replay.Capture = captureJSON{}
	// A live backend can observe a final control response after the client FIN
	// has already completed the reassembly stream, while an EOF replay flushes
	// both directions together. This does not affect operation attribution.
	delete(live.ProtocolIssues, "unknown_response_to")
	delete(replay.ProtocolIssues, "unknown_response_to")
	sort.Slice(live.Operations, func(i, j int) bool { return operationKey(live.Operations[i]) < operationKey(live.Operations[j]) })
	sort.Slice(replay.Operations, func(i, j int) bool { return operationKey(replay.Operations[i]) < operationKey(replay.Operations[j]) })
	stripLatency(live.Operations)
	stripLatency(replay.Operations)
	if !reflect.DeepEqual(live, replay) {
		t.Fatalf("live/replay differ\nlive=%+v\nreplay=%+v", live, replay)
	}
}
func operationKey(op operationJSON) string {
	return op.Dimensions.Command + "\x00" + op.Dimensions.ApplicationName + "\x00" + op.Dimensions.ServerAddress + "\x00" + op.FingerprintID + "\x00" + op.Fingerprint
}
func stripLatency(ops []operationJSON) {
	for i := range ops {
		observations := ops[i].Latency.Observations
		first := ops[i].Latency.FirstResponse.Observations
		transfer := ops[i].Latency.ResponseTransfer.Observations
		ops[i].Latency = latencyJSON{Observations: observations, FirstResponse: phaseJSON{Observations: first}, ResponseTransfer: phaseJSON{Observations: transfer}}
		if ops[i].IncompleteObserved != nil {
			ops[i].IncompleteObserved = &phaseJSON{Observations: ops[i].IncompleteObserved.Observations}
		}
	}
}

func (h *harness) cleanup() {
	for i := len(h.resources) - 1; i >= 0; i-- {
		r := h.resources[i]
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		_ = exec.CommandContext(ctx, "docker", r.kind, "rm", "-f", r.name).Run()
		cancel()
	}
	if h.t.Failed() || h.retain {
		h.t.Logf("E2E artifacts: %s", h.artifacts)
	} else {
		_ = os.RemoveAll(h.artifacts)
	}
}
func (h *harness) docker(t *testing.T, args ...string) { h.run(t, h.repo, "docker", args...) }
func (h *harness) dockerOutput(t *testing.T, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	output, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	return string(output), err
}
func (h *harness) run(t *testing.T, dir, name string, args ...string) {
	h.runWithTimeout(t, commandTimeout, dir, name, args...)
}
func (h *harness) runWithTimeout(t *testing.T, timeout time.Duration, dir, name string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, output)
	}
}
func (h *harness) runOutput(t *testing.T, dir, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %s: %v\nstdout=%s\nstderr=%s", name, strings.Join(args, " "), err, stdout.String(), stderr.String())
	}
	return stdout.String()
}
func freePort(t *testing.T) int {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	return port
}

func (h *harness) generateTLS(t *testing.T, label string) (string, *tls.Config) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	now := time.Now()
	template := x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "localhost"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	dir := filepath.Join(h.artifacts, label+"-certs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	server := append(append([]byte(nil), certPEM...), keyPEM...)
	if err := os.WriteFile(filepath.Join(dir, "server.pem"), server, 0o644); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	return dir, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: "localhost"}
}
