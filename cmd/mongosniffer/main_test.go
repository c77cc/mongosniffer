package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/c77cc/mongosniffer/model"
	"github.com/c77cc/mongosniffer/report"
)

func TestParseAndValidateFlags(t *testing.T) {
	cfg, err := parseFlags([]string{"--server", "127.0.0.1:27017", "--read-pcap", "mongo.pcap", "--group-by", "fingerprint"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	servers, err := validateConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 || servers[0].Port() != 27017 {
		t.Fatalf("servers = %v", servers)
	}
	bad, _ := parseFlags([]string{"--server", "localhost:27017"}, io.Discard)
	if _, err := validateConfig(bad); err == nil {
		t.Fatal("hostname unexpectedly accepted; endpoint filtering requires an IP")
	}
}

func TestParseServerEndpoints(t *testing.T) {
	servers, err := parseServerEndpoints("127.0.0.1:27017, [::1]:27018,127.0.0.1:27017")
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:27017"), netip.MustParseAddrPort("[::1]:27018")}
	if len(servers) != len(want) || servers[0] != want[0] || servers[1] != want[1] {
		t.Fatalf("servers = %v, want %v", servers, want)
	}
	for _, value := range []string{"", "127.0.0.1:27017,", "localhost:27017", "127.0.0.1:0"} {
		if _, err := parseServerEndpoints(value); err == nil {
			t.Errorf("parseServerEndpoints(%q) unexpectedly succeeded", value)
		}
	}
	tooMany := strings.Repeat("127.0.0.1:27017,", maxServerEndpoints) + "127.0.0.1:27017"
	if _, err := parseServerEndpoints(tooMany); err == nil || !strings.Contains(err.Error(), "maximum is 64") {
		t.Fatalf("too many endpoints error = %v", err)
	}
}

func TestRepeatedServerFlagRejected(t *testing.T) {
	_, err := parseFlags([]string{"--server", "127.0.0.1:27017", "--server", "127.0.0.2:27017"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "separate endpoints with commas") {
		t.Fatalf("repeated --server error = %v", err)
	}
}

func TestRuntimeServices(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	path := filepath.Join(t.TempDir(), "reports.jsonl")
	cfg := config{listen: "127.0.0.1:0", reportFile: path, reportInterval: 10 * time.Millisecond}
	services, err := startServices(ctx, cancel, cfg, report.NewCollector(10, false))
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.Get("http://" + services.listener.Addr().String() + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || !bytes.Equal(body, []byte("ok\n")) {
		t.Fatalf("health response = %d %q", response.StatusCode, body)
	}
	time.Sleep(25 * time.Millisecond)
	if err := services.close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Windows does not expose POSIX permission bits through os.Chmod/os.Stat.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("report mode = %o", info.Mode().Perm())
	}
	contents, err := os.ReadFile(path)
	if err != nil || len(contents) == 0 {
		t.Fatalf("periodic report = %q, %v", contents, err)
	}
}

func TestCaptureStatusMessages(t *testing.T) {
	var output bytes.Buffer
	servers := []netip.AddrPort{netip.MustParseAddrPort("10.0.0.8:27017"), netip.MustParseAddrPort("10.0.0.9:27017")}
	writeCaptureStarted(&output, config{interfaceName: "eth0", server: "10.0.0.8:27017,10.0.0.9:27017"}, servers)
	writeCaptureWarning(&output, 10*time.Second, false)
	writeCaptureWarning(&output, 10*time.Second, true)

	collector := report.NewCollector(10, false)
	collector.AddPacket(128, true, false)
	collector.SetCaptureDrops(2, 3)
	collector.Add(model.OperationEvent{Command: "find", Fingerprint: "find {}", Acknowledged: true, Duration: time.Millisecond})
	collector.Add(model.OperationEvent{Command: "insert", Fingerprint: "insert {}", Acknowledged: true, Incomplete: true, IncompleteReason: "connection_closed", Duration: time.Millisecond})
	collector.AddEncryptedSession()
	writeCaptureStopped(&output, collector)

	for _, expected := range []string{
		`capture started interface="eth0" servers="10.0.0.8:27017,10.0.0.9:27017" filter="(host 10.0.0.8 and tcp port 27017) or (host 10.0.0.9 and tcp port 27017)"`,
		"press Ctrl+C to stop and print the report",
		"no matching MongoDB traffic detected after 10s",
		"traffic was detected, but no complete command was decoded after 10s",
		"capture stopped packets=1 matched=1 operations=2 incomplete=1 unacknowledged=0 encrypted_sessions=1 capture_drops=5",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("status output does not contain %q:\n%s", expected, output.String())
		}
	}
}

func TestCaptureStatusForOfflineAnalysis(t *testing.T) {
	var output bytes.Buffer
	writeCaptureStarted(&output, config{readPCAP: "traffic.pcap", server: "10.0.0.8:27017"}, []netip.AddrPort{netip.MustParseAddrPort("10.0.0.8:27017")})
	if got := output.String(); !strings.Contains(got, `PCAP analysis started file="traffic.pcap" servers="10.0.0.8:27017"`) || strings.Contains(got, "Ctrl+C") {
		t.Fatalf("offline status = %q", got)
	}
}
