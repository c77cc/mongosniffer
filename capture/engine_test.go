package capture

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/c77cc/mongosniffer/report"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"go.mongodb.org/mongo-driver/bson"
)

func TestOfflineCaptureEndToEnd(t *testing.T) {
	requestBody, _ := bson.Marshal(bson.D{{Key: "find", Value: "orders"}, {Key: "filter", Value: bson.D{{Key: "status", Value: "paid"}}}, {Key: "$db", Value: "shop"}})
	responseBody, _ := bson.Marshal(bson.D{{Key: "ok", Value: 1}, {Key: "cursor", Value: bson.D{{Key: "id", Value: int64(0)}, {Key: "ns", Value: "shop.orders"}, {Key: "firstBatch", Value: bson.A{bson.D{{Key: "_id", Value: 1}}}}}}})
	request := testOPMsg(10, 0, requestBody)
	response := testOPMsg(20, 10, responseBody)
	t0 := time.Unix(1000, 0)
	path := filepath.Join(t.TempDir(), "mongo.pcap")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	packets := []struct {
		at   time.Time
		data []byte
	}{{t0, testTCPPacket(t, true, 100, request)}, {t0.Add(10 * time.Millisecond), testTCPPacket(t, false, 500, response)}}
	for _, packet := range packets {
		if err := writer.WritePacket(gopacket.CaptureInfo{Timestamp: packet.at, CaptureLength: len(packet.data), Length: len(packet.data)}, packet.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	collector := report.NewCollector(100, false)
	server := netip.MustParseAddrPort("10.0.0.1:27017")
	if err := Run(context.Background(), Config{ReadPCAP: path, Servers: []netip.AddrPort{server}, Collector: collector}); err != nil {
		t.Fatal(err)
	}
	snapshot := collector.Snapshot(report.BuildInfo{Version: "test"}, 0)
	if len(snapshot.Operations) != 1 {
		t.Fatalf("operations = %+v issues=%+v", snapshot.Operations, snapshot.ProtocolIssues)
	}
	op := snapshot.Operations[0]
	if op.Dimensions.Command != "find" || op.Dimensions.ServerAddress != server.String() || op.ReturnedDocuments != 1 || op.LatencyMS.Observations != 1 {
		t.Fatalf("operation = %+v", op)
	}
	if snapshot.Capture.PacketsMatched != 2 {
		t.Fatalf("capture = %+v", snapshot.Capture)
	}
}

func testOPMsg(requestID, responseTo uint32, body []byte) []byte {
	size := 16 + 4 + 1 + len(body)
	out := make([]byte, size)
	binary.LittleEndian.PutUint32(out[:4], uint32(size))
	binary.LittleEndian.PutUint32(out[4:8], requestID)
	binary.LittleEndian.PutUint32(out[8:12], responseTo)
	binary.LittleEndian.PutUint32(out[12:16], 2013)
	out[20] = 0
	copy(out[21:], body)
	return out
}
func testTCPPacket(t *testing.T, client bool, sequence uint32, payload []byte) []byte {
	t.Helper()
	sourceIP, destinationIP := net.ParseIP("10.0.0.2"), net.ParseIP("10.0.0.1")
	sourcePort, destinationPort := layers.TCPPort(40000), layers.TCPPort(27017)
	sourceMAC, destinationMAC := net.HardwareAddr{0, 1, 2, 3, 4, 5}, net.HardwareAddr{6, 7, 8, 9, 10, 11}
	if !client {
		sourceIP, destinationIP = destinationIP, sourceIP
		sourcePort, destinationPort = destinationPort, sourcePort
		sourceMAC, destinationMAC = destinationMAC, sourceMAC
	}
	ethernet := &layers.Ethernet{SrcMAC: sourceMAC, DstMAC: destinationMAC, EthernetType: layers.EthernetTypeIPv4}
	ipv4 := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: sourceIP, DstIP: destinationIP}
	tcp := &layers.TCP{SrcPort: sourcePort, DstPort: destinationPort, Seq: sequence, ACK: true, PSH: true, Window: 65535}
	if err := tcp.SetNetworkLayerForChecksum(ipv4); err != nil {
		t.Fatal(err)
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ethernet, ipv4, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}
