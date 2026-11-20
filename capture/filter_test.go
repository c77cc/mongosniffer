package capture

import (
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestMultipleServerFilterAndMatching(t *testing.T) {
	servers := []netip.AddrPort{
		netip.MustParseAddrPort("10.0.0.1:27017"),
		netip.MustParseAddrPort("10.0.0.3:27018"),
	}
	filter := ServerBPFFilter(servers)
	for _, expected := range []string{"host 10.0.0.1 and tcp port 27017", "host 10.0.0.3 and tcp port 27018", " or "} {
		if !strings.Contains(filter, expected) {
			t.Fatalf("filter %q does not contain %q", filter, expected)
		}
	}
	ports := uniqueServerPorts(servers)
	if len(ports) != 2 || ports[0] != 27017 || ports[1] != 27018 {
		t.Fatalf("ports = %v", ports)
	}
	if instructions, err := serverPortFilter(ports); err != nil || len(instructions) == 0 {
		t.Fatalf("multi-port filter = %v, %v", instructions, err)
	}

	set := makeServerSet(servers)
	flow := ipv4Flow("10.0.0.2", "10.0.0.3")
	endpoint, clientToServer, ok := matchServer(flow, &layers.TCP{SrcPort: 40000, DstPort: 27018}, set)
	if !ok || !clientToServer || endpoint != servers[1] {
		t.Fatalf("client match = %s, %t, %t", endpoint, clientToServer, ok)
	}
	endpoint, clientToServer, ok = matchServer(ipv4Flow("10.0.0.3", "10.0.0.2"), &layers.TCP{SrcPort: 27018, DstPort: 40000}, set)
	if !ok || clientToServer || endpoint != servers[1] {
		t.Fatalf("server match = %s, %t, %t", endpoint, clientToServer, ok)
	}
	if _, _, ok = matchServer(flow, &layers.TCP{SrcPort: 40000, DstPort: 27019}, set); ok {
		t.Fatal("unconfigured port unexpectedly matched")
	}
	if _, _, ok = matchServer(ipv4Flow("10.0.0.1", "10.0.0.3"), &layers.TCP{SrcPort: 27017, DstPort: 27018}, set); ok {
		t.Fatal("traffic between two configured endpoints is ambiguous and must not match")
	}
}

func ipv4Flow(source, destination string) gopacket.Flow {
	return gopacket.NewFlow(layers.EndpointIPv4, net.ParseIP(source).To4(), net.ParseIP(destination).To4())
}
