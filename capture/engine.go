package capture

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/c77cc/mongosniffer/bsonshape"
	"github.com/c77cc/mongosniffer/model"
	"github.com/c77cc/mongosniffer/report"
	"github.com/c77cc/mongosniffer/wire"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/ip4defrag"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/reassembly"
)

type Config struct {
	Interface   string
	ReadPCAP    string
	Servers     []netip.AddrPort
	Collector   *report.Collector
	OnReady     func()
	OnTraffic   func()
	OnOperation func(model.OperationEvent)
	OnEncrypted func()
	RawCommand  bool
	GroupByRaw  bool
}

type captureContext struct{ info gopacket.CaptureInfo }

func (c captureContext) GetCaptureInfo() gopacket.CaptureInfo { return c.info }

type streamFactory struct {
	servers      serverSet
	collector    *report.Collector
	onOperation  func(model.OperationEvent)
	onEncrypted  func()
	rawCommand   bool
	groupByRaw   bool
	cursorBudget *wire.CursorBudget
}
type mongoStream struct {
	session                                                   *wire.Session
	collector                                                 *report.Collector
	firstIsClient                                             bool
	lastSeen                                                  time.Time
	sawTCPClose, handshakeCounted, stateLossCounted, disabled bool
}

func (f *streamFactory) New(netFlow, _ gopacket.Flow, tcp *layers.TCP, _ reassembly.AssemblerContext) reassembly.Stream {
	endpoint, firstIsClient, matched := matchServer(netFlow, tcp, f.servers)
	if !matched {
		return &mongoStream{disabled: true}
	}
	clientIP := netFlow.Src().String()
	if !firstIsClient {
		clientIP = netFlow.Dst().String()
	}
	midstream := !tcp.SYN || tcp.ACK
	f.collector.AddConnection(midstream)
	s := &mongoStream{collector: f.collector, firstIsClient: firstIsClient}
	s.session = wire.NewSession(wire.SessionConfig{
		Decode: wire.DefaultDecodeLimits(), Fingerprint: bsonshape.DefaultLimits(),
		Metadata: model.ConnectionMetadata{ClientAddress: clientIP, ServerAddress: endpoint.String(), Midstream: midstream},
		OnEvent: func(event model.OperationEvent) {
			f.collector.Add(event)
			if f.onOperation != nil {
				f.onOperation(event)
			}
		},
		OnIssue: f.collector.AddIssue, OnEncrypted: func() {
			f.collector.AddEncryptedSession()
			if f.onEncrypted != nil {
				f.onEncrypted()
			}
		},
		RawCommand:   f.rawCommand,
		GroupByRaw:   f.groupByRaw,
		CursorBudget: f.cursorBudget,
	})
	return s
}

func (s *mongoStream) Accept(tcp *layers.TCP, info gopacket.CaptureInfo, _ reassembly.TCPFlowDirection, _ reassembly.Sequence, start *bool, _ reassembly.AssemblerContext) bool {
	*start = true
	if tcp.FIN || tcp.RST {
		s.sawTCPClose = true
	}
	if info.Timestamp.After(s.lastSeen) {
		s.lastSeen = info.Timestamp
	}
	return true
}
func (s *mongoStream) ReassembledSG(sg reassembly.ScatterGather, _ reassembly.AssemblerContext) {
	if s.disabled {
		return
	}
	length, _ := sg.Lengths()
	if length == 0 {
		return
	}
	data := sg.Fetch(length)
	started := sg.CaptureInfo(0)
	completed := sg.CaptureInfo(length - 1)
	if completed.Timestamp.Before(started.Timestamp) {
		completed = started
	}
	if completed.Timestamp.After(s.lastSeen) {
		s.lastSeen = completed.Timestamp
	}
	direction, _, end, skip := sg.Info()
	if end {
		s.sawTCPClose = true
	}
	if skip > 0 {
		s.collector.AddTCPGap(skip)
		s.collector.AddDecodeError()
		s.markStateLoss()
		s.session.Gap(started.Timestamp, skip)
		s.disabled = true
		return
	}
	clientToServer := direction == reassembly.TCPDirClientToServer
	if !s.firstIsClient {
		clientToServer = !clientToServer
	}
	d := model.ServerToClient
	if clientToServer {
		d = model.ClientToServer
	}
	if err := s.session.FeedSpan(d, data, started.Timestamp, completed.Timestamp); err != nil {
		s.collector.AddDecodeError()
		s.markStateLoss()
		s.disabled = true
		return
	}
	if s.session.Metadata().HandshakeObserved && !s.handshakeCounted {
		s.handshakeCounted = true
		s.collector.AddHandshakeConnection()
	}
}
func (s *mongoStream) markStateLoss() {
	if !s.stateLossCounted {
		s.stateLossCounted = true
		s.collector.AddProtocolStateLoss()
	}
}
func (s *mongoStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	if s.session == nil {
		return true
	}
	at := s.lastSeen
	if ac != nil && ac.GetCaptureInfo().Timestamp.After(at) {
		at = ac.GetCaptureInfo().Timestamp
	}
	if at.IsZero() {
		at = time.Now()
	}
	reason := "capture_or_idle_timeout"
	if s.sawTCPClose {
		reason = "connection_closed"
	}
	s.session.Close(at, reason)
	return true
}

func Run(ctx context.Context, cfg Config) error {
	if cfg.Collector == nil {
		return fmt.Errorf("collector is required")
	}
	if len(cfg.Servers) == 0 {
		return fmt.Errorf("at least one server endpoint is required")
	}
	handle, err := openCapture(cfg.ReadPCAP, cfg.Interface, cfg.Servers)
	if err != nil {
		return err
	}
	defer handle.Close()
	defer updateStats(handle, cfg.Collector)
	if cfg.OnReady != nil {
		cfg.OnReady()
	}
	servers := makeServerSet(cfg.Servers)
	factory := &streamFactory{servers: servers, collector: cfg.Collector, onOperation: cfg.OnOperation, onEncrypted: cfg.OnEncrypted, rawCommand: cfg.RawCommand, groupByRaw: cfg.GroupByRaw, cursorBudget: wire.NewCursorBudget(100000)}
	pool := reassembly.NewStreamPool(factory)
	assembler := reassembly.NewAssembler(pool)
	assembler.MaxBufferedPagesPerConnection = 128
	assembler.MaxBufferedPagesTotal = 4096
	defragmenter := ip4defrag.NewIPv4Defragmenter()
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := source.Packets()
	flush := time.NewTicker(30 * time.Second)
	defer flush.Stop()
	stats := time.NewTicker(10 * time.Second)
	defer stats.Stop()
	var latest time.Time
	var count uint64
	traffic := false
	for {
		select {
		case <-ctx.Done():
			assembler.FlushAll()
			return ctx.Err()
		case <-flush.C:
			if !latest.IsZero() {
				assembler.FlushCloseOlderThan(latest.Add(-2 * time.Minute))
				defragmenter.DiscardOlderThan(latest.Add(-2 * time.Minute))
			}
		case <-stats.C:
			updateStats(handle, cfg.Collector)
		case packet, ok := <-packets:
			if !ok || packet == nil {
				assembler.FlushAll()
				return nil
			}
			metadata := packet.Metadata()
			if metadata == nil {
				cfg.Collector.AddDecodeError()
				continue
			}
			latest = metadata.Timestamp
			if packet.ErrorLayer() != nil {
				cfg.Collector.AddDecodeError()
			}
			network, tcp, fragments, decodeErr := decodeNetworkTCP(packet, defragmenter, metadata.Timestamp)
			if decodeErr != nil {
				cfg.Collector.AddDecodeError()
				cfg.Collector.AddPacket(metadata.CaptureLength, false, metadata.CaptureLength < metadata.Length)
				continue
			}
			if fragments {
				cfg.Collector.AddPacket(metadata.CaptureLength, fragmentMatchesServer(packet.NetworkLayer(), servers), metadata.CaptureLength < metadata.Length)
				continue
			}
			matched := network != nil && tcp != nil && packetMatchesServer(network, tcp, servers)
			cfg.Collector.AddPacket(metadata.CaptureLength, matched, metadata.CaptureLength < metadata.Length)
			if !matched {
				continue
			}
			if !traffic {
				traffic = true
				if cfg.OnTraffic != nil {
					cfg.OnTraffic()
				}
			}
			assembler.AssembleWithContext(network.NetworkFlow(), tcp, captureContext{metadata.CaptureInfo})
			count++
			if count%10000 == 0 {
				assembler.FlushCloseOlderThan(latest.Add(-2 * time.Minute))
			}
		}
	}
}

func decodeNetworkTCP(packet gopacket.Packet, d *ip4defrag.IPv4Defragmenter, timestamp time.Time) (gopacket.NetworkLayer, *layers.TCP, bool, error) {
	network := packet.NetworkLayer()
	if ipv4, ok := network.(*layers.IPv4); ok && (ipv4.Flags&layers.IPv4MoreFragments != 0 || ipv4.FragOffset != 0) {
		defrag, err := d.DefragIPv4WithTimestamp(ipv4, timestamp)
		if err != nil {
			return nil, nil, false, err
		}
		if defrag == nil {
			return nil, nil, true, nil
		}
		tcp := &layers.TCP{}
		if err := tcp.DecodeFromBytes(defrag.Payload, gopacket.NilDecodeFeedback); err != nil {
			return nil, nil, false, err
		}
		return defrag, tcp, false, nil
	}
	tcp, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	return network, tcp, false, nil
}

type serverSet map[netip.AddrPort]struct{}

func makeServerSet(servers []netip.AddrPort) serverSet {
	result := make(serverSet, len(servers))
	for _, server := range servers {
		result[netip.AddrPortFrom(server.Addr().Unmap(), server.Port())] = struct{}{}
	}
	return result
}

func fragmentMatchesServer(network gopacket.NetworkLayer, servers serverSet) bool {
	if network == nil {
		return false
	}
	flow := network.NetworkFlow()
	source, e1 := netip.ParseAddr(flow.Src().String())
	destination, e2 := netip.ParseAddr(flow.Dst().String())
	if e1 != nil || e2 != nil {
		return false
	}
	for server := range servers {
		if source.Unmap() == server.Addr() || destination.Unmap() == server.Addr() {
			return true
		}
	}
	return false
}
func packetMatchesServer(network gopacket.NetworkLayer, tcp *layers.TCP, servers serverSet) bool {
	_, _, matched := matchServer(network.NetworkFlow(), tcp, servers)
	return matched
}

func matchServer(flow gopacket.Flow, tcp *layers.TCP, servers serverSet) (netip.AddrPort, bool, bool) {
	source, e1 := netip.ParseAddr(flow.Src().String())
	destination, e2 := netip.ParseAddr(flow.Dst().String())
	if e1 != nil || e2 != nil {
		return netip.AddrPort{}, false, false
	}
	sourceEndpoint := netip.AddrPortFrom(source.Unmap(), uint16(tcp.SrcPort))
	destinationEndpoint := netip.AddrPortFrom(destination.Unmap(), uint16(tcp.DstPort))
	_, sourceIsServer := servers[sourceEndpoint]
	_, destinationIsServer := servers[destinationEndpoint]
	if sourceIsServer == destinationIsServer {
		return netip.AddrPort{}, false, false
	}
	if destinationIsServer {
		return destinationEndpoint, true, true
	}
	return sourceEndpoint, false, true
}
func updateStats(handle Handle, collector *report.Collector) {
	if stats, err := handle.Stats(); err == nil {
		collector.SetCaptureDrops(stats.PacketsDropped, stats.InterfaceDropped)
	}
}
