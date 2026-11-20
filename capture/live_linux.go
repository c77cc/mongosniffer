//go:build linux

package capture

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/afpacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/sys/unix"
)

const linuxCaptureBufferSize = captureFilterSnapshotLength

func defaultCaptureInterface() string { return "lo" }

type linuxCapture struct {
	mu        sync.Mutex
	packet    *afpacket.TPacket
	promiscFD int
}

func openLiveCapture(interfaceName string, servers []netip.AddrPort) (Handle, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("open interface %q: %w", interfaceName, err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
	if err != nil {
		return nil, fmt.Errorf("open promiscuous membership socket on %q: %w", interfaceName, err)
	}
	request := &unix.PacketMreq{Ifindex: int32(iface.Index), Type: unix.PACKET_MR_PROMISC}
	if err := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, request); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("enable promiscuous capture on %q: %w", interfaceName, err)
	}
	packet, err := afpacket.NewTPacket(afpacket.OptInterface(interfaceName), afpacket.OptFrameSize(linuxCaptureBufferSize), afpacket.OptBlockSize(1<<20), afpacket.OptNumBlocks(64), afpacket.OptPollTimeout(500*time.Millisecond), afpacket.OptTPacketVersion(afpacket.TPacketVersion3))
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	c := &linuxCapture{packet: packet, promiscFD: fd}
	ports := uniqueServerPorts(servers)
	filter, err := serverPortFilter(ports)
	if err != nil {
		c.Close()
		return nil, err
	}
	if err := packet.SetBPF(filter); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}
func (c *linuxCapture) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	c.mu.Lock()
	p := c.packet
	c.mu.Unlock()
	if p == nil {
		return nil, gopacket.CaptureInfo{}, net.ErrClosed
	}
	return p.ReadPacketData()
}
func (c *linuxCapture) LinkType() layers.LinkType { return layers.LinkTypeEthernet }
func (c *linuxCapture) Stats() (Stats, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.packet == nil {
		return Stats{}, net.ErrClosed
	}
	_, stats, err := c.packet.SocketStats()
	if err != nil {
		return Stats{}, err
	}
	return Stats{PacketsReceived: uint64(stats.Packets()), PacketsDropped: uint64(stats.Drops())}, nil
}
func (c *linuxCapture) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.packet != nil {
		c.packet.Close()
		c.packet = nil
	}
	if c.promiscFD >= 0 {
		_ = unix.Close(c.promiscFD)
		c.promiscFD = -1
	}
}
func listCaptureDevices() ([]Device, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	devices := make([]Device, 0, len(interfaces))
	for _, iface := range interfaces {
		addrs, e := iface.Addrs()
		if e != nil {
			return nil, e
		}
		values := make([]string, 0, len(addrs))
		for _, addr := range addrs {
			values = append(values, addr.String())
		}
		devices = append(devices, Device{iface.Name, iface.Flags.String(), values})
	}
	return devices, nil
}
