package capture

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

type Handle interface {
	gopacket.PacketDataSource
	LinkType() layers.LinkType
	Stats() (Stats, error)
	Close()
}
type Stats struct{ PacketsReceived, PacketsDropped, InterfaceDropped uint64 }
type Device struct {
	Name, Description string
	Addresses         []string
}

type offlineCapture struct {
	file     *os.File
	source   gopacket.PacketDataSource
	linkType layers.LinkType
}

func (c *offlineCapture) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return c.source.ReadPacketData()
}
func (c *offlineCapture) LinkType() layers.LinkType { return c.linkType }
func (c *offlineCapture) Stats() (Stats, error)     { return Stats{}, nil }
func (c *offlineCapture) Close()                    { _ = c.file.Close() }

func openCapture(readPCAP, interfaceName string, servers []netip.AddrPort) (Handle, error) {
	if readPCAP != "" {
		return openOfflineCapture(readPCAP)
	}
	return openLiveCapture(interfaceName, servers)
}

func openOfflineCapture(path string) (Handle, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open PCAP file %q: %w", path, err)
	}
	reader := bufio.NewReader(file)
	magic, err := reader.Peek(4)
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("read PCAP header %q: %w", path, err)
	}
	result := &offlineCapture{file: file}
	if bytes.Equal(magic, []byte{0x0a, 0x0d, 0x0d, 0x0a}) {
		ng, readErr := pcapgo.NewNgReader(reader, pcapgo.NgReaderOptions{ErrorOnMismatchingLinkType: true})
		if readErr != nil {
			_ = file.Close()
			return nil, fmt.Errorf("open PCAPNG file %q: %w", path, readErr)
		}
		result.source, result.linkType = ng, ng.LinkType()
		return result, nil
	}
	pcap, err := pcapgo.NewReader(reader)
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("open PCAP file %q: %w", path, err)
	}
	result.source, result.linkType = pcap, pcap.LinkType()
	return result, nil
}

func DefaultInterface() string       { return defaultCaptureInterface() }
func ListDevices() ([]Device, error) { return listCaptureDevices() }
func PrintDevices(w io.Writer) error {
	devices, err := ListDevices()
	if err != nil {
		return fmt.Errorf("list interfaces: %w", err)
	}
	if len(devices) == 0 {
		_, err = fmt.Fprintln(w, "No capture interfaces found.")
		return err
	}
	for i, device := range devices {
		description := strings.TrimSpace(device.Description)
		if description == "" {
			description = device.Name
		}
		if _, err = fmt.Fprintf(w, "[%d] %s\n", i+1, description); err != nil {
			return err
		}
		if description != device.Name {
			if _, err = fmt.Fprintf(w, "    Device:    %s\n", device.Name); err != nil {
				return err
			}
		}
		if len(device.Addresses) == 0 {
			_, err = fmt.Fprintln(w, "    Addresses: not reported")
		} else {
			_, err = fmt.Fprintln(w, "    Addresses:")
			for _, address := range device.Addresses {
				if err == nil {
					_, err = fmt.Fprintf(w, "      - %s\n", address)
				}
			}
		}
		if err != nil {
			return err
		}
		if _, err = fmt.Fprintf(w, "    Usage:     --interface %q\n", device.Name); err != nil {
			return err
		}
		if i+1 < len(devices) {
			_, err = fmt.Fprintln(w)
		}
	}
	return err
}

func ServerBPFFilter(endpoints []netip.AddrPort) string {
	parts := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		clause := fmt.Sprintf("host %s and tcp port %d", endpoint.Addr(), endpoint.Port())
		if endpoint.Addr().Is6() {
			clause = "ip6 and " + clause
		}
		if len(endpoints) > 1 {
			clause = "(" + clause + ")"
		}
		parts = append(parts, clause)
	}
	return strings.Join(parts, " or ")
}
