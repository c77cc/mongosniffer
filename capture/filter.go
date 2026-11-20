package capture

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/gopacket/gopacket/layers"
	"golang.org/x/net/bpf"
)

const captureFilterSnapshotLength = 65536

type filterInstruction struct {
	instruction           bpf.Instruction
	trueLabel, falseLabel string
}
type filterBuilder struct {
	instructions []filterInstruction
	labels       map[string]int
}

func newFilterBuilder() *filterBuilder  { return &filterBuilder{labels: make(map[string]int)} }
func (b *filterBuilder) label(v string) { b.labels[v] = len(b.instructions) }
func (b *filterBuilder) add(v bpf.Instruction) {
	b.instructions = append(b.instructions, filterInstruction{instruction: v})
}
func (b *filterBuilder) jump(value uint32, yes, no string) {
	b.instructions = append(b.instructions, filterInstruction{bpf.JumpIf{Cond: bpf.JumpEqual, Val: value}, yes, no})
}
func (b *filterBuilder) jumpBits(value uint32, yes, no string) {
	b.instructions = append(b.instructions, filterInstruction{bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: value}, yes, no})
}
func (b *filterBuilder) assemble() ([]bpf.RawInstruction, error) {
	out := make([]bpf.Instruction, len(b.instructions))
	for i, symbolic := range b.instructions {
		jump, ok := symbolic.instruction.(bpf.JumpIf)
		if !ok {
			out[i] = symbolic.instruction
			continue
		}
		yes, err := b.skip(i, symbolic.trueLabel)
		if err != nil {
			return nil, err
		}
		no, err := b.skip(i, symbolic.falseLabel)
		if err != nil {
			return nil, err
		}
		jump.SkipTrue, jump.SkipFalse = uint8(yes), uint8(no)
		out[i] = jump
	}
	return bpf.Assemble(out)
}
func (b *filterBuilder) skip(i int, label string) (int, error) {
	target, ok := b.labels[label]
	if !ok {
		return 0, fmt.Errorf("unknown BPF label %q", label)
	}
	value := target - i - 1
	if value < 0 || value > 255 {
		return 0, fmt.Errorf("invalid BPF jump")
	}
	return value, nil
}

func uniqueServerPorts(servers []netip.AddrPort) []uint16 {
	seen := make(map[uint16]struct{}, len(servers))
	ports := make([]uint16, 0, len(servers))
	for _, server := range servers {
		port := server.Port()
		if _, exists := seen[port]; exists {
			continue
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	return ports
}

func serverPortFilter(ports []uint16) ([]bpf.RawInstruction, error) {
	if len(ports) == 0 {
		return nil, fmt.Errorf("at least one server port is required")
	}
	if len(ports) > 1 {
		// Exact endpoint matching still happens in userspace. Keeping this
		// fallback small avoids classic-BPF 8-bit jump limits for large,
		// heterogeneous endpoint lists while retaining link-layer filtering.
		return serverProtocolFilter()
	}
	port := ports[0]
	b := newFilterBuilder()
	b.add(bpf.LoadAbsolute{Off: 12, Size: 2})
	b.jump(uint32(layers.EthernetTypeIPv4), "ipv4", "check6")
	b.label("check6")
	b.jump(uint32(layers.EthernetTypeIPv6), "ipv6", "checkvlan")
	b.label("checkvlan")
	b.jump(uint32(layers.EthernetTypeDot1Q), "vlan1", "checkqinq")
	b.label("checkqinq")
	b.jump(uint32(layers.EthernetTypeQinQ), "vlan1", "drop")
	addIPv4Filter(b, "ipv4", 14, port)
	addIPv6Filter(b, "ipv6", 14, port)
	b.label("vlan1")
	b.add(bpf.LoadAbsolute{Off: 16, Size: 2})
	b.jump(uint32(layers.EthernetTypeIPv4), "vlan1v4", "vlan1check6")
	b.label("vlan1check6")
	b.jump(uint32(layers.EthernetTypeIPv6), "vlan1v6", "vlan2check")
	b.label("vlan2check")
	b.jump(uint32(layers.EthernetTypeDot1Q), "vlan2", "vlan2qinq")
	b.label("vlan2qinq")
	b.jump(uint32(layers.EthernetTypeQinQ), "vlan2", "drop")
	addIPv4Filter(b, "vlan1v4", 18, port)
	addIPv6Filter(b, "vlan1v6", 18, port)
	b.label("vlan2")
	b.add(bpf.LoadAbsolute{Off: 20, Size: 2})
	b.jump(uint32(layers.EthernetTypeIPv4), "vlan2v4", "vlan2check6")
	b.label("vlan2check6")
	b.jump(uint32(layers.EthernetTypeIPv6), "vlan2v6", "drop")
	addIPv4Filter(b, "vlan2v4", 22, port)
	addIPv6Filter(b, "vlan2v6", 22, port)
	b.label("accept")
	b.add(bpf.RetConstant{Val: captureFilterSnapshotLength})
	b.label("drop")
	b.add(bpf.RetConstant{})
	return b.assemble()
}

func serverProtocolFilter() ([]bpf.RawInstruction, error) {
	return bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: 12, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(layers.EthernetTypeIPv4), SkipTrue: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(layers.EthernetTypeIPv6), SkipTrue: 3},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(layers.EthernetTypeDot1Q), SkipTrue: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(layers.EthernetTypeQinQ), SkipTrue: 1},
		bpf.RetConstant{},
		bpf.RetConstant{Val: captureFilterSnapshotLength},
	})
}
func addIPv4Filter(b *filterBuilder, label string, offset uint32, port uint16) {
	b.label(label)
	b.add(bpf.LoadAbsolute{Off: offset + 9, Size: 1})
	b.jump(uint32(layers.IPProtocolTCP), label+"frag", "drop")
	b.label(label + "frag")
	b.add(bpf.LoadAbsolute{Off: offset + 6, Size: 2})
	b.jumpBits(0x3fff, "accept", label+"ports")
	b.label(label + "ports")
	b.add(bpf.LoadMemShift{Off: offset})
	b.add(bpf.LoadIndirect{Off: offset, Size: 2})
	b.jump(uint32(port), "accept", label+"dst")
	b.label(label + "dst")
	b.add(bpf.LoadIndirect{Off: offset + 2, Size: 2})
	b.jump(uint32(port), "accept", "drop")
}
func addIPv6Filter(b *filterBuilder, label string, offset uint32, port uint16) {
	b.label(label)
	b.add(bpf.LoadAbsolute{Off: offset + 6, Size: 1})
	b.jump(uint32(layers.IPProtocolTCP), label+"src", "accept")
	b.label(label + "src")
	b.add(bpf.LoadAbsolute{Off: offset + 40, Size: 2})
	b.jump(uint32(port), "accept", label+"dst")
	b.label(label + "dst")
	b.add(bpf.LoadAbsolute{Off: offset + 42, Size: 2})
	b.jump(uint32(port), "accept", "drop")
}
