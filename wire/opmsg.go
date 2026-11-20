package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"

	"github.com/c77cc/mongosniffer/bsonshape"
)

const (
	FlagChecksumPresent uint32 = 1 << 0
	FlagMoreToCome      uint32 = 1 << 1
	FlagExhaustAllowed  uint32 = 1 << 16
	knownRequiredFlags         = FlagChecksumPresent | FlagMoreToCome
)

type Message struct {
	Header                      Header
	Flags                       uint32
	Body                        []byte
	Sequences                   []bsonshape.Sequence
	Compression                 string
	ProtocolBytes               int64
	UnsupportedOptionalSections int
	UnknownOptionalFlags        uint32
}

func ParseMessage(frame []byte, limits DecodeLimits) (Message, error) {
	if limits.FrameLimit == 0 {
		limits = DefaultDecodeLimits()
	}
	h, err := ParseHeader(frame)
	if err != nil {
		return Message{}, err
	}
	if int64(len(frame)) != int64(h.MessageLength) {
		return Message{}, fmt.Errorf("invalid_message_length: header=%d actual=%d", h.MessageLength, len(frame))
	}
	if len(frame) > limits.FrameLimit || len(frame) > AbsoluteFrameLimit {
		return Message{}, errors.New("invalid_message_length: frame exceeds limit")
	}
	switch h.OpCode {
	case OpMsg:
		return parseOPMsg(frame, h, "", int64(len(frame)), limits)
	case OpCompressed:
		return parseCompressed(frame, h, limits)
	default:
		return Message{Header: h, ProtocolBytes: int64(len(frame))}, fmt.Errorf("legacy_or_unsupported_opcode: %d", h.OpCode)
	}
}

func parseOPMsg(frame []byte, h Header, compression string, protocolBytes int64, limits DecodeLimits) (Message, error) {
	if len(frame) < HeaderSize+4 {
		return Message{}, errors.New("invalid_op_msg: missing flagBits")
	}
	flags := binary.LittleEndian.Uint32(frame[HeaderSize : HeaderSize+4])
	if unknown := flags & 0xffff &^ knownRequiredFlags; unknown != 0 {
		return Message{}, fmt.Errorf("unknown_required_flag: 0x%x", unknown)
	}
	end := len(frame)
	if flags&FlagChecksumPresent != 0 {
		if end < HeaderSize+8 {
			return Message{}, errors.New("invalid_op_msg: missing checksum")
		}
		want := binary.LittleEndian.Uint32(frame[end-4:])
		got := crc32.Checksum(frame[:end-4], crc32.MakeTable(crc32.Castagnoli))
		if got != want {
			return Message{}, fmt.Errorf("checksum_mismatch: got 0x%x want 0x%x", got, want)
		}
		end -= 4
	}
	msg := Message{Header: h, Flags: flags, Compression: compression, ProtocolBytes: protocolBytes}
	msg.UnknownOptionalFlags = flags & 0xffff0000 &^ FlagExhaustAllowed
	offset := HeaderSize + 4
	bodyCount := 0
	for offset < end {
		kind := frame[offset]
		offset++
		switch kind {
		case 0:
			doc, next, err := readDocument(frame, offset, end)
			if err != nil {
				return Message{}, err
			}
			bodyCount++
			if bodyCount > 1 {
				return Message{}, errors.New("invalid_op_msg: multiple kind 0 bodies")
			}
			msg.Body = doc
			offset = next
		case 1:
			if end-offset < 4 {
				return Message{}, errors.New("invalid_op_msg: short kind 1 size")
			}
			size := int64(int32(binary.LittleEndian.Uint32(frame[offset : offset+4])))
			if size < 5 || size > int64(end-offset) {
				return Message{}, errors.New("invalid_op_msg: invalid kind 1 size")
			}
			sectionEnd := offset + int(size)
			nameStart := offset + 4
			nameEnd := nameStart
			for nameEnd < sectionEnd && frame[nameEnd] != 0 {
				nameEnd++
			}
			if nameEnd == sectionEnd {
				return Message{}, errors.New("invalid_op_msg: unterminated sequence identifier")
			}
			seq := bsonshape.Sequence{Identifier: string(frame[nameStart:nameEnd])}
			pos := nameEnd + 1
			for pos < sectionEnd {
				doc, next, err := readDocument(frame, pos, sectionEnd)
				if err != nil {
					return Message{}, err
				}
				seq.Count++
				seq.BSONBytes += int64(len(doc))
				if len(seq.Documents) < limits.MaxSequenceShapes {
					seq.Documents = append(seq.Documents, doc)
				}
				pos = next
			}
			if pos != sectionEnd {
				return Message{}, errors.New("invalid_op_msg: kind 1 boundary mismatch")
			}
			msg.Sequences = append(msg.Sequences, seq)
			offset = sectionEnd
		case 2, 3:
			// These sections are optional in modern OP_MSG. Their public framing is
			// not stable enough to skip without a length, so exclude the connection
			// instead of guessing the next BSON boundary.
			msg.UnsupportedOptionalSections++
			return Message{}, fmt.Errorf("unsupported_optional_section: kind %d", kind)
		default:
			return Message{}, fmt.Errorf("invalid_op_msg: unknown section kind %d", kind)
		}
	}
	if offset != end || bodyCount != 1 {
		return Message{}, errors.New("invalid_op_msg: exactly one kind 0 body is required")
	}
	return msg, nil
}

func readDocument(data []byte, offset, end int) ([]byte, int, error) {
	if offset < 0 || end < offset || end-offset < 5 {
		return nil, offset, errors.New("invalid_bson: short document")
	}
	length := int64(int32(binary.LittleEndian.Uint32(data[offset : offset+4])))
	if length < 5 || length > int64(end-offset) {
		return nil, offset, fmt.Errorf("invalid_bson: length %d outside section", length)
	}
	next := offset + int(length)
	if data[next-1] != 0 {
		return nil, offset, errors.New("invalid_bson: missing document terminator")
	}
	return data[offset:next], next, nil
}
