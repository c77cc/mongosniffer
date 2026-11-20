package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	HeaderSize               = 16
	OpCompressed       int32 = 2012
	OpMsg              int32 = 2013
	DefaultFrameLimit        = 64 << 20
	AbsoluteFrameLimit       = 128 << 20
)

type Header struct {
	MessageLength int32
	RequestID     uint32
	ResponseTo    uint32
	OpCode        int32
}

func ParseHeader(data []byte) (Header, error) {
	if len(data) < HeaderSize {
		return Header{}, errors.New("short MongoDB message header")
	}
	h := Header{
		MessageLength: int32(binary.LittleEndian.Uint32(data[0:4])),
		RequestID:     binary.LittleEndian.Uint32(data[4:8]),
		ResponseTo:    binary.LittleEndian.Uint32(data[8:12]),
		OpCode:        int32(binary.LittleEndian.Uint32(data[12:16])),
	}
	if h.MessageLength < HeaderSize {
		return Header{}, fmt.Errorf("invalid_message_length: %d", h.MessageLength)
	}
	return h, nil
}

type Frame struct {
	Header                 Header
	Bytes                  []byte
	StartedAt, CompletedAt time.Time
}

type Framer struct {
	buffer    []byte
	startedAt time.Time
	limit     int
}

func NewFramer(limit int) *Framer {
	if limit < HeaderSize || limit > AbsoluteFrameLimit {
		limit = DefaultFrameLimit
	}
	return &Framer{limit: limit}
}

func (f *Framer) SetLimit(limit int) {
	if limit >= HeaderSize && limit <= AbsoluteFrameLimit {
		f.limit = limit
	}
}

func (f *Framer) Feed(data []byte, startedAt, completedAt time.Time, emit func(Frame) error) error {
	if len(data) == 0 {
		return nil
	}
	for len(data) > 0 {
		if len(f.buffer) == 0 {
			f.startedAt = startedAt
		}
		if len(f.buffer) < HeaderSize {
			take := min(HeaderSize-len(f.buffer), len(data))
			f.buffer = append(f.buffer, data[:take]...)
			data = data[take:]
			if len(f.buffer) < HeaderSize {
				return nil
			}
		}
		h, err := ParseHeader(f.buffer[:HeaderSize])
		if err != nil {
			return err
		}
		length := int64(h.MessageLength)
		if length > int64(f.limit) || length > AbsoluteFrameLimit {
			return fmt.Errorf("invalid_message_length: %d exceeds limit %d", length, f.limit)
		}
		need := int(length) - len(f.buffer)
		if need > 0 {
			take := min(need, len(data))
			f.buffer = append(f.buffer, data[:take]...)
			data = data[take:]
			if len(f.buffer) < int(length) {
				return nil
			}
		}
		frameBytes := f.buffer
		frame := Frame{Header: h, Bytes: frameBytes, StartedAt: f.startedAt, CompletedAt: completedAt}
		f.buffer = nil
		if err := emit(frame); err != nil {
			return err
		}
	}
	return nil
}

func (f *Framer) Buffered() int { return len(f.buffer) }
