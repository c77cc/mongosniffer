package wire

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/golang/snappy"
	"github.com/klauspost/compress/zstd"
)

type DecodeLimits struct {
	FrameLimit          int
	DecompressedLimit   int
	MaxCompressionRatio int
	MaxSequenceShapes   int
}

func DefaultDecodeLimits() DecodeLimits {
	return DecodeLimits{FrameLimit: DefaultFrameLimit, DecompressedLimit: AbsoluteFrameLimit, MaxCompressionRatio: 100, MaxSequenceShapes: 32}
}

func parseCompressed(frame []byte, outer Header, limits DecodeLimits) (Message, error) {
	if len(frame) < HeaderSize+9 {
		return Message{}, errors.New("decompression_failed: short OP_COMPRESSED")
	}
	body := frame[HeaderSize:]
	originalOpcode := int32(binary.LittleEndian.Uint32(body[0:4]))
	uncompressedSize := int64(int32(binary.LittleEndian.Uint32(body[4:8])))
	compressor := body[8]
	compressed := body[9:]
	if originalOpcode == OpCompressed {
		return Message{}, errors.New("decompression_failed: nested OP_COMPRESSED")
	}
	if uncompressedSize < 0 || uncompressedSize > int64(limits.DecompressedLimit) || uncompressedSize > AbsoluteFrameLimit-HeaderSize {
		return Message{}, fmt.Errorf("decompression_failed: invalid uncompressed size %d", uncompressedSize)
	}
	if len(compressed) == 0 && uncompressedSize != 0 {
		return Message{}, errors.New("decompression_failed: empty payload")
	}
	if len(compressed) > 0 && uncompressedSize > int64(len(compressed))*int64(limits.MaxCompressionRatio) {
		return Message{}, errors.New("decompression_failed: compression ratio exceeds limit")
	}
	decoded, name, err := decompress(compressor, compressed, int(uncompressedSize), limits.DecompressedLimit)
	if err != nil {
		return Message{}, err
	}
	if len(decoded) != int(uncompressedSize) {
		return Message{}, fmt.Errorf("decompression_failed: decoded %d bytes, expected %d", len(decoded), uncompressedSize)
	}
	virtual := make([]byte, HeaderSize+len(decoded))
	binary.LittleEndian.PutUint32(virtual[0:4], uint32(len(virtual)))
	binary.LittleEndian.PutUint32(virtual[4:8], outer.RequestID)
	binary.LittleEndian.PutUint32(virtual[8:12], outer.ResponseTo)
	binary.LittleEndian.PutUint32(virtual[12:16], uint32(originalOpcode))
	copy(virtual[16:], decoded)
	if originalOpcode != OpMsg {
		return Message{}, fmt.Errorf("legacy_or_unsupported_opcode: compressed opcode %d", originalOpcode)
	}
	msg, err := parseOPMsg(virtual, Header{MessageLength: int32(len(virtual)), RequestID: outer.RequestID, ResponseTo: outer.ResponseTo, OpCode: originalOpcode}, name, int64(len(frame)), limits)
	if err != nil {
		return Message{}, err
	}
	return msg, nil
}

func decompress(id byte, input []byte, expected, limit int) ([]byte, string, error) {
	switch id {
	case 0:
		if len(input) > limit {
			return nil, "noop", errors.New("decompression_failed: noop exceeds limit")
		}
		return append([]byte(nil), input...), "noop", nil
	case 1:
		length, err := snappy.DecodedLen(input)
		if err != nil || length > limit || length != expected {
			return nil, "snappy", errors.New("decompression_failed: invalid snappy payload")
		}
		out, err := snappy.Decode(nil, input)
		if err != nil {
			return nil, "snappy", fmt.Errorf("decompression_failed: %w", err)
		}
		return out, "snappy", nil
	case 2:
		r, err := zlib.NewReader(bytes.NewReader(input))
		if err != nil {
			return nil, "zlib", fmt.Errorf("decompression_failed: %w", err)
		}
		defer r.Close()
		out, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
		if err != nil || len(out) > limit {
			return nil, "zlib", errors.New("decompression_failed: zlib output exceeds limit")
		}
		return out, "zlib", nil
	case 3:
		decoder, err := zstd.NewReader(nil, zstd.WithDecoderMaxMemory(uint64(limit)), zstd.WithDecoderConcurrency(1))
		if err != nil {
			return nil, "zstd", fmt.Errorf("decompression_failed: %w", err)
		}
		defer decoder.Close()
		out, err := decoder.DecodeAll(input, make([]byte, 0, min(expected, limit)))
		if err != nil || len(out) > limit {
			return nil, "zstd", errors.New("decompression_failed: invalid zstd payload")
		}
		return out, "zstd", nil
	default:
		return nil, "", fmt.Errorf("unsupported_compressor: %d", id)
	}
}
