package aof

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"os"
)

const (
	// magic cookie is a value prefixing every AOF chunk to enable finding the
	// next chunk after corruption.
	magicCookie = 0x24716296

	// maxChunkSize is the maximum size of the data in each chunk in the AOF,
	// where a chunk is added on each call to Append.
	maxChunkSize = 1024

	perm = 0600
)

var (
	ErrChunkSizeLimitExceeded = fmt.Errorf("exceeds the maximum chunk size of %d", maxChunkSize)
)

// AOF represents an append-only file providing error protection.
//
// Error protection is provided though a CRC32 checksum of each chunk to detect
// corruption, and a fixed magic cookie prefixing each chunk such that the
// AOF can recover after a corrupted entry. Note this magic cookie does not
// restrict the bytes allowed in the appended data (ie the data appended may
// contain the magic cookie). This protects against corruption of the file
// and partial writes, where invalid entries will be skipped.
//
// Each chunk has the format:
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Magic Cookie (0x24716296)                  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         Data Length           |                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
// \                                                               \
// /                              Data                             /
// \                                                               \
// |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                              CRC32                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// The CRC32 covers the whole chunk (not just the data) which is why it is
// appended at the end.
// Note the CRC32 is added at the end rather than in the header since it covers
// the whole packet not just the data.
type AOF struct {
	rfile *os.File
	wfile *os.File
}

// NewAOF opens a new append-only file at the given path.
func NewAOF(path string) (*AOF, error) {
	rfile, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, perm)
	if err != nil {
		return nil, err
	}

	wfile, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, perm)
	if err != nil {
		return nil, err
	}

	return &AOF{rfile, wfile}, nil
}

// Append appends the given bytes to the file.
//
// The length of b must be less than or equal to 1024. If the application needs
// larger writes its up to the application to concatenate chunks. This is to
// avoid excessive allocations/reads when the file is corrupted.
func (aof *AOF) Append(b []byte) error {
	if len(b) > maxChunkSize {
		return ErrChunkSizeLimitExceeded
	}

	checksum := crc32.NewIEEE()

	checksum.Write(encodeU32(magicCookie))
	// As the file is append only don't need to seek.
	// Note errors occuring after a partial write can be ignored as will be
	// skipped when reading.
	if _, err := aof.wfile.Write(encodeU32(magicCookie)); err != nil {
		return err
	}

	checksum.Write(encodeU16(uint16(len(b))))
	if _, err := aof.wfile.Write(encodeU16(uint16(len(b)))); err != nil {
		return err
	}

	checksum.Write(b)
	if _, err := aof.wfile.Write(b); err != nil {
		return err
	}

	if _, err := aof.wfile.Write(encodeU32(checksum.Sum32())); err != nil {
		return err
	}

	return nil
}

// Lookup will lookup the next chunk from offset and returns the data in this
// chunk and the offset of the next chunk to read.
func (aof *AOF) Lookup(offset int64) ([]byte, int64, error) {
	ret, err := aof.rfile.Seek(offset, 0)
	if err != nil {
		return nil, 0, err
	}
	if ret != offset {
		return nil, 0, io.EOF
	}

	sync := make([]byte, 4)
	_, err = io.ReadFull(aof.rfile, sync)
	if err != nil {
		if err == io.ErrUnexpectedEOF { // TODO(AD) Refactor this into common.
			return nil, 0, io.EOF
		}
		return nil, 0, err
	}

	// Keep reading until the next magic cookie is found.
	// TODO(AD) Explain the test this properly.
	// https://github.com/FFmpeg/FFmpeg/blob/master/libavformat/oggdec.c#L331
	var sp int64 = 0
	for {
		if isCookie(sync, sp) {
			break
		}

		c, err := readU8(aof.rfile)
		if err != nil {
			return nil, 0, err
		}

		sp += 1
		sync[sp&3] = c
	}

	checksum := crc32.NewIEEE()

	checksum.Write(sync)

	size, err := readU16(aof.rfile)
	if err != nil {
		return nil, 0, err
	}
	// Check the size before allocating a buffer incase the data is corrupt
	// causing allocation errors.
	if size > maxChunkSize {
		// TODO(AD) Corrupt so restart.
	}

	checksum.Write(encodeU16(size))

	b := make([]byte, size)
	_, err = io.ReadFull(aof.rfile, b)
	if err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, 0, io.EOF
		}
		return nil, 0, err
	}

	checksum.Write(b)

	chunkChecksum, err := readU32(aof.rfile)
	if err != nil {
		return nil, 0, err
	}
	if checksum.Sum32() != chunkChecksum {
		// TODO(AD) Corrupt so restart
	}

	return b, offset + sp + 10 + int64(len(b)), nil
}

func isCookie(sync []byte, sp int64) bool {
	return sync[sp&3] == 0x24 &&
		sync[(sp+1)&3] == 0x71 &&
		sync[(sp+2)&3] == 0x62 &&
		sync[(sp+3)&3] == 0x96
}

func encodeU16(n uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, n)
	return b
}

func encodeU32(n uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	return b
}

func readU8(r io.Reader) (uint8, error) {
	buf := make([]uint8, 1)
	_, err := io.ReadFull(r, buf)
	if err != nil {
		if err == io.ErrUnexpectedEOF {
			return 0, io.EOF
		}
		return 0, err
	}
	return buf[0], nil
}

func readU16(r io.Reader) (uint16, error) {
	buf := make([]uint8, 2)
	_, err := io.ReadFull(r, buf)
	if err != nil {
		if err == io.ErrUnexpectedEOF {
			return 0, io.EOF
		}
		return 0, err
	}
	return binary.BigEndian.Uint16(buf), nil
}

func readU32(r io.Reader) (uint32, error) {
	buf := make([]uint8, 4)
	_, err := io.ReadFull(r, buf)
	if err != nil {
		if err == io.ErrUnexpectedEOF {
			return 0, io.EOF
		}
		return 0, err
	}
	return binary.BigEndian.Uint32(buf), nil
}
