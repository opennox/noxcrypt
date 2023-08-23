package crypt

import (
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/blowfish"
)

// NewWriter creates an encoder with a given key and a destination writer.
func NewWriter(w io.Writer, key int) (*Writer, error) {
	c, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	wr := &Writer{c: c}
	wr.Reset(w)
	return wr, nil
}

type Writer struct {
	w   io.Writer
	at  io.WriterAt
	c   *blowfish.Cipher
	buf [Block]byte
	n   int
	off int64
	crc uint32
	// NoZero is a compatibility flag that forces the writer to not cleanup internal buffer with zeros.
	// The result is that short writes followed by Flush may expose data from previous long writes.
	// It is needed to keep 1:1 output from the original game engine.
	NoZero bool
}

// Reset internal state and assign a new underlying writer to it.
func (w *Writer) Reset(d io.Writer) {
	w.w = d
	w.at, _ = d.(io.WriterAt)
	w.n = 0
	w.off = 0
	w.ResetCRC()
}

// ResetCRC resets CRC internal state.
func (w *Writer) ResetCRC() {
	w.crc = ZeroCRC
}

// CRC returns current CRC checksum.
func (w *Writer) CRC() uint32 {
	return w.crc
}

// Written returns a number of bytes written.
// It will differ from the actual number of written bytes unless Flush is called.
func (w *Writer) Written() int64 {
	return w.off
}

func (w *Writer) flush() error {
	w.crc = UpdateCRC(w.crc, w.buf[:])
	var dst [Block]byte
	w.c.Encrypt(dst[:], w.buf[:])
	_, err := w.w.Write(dst[:])
	w.off += int64(Block - w.n)
	w.n = 0
	return err
}

// Flush buffered data to the underlying writer. The data will be aligned to the block size.
func (w *Writer) Flush() error {
	if w.n == 0 {
		return nil
	}
	if !w.NoZero && w.n != len(w.buf) {
		var empty [Block]byte
		copy(w.buf[w.n:], empty[:])
	}
	return w.flush()
}

// Close flushes the data. See Flush.
func (w *Writer) Close() error {
	return w.Flush()
}

func (w *Writer) write(p []byte) (int, error) {
	n := copy(w.buf[w.n:], p)
	w.n += n
	w.off += int64(n)
	if w.n == len(w.buf) {
		if err := w.flush(); err != nil {
			return 0, err
		}
		if w.NoZero {
			var empty [Block]byte
			copy(w.buf[:], empty[:])
		}
	}
	return n, nil
}

// Write implements io.Writer.
func (w *Writer) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n, err := w.write(p)
		total += n
		if err != nil {
			return total, err
		}
		p = p[n:]
	}
	return total, nil
}

func (w *Writer) WriteU8(v byte) error {
	_, err := w.Write([]byte{v})
	return err
}

func (w *Writer) WriteU16(v uint16) error {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], v)
	_, err := w.Write(b[:])
	return err
}

func (w *Writer) WriteU32(v uint32) error {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	_, err := w.Write(b[:])
	return err
}

func (w *Writer) WriteU64(v uint64) error {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	_, err := w.Write(b[:])
	return err
}

func (w *Writer) WriteI8(v int8) error {
	return w.WriteU8(uint8(v))
}

func (w *Writer) WriteI16(v int16) error {
	return w.WriteU16(uint16(v))
}

func (w *Writer) WriteI32(v int32) error {
	return w.WriteU32(uint32(v))
}

func (w *Writer) WriteI64(v int64) error {
	return w.WriteU64(uint64(v))
}

// WriteEmpty flushes the data (if any), which aligns it to a block size,
// and then writes an additional empty block without encryption.
// This block can be later written with WriteBlockAt, WriteU64At, WriteU32At, etc.
func (w *Writer) WriteEmpty() (int64, error) {
	if err := w.Flush(); err != nil {
		return 0, err
	}
	var empty [Block]byte
	w.crc = UpdateCRC(w.crc, empty[:])
	_, err := w.w.Write(empty[:])
	off := w.off
	w.off += Block
	return off, err
}

// WriteBlockAt encrypts and writes a block at an offset, previously returned by WriteEmpty.
// It requires the underlying writer to implement io.WriterAt.
func (w *Writer) WriteBlockAt(buf [Block]byte, off int64) error {
	if w.at == nil {
		return errors.New("WriteAt is not supported by the underlying writer")
	}
	var dst [Block]byte
	w.c.Encrypt(dst[:], buf[:])
	_, err := w.at.WriteAt(dst[:], off)
	return err
}

// WriteU64At encrypts and writes uint64 at an offset, previously returned by WriteEmpty.
// It requires the underlying writer to implement io.WriterAt.
func (w *Writer) WriteU64At(v uint64, off int64) error {
	var buf [Block]byte
	binary.LittleEndian.PutUint64(buf[:], v)
	return w.WriteBlockAt(buf, off)
}

// WriteU32At encrypts and writes uint32 at an offset, previously returned by WriteEmpty.
// It requires the underlying writer to implement io.WriterAt.
func (w *Writer) WriteU32At(v uint32, off int64) error {
	var buf [Block]byte
	binary.LittleEndian.PutUint32(buf[:], v)
	return w.WriteBlockAt(buf, off)
}

// WriteI64At encrypts and writes int64 at an offset, previously returned by WriteEmpty.
// It requires the underlying writer to implement io.WriterAt.
func (w *Writer) WriteI64At(v int64, off int64) error {
	return w.WriteU64At(uint64(v), off)
}

// WriteI32At encrypts and writes int32 at an offset, previously returned by WriteEmpty.
// It requires the underlying writer to implement io.WriterAt.
func (w *Writer) WriteI32At(v int32, off int64) error {
	return w.WriteU32At(uint32(v), off)
}
