package crypt

import (
	"encoding/binary"
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
	c   *blowfish.Cipher
	buf [Block]byte
	n   int
	off int64
	// NoZero is a compatibility flag that forces the writer to not cleanup internal buffer with zeros.
	// The result is that short writes followed by Flush may expose data from previous long writes.
	// It is needed to keep 1:1 output from the original game engine.
	NoZero bool
}

// Reset internal state and assign a new underlying writer to it.
func (w *Writer) Reset(d io.Writer) {
	w.w = d
	w.n = 0
	w.off = 0
}

// Written returns a number of bytes written.
// It will differ from the actual number of written bytes unless Flush is called.
func (w *Writer) Written() int64 {
	return w.off
}

func (w *Writer) flush() error {
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
func (w *Writer) WriteEmpty() error {
	if err := w.Flush(); err != nil {
		return err
	}
	var empty [Block]byte
	_, err := w.w.Write(empty[:])
	w.off += Block
	return err
}
