package crypt

import (
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/blowfish"
)

// NewReader creates a decoder with a given key and byte stream.
func NewReader(r io.Reader, key int) (*Reader, error) {
	c, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	rd := &Reader{c: c}
	rd.Reset(r)
	return rd, nil
}

type Reader struct {
	r   io.Reader
	s   io.Seeker
	c   *blowfish.Cipher
	buf [Block]byte
	i   int
}

func (r *Reader) Reset(s io.Reader) {
	r.r = s
	r.s, _ = s.(io.Seeker)
	r.i = -1
}

func (r *Reader) Buffered() int {
	if r.i < 0 || r.i >= Block {
		return 0
	}
	return Block - r.i
}

func (r *Reader) readNext() error {
	_, err := io.ReadFull(r.r, r.buf[:])
	if err != nil {
		return err
	}
	r.i = 0
	if r.c != nil {
		r.c.Decrypt(r.buf[:], r.buf[:])
	}
	return nil
}

func (r *Reader) read(p []byte) (int, error) {
	if r.i < 0 || r.i >= Block {
		if err := r.readNext(); err != nil {
			return 0, err
		}
	}
	n := copy(p, r.buf[r.i:])
	r.i += n
	return n, nil
}

func (r *Reader) Read(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n, err := r.read(p)
		total += n
		if err != nil {
			return total, err
		}
		p = p[n:]
	}
	return total, nil
}

func (r *Reader) ReadU8() (byte, error) {
	var b [1]byte
	_, err := r.Read(b[:])
	return b[0], err
}

func (r *Reader) ReadU16() (uint16, error) {
	var b [2]byte
	_, err := r.Read(b[:])
	return binary.LittleEndian.Uint16(b[:]), err
}

func (r *Reader) ReadU32() (uint32, error) {
	var b [4]byte
	_, err := r.Read(b[:])
	return binary.LittleEndian.Uint32(b[:]), err
}

func (r *Reader) ReadU64() (uint64, error) {
	var b [8]byte
	_, err := r.Read(b[:])
	return binary.LittleEndian.Uint64(b[:]), err
}

func (r *Reader) ReadI8() (int8, error) {
	v, err := r.ReadU8()
	return int8(v), err
}

func (r *Reader) ReadI16() (int16, error) {
	v, err := r.ReadU16()
	return int16(v), err
}

func (r *Reader) ReadI32() (int32, error) {
	v, err := r.ReadU32()
	return int32(v), err
}

func (r *Reader) ReadI64() (int64, error) {
	v, err := r.ReadU64()
	return int64(v), err
}

func (r *Reader) Align() error {
	if n := r.Buffered(); n%Block != 0 {
		if err := r.readNext(); err != nil {
			return err
		}
	}
	return nil
}

func (r *Reader) ReadAligned(p []byte) (int, error) {
	if err := r.Align(); err != nil {
		return 0, err
	}
	var b [8]byte
	n, err := r.Read(b[:])
	if err != nil {
		return 0, err
	} else if n != 8 {
		return 0, io.ErrUnexpectedEOF
	}
	n = copy(p, b[:])
	return n, nil
}

func (r *Reader) Seek(off int64, whence int) (int64, error) {
	if r.s == nil {
		return 0, errors.New("reader cannot seek")
	}
	if whence == io.SeekCurrent {
		off -= int64(r.Buffered())
	}
	cur, err := r.s.Seek(off, whence)
	r.i = -1
	if err != nil {
		return 0, err
	}
	rem := cur % Block
	if rem == 0 {
		return cur, nil
	}
	_, err = r.s.Seek(-rem, io.SeekCurrent)
	if err != nil {
		return 0, err
	}
	err = r.readNext()
	if err != nil {
		return 0, err
	}
	r.i = int(rem)
	return cur, nil
}
