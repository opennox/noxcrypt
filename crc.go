package crypt

import "hash/crc32"

var crcTable = simpleMakeTable(crc32.IEEE)

// ZeroCRC is an initial value for UpdateCRC function.
const ZeroCRC = uint32(0xFFFFFFFF)

// ZeroCRCStd is an initial value for UpdateCRCStd function.
const ZeroCRCStd = uint32(0)

// UpdateCRC is a CRC update function used in Nox.
func UpdateCRC(crc uint32, p []byte) uint32 {
	// Function is very similar to crc32.simpleUpdate, but omits the first bit invert.
	// However, implementation starts from 0xFFFFFFFF, so _one_ call to this is exactly the same.
	// crc = ^crc
	for _, v := range p {
		crc = crcTable[byte(crc)^v] ^ (crc >> 8)
	}
	return ^crc
}

// UpdateCRCStd is a standard CRC update function.
func UpdateCRCStd(crc uint32, p []byte) uint32 {
	return simpleUpdate(crc, crcTable, p)
}
