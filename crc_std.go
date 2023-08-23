// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package crypt

import "hash/crc32"

// simpleUpdate uses the simple algorithm to update the CRC, given a table that
// was previously computed using simpleMakeTable.
func simpleUpdate(crc uint32, tab *crc32.Table, p []byte) uint32 {
	crc = ^crc
	for _, v := range p {
		crc = tab[byte(crc)^v] ^ (crc >> 8)
	}
	return ^crc
}

// simpleMakeTable allocates and constructs a Table for the specified
// polynomial. The table is suitable for use with the simple algorithm
// (simpleUpdate).
func simpleMakeTable(poly uint32) *crc32.Table {
	t := new(crc32.Table)
	simplePopulateTable(poly, t)
	return t
}

// simplePopulateTable constructs a Table for the specified polynomial, suitable
// for use with simpleUpdate.
func simplePopulateTable(poly uint32, t *crc32.Table) {
	for i := 0; i < 256; i++ {
		crc := uint32(i)
		for j := 0; j < 8; j++ {
			if crc&1 == 1 {
				crc = (crc >> 1) ^ poly
			} else {
				crc >>= 1
			}
		}
		t[i] = crc
	}
}
