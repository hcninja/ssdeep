/*
	Copyright 2017 - José González (josef@hackercat.ninja)

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	   http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package ssdeep

import (
	"bufio"
	"bytes"
	"fmt"
	"math"
	"os"
)

const FORMAT_STRING = "%d:%s:%s"

var rollingWindow uint32 = 7
var blockMin = 3

const spamSumLength = 64

var b64String = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
var b64 = []byte(b64String)
var hashPrime uint32 = 0x01000193
var hashIinit uint32 = 0x28021967

type rollingState struct {
	window []byte
	h1     uint32
	h2     uint32
	h3     uint32
	n      uint32
}

// SSDEEP state struct
type SSDEEP struct {
	rollingState rollingState
	blockSize    int
	hashString1  string
	hashString2  string
	blockHash1   uint32
	blockHash2   uint32
}

// NewSSDEEP creates a new SSDEEP hash
func NewSSDEEP() SSDEEP {
	return SSDEEP{
		blockHash1: hashIinit,
		blockHash2: hashIinit,
		rollingState: rollingState{
			window: make([]byte, rollingWindow),
		},
	}
}

func (sdeep *SSDEEP) newRollingState() {
	sdeep.rollingState = rollingState{}
	sdeep.rollingState.window = make([]byte, rollingWindow)
}

// rollHash based on Adler checksum
func (sdeep *SSDEEP) rollHash(c byte) uint32 {
	rs := &sdeep.rollingState
	rs.h2 -= rs.h1
	rs.h2 += rollingWindow * uint32(c)
	rs.h1 += uint32(c)
	rs.h1 -= uint32(rs.window[rs.n])
	rs.window[rs.n] = c
	rs.n++
	if rs.n == rollingWindow {
		rs.n = 0
	}
	rs.h3 = rs.h3 << 5
	rs.h3 ^= uint32(c)
	return rs.h1 + rs.h2 + rs.h3
}

func (sdeep *SSDEEP) getBlockSize(n int) {
	blockSize := blockMin * int(math.Exp2(math.Floor(math.Log2(float64(n/(spamSumLength*blockMin))))))
	if blockSize < 1 {
		blockSize = 1
	}

	for blockSize*spamSumLength < n {
		blockSize = blockSize * 2
	}

	sdeep.blockSize = blockSize
}

func (sdeep *SSDEEP) processByte(b byte) {
	sdeep.blockHash1 = sumHash(b, sdeep.blockHash1)
	sdeep.blockHash2 = sumHash(b, sdeep.blockHash2)
	rh := int(sdeep.rollHash(b))
	if rh%sdeep.blockSize == (sdeep.blockSize - 1) {
		if len(sdeep.hashString1) < spamSumLength-1 {
			sdeep.hashString1 += string(b64[sdeep.blockHash1%64])
			sdeep.blockHash1 = hashIinit
			sdeep.newRollingState()
		}
		if rh%(sdeep.blockSize*2) == ((sdeep.blockSize * 2) - 1) {
			if len(sdeep.hashString2) < spamSumLength/2-1 {
				sdeep.hashString2 += string(b64[sdeep.blockHash2%64])
				sdeep.blockHash2 = hashIinit
				sdeep.newRollingState()
			}
		}
	}
}

func (sdeep *SSDEEP) process(buff *bytes.Buffer) {
	r := bufio.NewReader(buff)
	sdeep.newRollingState()
	b, err := r.ReadByte()
	for err == nil {
		sdeep.processByte(b)
		b, err = r.ReadByte()
	}

	// Finalize the hash string with the remaining data
	sdeep.hashString1 += string(b64[sdeep.blockHash1%64])
	sdeep.hashString2 += string(b64[sdeep.blockHash2%64])
}

// Fuzzy hash of a provided buffer
func (sdeep *SSDEEP) Fuzzy(b *bytes.Buffer) {
	sdeep.getBlockSize(len(b.Bytes()))
	sdeep.process(b)
}

// ==============
// = Formatters =
// ==============

// func (sdeep *SSDEEP) Byte() []byte   { return []byte(sdeep.String()) }
func (sdeep *SSDEEP) Hash1() string  { return sdeep.hashString1 }
func (sdeep *SSDEEP) Hash2() string  { return sdeep.hashString1 }
func (sdeep *SSDEEP) BlockSize() int { return sdeep.blockSize }
func (sdeep *SSDEEP) String() string {
	return fmt.Sprintf(FORMAT_STRING, sdeep.blockSize, sdeep.hashString1, sdeep.hashString2)
}

// ===========
// = Helpers =
// ===========

// sumHash based on FNV hash
func sumHash(c byte, h uint32) uint32 {
	return (h * hashPrime) ^ uint32(c)
}

func getFileSize(f *os.File) (int, error) {
	fi, err := f.Stat()
	if err != nil {
		return 0, err
	}
	return int(fi.Size()), nil
}
