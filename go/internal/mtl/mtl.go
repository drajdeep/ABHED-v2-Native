// Copyright 2026 Rajdeep Das, IEM-UEM, Kolkata, India
// SPDX-License-Identifier: Apache-2.0

// Package mtl decodes ML-DSA-44-MTL RRSIG signature fields for analysis
// (draft-kaizer-dnsop-ml-dsa-mtl-dnssec-03, draft-hdong-...-sigtag-ext-01, ABHED 0xF1).
// Verification is done by libabhed in the servers; this package only parses.
package mtl

import (
	"encoding/binary"
	"errors"
)

const (
	TypeFull    = 0x01
	TypeCond    = 0x02
	TypeCompact = 0xF1
	SIDLen      = 32
	TagLen      = 40
)

// Info describes one MTL signature field.
type Info struct {
	Type     byte
	SID      []byte
	Leaf     uint64
	Siblings int
	LadderN  uint64 // leaves covered by the carried ladder (full signatures only)
	Rungs    int
	Size     int
}

var errShort = errors.New("mtl: short signature field")

// Parse decodes a signature field (the RRSIG Signature, MTL-Type byte included).
func Parse(b []byte) (Info, error) {
	in := Info{Size: len(b)}
	if len(b) < 1 {
		return in, errShort
	}
	in.Type = b[0]
	switch b[0] {
	case TypeFull, TypeCond:
		if len(b) < 1+76 {
			return in, errShort
		}
		c := b[1:]
		in.SID = c[2:34]
		in.Leaf = binary.BigEndian.Uint64(c[50:58])
		in.Siblings = int(binary.BigEndian.Uint16(c[74:76]))
		end := 76 + 16*in.Siblings
		if len(c) < end {
			return in, errShort
		}
		if b[0] == TypeFull {
			l := c[end:]
			if len(l) < 36 {
				return in, errShort
			}
			in.Rungs = int(binary.BigEndian.Uint16(l[34:36]))
			if in.Rungs == 0 || len(l) < 36+32*in.Rungs {
				return in, errShort
			}
			last := l[36+32*(in.Rungs-1):]
			in.LadderN = binary.BigEndian.Uint64(last[8:16]) + 1
		}
	case TypeCompact:
		if len(b) < 26 {
			return in, errShort
		}
		in.Leaf = binary.BigEndian.Uint64(b[17:25])
		in.Siblings = int(b[25])
	default:
		return in, errors.New("mtl: unknown MTL-Type")
	}
	return in, nil
}

// Tag returns the SigTag (SID | right index) of the ladder carried in a full signature.
func (i Info) Tag() []byte {
	if i.Type != TypeFull || i.LadderN == 0 {
		return nil
	}
	t := make([]byte, TagLen)
	copy(t, i.SID)
	binary.BigEndian.PutUint64(t[SIDLen:], i.LadderN-1)
	return t
}

// TypeName is a short label for reports.
func TypeName(t byte) string {
	switch t {
	case TypeFull:
		return "full"
	case TypeCond:
		return "condensed"
	case TypeCompact:
		return "compact"
	}
	return "unknown"
}
