// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 vico-hardware (Vico Studio) — https://github.com/vico-hardware/VicoVPN

// Package pkt fournit des helpers de lecture des en-têtes IP.
package pkt

import "encoding/binary"

const (
	ProtoICMP     = 1
	ProtoTCP      = 6
	ProtoUDP      = 17
	ProtoIPv6ICMP = 58
)

// IPVersion retourne 4 ou 6 d'après le premier nibble, 0 si invalide.
func IPVersion(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	return int(b[0] >> 4)
}

// Proto retourne le numéro de protocole du paquet IP (0 si trop court).
func Proto(b []byte) uint8 {
	switch IPVersion(b) {
	case 4:
		if len(b) < 20 {
			return 0
		}
		return b[9]
	case 6:
		if len(b) < 40 {
			return 0
		}
		// En-tête de chaîne : sauter les extensions de base.
		next := b[6]
		off := 40
		for isExt(next) && len(b) >= off+8 {
			switch next {
			case 0, 43, 60: // Hop-by-Hop, Routing, Destination
				next = b[off]
				off += (int(b[off+1]) + 1) * 8
			case 44: // Fragment : en-tête fixe 8 octets
				next = b[off]
				off += 8
			case 51: // AH
				next = b[off]
				off += (int(b[off+1]) + 2) * 4
			case 50: // ESP : non analysable
				return 50
			default:
				return next
			}
		}
		return next
	}
	return 0
}

func isExt(p uint8) bool {
	switch p {
	case 0, 43, 44, 50, 51, 60:
		return true
	}
	return false
}

// DstIP retourne l'adresse de destination sous forme d'octets
// (4 ou 16) et sa longueur.
func DstIP(b []byte) ([]byte, int) {
	switch IPVersion(b) {
	case 4:
		if len(b) < 20 {
			return nil, 0
		}
		return b[16:20], 4
	case 6:
		if len(b) < 40 {
			return nil, 0
		}
		return b[24:40], 16
	}
	return nil, 0
}

// SrcIP retourne l'adresse source.
func SrcIP(b []byte) ([]byte, int) {
	switch IPVersion(b) {
	case 4:
		if len(b) < 20 {
			return nil, 0
		}
		return b[12:16], 4
	case 6:
		if len(b) < 40 {
			return nil, 0
		}
		return b[8:24], 16
	}
	return nil, 0
}

// IsUDP indique si le paquet transporte UDP.
func IsUDP(b []byte) bool { return Proto(b) == ProtoUDP }

// UDPPayloadOffset retourne l'offset du payload UDP dans le paquet IP.
// Gère IPv4 (IHL variable) et IPv6 (en-têtes d'extension de base).
// ok=false si le paquet est trop court ou si le protocole n'est pas UDP.
func UDPPayloadOffset(b []byte) (off int, ok bool) {
	if !IsUDP(b) {
		return 0, false
	}
	switch IPVersion(b) {
	case 4:
		if len(b) < 20 {
			return 0, false
		}
		ihl := int(b[0]&0x0f) * 4
		if ihl < 20 || len(b) < ihl+8 {
			return 0, false
		}
		return ihl, true
	case 6:
		if len(b) < 40 {
			return 0, false
		}
		off = 40
		next := b[6]
		for isExt(next) && next != 17 {
			if len(b) < off+8 {
				return 0, false
			}
			switch next {
			case 0, 43, 60:
				next = b[off]
				off += (int(b[off+1]) + 1) * 8
			case 44:
				next = b[off]
				off += 8
			case 51:
				next = b[off]
				off += (int(b[off+1]) + 2) * 4
			default:
				return 0, false
			}
		}
		if next != 17 || len(b) < off+8 {
			return 0, false
		}
		return off, true
	}
	return 0, false
}

// UDPLen lit le champ longueur de l'en-tête UDP (inclut l'en-tête).
func UDPLen(b []byte, off int) int {
	if len(b) < off+4 {
		return 0
	}
	return int(binary.BigEndian.Uint16(b[off+4 : off+6]))
}
