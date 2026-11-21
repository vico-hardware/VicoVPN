// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 vico-hardware (Vico Studio) — https://github.com/vico-hardware/VicoVPN

// Package proto définit le protocole applicatif VicoVPN, encapsulé dans QUIC.
//
// Version 1 :
//   - Chaque connexion QUIC authentifiée (TLS 1.3 mutuel, certificats épinglés)
//     ouvre d'abord un flux bidirectionnel de contrôle.
//   - Le client envoie un ClientHello ; le relais répond un ServerHello.
//   - Ensuite, un flux unidirectionnel client->relais et un flux
//     relais->client transportent des trames IP de confiance.
//   - Les paquets IP dont le protocole interne est UDP sont envoyés en
//     DATAGRAM QUIC (RFC 9221) quand les deux pairs l'ont négocié ;
//     tous les autres paquets passent par les flux fiables.
//   - Toutes les trames portent un en-tête [u32 longueur][u8 type][payload].
package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	// Version est la version du protocole applicatif.
	Version uint16 = 1

	// TypeClientHello est envoyé par le client sur le flux de contrôle.
	TypeClientHello uint8 = 1
	// TypeServerHello est la réponse du relais.
	TypeServerHello uint8 = 2
	// TypeData est une trame de données fiable contenant un paquet IP.
	TypeData uint8 = 3
	// TypeClose indique une fermeture propre.
	TypeClose uint8 = 4
	// TypeError transporte un code d'erreur applicatif.
	TypeError uint8 = 5
	// TypeReady annonce l'ouverture du flux de données (QUIC n'annonce un
	// flux sortant qu'à sa première donnée).
	TypeReady uint8 = 6
)

const (
	// MaxPacketSize est la taille maximale d'un paquet IP transporté
	// (cohérent avec la MTU du tunnel).
	MaxPacketSize = 1600
	// MaxFrameSize est la taille maximale d'une trame protocolaire.
	MaxFrameSize = MaxPacketSize + 16
	// DefaultMTU est la MTU proposée quand les pairs ne la mesurent pas.
	DefaultMTU = 1280
)

var (
	ErrVersion    = errors.New("proto: version incompatible")
	ErrShortFrame = errors.New("proto: trame tronquée")
	ErrTooLarge   = errors.New("proto: trame trop grande")
)

// ClientHello est le message d'ouverture du client.
type ClientHello struct {
	Version uint16
	// MTU souhaitée pour l'interface tunnel (paquets IP max).
	MTU uint16
	// KeyID identifie la clé d'identité du client (empreinte du cert).
	KeyID [32]byte
	// WantIPv6 demande le transport IPv6 (V1 : toujours faux côté client,
	// le blocage IPv6 est géré par le pare-feu).
	WantIPv6 bool
}

// ServerHello est la réponse du relais.
type ServerHello struct {
	Version uint16
	MTU     uint16
	// Country est le pays déclaré par l'opérateur du relais.
	Country string
	// PolicyFlags : bit0 = IPv6 accepté, bit1 = DATAGRAM accepté.
	PolicyFlags uint8
}

const (
	PolicyIPv6     uint8 = 1 << 0
	PolicyDatagram uint8 = 1 << 1
)

// EncodeFrame écrit [u32 len][u8 type][payload] dans w.
func EncodeFrame(w io.Writer, typ uint8, payload []byte) error {
	if len(payload) > MaxFrameSize {
		return ErrTooLarge
	}
	var hdr [5]byte
	binary.BigEndian.PutUint32(hdr[:4], uint32(len(payload)+1))
	hdr[4] = typ
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// ReadFrame lit une trame complète depuis r.
func ReadFrame(r io.Reader) (typ uint8, payload []byte, err error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:4])
	if n < 1 || n > MaxFrameSize+1 {
		return 0, nil, ErrTooLarge
	}
	payload = make([]byte, int(n)-1)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return hdr[4], payload, nil
}

func putU16(b []byte, v uint16) { binary.BigEndian.PutUint16(b, v) }
func getU16(b []byte) uint16    { return binary.BigEndian.Uint16(b) }

// MarshalClientHello sérialise un ClientHello.
func MarshalClientHello(h ClientHello) []byte {
	b := make([]byte, 2+2+32+1)
	putU16(b[0:2], h.Version)
	putU16(b[2:4], h.MTU)
	copy(b[4:36], h.KeyID[:])
	if h.WantIPv6 {
		b[36] = 1
	}
	return b
}

// UnmarshalClientHello désérialise un ClientHello.
func UnmarshalClientHello(b []byte) (ClientHello, error) {
	var h ClientHello
	if len(b) < 37 {
		return h, ErrShortFrame
	}
	h.Version = getU16(b[0:2])
	h.MTU = getU16(b[2:4])
	copy(h.KeyID[:], b[4:36])
	h.WantIPv6 = b[36] != 0
	return h, nil
}

// MarshalServerHello sérialise un ServerHello.
func MarshalServerHello(h ServerHello) []byte {
	country := []byte(h.Country)
	if len(country) > 64 {
		country = country[:64]
	}
	b := make([]byte, 2+2+1+len(country))
	putU16(b[0:2], h.Version)
	putU16(b[2:4], h.MTU)
	b[4] = h.PolicyFlags
	copy(b[5:], country)
	return b
}

// UnmarshalServerHello désérialise un ServerHello.
func UnmarshalServerHello(b []byte) (ServerHello, error) {
	var h ServerHello
	if len(b) < 5 {
		return h, ErrShortFrame
	}
	h.Version = getU16(b[0:2])
	h.MTU = getU16(b[2:4])
	h.PolicyFlags = b[4]
	if len(b) > 5 {
		h.Country = string(b[5:])
	}
	return h, nil
}

// CheckVersion valide la version négociée.
func CheckVersion(v uint16) error {
	if v != Version {
		return fmt.Errorf("%w: %d", ErrVersion, v)
	}
	return nil
}
