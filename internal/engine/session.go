// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 vico-hardware (Vico Studio) — https://github.com/vico-hardware/VicoVPN

// Package engine implémente les machines à états du client et des relais.
package engine

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/vicovpn/vicovpn/internal/proto"
)

// Session est une connexion QUIC authentifiée avec le protocole applicatif
// VicoVPN négocié.
type Session struct {
	Conn  *quic.Conn
	Hello proto.ServerHello
	MTU   int

	ctrl      *quic.Stream // flux bidirectionnel de contrôle (Hello/Close)
	sendMu    sync.Mutex
	sendStr   *quic.SendStream
	recvStr   *quic.ReceiveStream
	datagrams bool
}

var debugPackets = os.Getenv("VICOVPN_DEBUG") != ""

func logf(format string, args ...any) {
	if debugPackets {
		log.Printf(format, args...)
	}
}

// QuicConfig retourne la configuration QUIC commune (0-RTT désactivé,
// DATAGRAM activé pour le trafic UDP interne).
func QuicConfig() *quic.Config {
	return &quic.Config{
		EnableDatagrams: true,
		// Allow0RTT absent => false : aucune donnée applicative en 0-RTT.
	}
}

// ClientHandshake ouvre une session côté client : QUIC + Hello/ServerHello.
// udpConn est le socket UDP local (déjà lié).
func ClientHandshake(ctx context.Context, udpConn *net.UDPConn, addr *net.UDPAddr, tlsConf *tls.Config, wantMTU int, wantIPv6 bool) (*Session, error) {
	conn, err := quic.Dial(ctx, udpConn, addr, tlsConf, QuicConfig())
	if err != nil {
		return nil, fmt.Errorf("engine: QUIC: %w", err)
	}
	return handshakeSession(ctx, conn, wantMTU, wantIPv6)
}

// handshakeSession exécute la négociation applicatif sur une connexion
// QUIC déjà établie (client).
func handshakeSession(ctx context.Context, conn *quic.Conn, wantMTU int, wantIPv6 bool) (*Session, error) {
	s := &Session{Conn: conn}
	fail := func(err error) (*Session, error) {
		conn.CloseWithError(0, "handshake failed")
		return nil, err
	}
	ctrl, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fail(fmt.Errorf("engine: flux contrôle: %w", err))
	}
	s.ctrl = ctrl
	hello := proto.ClientHello{
		Version:  proto.Version,
		MTU:      uint16(wantMTU),
		WantIPv6: wantIPv6,
	}
	if err := proto.EncodeFrame(ctrl, proto.TypeClientHello, proto.MarshalClientHello(hello)); err != nil {
		return fail(err)
	}
	typ, payload, err := proto.ReadFrame(ctrl)
	if err != nil {
		return fail(fmt.Errorf("engine: ServerHello: %w", err))
	}
	if typ != proto.TypeServerHello {
		return fail(fmt.Errorf("engine: type de trame inattendu %d", typ))
	}
	sh, err := proto.UnmarshalServerHello(payload)
	if err != nil {
		return fail(err)
	}
	if err := proto.CheckVersion(sh.Version); err != nil {
		return fail(err)
	}
	s.Hello = sh
	mtu := int(sh.MTU)
	if wantMTU > 0 && mtu > wantMTU {
		mtu = wantMTU
	}
	if mtu <= 0 || mtu > proto.MaxPacketSize {
		mtu = proto.DefaultMTU
	}
	s.MTU = mtu
	s.datagrams = sh.PolicyFlags&proto.PolicyDatagram != 0
	us, err := conn.OpenUniStreamSync(ctx)
	if err != nil {
		return fail(fmt.Errorf("engine: flux données sortant: %w", err))
	}
	s.sendStr = us
	// Forcer l'annonce QUIC du flux (sinon le pair attend indéfiniment).
	if err := proto.EncodeFrame(us, proto.TypeReady, nil); err != nil {
		return fail(err)
	}
	rs, err := conn.AcceptUniStream(ctx)
	if err != nil {
		return fail(fmt.Errorf("engine: flux données entrant: %w", err))
	}
	s.recvStr = rs
	return s, nil
}

// HandshakeOnConn est la variante exportée de handshakeSession pour le
// transport interne (QUIC dans QUIC).
func HandshakeOnConn(ctx context.Context, conn *quic.Conn, wantMTU int, wantIPv6 bool) (*Session, error) {
	return handshakeSession(ctx, conn, wantMTU, wantIPv6)
}

// ServerHandshake accepte une session côté relais. ctrl est le flux
// bidirectionnel ouvert par le client (AcceptStream).
func ServerHandshake(ctx context.Context, conn *quic.Conn, ctrl *quic.Stream, country string, policyFlags uint8, mtu int) (*Session, error) {
	s := &Session{Conn: conn, ctrl: ctrl}
	fail := func(err error) (*Session, error) {
		conn.CloseWithError(0, "handshake failed")
		return nil, err
	}
	typ, payload, err := proto.ReadFrame(ctrl)
	if err != nil {
		return fail(fmt.Errorf("engine: ClientHello: %w", err))
	}
	if typ != proto.TypeClientHello {
		return fail(fmt.Errorf("engine: type de trame inattendu %d", typ))
	}
	ch, err := proto.UnmarshalClientHello(payload)
	if err != nil {
		return fail(err)
	}
	if err := proto.CheckVersion(ch.Version); err != nil {
		return fail(err)
	}
	m := int(ch.MTU)
	if mtu > 0 && m > mtu {
		m = mtu
	}
	if m <= 0 || m > proto.MaxPacketSize {
		m = proto.DefaultMTU
	}
	sh := proto.ServerHello{
		Version:     proto.Version,
		MTU:         uint16(m),
		Country:     country,
		PolicyFlags: policyFlags,
	}
	if err := proto.EncodeFrame(ctrl, proto.TypeServerHello, proto.MarshalServerHello(sh)); err != nil {
		return fail(err)
	}
	s.Hello = sh
	s.MTU = m
	rs, err := conn.AcceptUniStream(ctx)
	if err != nil {
		return fail(fmt.Errorf("engine: flux données client: %w", err))
	}
	s.recvStr = rs
	us, err := conn.OpenUniStreamSync(ctx)
	if err != nil {
		return fail(err)
	}
	s.sendStr = us
	if err := proto.EncodeFrame(us, proto.TypeReady, nil); err != nil {
		return fail(err)
	}
	return s, nil
}

// AcceptControlStream accepte le flux de contrôle d'un client.
func AcceptControlStream(ctx context.Context, conn *quic.Conn) (*quic.Stream, error) {
	str, err := conn.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return str, nil
}

// SendPayload transmet une charge utile brute (non interprétée) sur le
// flux fiable. Utilisé pour le transport interne en mode deux relais.
func (s *Session) SendPayload(p []byte) error {
	dbgSent.Add(1)
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	return proto.EncodeFrame(s.sendStr, proto.TypeData, p)
}

var dbgSent atomic.Int64

func init() {
	if debugPackets {
		go func() {
			for range time.Tick(10 * time.Second) {
				if n := dbgSent.Load(); n > 0 {
					logf("engine: SendPacket a émis %d paquets", n)
					dbgSent.Store(0)
				}
			}
		}()
	}
}

// SendPacket transmet un paquet IP : DATAGRAM si UDP et négocié,
// sinon trame TypeData sur le flux fiable.
func (s *Session) SendPacket(pkt []byte) error {
	dbgSent.Add(1)
	if s.datagrams && isUDPForDatagram(pkt) {
		if err := s.Conn.SendDatagram(pkt); err == nil {
			return nil
		} else {
			var tooLarge *quic.DatagramTooLargeError
			if !errors.As(err, &tooLarge) {
				return err
			}
			// Trop grand pour un datagramme : repli sur le flux fiable.
		}
	}
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	return proto.EncodeFrame(s.sendStr, proto.TypeData, pkt)
}

// ReceiveLoop lit les paquets IP entrants (flux fiable + datagrammes)
// et appelle fn pour chacun. S'arrête à la fermeture.
func (s *Session) ReceiveLoop(fn func([]byte)) {
	var wg sync.WaitGroup
	var dbgN atomic.Int64
	if debugPackets {
		go func() {
			for range time.Tick(10 * time.Second) {
				if n := dbgN.Load(); n > 0 {
					logf("engine: ReceiveLoop a livré %d paquets", n)
					dbgN.Store(0)
				}
			}
		}()
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			typ, payload, err := proto.ReadFrame(s.recvStr)
			if err != nil {
				return
			}
			if typ != proto.TypeData {
				continue
			}
			cp := make([]byte, len(payload))
			copy(cp, payload)
			dbgN.Add(1)
			fn(cp)
		}
	}()
	go func() {
		defer wg.Done()
		for {
			p, err := s.Conn.ReceiveDatagram(context.Background())
			if err != nil {
				return
			}
			cp := make([]byte, len(p))
			copy(cp, p)
			fn(cp)
		}
	}()
	wg.Wait()
}

// Close ferme proprement la session.
func (s *Session) Close() error {
	if s.sendStr != nil {
		_ = proto.EncodeFrame(s.sendStr, proto.TypeClose, nil)
		_ = s.sendStr.Close()
	}
	if s.ctrl != nil {
		_ = proto.EncodeFrame(s.ctrl, proto.TypeClose, nil)
		_ = s.ctrl.Close()
	}
	return s.Conn.CloseWithError(0, "bye")
}

// Context retourne le contexte de vie de la connexion QUIC.
func (s *Session) Context() context.Context { return s.Conn.Context() }

// isUDPForDatagram décide si un paquet IP part en DATAGRAM QUIC.
// Le paquet doit être un datagramme IP complet (non fragmenté).
func isUDPForDatagram(b []byte) bool {
	switch {
	case len(b) >= 20 && b[0]>>4 == 4:
		if b[9] != 17 {
			return false
		}
		// Fragment IPv4 : offset=0 et MF=0 requis pour le datagramme.
		frag := uint16(b[6])<<8 | uint16(b[7])
		return frag&0x1FFF == 0 && frag&0x2000 == 0
	case len(b) >= 40 && b[0]>>4 == 6:
		// UDP/IPv6 sans en-tête de fragmentation (next header = 17).
		// Les en-têtes d'extension et fragments passent par le flux fiable.
		return b[6] == 17
	}
	return false
}
