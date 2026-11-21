// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 vico-hardware (Vico Studio) — https://github.com/vico-hardware/VicoVPN

package engine

import (
	"net"
	"sync"
	"time"

	"github.com/vicovpn/vicovpn/internal/proto"
)

// PayloadPacketConn adapte une Session en net.PacketConn : chaque WriteTo
// écrit une trame TypeData brute sur le flux fiable ; ReadFrom reçoit les
// charges utiles via le canal alimenté par ReceiveLoop. Utilisé pour faire
// transiter une QUIC interne à l'intérieur d'une session externe (mode
// deux relais).
type PayloadPacketConn struct {
	sess *Session

	ch       chan []byte
	once     sync.Once
	closed   chan struct{}
	mu       sync.Mutex
	deadline time.Time
}

// NewPayloadPacketConn crée le paquet et démarre la boucle de réception.
func NewPayloadPacketConn(sess *Session, buffer int) *PayloadPacketConn {
	p := &PayloadPacketConn{
		sess:   sess,
		ch:     make(chan []byte, buffer),
		closed: make(chan struct{}),
	}
	go sess.ReceiveLoop(func(payload []byte) {
		select {
		case p.ch <- payload:
		case <-p.closed:
		}
	})
	return p
}

var _ net.PacketConn = (*PayloadPacketConn)(nil)

type payloadAddr struct{}

func (payloadAddr) Network() string { return "udp" }
func (payloadAddr) String() string  { return "vicovpn-tunnel" }

// LocalAddr retourne une adresse factice : le chemin réel est le QUIC externe.
func (p *PayloadPacketConn) LocalAddr() net.Addr { return payloadAddr{} }

// WriteTo envoie la charge utile comme trame fiable (rien n'est perdu ni
// réordonné : la QUIC interne supporte un transport idéal).
func (p *PayloadPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	if len(b) > proto.MaxFrameSize {
		return 0, proto.ErrTooLarge
	}
	if err := p.sess.SendPayload(b); err != nil {
		return 0, err
	}
	return len(b), nil
}

// ReadFrom lit la prochaine charge utile.
func (p *PayloadPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		p.mu.Lock()
		dl := p.deadline
		p.mu.Unlock()
		if !dl.IsZero() && !time.Now().Before(dl) {
			return 0, nil, timeoutErr()
		}
		var pkt []byte
		var ok bool
		if dl.IsZero() {
			pkt, ok = <-p.ch
		} else {
			select {
			case pkt, ok = <-p.ch:
			case <-time.After(time.Until(dl)):
				return 0, nil, timeoutErr()
			case <-p.closed:
				return 0, nil, net.ErrClosed
			}
		}
		if !ok {
			return 0, nil, net.ErrClosed
		}
		if len(pkt) > len(b) {
			return 0, nil, errTooBig
		}
		return copy(b, pkt), payloadAddr{}, nil
	}
}

func (p *PayloadPacketConn) SetDeadline(t time.Time) error {
	p.mu.Lock()
	p.deadline = t
	p.mu.Unlock()
	return nil
}
func (p *PayloadPacketConn) SetReadDeadline(t time.Time) error { return p.SetDeadline(t) }
func (p *PayloadPacketConn) SetWriteDeadline(time.Time) error  { return nil }

// Close ferme le paquet (la session sous-jacente reste gérée ailleurs).
func (p *PayloadPacketConn) Close() error {
	p.once.Do(func() { close(p.closed) })
	return nil
}

type errString string

func (e errString) Error() string { return string(e) }

var errTooBig = errString("engine: paquet plus grand que le tampon")

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func timeoutErr() error { return timeoutError{} }
