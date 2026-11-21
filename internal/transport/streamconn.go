// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 vico-hardware (Vico Studio) — https://github.com/vico-hardware/VicoVPN

package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// DatagramPacketConn adapte une connexion QUIC authentifiée en net.PacketConn
// pour transporter une QUIC interne (mode deux relais) à l'intérieur des
// DATAGRAM QUIC externes (RFC 9221). Chaque WriteTo envoie un datagramme ;
// ReadFrom reçoit le suivant. Aucune fiabilité ajoutée : la QUIC interne
// gère pertes et réordonnancement.
type DatagramPacketConn struct {
	conn *quic.Conn

	mu           sync.Mutex
	readDeadline time.Time
	closed       chan struct{}
	once         sync.Once
}

// NewDatagramPacketConn enveloppe une connexion QUIC déjà authentifiée.
func NewDatagramPacketConn(c *quic.Conn) *DatagramPacketConn {
	return &DatagramPacketConn{conn: c, closed: make(chan struct{})}
}

var _ net.PacketConn = (*DatagramPacketConn)(nil)

type vaddr struct{ addr net.Addr }

func (v vaddr) Network() string { return "udp" }
func (v vaddr) String() string  { return v.addr.String() }

// LocalAddr retourne une adresse factice (le chemin réel est le QUIC externe).
func (d *DatagramPacketConn) LocalAddr() net.Addr {
	return vaddr{&net.UDPAddr{IP: net.IPv4zero, Port: 0}}
}

// WriteTo envoie p comme DATAGRAM QUIC externe.
func (d *DatagramPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if err := d.conn.SendDatagram(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// ReadFrom lit le prochain DATAGRAM QUIC externe.
func (d *DatagramPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		// Deadline gérée par un timer qui réveille la boucle.
		d.mu.Lock()
		dl := d.readDeadline
		d.mu.Unlock()

		if !dl.IsZero() && time.Now().After(dl) {
			return 0, nil, osErrDeadline()
		}
		ctx := context.Background()
		cancel := func() {}
		if !dl.IsZero() {
			var c context.CancelFunc
			ctx, c = context.WithDeadline(context.Background(), dl)
			cancel = c
		}
		b, err := d.conn.ReceiveDatagram(ctx)
		cancel()
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return 0, nil, osErrDeadline()
			}
			select {
			case <-d.closed:
				return 0, nil, net.ErrClosed
			default:
			}
			return 0, nil, err
		}
		if len(b) > len(p) {
			return 0, nil, errors.New("transport: datagramme plus grand que le tampon")
		}
		n := copy(p, b)
		return n, vaddr{&net.UDPAddr{IP: net.IPv4zero, Port: 0}}, nil
	}
}

func osErrDeadline() error {
	return &net.OpError{Op: "read", Net: "udp", Err: errDeadline{}}
}

type errDeadline struct{}

func (errDeadline) Error() string   { return "i/o timeout" }
func (errDeadline) Timeout() bool   { return true }
func (errDeadline) Temporary() bool { return true }

// SetDeadline implémente net.PacketConn.
func (d *DatagramPacketConn) SetDeadline(t time.Time) error {
	d.mu.Lock()
	d.readDeadline = t
	d.mu.Unlock()
	return nil
}

// SetReadDeadline implémente net.PacketConn.
func (d *DatagramPacketConn) SetReadDeadline(t time.Time) error { return d.SetDeadline(t) }

// SetWriteDeadline implémente net.PacketConn (no-op : QUIC gère l'envoi).
func (d *DatagramPacketConn) SetWriteDeadline(time.Time) error { return nil }

// Close libère la connexion enveloppante.
func (d *DatagramPacketConn) Close() error {
	d.once.Do(func() { close(d.closed) })
	return d.conn.CloseWithError(0, "packetconn closed")
}

var _ = io.EOF // référence pour garder io importé si besoin futur
