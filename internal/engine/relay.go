// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 vico-hardware (Vico Studio) — https://github.com/vico-hardware/VicoVPN

package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	vpkt "github.com/vicovpn/vicovpn/internal/pkt"
	"github.com/vicovpn/vicovpn/internal/proto"
	"github.com/vicovpn/vicovpn/internal/transport"
	"github.com/vicovpn/vicovpn/internal/tun"
)

// RelayRole identifie le rôle du relais.
type RelayRole int

const (
	RoleExit RelayRole = iota
	RoleEntry
)

// RelayOptions configure un relais.
type RelayOptions struct {
	Role   RelayRole
	Listen string // "ip:port" UDP

	Cert               tls.Certificate
	AllowedClientKeyID map[string]bool // empreintes hex des certificats clients
	Country            string
	MTU                int  // 0 = proto.DefaultMTU
	RateKbps           int  // 0 = illimité (bande passante par client)
	DatagramPolicy     bool // annoncer PolicyDatagram

	// Entry uniquement : adresse UDP du relais de sortie.
	ExitAddr string

	// Exit uniquement : configuration de l'interface TUN du relais.
	TunName string
	TunIP   string // ex. "10.99.0.1/24"
	// TunIP6, si non vide (ex. "fd00:dead:beef::1/64"), active le transport
	// IPv6 : le relais annonce PolicyIPv6 et configure le NAT66.
	TunIP6 string

	// NetSetup configure l'OS du relais (IP TUN v4/v6, forwarding, NAT).
	// nil = pas de configuration (tests unitaires).
	NetSetup    func(tunName, tunIP, tunIP6 string, mtu int) error
	NetTeardown func(tunName, tunIP, tunIP6 string) error

	Logf func(format string, args ...any)
}

func (o *RelayOptions) logf(format string, args ...any) {
	if o.Logf != nil {
		o.Logf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

// Serve démarre le relais jusqu'à annulation du contexte.
func Serve(ctx context.Context, o RelayOptions) error {
	if o.Listen == "" {
		o.Listen = ":4443"
	}
	pc, err := net.ListenPacket("udp", o.Listen)
	if err != nil {
		return fmt.Errorf("relay: écoute %s: %w", o.Listen, err)
	}
	defer pc.Close()

	allowed := o.AllowedClientKeyID
	if allowed == nil {
		allowed = map[string]bool{}
	}
	tlsConf := transport.ServerTLSConfig(o.Cert, allowed)
	listener, err := quic.Listen(pc, tlsConf, QuicConfig())
	if err != nil {
		return fmt.Errorf("relay: QUIC listen: %w", err)
	}
	defer listener.Close()

	policyFlags := uint8(0)
	if o.DatagramPolicy {
		policyFlags |= proto.PolicyDatagram
	}
	// IPv6 n'est annoncé que si le relais a un plan d'adressage v6 TUN.
	if o.TunIP6 != "" {
		policyFlags |= proto.PolicyIPv6
	}

	o.logf("relay: écoute sur %s (rôle=%v)", o.Listen, o.Role)
	for {
		conn, err := listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("relay: accept: %w", err)
		}
		go o.handleConn(ctx, conn, policyFlags)
	}
}

func (o *RelayOptions) handleConn(ctx context.Context, conn *quic.Conn, policyFlags uint8) {
	defer conn.CloseWithError(0, "done")
	remote := conn.RemoteAddr().String()
	o.logf("relay: connexion de %s", remote)

	ctrlCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	ctrl, err := conn.AcceptStream(ctrlCtx)
	cancel()
	if err != nil {
		o.logf("relay: pas de flux contrôle: %v", err)
		return
	}
	hctx, hcancel := context.WithTimeout(ctx, 15*time.Second)
	sess, err := ServerHandshake(hctx, conn, ctrl, o.Country, policyFlags, o.MTU)
	hcancel()
	if err != nil {
		o.logf("relay: handshake refusé pour %s: %v", remote, err)
		return
	}
	defer sess.Close()
	o.logf("relay: session établie %s (MTU=%d, pays=%s)", remote, sess.MTU, sess.Hello.Country)

	if o.Role == RoleEntry {
		o.serveEntry(ctx, sess)
		return
	}
	o.serveExit(ctx, sess)
}

// serveEntry transfère les paquets de la session vers le relais de sortie
// via un socket UDP (les données internes restent chiffrées de bout en bout :
// l'entrée ne voit que des datagrammes QUIC internes opaques).
func (o *RelayOptions) serveEntry(ctx context.Context, sess *Session) {
	if o.ExitAddr == "" {
		o.logf("relay(entry): ExitAddr non configuré")
		return
	}
	raddr, err := net.ResolveUDPAddr("udp", o.ExitAddr)
	if err != nil {
		o.logf("relay(entry): ExitAddr invalide: %v", err)
		return
	}
	local, err := net.ListenUDP("udp", nil)
	if err != nil {
		o.logf("relay(entry): socket UDP: %v", err)
		return
	}
	defer local.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	// Session -> sortie.
	go func() {
		defer wg.Done()
		sess.ReceiveLoop(func(payload []byte) {
			if !entryLimiter(o).Allow(len(payload)) {
				return
			}
			_, _ = local.WriteToUDP(payload, raddr)
		})
	}()
	// Sortie -> session.
	go func() {
		defer wg.Done()
		buf := make([]byte, proto.MaxPacketSize+128)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			_ = local.SetReadDeadline(time.Now().Add(time.Second))
			n, _, err := local.ReadFromUDP(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			p := make([]byte, n)
			copy(p, buf[:n])
			if err := sess.SendPayload(p); err != nil {
				return
			}
		}
	}()
	wg.Wait()
}

var entryLimiters sync.Map // *RelayOptions -> *RateLimiter (paresseux)

func entryLimiter(o *RelayOptions) *RateLimiter {
	if v, ok := entryLimiters.Load(o); ok {
		return v.(*RateLimiter)
	}
	l := NewRateLimiter(o.RateKbps * 1000 / 8)
	entryLimiters.Store(o, l)
	return l
}

// serveExit connecte la session au TUN du relais et applique la politique.
func (o *RelayOptions) serveExit(ctx context.Context, sess *Session) {
	dev, err := o.openTun()
	if err != nil {
		o.logf("relay(exit): TUN: %v", err)
		return
	}
	defer dev.Close()
	if o.NetSetup != nil {
		if err := o.NetSetup(dev.Name(), o.TunIP, o.TunIP6, sess.MTU); err != nil {
			o.logf("relay(exit): config réseau: %v", err)
			return
		}
		defer func() {
			if o.NetTeardown != nil {
				_ = o.NetTeardown(dev.Name(), o.TunIP, o.TunIP6)
			}
		}()
	}

	policy := &Policy{SelfIPs: localIPs(), LocalNets: parseLocalNets(o.TunIP, o.TunIP6)}
	limiter := NewRateLimiter(o.RateKbps * 1000 / 8)

	// Paquets du client -> TUN (vers Internet), avec politique + débit.
	recvDone := make(chan struct{})
	go func() {
		defer close(recvDone)
		sess.ReceiveLoop(func(pkt []byte) {
			if !policy.AllowedDst(pkt) {
				atomicDropped()
				if debugPackets {
					dst, _ := vpkt.DstIP(pkt)
					logf("relay(exit): drop v%d proto=%d dst=%v len=%d", vpkt.IPVersion(pkt), vpkt.Proto(pkt), dst, len(pkt))
				}
				return
			}
			if !limiter.Allow(len(pkt)) {
				return
			}
			if debugPackets && vpkt.IPVersion(pkt) == 6 {
				dst, _ := vpkt.DstIP(pkt)
				logf("relay(exit): v6 vers TUN proto=%d dst=%v len=%d", vpkt.Proto(pkt), dst, len(pkt))
			}
			_, _ = dev.Write(pkt)
		})
	}()

	// Paquets du TUN (d'Internet) -> client.
	go func() {
		buf := make([]byte, proto.MaxPacketSize+128)
		for {
			select {
			case <-ctx.Done():
				return
			case <-recvDone:
				return
			default:
			}
			n, err := dev.Read(buf)
			if err != nil {
				return
			}
			p := make([]byte, n)
			copy(p, buf[:n])
			if err := sess.SendPacket(p); err != nil {
				return
			}
		}
	}()
	<-recvDone
}

func (o *RelayOptions) openTun() (tun.Device, error) {
	name := o.TunName
	if name == "" {
		name = "vicovpn-relay"
	}
	return tun.Create(name, o.MTU)
}

var droppedCounter int64

func atomicDropped() { droppedCounter++ }

// DroppedPackets retourne le nombre de paquets bloqués par la politique.
func DroppedPackets() int64 { return droppedCounter }

// parseLocalNets extrait les réseaux locaux des adresses TUN du relais
// (ex. "10.99.0.1/24" -> 10.99.0.0/24, "fd00:dead:beef::1/64" -> /64).
func parseLocalNets(tunIP, tunIP6 string) []*net.IPNet {
	var out []*net.IPNet
	for _, addr := range []string{tunIP, tunIP6} {
		if addr == "" {
			continue
		}
		if !strings.Contains(addr, "/") {
			addr += "/24"
		}
		if _, n, err := net.ParseCIDR(addr); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// localIPs retourne les adresses IP locales de l'hôte (hors loopback).
func localIPs() map[string]bool {
	m := map[string]bool{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return m
	}
	for _, it := range ifaces {
		addrs, _ := it.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				m[ipn.IP.String()] = true
			}
		}
	}
	return m
}

var _ = os.Getenv // évite import inutilisé si besoin futur
var _ = fmt.Sprintf
