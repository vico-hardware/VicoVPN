// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 vico-hardware (Vico Studio) — https://github.com/vico-hardware/VicoVPN

package engine_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	vpncrypto "github.com/vicovpn/vicovpn/internal/crypto"
	"github.com/vicovpn/vicovpn/internal/engine"
	"github.com/vicovpn/vicovpn/internal/transport"
)

// fixtures contient les certificats d'un serveur et d'un client de test.
type fixtures struct {
	serverCert tls.Certificate
	serverPin  string // base64
	serverKey  string // hex
	clientCert tls.Certificate
	clientKey  string // hex
}

func newFixtures(t *testing.T) fixtures {
	t.Helper()
	sDER, sKey, err := vpncrypto.GenerateSelfSigned("test-relay")
	if err != nil {
		t.Fatal(err)
	}
	cDER, cKey, err := vpncrypto.GenerateSelfSigned("test-client")
	if err != nil {
		t.Fatal(err)
	}
	certFromDER := func(der, key []byte) tls.Certificate {
		// Rebuilder via PEM.
		certPEM := pemEncode("CERTIFICATE", der)
		keyPEM := pemEncode("EC PRIVATE KEY", key)
		c, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	return fixtures{
		serverCert: certFromDER(sDER, sKey),
		serverPin:  vpncrypto.CertFingerprint(sDER),
		serverKey:  vpncrypto.KeyID(sDER),
		clientCert: certFromDER(cDER, cKey),
		clientKey:  vpncrypto.KeyID(cDER),
	}
}

func pemEncode(typ string, der []byte) []byte {
	const enc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var sb []byte
	sb = append(sb, "-----BEGIN "+typ+"-----\n"...)
	for i := 0; i < len(der); i += 3 {
		var n uint32
		rem := len(der) - i
		n = uint32(der[i]) << 16
		if rem > 1 {
			n |= uint32(der[i+1]) << 8
		}
		if rem > 2 {
			n |= uint32(der[i+2])
		}
		sb = append(sb, enc[(n>>18)&63], enc[(n>>12)&63])
		if rem > 1 {
			sb = append(sb, enc[(n>>6)&63])
		} else {
			sb = append(sb, '=')
		}
		if rem > 2 {
			sb = append(sb, enc[n&63])
		} else {
			sb = append(sb, '=')
		}
	}
	sb = append(sb, '\n')
	sb = append(sb, "-----END "+typ+"-----\n"...)
	return sb
}

// startServer démarre un listener QUIC de test avec la poignée de main
// serveur et retourne l'adresse et un canal de sessions.
func startServer(t *testing.T, f fixtures, allowed map[string]bool) (string, <-chan *engine.Session) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsConf := transport.ServerTLSConfig(f.serverCert, allowed)
	ln, err := quic.Listen(pc, tlsConf, engine.QuicConfig())
	if err != nil {
		t.Fatal(err)
	}
	sessions := make(chan *engine.Session, 4)
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func(conn *quic.Conn) {
				ctrl, err := conn.AcceptStream(context.Background())
				if err != nil {
					return
				}
				sess, err := engine.ServerHandshake(context.Background(), conn, ctrl, "ZZ", 0, 0)
				if err != nil {
					conn.CloseWithError(0, "hs")
					return
				}
				sessions <- sess
			}(conn)
		}
	}()
	return pc.LocalAddr().String(), sessions
}

// dialClient effectue la poignée de main client vers addr.
func dialClient(t *testing.T, addr string, f fixtures) (*engine.Session, *net.UDPConn) {
	t.Helper()
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	tlsConf, err := transport.ClientTLSConfig(f.serverPin, "test-relay", f.clientCert)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sess, err := engine.ClientHandshake(ctx, udpConn, raddr, tlsConf, 1280, false)
	if err != nil {
		t.Fatalf("handshake client: %v", err)
	}
	return sess, udpConn
}

// TestSessionEcho valide l'échange de charges utiles dans les deux sens.
func TestSessionEcho(t *testing.T) {
	f := newFixtures(t)
	addr, sessions := startServer(t, f, map[string]bool{f.clientKey: true})

	cli, udp := dialClient(t, addr, f)
	defer udp.Close()
	defer cli.Close()

	var srv *engine.Session
	select {
	case srv = <-sessions:
	case <-time.After(5 * time.Second):
		t.Fatal("pas de session côté serveur")
	}
	defer srv.Close()

	// client -> serveur
	gotSrv := make(chan []byte, 1)
	go srv.ReceiveLoop(func(p []byte) { gotSrv <- p })
	payload := []byte("trame-ip-de-test-1234")
	if err := cli.SendPayload(payload); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-gotSrv:
		if string(p) != string(payload) {
			t.Fatalf("payload serveur = %q", p)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout réception serveur")
	}

	// serveur -> client
	gotCli := make(chan []byte, 1)
	go cli.ReceiveLoop(func(p []byte) { gotCli <- p })
	if err := srv.SendPayload([]byte("reponse-5678")); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-gotCli:
		if string(p) != "reponse-5678" {
			t.Fatalf("payload client = %q", p)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout réception client")
	}
}

// TestBadPin vérifie qu'une empreinte de certificat erronée est refusée.
func TestBadPin(t *testing.T) {
	f := newFixtures(t)
	addr, _ := startServer(t, f, map[string]bool{f.clientKey: true})

	udpConn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	defer udpConn.Close()
	raddr, _ := net.ResolveUDPAddr("udp", addr)
	badPin := vpncrypto.CertFingerprint([]byte("mauvaise empreinte"))
	tlsConf, err := transport.ClientTLSConfig(badPin, "test-relay", f.clientCert)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := engine.ClientHandshake(ctx, udpConn, raddr, tlsConf, 1280, false); err == nil {
		t.Fatal("handshake aurait dû échouer (mauvais épinglage)")
	}
}

// TestUnknownClient vérifie qu'un client non enrôlé est refusé par le relais.
func TestUnknownClient(t *testing.T) {
	f := newFixtures(t)
	// Le serveur n'autorise qu'une autre clé.
	other := newFixtures(t)
	addr, _ := startServer(t, f, map[string]bool{other.clientKey: true})

	udpConn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	defer udpConn.Close()
	raddr, _ := net.ResolveUDPAddr("udp", addr)
	tlsConf, err := transport.ClientTLSConfig(f.serverPin, "test-relay", f.clientCert)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := engine.ClientHandshake(ctx, udpConn, raddr, tlsConf, 1280, false); err == nil {
		t.Fatal("handshake aurait dû échouer (client non enrôlé)")
	}
}

// TestTwoRelay simule le mode deux relais : client --QUIC--> entrée --payloads--> sortie.
// L'entrée relaie les charges utiles via un socket UDP ; la QUIC interne
// est établie à travers le PayloadPacketConn.
func TestTwoRelay(t *testing.T) {
	f := newFixtures(t)

	// --- Relais de sortie (exit) : listener QUIC + handshake + écho. ---
	exitPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	exitAddr := exitPC.LocalAddr().String()
	exitLn, err := quic.Listen(exitPC, transport.ServerTLSConfig(f.serverCert, map[string]bool{f.clientKey: true}), engine.QuicConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer exitLn.Close()
	exitSessions := make(chan *engine.Session, 2)
	go func() {
		for {
			conn, err := exitLn.Accept(context.Background())
			if err != nil {
				return
			}
			go func(conn *quic.Conn) {
				ctrl, err := conn.AcceptStream(context.Background())
				if err != nil {
					return
				}
				sess, err := engine.ServerHandshake(context.Background(), conn, ctrl, "FR", 0, 0)
				if err != nil {
					return
				}
				exitSessions <- sess
			}(conn)
		}
	}()

	// --- Relais d'entrée (entry) : listener QUIC + transfert UDP vers exit. ---
	entryPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	entryAddr := entryPC.LocalAddr().String()
	entryLn, err := quic.Listen(entryPC, transport.ServerTLSConfig(f.serverCert, map[string]bool{f.clientKey: true}), engine.QuicConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer entryLn.Close()
	go func() {
		for {
			conn, err := entryLn.Accept(context.Background())
			if err != nil {
				return
			}
			go func(conn *quic.Conn) {
				ctrl, err := conn.AcceptStream(context.Background())
				if err != nil {
					return
				}
				sess, err := engine.ServerHandshake(context.Background(), conn, ctrl, "DE", 0, 0)
				if err != nil {
					return
				}
				defer sess.Close()
				// Pipe session <-> UDP vers exitAddr (comme serveEntry).
				raddr, _ := net.ResolveUDPAddr("udp", exitAddr)
				local, err := net.ListenUDP("udp", nil)
				if err != nil {
					return
				}
				defer local.Close()
				go func() {
					sess.ReceiveLoop(func(p []byte) {
						_, _ = local.WriteToUDP(p, raddr)
					})
				}()
				buf := make([]byte, 2048)
				for {
					_ = local.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
					n, _, err := local.ReadFromUDP(buf)
					if err != nil {
						if ne, ok := err.(net.Error); ok && ne.Timeout() {
							continue
						}
						return
					}
					p := make([]byte, n)
					copy(p, buf[:n])
					if err := sess.SendPayload(p); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	// --- Client : QUIC externe vers entry, QUIC interne vers exit. ---
	udpConn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	defer udpConn.Close()

	entryRaddr, _ := net.ResolveUDPAddr("udp", entryAddr)
	entryTLS, err := transport.ClientTLSConfig(f.serverPin, "entry", f.clientCert)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	outer, err := engine.ClientHandshake(ctx, udpConn, entryRaddr, entryTLS, 1280, false)
	if err != nil {
		t.Fatalf("handshake externe: %v", err)
	}
	defer outer.Close()

	pc := engine.NewPayloadPacketConn(outer, 256)
	defer pc.Close()

	exitRaddr, _ := net.ResolveUDPAddr("udp", exitAddr)
	exitTLS, err := transport.ClientTLSConfig(f.serverPin, "exit", f.clientCert)
	if err != nil {
		t.Fatal(err)
	}
	innerConn, err := quic.Dial(ctx, pc, exitRaddr, exitTLS, engine.QuicConfig())
	if err != nil {
		t.Fatalf("QUIC interne: %v", err)
	}
	inner, err := engine.HandshakeOnConn(ctx, innerConn, 1280, false)
	if err != nil {
		t.Fatalf("handshake interne: %v", err)
	}
	defer inner.Close()

	// Vérifier que la sortie a bien vu une connexion (via l'entrée).
	var exitSess *engine.Session
	select {
	case exitSess = <-exitSessions:
	case <-time.After(5 * time.Second):
		t.Fatal("pas de session côté sortie")
	}
	defer exitSess.Close()

	// Échange de données de bout en bout : client -> entry -> exit.
	got := make(chan []byte, 1)
	go exitSess.ReceiveLoop(func(p []byte) { got <- p })
	if err := inner.SendPayload([]byte("via-deux-relais")); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-got:
		if string(p) != "via-deux-relais" {
			t.Fatalf("payload=%q", p)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout données deux relais")
	}

	// Réponse exit -> entry -> client.
	gotCli := make(chan []byte, 1)
	go inner.ReceiveLoop(func(p []byte) { gotCli <- p })
	if err := exitSess.SendPayload([]byte("retour-ok")); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-gotCli:
		if string(p) != "retour-ok" {
			t.Fatalf("payload client=%q", p)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout réponse deux relais")
	}
}

var _ = fmt.Sprintf // garde fmt importé
