// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 vico-hardware (Vico Studio) — https://github.com/vico-hardware/VicoVPN

package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/vicovpn/vicovpn/internal/config"
	vpncrypto "github.com/vicovpn/vicovpn/internal/crypto"
	"github.com/vicovpn/vicovpn/internal/proto"
	"github.com/vicovpn/vicovpn/internal/transport"
	"github.com/vicovpn/vicovpn/internal/tun"
)

// State est l'état visible de la protection.
type State int

const (
	StateDisabled State = iota
	StateConnecting
	StateProtected
	StateBlocked // protection demandée mais tunnel indisponible
)

func (s State) String() string {
	switch s {
	case StateDisabled:
		return "desactive"
	case StateConnecting:
		return "connexion"
	case StateProtected:
		return "protege"
	case StateBlocked:
		return "bloque"
	}
	return "?"
}

// ClientNetOps est le point d'injection de la configuration réseau OS
// (pare-feu, routes, IP du TUN). Fourni par internal/netcfg.
type ClientNetOps interface {
	// Protect installe le coupe-circuit AVANT toute connexion : règles
	// pare-feu n'autorisant que allowedUDPDests, routes IPv4 via le TUN,
	// adresse IPv4 du TUN et, si wantIPv6, adresse IPv6 du TUN.
	// Les routes IPv6 fourre-tout n'arrivent qu'après négociation via
	// EnableIPv6 (le relais doit annoncer PolicyIPv6).
	Protect(ctx context.Context, tunName string, mtu int, allowedUDPDests []string, wantIPv6 bool) error
	// EnableIPv6 ajoute les routes IPv6 (::/1 et 8000::/1) via le TUN.
	// Appelé uniquement si le relais a négocié PolicyIPv6.
	EnableIPv6(ctx context.Context, tunName string) error
	// Unprotect retire règles, routes et adresses (arrêt volontaire ou
	// récupération). Doit être idempotent.
	Unprotect() error
	// IsProtected indique si la protection est actuellement installée.
	IsProtected() bool
}

// ClientOptions configure le moteur client.
type ClientOptions struct {
	ConfigDir string
	TunName   string
	MTU       int // 0 => proto.DefaultMTU
	WantIPv6  bool
	NetOps    ClientNetOps // nil = laboratoire sans pare-feu

	OnState func(State, string)
	Logf    func(format string, args ...any)
}

// Client est le moteur du VPN côté utilisateur.
type Client struct {
	o ClientOptions

	mu         sync.Mutex
	state      State
	lastInfo   string
	cancel     context.CancelFunc
	running    bool
	retry      chan struct{}
	exitChoice string // sélection de sortie à chaud ("" = config)
}

// NewClient crée un moteur client.
func NewClient(o ClientOptions) *Client {
	if o.MTU <= 0 {
		o.MTU = proto.DefaultMTU
	}
	if o.TunName == "" {
		o.TunName = "VicoVPN"
	}
	return &Client{o: o, state: StateDisabled}
}

// State retourne l'état courant.
func (c *Client) State() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// Status retourne "etat info" pour le canal de commande.
func (c *Client) Status() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lastInfo == "" {
		return c.state.String()
	}
	return c.state.String() + " " + c.lastInfo
}

// SelectExit choisit la sortie par son nom ("" = retour à la config) et
// force une reconnexion. Persistance en V2 ; V1 = mémoire vive.
func (c *Client) SelectExit(name string) {
	c.mu.Lock()
	c.exitChoice = name
	c.mu.Unlock()
	c.Retry()
}

// ExitChoice retourne la sélection à chaud courante.
func (c *Client) ExitChoice() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.exitChoice
}

func (c *Client) setState(s State, info string) {
	c.mu.Lock()
	c.state = s
	c.lastInfo = info
	c.mu.Unlock()
	if c.o.OnState != nil {
		c.o.OnState(s, info)
	}
}

func (c *Client) logf(format string, args ...any) {
	if c.o.Logf != nil {
		c.o.Logf(format, args...)
	}
}

// Enable démarre la protection. Retourne immédiatement ; l'état évolue
// via OnState (connexion -> protégé/bloqué).
func (c *Client) Enable() error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("engine: déjà actif")
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	c.retry = make(chan struct{}, 1)
	c.running = true
	c.mu.Unlock()
	go c.loop(ctx)
	return nil
}

// Disable arrête la protection et restaure la connexion normale.
func (c *Client) Disable() {
	c.mu.Lock()
	cancel := c.cancel
	running := c.running
	c.running = false
	c.cancel = nil
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if c.o.NetOps != nil {
		_ = c.o.NetOps.Unprotect()
	}
	if running {
		c.setState(StateDisabled, "")
	}
}

// Retry force une nouvelle tentative immédiate (commande Réessayer) :
// elle remet le backoff à zéro et, si une connexion est en cours d'échec,
// la boucle retente sans attendre.
func (c *Client) Retry() {
	c.mu.Lock()
	ch := c.retry
	c.mu.Unlock()
	if ch != nil {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (c *Client) loop(ctx context.Context) {
	defer func() {
		c.mu.Lock()
		c.running = false
		c.mu.Unlock()
	}()
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		err := c.connectOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		c.setState(StateBlocked, err.Error())
		c.logf("engine: connexion perdue/échouée: %v (nouvelle tentative dans %s)", err, backoff)
		select {
		case <-ctx.Done():
			return
		case <-c.retry:
			backoff = time.Second
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

// connectOnce tente d'établir le tunnel une fois. Retourne nil si la
// session a tenu jusqu'à fermeture volontaire/contexte.
func (c *Client) connectOnce(ctx context.Context) error {
	cfg, err := loadClientConfig(c.o.ConfigDir)
	if err != nil {
		return err
	}
	exit, err := c.pickExit(cfg)
	if err != nil {
		return err
	}
	entry, hasEntry := cfg.FirstEntry()

	// 1. Créer l'interface TUN.
	mtu := c.o.MTU
	dev, err := tun.Create(c.o.TunName, mtu)
	if err != nil {
		return fmt.Errorf("engine: TUN: %w", err)
	}
	defer dev.Close()

	// 2. Installer les filtres AVANT toute connexion (coupe-circuit).
	var allowed []string
	if hasEntry {
		allowed = append(allowed, entry.Addr)
	} else {
		allowed = append(allowed, exit.Addr)
	}
	if c.o.NetOps != nil {
		c.setState(StateConnecting, "installation des filtres")
		if err := c.o.NetOps.Protect(ctx, dev.Name(), mtu, allowed, c.o.WantIPv6); err != nil {
			return fmt.Errorf("engine: protection: %w", err)
		}
	}

	// 3. Identité et TLS.
	cert, err := vpncrypto.ParseKeyPair(cfg.Identity.CertPEM, cfg.Identity.KeyPEM)
	if err != nil {
		return err
	}

	// 4. Connexion QUIC.
	c.setState(StateConnecting, "connexion au relais")
	sess, cleanup, err := c.dialSession(ctx, exit, entry, hasEntry, cert, mtu)
	if err != nil {
		return err
	}
	defer cleanup()
	stateInfo := fmt.Sprintf("pays=%s mtu=%d", sess.Hello.Country, sess.MTU)
	// IPv6 : n'activer les routes fourre-tout que si le relais sait
	// transporter IPv6 ; sinon le blocage pare-feu reste en vigueur.
	if c.o.WantIPv6 && c.o.NetOps != nil {
		if sess.Hello.PolicyFlags&proto.PolicyIPv6 != 0 {
			if err := c.o.NetOps.EnableIPv6(ctx, dev.Name()); err != nil {
				c.logf("engine: routes IPv6: %v", err)
				stateInfo += " ipv6=routes-échec"
			} else {
				stateInfo += " ipv6=ok"
			}
		} else {
			stateInfo += " ipv6=non-supporté-par-le-relais"
		}
	}
	c.setState(StateProtected, stateInfo)
	c.logf("engine: protégé via %s (pays déclaré: %s)", exit.Name, sess.Hello.Country)

	// 5. Pompes TUN <-> session jusqu'à coupure.
	errCh := make(chan error, 2)
	go func() {
		buf := make([]byte, proto.MaxPacketSize+128)
		for {
			n, rerr := dev.Read(buf)
			if rerr != nil {
				errCh <- rerr
				return
			}
			p := make([]byte, n)
			copy(p, buf[:n])
			if err := sess.SendPacket(p); err != nil {
				errCh <- err
				return
			}
		}
	}()
	go func() {
		sess.ReceiveLoop(func(pkt []byte) {
			_, _ = dev.Write(pkt)
		})
		errCh <- fmt.Errorf("session fermée")
	}()
	err = <-errCh
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// pickExit choisit la sortie : la sélection à chaud si définie, sinon
// SelectedRelay() de la configuration.
func (c *Client) pickExit(cfg *config.Config) (config.Relay, error) {
	choice := c.ExitChoice()
	if choice == "" {
		return cfg.SelectedRelay()
	}
	for _, r := range cfg.Relays {
		if r.Name == choice && r.IsExit() {
			return r, nil
		}
	}
	return config.Relay{}, fmt.Errorf("engine: sortie %q introuvable", choice)
}

// dialSession établit la session de bout en bout : directe vers la sortie
// (mode laboratoire) ou via l'entrée + QUIC interne (mode deux relais).
func (c *Client) dialSession(ctx context.Context, exit, entry config.Relay, hasEntry bool, cert tls.Certificate, mtu int) (*Session, func(), error) {
	if !hasEntry {
		sess, err := c.dialDirect(ctx, exit, cert, mtu)
		if err != nil {
			return nil, nil, err
		}
		return sess, func() { _ = sess.Close() }, nil
	}
	// Deux relais : QUIC externe vers l'entrée, QUIC interne vers la sortie
	// à l'intérieur des trames du canal externe.
	outer, outerCleanup, err := c.dialDirectSession(ctx, entry, cert, mtu)
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() {
		outerCleanup()
	}
	pc := NewPayloadPacketConn(outer, 256)
	defer pc.Close()

	exitAddr, err := resolveRelayAddr(exit.Addr)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	tlsConf, err := transport.ClientTLSConfig(exit.CertSHA256, exit.Name, cert)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	innerConn, err := quic.Dial(ctx, pc, exitAddr, tlsConf, QuicConfig())
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("engine: QUIC interne: %w", err)
	}
	sess, err := handshakeSession(ctx, innerConn, c.o.MTU, c.o.WantIPv6)
	if err != nil {
		innerConn.CloseWithError(0, "inner handshake")
		cleanup()
		return nil, nil, err
	}
	return sess, func() {
		_ = sess.Close()
		cleanup()
	}, nil
}

// dialDirect établit une session QUIC directe vers un relais.
func (c *Client) dialDirect(ctx context.Context, r config.Relay, cert tls.Certificate, mtu int) (*Session, error) {
	sess, _, err := c.dialDirectSession(ctx, r, cert, mtu)
	return sess, err
}

// dialDirectSession compose socket UDP + TLS + ClientHandshake.
func (c *Client) dialDirectSession(ctx context.Context, r config.Relay, cert tls.Certificate, mtu int) (*Session, func(), error) {
	tlsConf, err := transport.ClientTLSConfig(r.CertSHA256, r.Name, cert)
	if err != nil {
		return nil, nil, err
	}
	udpAddr, err := net.ResolveUDPAddr("udp", r.Addr)
	if err != nil {
		return nil, nil, err
	}
	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, nil, err
	}
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	sess, err := ClientHandshake(dialCtx, udpConn, udpAddr, tlsConf, mtu, c.o.WantIPv6)
	if err != nil {
		udpConn.Close()
		return nil, nil, err
	}
	cleanup := func() {
		_ = sess.Close()
		udpConn.Close()
	}
	return sess, cleanup, nil
}

func resolveRelayAddr(addr string) (*net.UDPAddr, error) {
	return net.ResolveUDPAddr("udp", addr)
}

// loadClientConfig charge la configuration du client.
func loadClientConfig(dir string) (*config.Config, error) {
	return config.Load(dir)
}
