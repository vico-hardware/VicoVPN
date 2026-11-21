// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 vico-hardware (Vico Studio) — https://github.com/vico-hardware/VicoVPN

// vicovpn-relay : logiciel à installer sur les relais volontaires.
// Rôles : "exit" (sortie vers Internet) ou "entry" (relais d'entrée qui
// transmet le canal interne chiffré vers la sortie).
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	vpncrypto "github.com/vicovpn/vicovpn/internal/crypto"
	"github.com/vicovpn/vicovpn/internal/engine"
	"github.com/vicovpn/vicovpn/internal/netcfg"
)

// relayConfig est le fichier de configuration du relais (JSON).
type relayConfig struct {
	Role        string `json:"role"` // "exit" | "entry"
	Listen      string `json:"listen"`
	CertFile    string `json:"cert_file"`
	KeyFile     string `json:"key_file"`
	Country     string `json:"country"`
	MTU         int    `json:"mtu"`
	RateKbps    int    `json:"rate_kbps"`
	ExitAddr    string `json:"exit_addr"`    // entry uniquement
	TunName     string `json:"tun_name"`     // exit uniquement
	TunIP       string `json:"tun_ip"`       // ex. "10.99.0.1/24"
	TunIP6      string `json:"tun_ip6"`      // ex. "fd00:dead:beef::1/64" (active IPv6)
	ClientsFile string `json:"clients_file"` // empreintes hex, une par ligne
}

func main() {
	var (
		cfgPath   = flag.String("config", "relay.json", "fichier de configuration du relais")
		keygenDir = flag.String("keygen", "", "génère une identité dans ce dossier et quitte")
		fpFile    = flag.String("fingerprint", "", "affiche l'empreinte SHA-256 d'un certificat (PEM/DER) et quitte")
	)
	flag.Parse()

	if *fpFile != "" {
		showFingerprint(*fpFile)
		return
	}

	if *keygenDir != "" {
		if err := generateIdentity(*keygenDir); err != nil {
			fatal(err)
		}
		fmt.Println("identité générée dans", *keygenDir)
		return
	}

	b, err := os.ReadFile(*cfgPath)
	if err != nil {
		fatal(err)
	}
	var rc relayConfig
	if err := json.Unmarshal(b, &rc); err != nil {
		fatal(fmt.Errorf("config relais: %w", err))
	}

	certPEM, err := os.ReadFile(rc.CertFile)
	if err != nil {
		fatal(err)
	}
	keyPEM, err := os.ReadFile(rc.KeyFile)
	if err != nil {
		fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		fatal(err)
	}

	allowed, err := loadAllowedClients(rc.ClientsFile)
	if err != nil {
		fatal(err)
	}
	if len(allowed) == 0 {
		fmt.Fprintln(os.Stderr, "attention: aucun client enrôlé (clients_file vide)")
	}

	role := engine.RoleExit
	if rc.Role == "entry" {
		role = engine.RoleEntry
	}

	opts := engine.RelayOptions{
		Role:               role,
		Listen:             rc.Listen,
		Cert:               cert,
		AllowedClientKeyID: allowed,
		Country:            rc.Country,
		MTU:                rc.MTU,
		RateKbps:           rc.RateKbps,
		DatagramPolicy:     true,
		ExitAddr:           rc.ExitAddr,
		TunName:            rc.TunName,
		TunIP:              rc.TunIP,
		TunIP6:             rc.TunIP6,
		NetSetup: func(tunName, tunIP, tunIP6 string, mtu int) error {
			return netcfg.RelayTunSetup(tunName, tunIP, tunIP6, mtu)
		},
		NetTeardown: func(tunName, tunIP, tunIP6 string) error {
			if tunIP != "" || tunIP6 != "" {
				return netcfg.RelayTunTeardown(tunName, tunIP, tunIP6)
			}
			return nil
		},
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Printf("vicovpn-relay: rôle=%s écoute=%s\n", rc.Role, rc.Listen)
	if err := engine.Serve(ctx, opts); err != nil {
		fatal(err)
	}
}

// showFingerprint affiche l'empreinte SHA-256 base64 d'un certificat.
func showFingerprint(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		fatal(err)
	}
	if block, _ := pem.Decode(b); block != nil {
		b = block.Bytes
	}
	fmt.Println(vpncrypto.CertFingerprint(b))
}

func generateIdentity(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	certDER, keyDER, err := vpncrypto.GenerateSelfSigned("vicovpn-relay")
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(filepath.Join(dir, "relay.crt"), certPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "relay.key"), keyPEM, 0o600); err != nil {
		return err
	}
	fmt.Println("Empreinte du certificat relais (à épingler côté client) :")
	fmt.Println(vpncrypto.CertFingerprint(certDER))
	return nil
}

func loadAllowedClients(path string) (map[string]bool, error) {
	m := map[string]bool{}
	if path == "" {
		return m, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m[line] = true
	}
	return m, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "vicovpn-relay:", err)
	os.Exit(1)
}
