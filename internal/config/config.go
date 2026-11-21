// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 vico-hardware (Vico Studio) — https://github.com/vico-hardware/VicoVPN

// Package config gère le fichier local de relais enrôlés et l'identité
// du client. Aucun serveur central n'est requis.
//
// Le fichier est au format JSON. Les clés privées sont stockées en clair
// dans le fichier en V1 ; la protection repose sur les ACL NTFS du dossier
// (%ProgramData%\VicoVPN, SYSTEM + Administrateurs). La V2 devra utiliser
// DPAPI (CryptProtectData) — voir docs/LIMITES.md.
package config

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vicovpn/vicovpn/internal/crypto"
)

const (
	// FileName est le nom du fichier de configuration du client.
	FileName = "relays.json"
	// DirName est le dossier de données du produit.
	DirName = "VicoVPN"
)

// DataDir retourne le dossier de données (%ProgramData%\VicoVPN sous Windows,
// ~/.vicovpn ailleurs).
func DataDir() (string, error) {
	if dir := os.Getenv("VICOVPN_HOME"); dir != "" {
		return dir, nil
	}
	if base := os.Getenv("ProgramData"); base != "" {
		return filepath.Join(base, DirName), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "."+DirName), nil
}

// Relay décrit un relais enrôlé.
type Relay struct {
	Name string `json:"name"`
	// Role : "exit" (sortie) ou "entry" (entrée de dissimulation d'IP).
	Role string `json:"role"`
	// Addr est "hote:port" du point QUIC du relais.
	Addr string `json:"addr"`
	// CertSHA256 est l'empreinte SHA-256 (base64) du certificat TLS du relais,
	// vérifiée par un canal indépendant lors de l'enrôlement.
	CertSHA256 string `json:"cert_sha256"`
	// Country est le pays déclaré par l'opérateur.
	Country string `json:"country"`
	// ClientKeySHA256 restreint les clients autorisés (empreintes de cert
	// client enrôlées). Vide = tous les clients enrôlés par le canal
	// d'enrôlement du relais.
	ClientKeySHA256 []string `json:"client_key_sha256,omitempty"`
}

// IsExit / IsEntry qualifient le rôle.
func (r Relay) IsExit() bool  { return r.Role == "exit" }
func (r Relay) IsEntry() bool { return r.Role == "entry" }

// Config est le fichier de configuration du client.
type Config struct {
	Version  int      `json:"version"`
	Identity Identity `json:"identity"`
	Relays   []Relay  `json:"relays"`
	// SelectedExit est le nom du relais de sortie choisi ("" = premier exit).
	SelectedExit string `json:"selected_exit,omitempty"`
}

// Identity contient la paire de clés du client.
type Identity struct {
	// CertPEM / KeyPEM : certificat auto-signé et clé privée ECDSA P-256.
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
	// KeyID = SHA-256 du certificat DER, hex.
	KeyID string `json:"key_id"`
}

// Load lit la configuration depuis dir.
func Load(dir string) (*Config, error) {
	b, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("config: JSON invalide: %w", err)
	}
	if c.Version != 1 {
		return nil, fmt.Errorf("config: version %d non supportée", c.Version)
	}
	// Zéro relais est valide : installation « Tor uniquement ».
	// Le mode relais classique échouera proprement au ENABLE.
	return &c, nil
}

// Save écrit la configuration (droits restrictifs recommandés par l'appelant).
func (c *Config) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, FileName), b, 0o600)
}

// SelectedRelay retourne le relais de sortie sélectionné.
func (c *Config) SelectedRelay() (Relay, error) {
	if c.SelectedExit != "" {
		for _, r := range c.Relays {
			if r.Name == c.SelectedExit && r.IsExit() {
				return r, nil
			}
		}
		return Relay{}, fmt.Errorf("config: sortie %q introuvable", c.SelectedExit)
	}
	for _, r := range c.Relays {
		if r.IsExit() {
			return r, nil
		}
	}
	return Relay{}, errors.New("config: aucun relais de sortie")
}

// FirstEntry retourne le premier relais d'entrée enrôlé, s'il existe.
func (c *Config) FirstEntry() (Relay, bool) {
	for _, r := range c.Relays {
		if r.IsEntry() {
			return r, true
		}
	}
	return Relay{}, false
}

// CertFingerprint calcule l'empreinte SHA-256 base64 d'un certificat DER.
func CertFingerprint(certDER []byte) string { return vpncrypto.CertFingerprint(certDER) }

// KeyIDFromCertPEM retourne l'empreinte hex du certificat.
func KeyIDFromCertPEM(pemBytes string) (string, error) {
	return vpncrypto.KeyIDFromCertPEM(pemBytes)
}

// LoadOrCreateIdentity charge l'identité du client ou en crée une nouvelle
// persistée dans dir/relays.json.
func LoadOrCreateIdentity(dir string) (*Identity, error) {
	c, err := Load(dir)
	if err == nil {
		return &c.Identity, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	id, err := GenerateIdentity()
	if err != nil {
		return nil, err
	}
	c = &Config{Version: 1, Identity: *id}
	if err := c.Save(dir); err != nil {
		return nil, err
	}
	return id, nil
}

// GenerateIdentity crée une identité auto-signée ECDSA P-256.
func GenerateIdentity() (*Identity, error) {
	certDER, keyDER, err := vpncrypto.GenerateSelfSigned("vicovpn-client")
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return &Identity{
		CertPEM: string(certPEM),
		KeyPEM:  string(keyPEM),
		KeyID:   vpncrypto.KeyID(certDER),
	}, nil
}
