// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 vico-hardware (Vico Studio) — https://github.com/vico-hardware/VicoVPN

// Package transport encapsule QUIC/TLS 1.3 avec authentification mutuelle
// par certificats auto-signés épinglés (SHA-256). Les clés de session et la
// protection des enregistrements sont déléguées à quic-go ; le 0-RTT est
// désactivé (Dial simple, jamais DialEarly).
package transport

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"

	vpncrypto "github.com/vicovpn/vicovpn/internal/crypto"
)

// ErrPinMismatch est renvoyé quand l'empreinte du pair ne correspond pas
// à la valeur enrôlée.
var ErrPinMismatch = errors.New("transport: empreinte de certificat non enrôlée")

// ClientTLSConfig construit la config TLS côté client.
//   - serverPin : empreinte SHA-256 base64 du certificat du relais (config).
//   - clientCert : certificat+clé de l'identité client (auth mutuelle).
//   - serverName : nom attendu (le nom du relais, pour SNI).
func ClientTLSConfig(serverPin, serverName string, clientCert tls.Certificate) (*tls.Config, error) {
	pin, err := base64.StdEncoding.DecodeString(serverPin)
	if err != nil || len(pin) != sha256.Size {
		return nil, fmt.Errorf("transport: épinglage invalide: %w", err)
	}
	return &tls.Config{
		ServerName:         serverName,
		Certificates:       []tls.Certificate{clientCert},
		InsecureSkipVerify: true, // vérification manuelle par épinglage ci-dessous
		MinVersion:         tls.VersionTLS13,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("transport: aucun certificat pair")
			}
			sum := sha256.Sum256(rawCerts[0])
			if !equalBytes(sum[:], pin) {
				return ErrPinMismatch
			}
			return nil
		},
		// 0-RTT désactivé : pas de session ticket réutilisé pour les données
		// applicatives (ClientSessionCache nil + Dial sans Early).
		ClientSessionCache: nil,
	}, nil
}

// ServerTLSConfig construit la config TLS côté relais.
//   - cert : identité du relais.
//   - allowedClientKeyIDs : empreintes hex SHA-256 des certificats clients
//     enrôlés (auth mutuelle). Si vide, tout client certificat est refusé.
func ServerTLSConfig(cert tls.Certificate, allowedClientKeyIDs map[string]bool) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAnyClientCert,
		MinVersion:   tls.VersionTLS13,
		// Vérification manuelle : auto-signé, pas de chaîne.
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: clientCertVerifier(allowedClientKeyIDs),
		ClientSessionCache:    nil,
	}
}

// clientCertVerifier vérifie que le certificat client présenté figure dans
// la liste d'enrôlement (empreinte hex SHA-256 du DER).
func clientCertVerifier(allowed map[string]bool) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("transport: certificat client absent")
		}
		keyID := vpncrypto.KeyID(rawCerts[0])
		if !allowed[keyID] {
			return fmt.Errorf("%w: client %s", ErrPinMismatch, keyID)
		}
		return nil
	}
}

// FingerprintB64 retourne l'empreinte base64 d'un certificat DER.
func FingerprintB64(certDER []byte) string { return vpncrypto.CertFingerprint(certDER) }

// FingerprintHex retourne l'empreinte hex d'un certificat DER.
func FingerprintHex(certDER []byte) string { return vpncrypto.KeyID(certDER) }

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
