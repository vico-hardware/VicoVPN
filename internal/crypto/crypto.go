// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 vico-hardware (Vico Studio) — https://github.com/vico-hardware/VicoVPN

// Package vpncrypto fournit la génération et la vérification des
// certificats auto-signés utilisés pour l'authentification mutuelle QUIC.
// Les clés de session TLS 1.3 sont gérées par la bibliothèque QUIC ;
// ici on ne gère que l'identité (certificats épinglés SHA-256).
package vpncrypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// GenerateSelfSigned crée une paire certificat/clé ECDSA P-256 auto-signée.
func GenerateSelfSigned(commonName string) (certDER, keyDER []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
		DNSNames:              []string{commonName},
		IPAddresses:           nil,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err = x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return der, keyDER, nil
}

// CertFingerprint retourne l'empreinte SHA-256 base64 d'un certificat DER.
func CertFingerprint(certDER []byte) string {
	s := sha256.Sum256(certDER)
	return base64.StdEncoding.EncodeToString(s[:])
}

// KeyID retourne l'empreinte SHA-256 hex d'un certificat DER.
func KeyID(certDER []byte) string {
	s := sha256.Sum256(certDER)
	return fmt.Sprintf("%x", s[:])
}

// ParseKeyPair charge une paire PEM certificat + clé EC.
func ParseKeyPair(certPEM, keyPEM string) (tls.Certificate, error) {
	return tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
}

// CertDERFromPEM extrait le DER d'un PEM certificat.
func CertDERFromPEM(pemBytes []byte) ([]byte, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("vpncrypto: PEM certificat invalide")
	}
	return block.Bytes, nil
}

// KeyIDFromCertPEM retourne l'empreinte hex d'un certificat PEM.
func KeyIDFromCertPEM(certPEM string) (string, error) {
	der, err := CertDERFromPEM([]byte(certPEM))
	if err != nil {
		return "", err
	}
	return KeyID(der), nil
}

// CertFromLeaf décode le certificat feuille d'une chaîne parseée.
func CertFromLeaf(leaf *x509.Certificate) []byte {
	if leaf == nil {
		return nil
	}
	return leaf.Raw
}
