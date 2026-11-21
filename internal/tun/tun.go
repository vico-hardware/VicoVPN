// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 vico-hardware (Vico Studio) — https://github.com/vico-hardware/VicoVPN

// Package tun abstrait l'interface réseau de couche 3.
// Windows : adaptateur wintun (pilote signé). Linux : /dev/net/tun.
package tun

import "errors"

// Device est une interface TUN : chaque Read/Write transporte un paquet IP
// complet (pas d'en-tête TUN supplémentaire).
type Device interface {
	// Read retourne un paquet IP complet. Bloquant jusqu'à annulation via Close.
	Read(buf []byte) (int, error)
	// Write injecte un paquet IP complet dans l'interface.
	Write(pkt []byte) (int, error)
	// MTU retourne l'unité de transmission courante.
	MTU() int
	// Name retourne le nom de l'interface.
	Name() string
	// Close détruit la session et, sous Windows, l'adaptateur.
	Close() error
}

// ErrClosed est renvoyé après fermeture.
var ErrClosed = errors.New("tun: interface fermée")

// Create crée l'interface demandée. L'implémentation dépend de l'OS.
func Create(name string, mtu int) (Device, error) {
	return create(name, mtu)
}
