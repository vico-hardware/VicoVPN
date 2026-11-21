// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 vico-hardware (Vico Studio) — https://github.com/vico-hardware/VicoVPN

//go:build windows

package netcfg

import (
	"net"
	"testing"
)

func TestV4Complement(t *testing.T) {
	got, err := v4Complement([]string{"10.0.0.0/8", "192.168.1.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	// 10.x et l'hôte autorisé ne doivent pas être bloqués.
	for _, c := range got {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatalf("CIDR invalide %q: %v", c, err)
		}
		if n.Contains(net.ParseIP("10.1.2.3")) {
			t.Fatalf("10/8 bloqué par %s", c)
		}
		if n.Contains(net.ParseIP("192.168.1.1")) {
			t.Fatalf("hôte autorisé bloqué par %s", c)
		}
	}
	// 8.8.8.8 doit être couvert.
	found := false
	for _, c := range got {
		_, n, _ := net.ParseCIDR(c)
		if n.Contains(net.ParseIP("8.8.8.8")) {
			found = true
		}
	}
	if !found {
		t.Fatalf("8.8.8.8 non bloqué: %v", got)
	}
	// 1.1.1.1 aussi.
	found = false
	for _, c := range got {
		_, n, _ := net.ParseCIDR(c)
		if n.Contains(net.ParseIP("1.1.1.1")) {
			found = true
		}
	}
	if !found {
		t.Fatalf("1.1.1.1 non bloqué: %v", got)
	}
	if len(got) > 64 {
		t.Fatalf("trop de CIDR: %d (%v)", len(got), got)
	}
}
