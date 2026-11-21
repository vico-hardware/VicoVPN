// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 vico-hardware (Vico Studio) — https://github.com/vico-hardware/VicoVPN

package engine_test

import (
	"testing"

	"github.com/vicovpn/vicovpn/internal/engine"
	"github.com/vicovpn/vicovpn/internal/pkt"
)

// ipv4 construit un en-tête IPv4 minimal avec le protocole donné.
func ipv4(protoNum byte, dst [4]byte) []byte {
	b := make([]byte, 20)
	b[0] = 0x45
	b[9] = protoNum
	copy(b[16:20], dst[:])
	return b
}

func TestPolicyBlocksPrivate(t *testing.T) {
	p := &engine.Policy{SelfIPs: map[string]bool{"1.2.3.4": true}}
	cases := []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"public", ipv4(6, [4]byte{8, 8, 8, 8}), true},
		{"rfc1918-10", ipv4(6, [4]byte{10, 0, 0, 1}), false},
		{"rfc1918-192", ipv4(6, [4]byte{192, 168, 1, 1}), false},
		{"rfc1918-172", ipv4(6, [4]byte{172, 16, 0, 1}), false},
		{"loopback", ipv4(6, [4]byte{127, 0, 0, 1}), false},
		{"linklocal", ipv4(6, [4]byte{169, 254, 1, 1}), false},
		{"cgnat", ipv4(6, [4]byte{100, 64, 0, 1}), false},
		{"multicast", ipv4(6, [4]byte{224, 0, 0, 1}), false},
		{"broadcast", ipv4(6, [4]byte{255, 255, 255, 255}), false},
		{"self-ip", ipv4(6, [4]byte{1, 2, 3, 4}), false},
		{"doc-testnet", ipv4(6, [4]byte{192, 0, 2, 1}), false},
	}
	for _, c := range cases {
		if got := p.AllowedDst(c.pkt); got != c.want {
			t.Errorf("%s: AllowedDst=%v want %v", c.name, got, c.want)
		}
	}
}

func TestPktHelpers(t *testing.T) {
	// IPv4 UDP
	b := make([]byte, 20+8+4)
	b[0] = 0x45
	b[9] = 17
	uoff, ok := pkt.UDPPayloadOffset(b)
	if !ok || uoff != 20 {
		t.Fatalf("UDPPayloadOffset=%d ok=%v", uoff, ok)
	}
	if !pkt.IsUDP(b) {
		t.Fatal("IsUDP=false")
	}
	// IPv6 TCP
	v6 := make([]byte, 40)
	v6[0] = 0x60
	v6[6] = 6
	if pkt.Proto(v6) != 6 {
		t.Fatal("proto v6")
	}
	if pkt.IsUDP(v6) {
		t.Fatal("v6 UDP?")
	}
}
