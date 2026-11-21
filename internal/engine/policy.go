// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 vico-hardware (Vico Studio) — https://github.com/vico-hardware/VicoVPN

package engine

import (
	"net"
	"time"
)

// Policy décide si un paquet IP peut sortir vers Internet depuis le relais.
// Elle bloque : loopback, privé (RFC1918 + CGNAT), link-local, multicast,
// broadcast, et toute adresse appartenant au relais lui-même.
type Policy struct {
	// SelfIPs contient les adresses IP locales du relais (IPv4/IPv6)
	// à ne jamais atteindre depuis le tunnel.
	SelfIPs map[string]bool
	// LocalNets contient les sous-réseaux locaux du tunnel (ex. le /24 de
	// l'interface TUN du relais) : leurs destinations sont livrées
	// localement par l'hôte relais, pas émises vers Internet.
	LocalNets []*net.IPNet
}

// AllowedDst indique si le paquet (vue comme octets IP) peut être émis.
func (p *Policy) AllowedDst(pkt []byte) bool {
	if len(pkt) == 0 {
		return false
	}
	var ip net.IP
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return false
		}
		ip = net.IP(pkt[16:20])
	case 6:
		if len(pkt) < 40 {
			return false
		}
		ip = net.IP(pkt[24:40])
	default:
		return false
	}
	for _, n := range p.LocalNets {
		if n.Contains(ip) {
			return true
		}
	}
	if p.SelfIPs[ip.String()] {
		return false
	}
	return allowedPublicIP(ip)
}

// allowedPublicIP refuse les destinations non publiques.
func allowedPublicIP(ip net.IP) bool {
	// Multicast link-local IPv6 (ff02::/16) : nécessaire au Neighbor
	// Discovery à l'intérieur du tunnel. Ne peut pas être routé sur
	// Internet — la pile de l'hôte relais le consomme localement.
	if len(ip) == net.IPv6len && ip[0] == 0xff && ip[1] == 0x02 {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		return allowedPublicV4(ip4)
	}
	// IPv6 : refuser ULA fc00::/7, documentation 2001:db8::/32, etc.
	if len(ip) == net.IPv6len {
		if ip[0]&0xfe == 0xfc { // fc00::/7
			return false
		}
		if ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x0d && ip[3] == 0xb8 { // 2001:db8::/32
			return false
		}
	}
	return true
}

func allowedPublicV4(ip net.IP) bool {
	if ip[0] == 0 || ip[0] == 10 || ip[0] == 127 {
		return false
	}
	if ip[0] == 169 && ip[1] == 254 {
		return false
	}
	if ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31 {
		return false
	}
	if ip[0] == 192 && ip[1] == 168 {
		return false
	}
	if ip[0] == 100 && ip[1] >= 64 && ip[1] <= 127 { // CGNAT
		return false
	}
	if ip[0] >= 224 { // multicast + broadcast + réservé
		return false
	}
	if ip[0] == 192 && ip[1] == 0 && ip[2] == 0 { // 192.0.0.0/24
		return false
	}
	if ip[0] == 192 && ip[1] == 0 && ip[2] == 2 { // TEST-NET-1
		return false
	}
	if ip[0] == 198 && (ip[1] == 18 || ip[1] == 19) { // benchmark
		return false
	}
	if ip[0] == 198 && ip[1] == 51 && ip[2] == 100 { // TEST-NET-2
		return false
	}
	if ip[0] == 203 && ip[1] == 0 && ip[2] == 113 { // TEST-NET-3
		return false
	}
	return true
}

// RateLimiter est un limiteur de débit à seau de jetons (octets/seconde).
type RateLimiter struct {
	rate   float64
	burst  float64
	tokens float64
	last   int64 // ns
}

// NewRateLimiter retourne un limiteur ; rateBps <= 0 = illimité.
func NewRateLimiter(rateBps int) *RateLimiter {
	if rateBps <= 0 {
		return nil
	}
	return &RateLimiter{rate: float64(rateBps), burst: float64(rateBps) / 10, tokens: float64(rateBps) / 10}
}

// Allow consomme n octets ; retourne true si le débit est respecté.
func (r *RateLimiter) Allow(n int) bool {
	if r == nil {
		return true
	}
	now := time.Now().UnixNano()
	elapsed := float64(now-r.last) / 1e9
	if elapsed > 0 {
		r.tokens += elapsed * r.rate
		if r.tokens > r.burst {
			r.tokens = r.burst
		}
		r.last = now
	}
	if r.tokens >= float64(n) {
		r.tokens -= float64(n)
		return true
	}
	return false
}
