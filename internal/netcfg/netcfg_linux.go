// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 vico-hardware (Vico Studio) — https://github.com/vico-hardware/VicoVPN

//go:build linux

package netcfg

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

// RelayTunSetup configure l'hôte relais Linux : adresse sur l'interface
// TUN, forwarding IP et NAT (MASQUERADE) vers la route par défaut.
// Si tunAddr6 est non vide, ajoute l'adresse IPv6 du tunnel, le forwarding
// IPv6 et le NAT66 (ip6tables MASQUERADE).
// Nécessite root. Appelée par engine.RelayOptions.NetSetup.
func RelayTunSetup(tunName, tunAddr, tunAddr6 string, mtu int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ip, ipnet, err := net.ParseCIDR(tunAddr)
	if err != nil {
		return fmt.Errorf("netcfg: TunIP invalide %q: %w", tunAddr, err)
	}
	prefix, _ := ipnet.Mask.Size()

	if err := run(ctx, "ip", "link", "set", "dev", tunName, "up"); err != nil {
		return err
	}
	if err := run(ctx, "ip", "addr", "replace", fmt.Sprintf("%s/%d", ip, prefix), "dev", tunName); err != nil {
		return err
	}
	if mtu > 0 {
		_ = run(ctx, "ip", "link", "set", "dev", tunName, "mtu", fmt.Sprint(mtu))
	}
	// Forwarding IPv4.
	if err := run(ctx, "sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return fmt.Errorf("netcfg: ip_forward: %w", err)
	}
	// NAT : masquerade du sous-réseau tunnel vers l'interface par défaut.
	out, err := exec.CommandContext(ctx, "ip", "route", "show", "default").Output()
	if err != nil {
		return fmt.Errorf("netcfg: route par défaut: %w", err)
	}
	fields := strings.Fields(string(out))
	if len(fields) < 5 || fields[0] != "default" {
		return fmt.Errorf("netcfg: route par défaut introuvable")
	}
	egressIf := fields[4]
	_, egressNet, _ := net.ParseCIDR(tunAddr)
	src := egressNet.String()
	if err := run(ctx, "iptables", "-t", "nat", "-C", "POSTROUTING", "-s", src, "-o", egressIf, "-j", "MASQUERADE"); err != nil {
		// Règle absente : l'ajouter.
		if err2 := run(ctx, "iptables", "-t", "nat", "-A", "POSTROUTING", "-s", src, "-o", egressIf, "-j", "MASQUERADE"); err2 != nil {
			return fmt.Errorf("netcfg: iptables MASQUERADE: %w", err2)
		}
	}
	// Forwarding du sous-réseau tunnel.
	_ = run(ctx, "iptables", "-C", "FORWARD", "-s", src, "-j", "ACCEPT")
	_ = run(ctx, "iptables", "-C", "FORWARD", "-d", src, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	_ = run(ctx, "iptables", "-A", "FORWARD", "-s", src, "-j", "ACCEPT")
	_ = run(ctx, "iptables", "-A", "FORWARD", "-d", src, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")

	// --- IPv6 (optionnel) ---
	if tunAddr6 == "" {
		return nil
	}
	ip6, ipnet6, err := net.ParseCIDR(tunAddr6)
	if err != nil {
		return fmt.Errorf("netcfg: TunIP6 invalide %q: %w", tunAddr6, err)
	}
	prefix6, _ := ipnet6.Mask.Size()
	if err := run(ctx, "ip", "-6", "addr", "replace", fmt.Sprintf("%s/%d", ip6, prefix6), "dev", tunName); err != nil {
		return err
	}
	// Le lien-local IPv6 de l'interface doit être activé pour joindre
	// la passerelle ; 'ip link set up' l'a déjà fait, mais on force.
	if err := run(ctx, "sysctl", "-w", "net.ipv6.conf.all.forwarding=1"); err != nil {
		return fmt.Errorf("netcfg: ipv6 forwarding: %w", err)
	}
	// NAT66 : MASQUERADE du préfixe tunnel vers l'interface de sortie.
	src6 := ipnet6.String()
	if err := run(ctx, "ip6tables", "-t", "nat", "-C", "POSTROUTING", "-s", src6, "-o", egressIf, "-j", "MASQUERADE"); err != nil {
		if err2 := run(ctx, "ip6tables", "-t", "nat", "-A", "POSTROUTING", "-s", src6, "-o", egressIf, "-j", "MASQUERADE"); err2 != nil {
			return fmt.Errorf("netcfg: ip6tables MASQUERADE (IPv6 requis ? ip6tables installé ?) : %w", err2)
		}
	}
	_ = run(ctx, "ip6tables", "-C", "FORWARD", "-s", src6, "-j", "ACCEPT")
	_ = run(ctx, "ip6tables", "-C", "FORWARD", "-d", src6, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	_ = run(ctx, "ip6tables", "-A", "FORWARD", "-s", src6, "-j", "ACCEPT")
	_ = run(ctx, "ip6tables", "-A", "FORWARD", "-d", src6, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	return nil
}

// RelayTunTeardown retire la configuration NAT du relais.
func RelayTunTeardown(tunName, tunAddr, tunAddr6 string) error {
	_, ipnet, err := net.ParseCIDR(tunAddr)
	if err != nil {
		return nil
	}
	src := ipnet.String()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "ip", "route", "show", "default").Output()
	egressIf := ""
	if f := strings.Fields(string(out)); len(f) >= 5 {
		egressIf = f[4]
	}
	if egressIf != "" {
		_ = run(ctx, "iptables", "-t", "nat", "-D", "POSTROUTING", "-s", src, "-o", egressIf, "-j", "MASQUERADE")
	}
	_ = run(ctx, "iptables", "-D", "FORWARD", "-s", src, "-j", "ACCEPT")
	if tunAddr6 != "" {
		if _, ipnet6, err := net.ParseCIDR(tunAddr6); err == nil {
			src6 := ipnet6.String()
			if egressIf != "" {
				_ = run(ctx, "ip6tables", "-t", "nat", "-D", "POSTROUTING", "-s", src6, "-o", egressIf, "-j", "MASQUERADE")
			}
			_ = run(ctx, "ip6tables", "-D", "FORWARD", "-s", src6, "-j", "ACCEPT")
			_ = run(ctx, "ip6tables", "-D", "FORWARD", "-d", src6, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")
		}
		_ = run(ctx, "ip", "-6", "addr", "flush", "dev", tunName)
	}
	_ = run(ctx, "ip", "addr", "flush", "dev", tunName)
	return nil
}

func run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
