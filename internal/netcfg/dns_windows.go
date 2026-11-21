// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 vico-hardware (Vico Studio) — https://github.com/vico-hardware/VicoVPN

//go:build windows

package netcfg

// Gestion DNS système : sauvegarde complète (JSON), application de serveurs
// statiques sur toutes les cartes actives, restauration. Reprend le
// comportement d'AdZ-Vanced / QuickSetDNS en l'intégrant au client.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DNSBackup est la sauvegarde des serveurs DNS par interface.
type DNSBackup map[string]DNSBackupEntry

// DNSBackupEntry : serveurs IPv4 et IPv6 d'une interface.
type DNSBackupEntry struct {
	IPv4 []string `json:"IPv4,omitempty"`
	IPv6 []string `json:"IPv6,omitempty"`
}

// dnsBackupPath retourne le chemin du fichier de sauvegarde.
func dnsBackupPath(dir string) string { return filepath.Join(dir, "dns_backup.json") }

// DNSBackupPath expose le chemin pour le client.
func DNSBackupPath(dir string) string { return dnsBackupPath(dir) }

// activeAdapters retourne les alias (Name) des cartes réseau actives,
// hors interfaces créées par VicoVPN/Tor.
func activeAdapters() ([]string, error) {
	out, err := psJSON(`Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -ExpandProperty Name`)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, l := range strings.Split(out, "\n") {
		n := strings.Trim(strings.TrimSpace(l), `"`)
		if n == "" {
			continue
		}
		ln := strings.ToLower(n)
		if strings.HasPrefix(ln, "vicovpn") || strings.HasPrefix(ln, "vicotor") {
			continue
		}
		names = append(names, n)
	}
	return names, nil
}

// BackupDNS sauvegarde les DNS actuels de toutes les cartes actives.
func BackupDNS(dir string) error {
	out, err := psJSON(`Get-DnsClientServerAddress | ForEach-Object {
		[pscustomobject]@{ Alias=$_.InterfaceAlias; Family=[string]$_.AddressFamily; Servers=@($_.ServerAddresses) }
	} | ConvertTo-Json -Depth 4 -Compress`)
	if err != nil {
		return err
	}
	var raw []map[string]any
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		// un seul objet -> tableau d'un element
		var one map[string]any
		if err2 := json.Unmarshal([]byte(out), &one); err2 != nil {
			return fmt.Errorf("dns backup: JSON invalide")
		}
		raw = []map[string]any{one}
	}
	bk := DNSBackup{}
	for _, e := range raw {
		alias, _ := e["Alias"].(string)
		if alias == "" {
			continue
		}
		entry := bk[alias]
		if entry.IPv4 == nil {
			entry.IPv4 = []string{}
			entry.IPv6 = []string{}
		}
		fam, _ := e["Family"].(string)
		// AddressFamily : IPv4=2, IPv6=23 (Enum.ToString peut donner le nom)
		var dst *[]string
		switch {
		case fam == "IPv4" || fam == "2":
			dst = &entry.IPv4
		case fam == "IPv6" || fam == "23":
			dst = &entry.IPv6
		}
		if dst != nil {
			if arr, ok := e["Servers"].([]any); ok {
				for _, s := range arr {
					if str, ok := s.(string); ok {
						*dst = append(*dst, str)
					}
				}
			}
		}
		bk[alias] = entry
	}
	b, err := json.MarshalIndent(bk, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dnsBackupPath(dir)), 0o700); err != nil {
		return err
	}
	return os.WriteFile(dnsBackupPath(dir), b, 0o600)
}

// loadDNSBackup lit la sauvegarde (vide si absente).
func loadDNSBackup(dir string) DNSBackup {
	b, err := os.ReadFile(dnsBackupPath(dir))
	if err != nil {
		return DNSBackup{}
	}
	var bk DNSBackup
	if json.Unmarshal(b, &bk) != nil {
		return DNSBackup{}
	}
	return bk
}

// cleanDNS6 retire les adresses IPv6 site-local dépréciées (fec0::/10) :
// netsh met ~11 s par serveur à les appliquer (validation Windows) et ce
// ne sont pas de vrais résolveurs (valeurs par défaut Teredo & co).
func cleanDNS6(servers []string) []string {
	out := servers[:0]
	for _, s := range servers {
		ip := net.ParseIP(s)
		if ip != nil && ip.To4() == nil {
			b := ip.To16()
			if len(b) >= 2 && b[0] == 0xfe && b[1]&0xc0 == 0xc0 {
				continue
			}
		}
		out = append(out, s)
	}
	return out
}

// dnsPSCmd genere la commande PowerShell pour une interface : un seul
// Set-DnsClientServerAddress gère IPv4 et IPv6 (les familles sont
// déduites des adresses). Liste vide = retour DHCP.
func dnsPSCmd(iface string, v4, v6 []string) string {
	alias := strings.ReplaceAll(iface, "'", "''")
	servers := append(append([]string{}, v4...), cleanDNS6(v6)...)
	if len(servers) == 0 {
		return fmt.Sprintf(`Set-DnsClientServerAddress -InterfaceAlias '%s' -ResetServerAddresses -ErrorAction SilentlyContinue`, alias)
	}
	q := make([]string, len(servers))
	for i, s := range servers {
		q[i] = "'" + s + "'"
	}
	return fmt.Sprintf(`Set-DnsClientServerAddress -InterfaceAlias '%s' -ServerAddresses %s -ErrorAction SilentlyContinue`,
		alias, strings.Join(q, ","))
}

// runDNSBatch execute toutes les commandes netsh en UN SEUL processus
// PowerShell (beaucoup plus rapide que un spawn par commande).
func runDNSBatch(cmds []string) error {
	if len(cmds) == 0 {
		return nil
	}
	return runPS(context.Background(), strings.Join(cmds, "; "))
}

// validateDNSServers vérifie que chaque entrée est une IP valide.
func validateDNSServers(servers []string) error {
	for _, s := range servers {
		if net.ParseIP(s) == nil {
			return fmt.Errorf("serveur DNS invalide: %q", s)
		}
	}
	return nil
}

// ApplyDNS applique des serveurs DNS statiques sur toutes les cartes actives.
// Sauvegarde d'abord la config actuelle (sauf si skipBackup).
// Retourne la liste des interfaces modifiées.
func ApplyDNS(dir string, v4, v6 []string, skipBackup bool) ([]string, error) {
	if err := validateDNSServers(v4); err != nil {
		return nil, err
	}
	if err := validateDNSServers(v6); err != nil {
		return nil, err
	}
	// La sauvegarde garde les DNS d'origine : on ne l'écrase pas à chaque
	// « Appliquer » (sinon elle finit par contenir les DNS de VicoVPN).
	if _, err := os.Stat(dnsBackupPath(dir)); err == nil {
		skipBackup = true
	}
	if !skipBackup {
		if err := BackupDNS(dir); err != nil {
			return nil, fmt.Errorf("sauvegarde DNS: %w", err)
		}
	}
	ifaces, err := activeAdapters()
	if err != nil {
		return nil, err
	}
	var cmds []string
	for _, name := range ifaces {
		cmds = append(cmds, dnsPSCmd(name, v4, v6))
	}
	if err := runDNSBatch(cmds); err != nil {
		return ifaces, fmt.Errorf("dns: %w", err)
	}
	return ifaces, nil
}

// RestoreDNS (bouton « Restaurer auto ») remet les DNS en automatique
// (DHCP / box) en IPv4 ET en IPv6, sur toutes les cartes — y compris
// celles déconnectées ou masquées qui auraient gardé des DNS fixes —, puis
// efface la sauvegarde. Retourne les cartes actives traitées.
func RestoreDNS(dir string) ([]string, error) {
	ifaces, err := activeAdapters()
	if err != nil {
		return nil, err
	}
	out, err := psJSON(`Get-NetAdapter -IncludeHidden | Select-Object -ExpandProperty Name`)
	if err != nil {
		out = ""
	}
	seen := map[string]bool{}
	var all []string
	add := func(n string) {
		n = strings.Trim(strings.TrimSpace(n), `"`)
		ln := strings.ToLower(n)
		if n == "" || seen[n] || strings.HasPrefix(ln, "vicovpn") || strings.HasPrefix(ln, "vicotor") {
			return
		}
		seen[n] = true
		all = append(all, n)
	}
	for _, n := range ifaces {
		add(n)
	}
	for _, l := range strings.Split(out, "\n") {
		add(l)
	}
	for n := range loadDNSBackup(dir) {
		add(n)
	}
	var cmds []string
	for _, name := range all {
		cmds = append(cmds, dnsPSCmd(name, nil, nil))
	}
	if err := runDNSBatch(cmds); err != nil {
		return ifaces, fmt.Errorf("dns restauration: %w", err)
	}
	_ = os.Remove(dnsBackupPath(dir))
	return ifaces, nil
}

// DNSList retourne l'état courant : lignes « alias|ipv4csv|ipv6csv».
func DNSList() (string, error) {
	out, err := psJSON(`Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses.Count -gt 0 } |
		ForEach-Object { [pscustomobject]@{ Alias=$_.InterfaceAlias; Family=[string]$_.AddressFamily; Servers=@($_.ServerAddresses) } } |
		ConvertTo-Json -Depth 4 -Compress`)
	if err != nil {
		return "", err
	}
	type ent struct {
		Alias   string   `json:"Alias"`
		Family  string   `json:"Family"`
		Servers []string `json:"Servers"`
	}
	var raw []ent
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		var one ent
		if err2 := json.Unmarshal([]byte(out), &one); err2 != nil {
			return "", fmt.Errorf("dns list: JSON invalide")
		}
		raw = []ent{one}
	}
	m := map[string]*DNSBackupEntry{}
	var order []string
	for _, e := range raw {
		if e.Alias == "" {
			continue
		}
		entry, ok := m[e.Alias]
		if !ok {
			entry = &DNSBackupEntry{}
			m[e.Alias] = entry
			order = append(order, e.Alias)
		}
		switch {
		case e.Family == "IPv4" || e.Family == "2":
			entry.IPv4 = e.Servers
		case e.Family == "IPv6" || e.Family == "23":
			entry.IPv6 = e.Servers
		}
	}
	sort.Strings(order)
	var b strings.Builder
	for _, a := range order {
		e := m[a]
		fmt.Fprintf(&b, "%s|%s|%s\n", a, strings.Join(e.IPv4, ","), strings.Join(e.IPv6, ","))
	}
	return strings.TrimRight(b.String(), "\n"), nil
}
