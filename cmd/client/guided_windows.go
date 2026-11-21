// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 vico-hardware (Vico Studio) — https://github.com/vico-hardware/VicoVPN

//go:build windows

package main

// guided : protection maison pour les box sans pilotage automatique
// (Livebox, Bbox, box SFR, autres). L'utilisateur coupe le DHCP (et
// l'IPv6) de sa box en suivant le guide ; VicoVPN le note, distribue
// lui-même les réglages pendant la protection et, quand la protection
// s'arrête, continue de distribuer des réglages normaux (box en
// passerelle) jusqu'à ce que le DHCP de la box réponde de nouveau — la
// maison ne perd jamais le réseau tant que ce PC est allumé.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vicovpn/vicovpn/internal/netcfg"
)

const guidedFile = "box-guidee.json"

type guidedState struct {
	Brand     string    `json:"marque"`
	DHCPOff   bool      `json:"dhcp_box_coupe"` // l'utilisateur a coupé le DHCP de la box
	IPv6Off   bool      `json:"ipv6_box_coupee"`
	ChangedAt time.Time `json:"modifie_le"`
}

func loadGuided(dir string) guidedState {
	var g guidedState
	if b, err := os.ReadFile(filepath.Join(dir, guidedFile)); err == nil {
		_ = json.Unmarshal(b, &g)
	}
	return g
}

func saveGuided(dir string, g guidedState) {
	g.ChangedAt = time.Now()
	if b, err := json.MarshalIndent(g, "", "  "); err == nil {
		_ = os.WriteFile(filepath.Join(dir, guidedFile), b, 0o600)
	}
}

// detectBrand reconnaît la box d'après sa page d'accueil :
// freebox | livebox | bbox | sfr | autre.
func detectBrand(box string) string {
	if box == "" {
		return "autre"
	}
	cl := &http.Client{Timeout: 3 * time.Second}
	get := func(url, host string) string {
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return ""
		}
		if host != "" {
			req.Host = host
		}
		resp, err := cl.Do(req)
		if err != nil {
			return ""
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		return strings.ToLower(resp.Header.Get("Server") + " " + string(b))
	}
	if s := get("http://"+box+"/api_version", "mafreebox.freebox.fr"); strings.Contains(s, "api_base_url") {
		return "freebox"
	}
	if s := get("http://"+box+"/api/1.0/?method=system.getInfo", ""); strings.Contains(s, "<rsp") {
		return "sfr"
	}
	s := get("http://"+box+"/", "")
	switch {
	case strings.Contains(s, "livebox") || strings.Contains(s, "sah") && strings.Contains(s, "orange"):
		return "livebox"
	case strings.Contains(s, "bbox") || strings.Contains(s, "bytel") || strings.Contains(s, "bouygues"):
		return "bbox"
	case strings.Contains(s, "sfr") || strings.Contains(s, "neufbox") || strings.Contains(s, "red by"):
		return "sfr"
	case strings.Contains(s, "freebox"):
		return "freebox"
	}
	return "autre"
}

var brandNames = map[string]string{
	"freebox": "Freebox", "livebox": "Livebox (Orange)", "bbox": "Bbox (Bouygues Telecom)",
	"sfr": "Box SFR / RED", "autre": "Box",
}

// boxCommand : BOXINFO / BOXGUIDE <on|off> [ipv6]
func boxCommand(dir string, gw *gateway, cmd string, args []string) string {
	a, err := currentBox()
	if err != nil {
		return "ERR " + err.Error()
	}
	st := loadGuided(dir)
	if strings.EqualFold(cmd, "BOXGUIDE") {
		if len(args) == 0 {
			return "ERR usage : BOXGUIDE on|off [ipv6]"
		}
		on := strings.EqualFold(args[0], "on")
		if st.Brand == "" {
			st.Brand = detectBrand(a.Box)
		}
		st.DHCPOff = on
		st.IPv6Off = on && len(args) > 1 && strings.EqualFold(args[1], "ipv6")
		saveGuided(dir, st)
		if on {
			logEvent(dir, "box : DHCP coupé par l'utilisateur — ce PC distribuera les réglages")
			gw.StartNormalDHCP() // la maison garde le réseau même protection arrêtée
		} else {
			logEvent(dir, "box : DHCP de la box rétabli par l'utilisateur")
			gw.StopNormalDHCP()
		}
		return "OK"
	}
	// BOXINFO : marque|nom|dhcp_coupe|ipv6_coupee|dhcp_box_vu
	if st.Brand == "" {
		st.Brand = detectBrand(a.Box)
		saveGuided(dir, st)
	}
	seen := "0"
	if gw.BoxDHCPSeen() {
		seen = "1"
	}
	return "OK " + st.Brand + "|" + brandNames[st.Brand] + "|" + b2s(st.DHCPOff) + "|" + b2s(st.IPv6Off) + "|" + seen + "|" + a.Box
}

func b2s(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// StartNormalDHCP démarre (ou garde) le DHCP du PC en mode « normal ».
func (g *gateway) StartNormalDHCP() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.on || g.dhcp != nil {
		return // la protection maison gère déjà le DHCP
	}
	if g.dhcpNormal != nil {
		return
	}
	a, err := currentBox()
	if err != nil {
		logEvent(g.dir, "box : DHCP du PC impossible ("+err.Error()+")")
		return
	}
	if err := allowDHCPRule(); err != nil {
		logEvent(g.dir, "box : pare-feu DHCP : "+err.Error())
	}
	srv, err := newDHCPServer(g.dir, a, "", "", map[string]string{}, map[string]string{})
	if err == nil {
		srv.normal = true
		srv.onBoxDHCP = g.boxDHCPBack
		err = srv.Start()
	}
	if err != nil {
		logEvent(g.dir, "box : DHCP du PC impossible : "+err.Error())
		return
	}
	g.dhcpNormal = srv
	logEvent(g.dir, "box : ce PC distribue des réglages normaux (box en passerelle) tant que le DHCP de la box est coupé")
}

// StopNormalDHCP arrête le DHCP « normal » du PC.
func (g *gateway) StopNormalDHCP() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.dhcpNormal != nil {
		g.dhcpNormal.Close()
		g.dhcpNormal = nil
		if !g.on {
			removeGatewayRules()
		}
	}
}

// boxDHCPBack : un appareil a pris une adresse de la box.
func (g *gateway) boxDHCPBack() {
	g.mu.Lock()
	g.boxDHCPAt = time.Now()
	normal := g.dhcpNormal != nil && !g.on
	g.mu.Unlock()
	if normal {
		// Le DHCP de la box répond de nouveau : ce PC s'efface.
		st := loadGuided(g.dir)
		st.DHCPOff, st.IPv6Off = false, false
		saveGuided(g.dir, st)
		g.StopNormalDHCP()
		logEvent(g.dir, "box : le DHCP de la box répond de nouveau — ce PC arrête de distribuer les réglages")
	}
}

// BoxDHCPSeen : la box a-t-elle distribué une adresse ces 10 dernières min ?
func (g *gateway) BoxDHCPSeen() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return !g.boxDHCPAt.IsZero() && time.Since(g.boxDHCPAt) < 10*time.Minute
}

// guidedTakeoverLocked : protection maison avec une box en mode guidé.
func (g *gateway) guidedTakeoverLocked() {
	st := loadGuided(g.dir)
	if !st.DHCPOff || len(g.lan) == 0 {
		return
	}
	if g.dhcpNormal != nil {
		g.dhcpNormal.Close()
		g.dhcpNormal = nil
	}
	if g.dhcpOld != nil {
		g.dhcpOld.Close()
		g.dhcpOld = nil
	}
	srv, err := newDHCPServer(g.dir, g.lan[0], "", "", map[string]string{}, map[string]string{})
	if err == nil {
		srv.onLease = g.onLease
		srv.onBoxDHCP = func() {
			g.mu.Lock()
			g.boxDHCPAt = time.Now()
			g.mu.Unlock()
		}
		err = srv.Start()
	}
	if err != nil {
		g.boxErr = err.Error()
		logEvent(g.dir, "protection maison : "+err.Error())
		return
	}
	g.dhcp = srv
	g.guidedMode = true
	logEvent(g.dir, "protection maison : ce PC distribue les réglages (DHCP de la box coupé à la main)")
}

// releaseGuidedLocked : fin de protection en mode guidé — le DHCP du PC
// continue en mode normal (box en passerelle).
func (g *gateway) releaseGuidedLocked() {
	if !g.guidedMode || g.dhcp == nil {
		return
	}
	g.dhcp.SetNormal(true)
	g.dhcp.onLease = nil
	g.dhcp.onBoxDHCP = g.boxDHCPBack
	g.dhcpNormal = g.dhcp
	g.dhcp = nil
	g.guidedMode = false
	logEvent(g.dir, "protection maison : réglages normaux redistribués (box en passerelle) — pense à réactiver le DHCP de ta box")
}

// allowDHCPRule ouvre seulement le port 67 (mode normal).
func allowDHCPRule() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	ps := `Get-NetFirewallRule -DisplayName '` + gwRulePrefix + `DHCP' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; ` +
		`New-NetFirewallRule -DisplayName '` + gwRulePrefix + `DHCP' -Direction Inbound -Action Allow ` +
		`-Protocol UDP -LocalPort 67 -RemotePort 68 -Profile Any -Program '` + strings.ReplaceAll(exe, "'", "''") + `' -ErrorAction Stop | Out-Null`
	return runHiddenPS(ps)
}

func runHiddenPS(ps string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := netcfg.HiddenCmd(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", ps).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
