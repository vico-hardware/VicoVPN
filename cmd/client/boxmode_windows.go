// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 vico-hardware (Vico Studio) — https://github.com/vico-hardware/VicoVPN

//go:build windows

package main

// boxmode : protection maison pilotée par la Freebox. À l'activation, la
// box est sauvegardée puis son IPv6 et son DHCP sont coupés ; le serveur
// DHCP de ce PC distribue alors à chaque appareil ce PC comme passerelle
// et comme DNS — aucun réglage sur les appareils. À la désactivation (ou
// au prochain démarrage du service après un plantage), la box est remise
// exactement comme avant.

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/vicovpn/vicovpn/internal/freebox"
	"github.com/vicovpn/vicovpn/internal/netcfg"
)

// boxCache retient l'adresse de la box (évite PowerShell à chaque appel).
var boxCache struct {
	sync.Mutex
	ip  string
	at  time.Time
	lan lanAddr
}

func currentBox() (lanAddr, error) {
	boxCache.Lock()
	defer boxCache.Unlock()
	if boxCache.ip != "" && time.Since(boxCache.at) < 5*time.Minute {
		return boxCache.lan, nil
	}
	lan, err := detectLAN()
	if err != nil {
		return lanAddr{}, err
	}
	for _, a := range lan {
		if a.Box != "" {
			boxCache.ip, boxCache.at, boxCache.lan = a.Box, time.Now(), a
			return a, nil
		}
	}
	return lanAddr{}, fmt.Errorf("passerelle de la box introuvable")
}

// fbxLabels : textes de l'interface pour chaque état d'association.
var fbxLabels = map[string]string{
	"absente":       "Aucune Freebox détectée sur ce réseau : réglage manuel des appareils.",
	"non_associee":  "Freebox détectée. Associe-la pour que VicoVPN règle tout seul les appareils (IPv6 et DHCP de la box).",
	"attente":       "Valide la demande « VicoVPN » sur l'écran de ta Freebox (flèche droite puis OK).",
	"refusee":       "Demande refusée sur la Freebox. Relance l'association pour réessayer.",
	"droits_profil": "Freebox prête. Pour bloquer aussi l'IPv6 des appareils (ta box refuse de couper son IPv6) : dans Freebox OS → Paramètres de la Freebox → Mode avancé → Gestion des accès → Applications → VicoVPN → Modifier, coche aussi « Accès à la gestion des profils utilisateur » → OK, puis clique sur « Vérifier ».",
	"droits":        "Association faite, mais la Freebox n'accorde pas encore le droit de modifier ses réglages. Dans Freebox OS (mafreebox.freebox.fr) : Paramètres de la Freebox → passe en « Mode avancé » → Gestion des accès → onglet Applications → ligne VicoVPN → bouton Modifier (crayon) → coche « Modification des réglages de la Freebox » → OK. Puis clique sur « Vérifier ».",
	"prete":         "Freebox prête : à l'activation, VicoVPN coupe l'IPv6 et le DHCP de la box et distribue lui-même les réglages. Tout est remis à la désactivation.",
}

// freeboxCommand traite FBXSTATUS / FBXPAIR / FBXRESTORE (hors verrou
// runtime : appels réseau vers la box).
func freeboxCommand(dir string, gw *gateway, cmd string) string {
	a, err := currentBox()
	if err != nil {
		return "OK absente " + fbxLabels["absente"]
	}
	c := freebox.New(dir, a.Box)
	switch strings.ToUpper(cmd) {
	case "FBXPAIR":
		host, _ := os.Hostname()
		if err := c.Pair("PC " + host); err != nil {
			return "ERR " + err.Error()
		}
		logEvent(dir, "Freebox : demande d'association envoyée (à valider sur l'écran de la box)")
		return "OK attente " + fbxLabels["attente"]
	case "FBXWIFI":
		// Bascule tous les appareils Wi-Fi d'un coup : redémarrage du
		// Wi-Fi de la box pendant la protection maison.
		on, box, _, _ := gw.BoxInfo()
		if !on || !box {
			return "ERR active d'abord la protection maison avec la Freebox associée"
		}
		if gw.lanOnWifi() {
			return "ERR ce PC est relié à la box en Wi-Fi : couper le Wi-Fi le déconnecterait aussi. Branche-le en Ethernet."
		}
		logEvent(dir, "Freebox : redémarrage du Wi-Fi pour basculer tous les appareils")
		go func() {
			if err := c.RestartWifi(); err != nil {
				logEvent(dir, "Freebox : "+err.Error())
				return
			}
			logEvent(dir, "Freebox : Wi-Fi rallumé — les appareils se reconnectent via ce PC")
		}()
		return "OK Wi-Fi de la box en cours de redémarrage : les appareils se reconnectent d'ici 30 secondes à 1 minute."
	case "FBXRESTORE":
		if err := freebox.Restore(dir); err != nil {
			logEvent(dir, "Freebox : restauration impossible : "+err.Error())
			return "ERR " + err.Error()
		}
		logEvent(dir, "Freebox : réglages d'origine restaurés")
		return "OK restauree Réglages de la box restaurés."
	}
	// FBXSTATUS
	if on, box, kept, berr := gw.BoxInfo(); box && kept && gw.Blocking() {
		return "OK auto " + c.ModelOrDefault() + " : DHCP de la box coupé, ce PC distribue les réglages. La box refuse de couper son IPv6 : VicoVPN coupe donc l'accès Internet direct des appareils basculés (profil « VicoVPN » de la box), IPv6 comprise — tout passe par ce PC."
	} else if box && kept {
		return "OK auto_ipv6 " + c.ModelOrDefault() + " : DHCP de la box coupé, ce PC distribue les réglages. Attention : la box refuse de couper son IPv6 et le blocage n'a pas pu être posé (" + berr + "), certains sites passent encore en IPv6 sans Tor. Coche « Accès à la gestion des profils utilisateur » pour VicoVPN dans Freebox OS (Gestion des accès → Applications), puis désactive et réactive la protection."
	} else if box {
		return "OK auto " + c.ModelOrDefault() + " : IPv6 et DHCP de la box coupés, ce PC distribue les réglages aux appareils."
	} else if on && berr != "" {
		return "OK erreur La prise en main de la box a échoué : " + berr + " Les appareils doivent être réglés à la main (valeurs ci-dessous), ou désactive puis réactive la protection."
	}
	if freebox.LoadSaved(dir) != nil {
		return "OK a_restaurer Les réglages d'origine de la box n'ont pas encore été remis (box injoignable ?)."
	}
	st, err := c.State()
	msg := fbxLabels[st]
	if err != nil && st != "absente" {
		msg += " (" + err.Error() + ")"
	}
	if st == "prete" || st == "droits" {
		msg = c.ModelOrDefault() + " — " + msg
	}
	return "OK " + st + " " + msg
}

// BoxInfo : protection active, box pilotée, IPv6 non coupée, erreur.
func (g *gateway) BoxInfo() (on, box, ipv6Kept bool, err string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.on, g.boxMode, g.ipv6Kept, g.boxErr
}

// Blocking : le profil de blocage des appareils est-il posé ?
func (g *gateway) Blocking() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.blockProfile > 0
}

// syncBlocked met à jour la liste des appareils bloqués sur la box :
// tous ceux qui ont reçu une adresse de ce PC (jamais le PC lui-même).
func (g *gateway) syncBlocked() {
	g.mu.Lock()
	if g.blockProfile == 0 || g.dhcp == nil || g.fbx == nil {
		g.mu.Unlock()
		return
	}
	set := map[string]bool{}
	for _, m := range g.blocked {
		set[m] = true
	}
	changed := false
	for _, l := range g.dhcp.Leases() {
		if !g.dhcp.selfMACs[l.MAC] && !set[l.MAC] {
			set[l.MAC] = true
			changed = true
		}
	}
	if !changed {
		g.mu.Unlock()
		return
	}
	macs := make([]string, 0, len(set))
	for m := range set {
		macs = append(macs, m)
	}
	id, c := g.blockProfile, g.fbx
	g.mu.Unlock()
	if err := c.SetBlocked(id, macs); err != nil {
		g.mu.Lock()
		if g.blockErr != err.Error() {
			g.blockErr = err.Error()
			logEvent(g.dir, "Freebox : mise à jour du blocage impossible : "+err.Error())
		}
		g.mu.Unlock()
		return
	}
	g.mu.Lock()
	g.blocked = macs
	g.mu.Unlock()
	logEvent(g.dir, fmt.Sprintf("Freebox : accès direct par la box bloqué pour %d appareil(s) basculé(s)", len(macs)))
}

// BoxMode : la box est-elle actuellement pilotée ?
func (g *gateway) BoxMode() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.boxMode
}

// takeoverLocked bascule la box en mode « PC distributeur ». En cas
// d'échec, la protection maison continue en réglage manuel.
func (g *gateway) takeoverLocked() {
	g.boxErr = ""
	if len(g.lan) == 0 || g.lan[0].Box == "" {
		return
	}
	a := g.lan[0]
	c := freebox.New(g.dir, a.Box)
	if st, _ := c.State(); st != "prete" && st != "droits_profil" {
		if st != "absente" {
			g.boxErr = fbxLabels[st]
		}
		return
	}
	// Bail du PC rafraîchi tant que la box distribue encore.
	renewPCLease(a.Alias)
	saved, err := c.Takeover()
	if err != nil {
		g.boxErr = err.Error()
		logEvent(g.dir, "Freebox : "+err.Error())
		_ = freebox.Restore(g.dir)
		return
	}
	prefer, reserved := map[string]string{}, map[string]string{}
	for _, l := range saved.Leases {
		mac := strings.ToUpper(l.MAC)
		if l.Static {
			reserved[l.IP] = mac
		}
		prefer[mac] = l.IP
	}
	if g.dhcpOld != nil {
		g.dhcpOld.Close()
		g.dhcpOld = nil
	}
	srv, err := newDHCPServer(g.dir, a, saved.DHCP.RangeStart, saved.DHCP.RangeEnd, prefer, reserved)
	if err == nil {
		srv.onLease = g.onLease
		err = srv.Start()
	}
	if err != nil {
		g.boxErr = err.Error()
		logEvent(g.dir, "protection maison : "+err.Error()+" — box remise comme avant")
		if rerr := freebox.Restore(g.dir); rerr != nil {
			logEvent(g.dir, "Freebox : restauration impossible : "+rerr.Error())
		}
		return
	}
	g.fbx = c
	g.dhcp = srv
	g.boxMode = true
	g.ipv6Kept = saved.IPv6Kept
	g.blockProfile, g.blocked = 0, nil
	if saved.IPv6Kept {
		// La box garde son IPv6 : les appareils basculés perdent l'accès
		// Internet direct par la box (profil Freebox « bloqué ») ; leur
		// IPv4 passe par ce PC, que la box ne bloque pas.
		if !c.Perm("profile") {
			g.boxErr = "droit « Gestion des profils » manquant"
		} else if id, err := c.CreateBlockProfile(); err != nil {
			g.boxErr = "profil de blocage : " + err.Error()
			logEvent(g.dir, "Freebox : profil de blocage IPv6 impossible : "+err.Error())
		} else if err := c.SetBlocked(id, nil); err != nil {
			_ = c.DeleteProfile(id)
			g.boxErr = "profil de blocage : " + err.Error()
			logEvent(g.dir, "Freebox : profil de blocage IPv6 impossible : "+err.Error())
		} else {
			saved.ProfileID = id
			_ = freebox.SaveSaved(g.dir, saved)
			g.blockProfile = id
			logEvent(g.dir, "Freebox : profil « "+freebox.ProfileName+" » créé — l'accès direct des appareils basculés (IPv6 compris) sera bloqué")
		}
	}
	if saved.IPv6Kept {
		logEvent(g.dir, "Freebox : DHCP de la box coupé — ce PC distribue les réglages aux appareils ; la box a refusé de couper l'IPv6")
	} else {
		logEvent(g.dir, "Freebox : IPv6 et DHCP de la box coupés — ce PC distribue les réglages aux appareils")
	}
}

// releaseBoxLocked rend la main à la box (DHCP puis IPv6).
func (g *gateway) releaseBoxLocked() {
	if g.dhcp != nil {
		g.dhcp.Retour()
		g.dhcpOld = g.dhcp
		g.dhcp = nil
		old := g.dhcpOld
		time.AfterFunc(dhcpRetour+5*time.Second, func() {
			g.mu.Lock()
			defer g.mu.Unlock()
			if g.dhcpOld == old {
				g.dhcpOld = nil
				if !g.on {
					removeGatewayRules()
				}
			}
		})
	}
	if !g.boxMode && freebox.LoadSaved(g.dir) == nil {
		return
	}
	g.boxMode = false
	g.fbx = nil
	g.blockProfile, g.blocked = 0, nil
	if err := freebox.Restore(g.dir); err != nil {
		g.boxErr = "box non restaurée : " + err.Error()
		logEvent(g.dir, "Freebox : restauration impossible ("+err.Error()+") — nouvel essai au prochain démarrage, ou bouton « Restaurer la box »")
		return
	}
	logEvent(g.dir, "Freebox : IPv6 et DHCP de la box rétablis (les appareils y reviennent en moins de 2 minutes)")
}

// onLease : un appareil vient de recevoir (ou renouveler) son adresse.
func (g *gateway) onLease(mac, ip, host string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.devs == nil {
		return
	}
	d := g.devLocked(ip)
	d.MAC = mac
	d.Last = time.Now()
	d.viaDHCP = true
	if n := g.customNameLocked(d); n != "" {
		d.Name, d.NameSrc = n, "perso"
	} else if host != "" && (d.NameSrc == "" || d.NameSrc == "netbios" || d.NameSrc == "mdns" || d.NameSrc == "box") {
		d.Name, d.NameSrc = host, "dhcp"
	}
}

// boxHosts complète les noms avec ceux connus de la Freebox et retient
// les appareils qui passent encore directement par la box.
func (g *gateway) boxHosts() {
	g.mu.Lock()
	c := g.fbx
	g.mu.Unlock()
	if c == nil {
		return
	}
	hosts, err := c.Hosts()
	if err != nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.devs == nil {
		return
	}
	leased := map[string]bool{}
	if g.dhcp != nil {
		for _, l := range g.dhcp.Leases() {
			leased[l.MAC] = true
		}
	}
	var waiting []waitingHost
	for _, h := range hosts {
		var d *device
		for _, x := range g.devs {
			if (h.MAC != "" && x.MAC == h.MAC) || (x.MAC == "" && containsStr(h.IPs, x.IP)) {
				d = x
				break
			}
		}
		if d != nil && h.Name != "" && d.NameSrc != "perso" {
			d.Name, d.NameSrc = h.Name, "freebox"
		}
		if !h.Active || leased[h.MAC] || d != nil {
			continue
		}
		ip := ""
		for _, x := range h.IPs {
			if g.isDeviceLocked(x) {
				ip = x
			}
		}
		if ip != "" {
			waiting = append(waiting, waitingHost{Name: h.Name, MAC: h.MAC, IP: ip})
		}
	}
	g.waiting = waiting
}

type waitingHost struct{ Name, MAC, IP string }

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// renewPCLease renouvelle le bail DHCP du PC (ipconfig /renew).
func renewPCLease(alias string) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	_ = netcfg.HiddenCmd(ctx, "ipconfig", "/renew", alias).Run()
}

// pcLeaseCheck : si le PC tient encore son adresse d'un bail de la box
// qui expire bientôt, rouvre brièvement le DHCP de la box le temps du
// renouvellement (le DHCP de ce PC sert sinon le PC lui-même).
func (g *gateway) pcLeaseCheck() {
	g.mu.Lock()
	if !g.boxMode || g.fbx == nil || len(g.lan) == 0 {
		g.mu.Unlock()
		return
	}
	c, a := g.fbx, g.lan[0]
	g.mu.Unlock()
	ps := fmt.Sprintf(`Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" | `+
		`Where-Object { $_.IPAddress -contains '%s' } | Select-Object -First 1 | `+
		`ForEach-Object { "$($_.DHCPEnabled)|$($_.DHCPServer)|$([int]($_.DHCPLeaseExpires - (Get-Date)).TotalSeconds)" }`, a.IP)
	out, err := netcfg.HiddenCmd(context.Background(), "powershell", "-NoProfile", "-NonInteractive", "-Command", ps).Output()
	if err != nil {
		return
	}
	f := strings.Split(strings.TrimSpace(string(out)), "|")
	if len(f) != 3 || !strings.EqualFold(f[0], "True") || f[1] == a.IP {
		return // IP fixe, ou bail déjà servi par ce PC
	}
	var left int
	if _, err := fmt.Sscan(f[2], &left); err != nil || left > 1800 {
		return
	}
	logEvent(g.dir, "Freebox : bail du PC bientôt expiré, renouvellement auprès de la box")
	if err := c.SetDHCPEnabled(true); err != nil {
		return
	}
	time.Sleep(2 * time.Second)
	renewPCLease(a.Alias)
	_ = c.SetDHCPEnabled(false)
}

// restoreBoxAtStartup : après un plantage ou un redémarrage, la box est
// remise comme avant (la protection maison repart toujours désactivée).
func restoreBoxAtStartup(dir string, busy func() bool) {
	if freebox.LoadSaved(dir) == nil {
		return
	}
	for i := 0; i < 8; i++ {
		if busy() || freebox.LoadSaved(dir) == nil {
			return // protection maison relancée entre-temps : elle s'en charge
		}
		if err := freebox.Restore(dir); err == nil {
			logEvent(dir, "Freebox : réglages d'origine restaurés au démarrage")
			return
		} else if i == 7 {
			logEvent(dir, "Freebox : restauration au démarrage impossible : "+err.Error())
		}
		time.Sleep(15 * time.Second)
	}
}

// lanOnWifi : la carte qui relie ce PC à la box est-elle sans fil ?
func (g *gateway) lanOnWifi() bool {
	g.mu.Lock()
	var aliases []string
	for _, a := range g.lan {
		aliases = append(aliases, a.Alias)
	}
	g.mu.Unlock()
	for _, a := range aliases {
		out, err := netcfg.HiddenCmd(context.Background(), "powershell", "-NoProfile", "-NonInteractive", "-Command",
			fmt.Sprintf("(Get-NetAdapter -Name '%s' -ErrorAction SilentlyContinue).PhysicalMediaType", strings.ReplaceAll(a, "'", "''"))).Output()
		if err == nil && strings.Contains(strings.ToLower(string(out)), "802.11") {
			return true
		}
	}
	return false
}
