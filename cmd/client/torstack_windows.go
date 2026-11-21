// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 vico-hardware (Vico Studio) — https://github.com/vico-hardware/VicoVPN

//go:build windows

package main

// torstack gere le mode « Tor » : tor.exe ( SOCKS5 + DNSPort ) associe a
// tun2socks qui capture tout le trafic IP de la machine dans un adaptateur
// TUN et l'injecte dans Tor. Le tout est pilote comme un relais de sortie
// ordinaire : SELECT tor-<pays> + ENABLE.
//
// Limites : Tor ne transporte que TCP/IPv4 — l'UDP et IPv6 sont coupes
// pendant le mode Tor (pile IPv6 des cartes physiques desactivee pour
// eviter toute fuite). Le DNS est resolu a travers Tor (DNSPort).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/vicovpn/vicovpn/internal/netcfg"
)

// torPays associe le code ISO du pays de sortie Tor au nom affiche.
// Liste = pays avec sorties Tor actives (onionoo.torproject.org, flag=exit).
var torPays = map[string]string{
	"ae": "Émirats arabes unis", "at": "Autriche", "au": "Australie",
	"be": "Belgique", "bg": "Bulgarie", "ca": "Canada",
	"ch": "Suisse", "cl": "Chili", "cr": "Costa Rica", "cy": "Chypre",
	"cz": "Tchéquie", "de": "Allemagne", "dk": "Danemark", "ee": "Estonie",
	"es": "Espagne", "fi": "Finlande", "fr": "France", "gb": "Royaume-Uni",
	"hk": "Hong Kong", "hr": "Croatie", "hu": "Hongrie", "id": "Indonésie",
	"il": "Israël", "is": "Islande", "it": "Italie", "jp": "Japon",
	"kr": "Corée du Sud", "kz": "Kazakhstan", "lt": "Lituanie",
	"lu": "Luxembourg", "md": "Moldavie", "mx": "Mexique",
	"my": "Malaisie", "nl": "Pays-Bas", "no": "Norvège",
	"nz": "Nouvelle-Zélande", "pe": "Pérou", "pl": "Pologne",
	"ro": "Roumanie", "rs": "Serbie", "sc": "Seychelles", "se": "Suède",
	"sg": "Singapour", "tr": "Turquie", "tw": "Taïwan", "ua": "Ukraine",
	"us": "États-Unis", "vn": "Viêt Nam", "za": "Afrique du Sud",
}

// torStack pilote les processus tor + tun2socks.
type torStack struct {
	mu       sync.Mutex
	dir      string // dossier de config client
	exeDir   string
	country  string
	torCmd   *exec.Cmd
	t2sCmd   *exec.Cmd
	state    string // desactive|connexion|protege|bloque
	info     string
	dnsDone  []string // alias d'adaptateurs dont le DNS a ete force
	v6Off    []string // alias dont la pile IPv6 a ete coupee (fuite)
	ksOn     bool     // coupe-circuit pare-feu actif
	ksGuards []string
	ksSet    map[string]bool // union des IPs gardes vues
	torDead  bool            // tor.exe s'est arrêté
	t2sDead  bool            // tun2socks.exe s'est arrêté
	onDown   func()          // appelé (hors verrou) quand un processus meurt
	gen      int             // génération de démarrage (annule les attentes périmées)
	apiAddr  string          // API REST locale de tun2socks (statistiques)
	apiToken string
}

// API retourne l'adresse et le jeton de l'API statistiques de tun2socks
// ("" si le tunnel ne tourne pas).
func (t *torStack) API() (addr, token string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.t2sCmd == nil || t.t2sDead {
		return "", ""
	}
	return t.apiAddr, t.apiToken
}

func newTorStack(dir string) *torStack {
	exe, _ := os.Executable()
	return &torStack{dir: dir, exeDir: filepath.Dir(exe), state: "desactive"}
}

// torDir retourne le dossier contenant tor.exe / tun2socks.exe / data/.
func (t *torStack) torDir() string {
	for _, c := range []string{
		filepath.Join(t.exeDir, "tor"),
		filepath.Join(t.dir, "tor"),
	} {
		if _, err := os.Stat(filepath.Join(c, "tor.exe")); err == nil {
			return c
		}
	}
	return ""
}

// isTorExit indique si un nom de sortie correspond au mode Tor.
func isTorExit(name string) bool {
	return strings.HasPrefix(strings.ToLower(name), "tor-")
}

func torExitCode(name string) string {
	return strings.ToLower(strings.TrimPrefix(name, "tor-"))
}

// Healthy indique si le tunnel est réellement utilisable : état
// « protégé » et les deux processus (tor, tun2socks) vivants.
func (t *torStack) Healthy() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.state == "protege" && t.torCmd != nil && t.t2sCmd != nil && !t.torDead && !t.t2sDead
}

// watchProc attend la fin d'un processus enfant. S'il meurt alors qu'il
// est toujours le processus courant (arrêt non demandé), le tunnel passe
// « bloqué » : le coupe-circuit pare-feu reste en place pour le PC et la
// passerelle maison coupe son routage (onDown).
func (t *torStack) watchProc(cmd *exec.Cmd, name string) {
	_ = cmd.Wait()
	t.mu.Lock()
	current := false
	switch {
	case cmd == t.torCmd:
		t.torDead, current = true, true
	case cmd == t.t2sCmd:
		t.t2sDead, current = true, true
	}
	if current && (t.state == "protege" || t.state == "connexion") {
		t.state = "bloque"
		t.info = name + " s'est arrêté — clique Réessayer"
		logEvent(t.dir, "Tor : "+name+" arrêté de façon inattendue")
	}
	cb := t.onDown
	t.mu.Unlock()
	if cb != nil {
		cb()
	}
}

// Start active le tunnel Tor pour le pays donne (code ISO). Si le tunnel
// tourne déjà vers un autre pays, il est relancé vers le nouveau.
func (t *torStack) Start(cc string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if (t.state == "connexion" || t.state == "protege") && t.country == cc {
		return nil
	}
	td := t.torDir()
	if td == "" {
		return fmt.Errorf("binaires Tor introuvables (attendu: <exe>\\tor\\)")
	}
	if _, ok := torPays[cc]; !ok {
		return fmt.Errorf("pays Tor inconnu: %q", cc)
	}
	t.stopLocked()
	t.country = cc
	t.state = "connexion"
	t.info = "amorçage de Tor…"
	logEvent(t.dir, "Tor "+torPays[cc]+" : amorçage")

	// torrc dedie : SOCKS5 + DNS resolu via Tor + sortie imposee.
	runDir := filepath.Join(td, "run")
	_ = os.MkdirAll(runDir, 0o700)
	rc := filepath.Join(td, "client-torrc")
	// Les connexions de tor.exe vers ses relais doivent sortir par la carte
	// physique : sans cette adresse source, les routes /1 du tunnel les
	// renverraient dans le tunnel lui-même (Tor dans Tor, refusé par Tor :
	// plus aucune connexion ne passe).
	bind := ""
	if ip := physicalIPv4(defaultInterface()); ip != "" {
		bind = "OutboundBindAddress " + ip + "\n"
	}
	content := fmt.Sprintf(`SocksPort 127.0.0.1:9050
DNSPort 127.0.0.1:53
DataDirectory %s
GeoIPFile %s
GeoIPv6File %s
Log notice file %s
ExitNodes {%s}
StrictNodes 1
AvoidDiskWrites 1
%s`, runDir, filepath.Join(td, "data", "geoip"), filepath.Join(td, "data", "geoip6"), filepath.Join(td, "tor.log"), cc, bind)
	if err := os.WriteFile(rc, []byte(content), 0o600); err != nil {
		t.state = "bloque"
		return err
	}

	// Tor ajoute à la fin de son journal : seule la partie écrite après ce
	// point compte, sinon un « Bootstrapped 100% » d'une session
	// précédente ferait croire que la nouvelle est prête.
	var logOff int64
	if st, err := os.Stat(filepath.Join(td, "tor.log")); err == nil {
		logOff = st.Size()
	}

	t.torDead, t.t2sDead = false, false
	t.torCmd = netcfg.HiddenCmd(context.Background(), filepath.Join(td, "tor.exe"), "-f", rc)
	t.torCmd.Dir = td
	if err := t.torCmd.Start(); err != nil {
		t.torCmd = nil
		t.state = "bloque"
		return fmt.Errorf("tor: %w", err)
	}
	go t.watchProc(t.torCmd, "tor")

	// Attendre que Tor ait bootstrapé (consensus + circuits) avant
	// d'ouvrir le TUN : sinon tout le trafic serait perdu.
	t.gen++
	go t.waitBootstrap(filepath.Join(td, "tor.log"), logOff, t.gen)
	return nil
}

// waitBootstrap surveille le journal Tor puis lance tun2socks.
func (t *torStack) waitBootstrap(logPath string, logOff int64, gen int) {
	start := time.Now()
	deadline := start.Add(180 * time.Second)
	ready := false
	resets := 0
	for time.Now().Before(deadline) {
		// Tor bloqué à « 95 % Establishing a Tor circuit » : son fichier
		// d'état (gardes mémorisées) est en cause. Relance avec l'état
		// effacé à 35 s, puis avec tout le cache effacé à 85 s.
		if (resets == 0 && time.Since(start) > 35*time.Second) ||
			(resets == 1 && time.Since(start) > 85*time.Second) {
			resets++
			off, err := t.restartFresh(gen, resets > 1)
			if err != nil {
				break
			}
			logOff = off
		}
		if b, err := os.ReadFile(logPath); err == nil {
			if int64(len(b)) < logOff { // journal tronqué/recréé
				logOff = 0
			}
			if strings.Contains(string(b[logOff:]), "Bootstrapped 100%") {
				ready = true
				break
			}
			// Progression affichée dans l'interface (« amorçage de Tor… 75 % »).
			if i := strings.LastIndex(string(b[logOff:]), "Bootstrapped "); i >= 0 {
				rest := string(b[logOff:])[i+len("Bootstrapped "):]
				if j := strings.IndexByte(rest, '%'); j > 0 && j <= 3 {
					t.mu.Lock()
					if t.gen == gen && t.state == "connexion" {
						t.info = "amorçage de Tor… " + rest[:j] + " %"
					}
					t.mu.Unlock()
				}
			}
		}
		// tor mort ou arrêt demandé ?
		t.mu.Lock()
		dead := t.torCmd == nil || t.torDead || t.state != "connexion" || t.gen != gen
		t.mu.Unlock()
		if dead {
			break
		}
		time.Sleep(2 * time.Second)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.state != "connexion" || t.torCmd == nil || t.gen != gen {
		return
	}
	if !ready {
		t.state = "bloque"
		t.info = "Tor n'a pas pu se connecter (réseau bloqué ?)"
		logEvent(t.dir, "Tor "+torPays[t.country]+" : échec de l'amorçage")
		return
	}
	if err := t.launchTun2Socks(); err != nil {
		t.state = "bloque"
		t.info = err.Error()
		logEvent(t.dir, "Tor "+torPays[t.country]+" : "+err.Error())
		return
	}
	t.info = "vérification du tunnel…"
	go t.confirmAndMonitor(gen)
}

// confirmAndMonitor n'annonce « protégé » qu'après une vraie connexion à
// travers Tor, puis la refait toutes les 60 s : si Tor ne fait plus rien
// passer, l'état devient « bloqué » (la protection maison coupe alors le
// routage des appareils) et redevient « protégé » quand il repart.
func (t *torStack) confirmAndMonitor(gen int) {
	alive := func() bool {
		t.mu.Lock()
		defer t.mu.Unlock()
		return t.gen == gen && (t.state == "connexion" || t.state == "protege" || t.state == "bloque") && t.t2sCmd != nil
	}
	ok := false
	for i := 0; i < 4 && alive(); i++ {
		if err := torSocksCheck(); err == nil {
			ok = true
			break
		}
		time.Sleep(5 * time.Second)
	}
	t.mu.Lock()
	if t.gen != gen || t.t2sCmd == nil {
		t.mu.Unlock()
		return
	}
	if ok {
		t.state = "protege"
		t.info = "sortie Tor · " + torPays[t.country]
		logEvent(t.dir, "Tor "+torPays[t.country]+" : protégé (connexion vérifiée)")
	} else {
		t.state = "bloque"
		t.info = "Tor ne fait passer aucune connexion — clique Réessayer"
		logEvent(t.dir, "Tor "+torPays[t.country]+" : aucune connexion ne passe, tunnel bloqué")
	}
	cb := t.onDown
	t.mu.Unlock()
	if cb != nil {
		cb()
	}
	fails := 0
	for {
		time.Sleep(60 * time.Second)
		if !alive() {
			return
		}
		err := torSocksCheck()
		t.mu.Lock()
		if t.gen != gen || t.t2sCmd == nil || t.torDead || t.t2sDead {
			t.mu.Unlock()
			return
		}
		changed := false
		if err == nil {
			fails = 0
			if t.state == "bloque" {
				t.state, t.info, changed = "protege", "sortie Tor · "+torPays[t.country], true
				logEvent(t.dir, "Tor "+torPays[t.country]+" : de nouveau opérationnel")
			}
		} else {
			fails++
			if fails >= 2 && t.state == "protege" {
				t.state, t.info, changed = "bloque", "Tor ne répond plus — clique Réessayer", true
				logEvent(t.dir, "Tor "+torPays[t.country]+" : ne répond plus, tunnel bloqué")
			}
		}
		cb := t.onDown
		t.mu.Unlock()
		if changed && cb != nil {
			cb()
		}
	}
}

// torSocksCheck ouvre une vraie connexion TCP à travers Tor (SOCKS5,
// nom résolu par la sortie Tor).
func torSocksCheck() error {
	c, err := net.DialTimeout("tcp", "127.0.0.1:9050", 3*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(25 * time.Second))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	r := make([]byte, 2)
	if _, err := io.ReadFull(c, r); err != nil || r[0] != 5 || r[1] != 0 {
		return fmt.Errorf("SOCKS refusé")
	}
	host := "check.torproject.org"
	req := append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
	req = append(req, 1, 187) // port 443
	if _, err := c.Write(req); err != nil {
		return err
	}
	if _, err := io.ReadFull(c, r); err != nil {
		return err
	}
	if r[1] != 0 {
		return fmt.Errorf("Tor : connexion refusée (code %d)", r[1])
	}
	return nil
}

// physicalIPv4 retourne l'adresse IPv4 de la carte donnée.
func physicalIPv4(alias string) string {
	if alias == "" {
		return ""
	}
	ifc, err := net.InterfaceByName(alias)
	if err != nil {
		return ""
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLinkLocalUnicast() {
			return n.IP.String()
		}
	}
	return ""
}

// restartFresh relance tor.exe après avoir effacé son fichier d'état
// (full : tout le cache du dossier run, sauf les clés). Retourne la
// position du journal à partir de laquelle chercher « Bootstrapped 100% ».
func (t *torStack) restartFresh(gen int, full bool) (int64, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.gen != gen || t.state != "connexion" {
		return 0, fmt.Errorf("arrêt demandé")
	}
	td := t.torDir()
	if td == "" {
		return 0, fmt.Errorf("binaires Tor introuvables")
	}
	if t.torCmd != nil && t.torCmd.Process != nil {
		_ = t.torCmd.Process.Kill()
	}
	t.torCmd = nil // le surveillant de l'ancien processus ne change rien
	time.Sleep(1500 * time.Millisecond)
	runDir := filepath.Join(td, "run")
	if full {
		if ents, err := os.ReadDir(runDir); err == nil {
			for _, e := range ents {
				if e.Name() != "keys" {
					_ = os.RemoveAll(filepath.Join(runDir, e.Name()))
				}
			}
		}
		logEvent(t.dir, "Tor "+torPays[t.country]+" : toujours bloqué, nouvel essai avec un cache vide")
	} else {
		_ = os.Remove(filepath.Join(runDir, "state"))
		logEvent(t.dir, "Tor "+torPays[t.country]+" : amorçage bloqué, nouvel essai sans l'état mémorisé")
	}
	var off int64
	if st, err := os.Stat(filepath.Join(td, "tor.log")); err == nil {
		off = st.Size()
	}
	t.torDead = false
	cmd := netcfg.HiddenCmd(context.Background(), filepath.Join(td, "tor.exe"), "-f", filepath.Join(td, "client-torrc"))
	cmd.Dir = td
	if err := cmd.Start(); err != nil {
		t.state = "bloque"
		t.info = "Tor ne redémarre pas : " + err.Error()
		return 0, err
	}
	t.torCmd = cmd
	go t.watchProc(cmd, "tor")
	return off, nil
}

// launchTun2Socks demarre le pont TUN et verrouille le DNS sur Tor.
func (t *torStack) launchTun2Socks() error {
	td := t.torDir()
	iface := defaultInterface()
	if iface == "" {
		return fmt.Errorf("interface physique introuvable")
	}
	args := []string{
		"--device", "tun://vicotor0",
		"--proxy", "socks5://127.0.0.1:9050",
		"--interface", iface,
		"--mtu", "1500",
		"--loglevel", "warn",
	}
	// API statistiques (boucle locale + jeton) : volume par appareil
	// dans l'onglet Maison. Facultative : sans port libre, on s'en passe.
	t.apiAddr, t.apiToken = "", ""
	if addr, err := freeLocalPort(); err == nil {
		t.apiAddr, t.apiToken = addr, randomToken()
		args = append(args, "--restapi", "http://"+t.apiToken+"@"+t.apiAddr)
	}
	cmd := netcfg.HiddenCmd(context.Background(), filepath.Join(td, "tun2socks.exe"), args...)
	cmd.Dir = td
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("tun2socks: %w", err)
	}
	t.t2sCmd = cmd
	go t.watchProc(cmd, "tun2socks")

	// tun2socks ne pose pas les routes fourre-tout sous Windows :
	// on les ajoute nous-memes (/1 + /1 couvrent tout l'IPv4 sans
	// toucher a la route par defaut, donc retour propre a la mort).
	// Attendre que l'adaptateur existe (au plus 15 s) plutôt qu'un délai fixe.
	time.Sleep(2 * time.Second)
	for i := 0; i < 26; i++ {
		if _, err := net.InterfaceByName("vicotor0"); err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	addTorRoutes()
	// Routes vérifiées : sans elles, le trafic (et celui des appareils
	// de la passerelle maison) partirait en direct par la box.
	if err := verifyTorRoutes(); err != nil {
		if t.t2sCmd != nil && t.t2sCmd.Process != nil {
			_ = t.t2sCmd.Process.Kill()
		}
		t.t2sCmd = nil
		delTorRoutes()
		return err
	}
	// Filet de sécurité : si tun2socks meurt, vicotor0 disparaît avec ses
	// routes ; sans ce filet, le trafic (et celui des appareils de la
	// maison) repartirait aussitôt en clair par la box, le temps que la
	// surveillance réagisse. Les routes « mortes » prennent le relais.
	addDeadRoutes()

	// Forcer tout le DNS vers Tor (DNSPort 127.0.0.1:53).
	t.dnsDone = setAllDNS("127.0.0.1")

	// Tor ne transporte que de l'IPv4 : sans cette coupure, le trafic
	// IPv6 sortirait en direct par la box et fuiterait la vraie adresse.
	t.v6Off = setIPv6(false)
	saveIPv6Off(t.dir, t.v6Off)

	// Coupe-circuit : tout est bloqué sur les cartes physiques sauf les
	// gardes Tor (decouvertes via ControlPort) et le local.
	go t.installKillSwitch()
	return nil
}

// installKillSwitch decouvre les IPs des gardes Tor (les seules cibles
// des connexions sortantes de tor.exe), installe les règles pare-feu,
// puis les rafraîchit périodiquement.
func (t *torStack) installKillSwitch() {
	t.mu.Lock()
	pid := 0
	if t.torCmd != nil && t.torCmd.Process != nil {
		pid = t.torCmd.Process.Pid
	}
	t.mu.Unlock()
	if pid == 0 {
		return
	}

	// Ensemble cumulatif : les connexions aux gardes peuvent changer,
	// on garde l'union (toutes sont des relais Tor publics de toute
	// façon — les autoriser ne ouvre pas de fuite).
	t.mu.Lock()
	if t.ksSet == nil {
		t.ksSet = map[string]bool{}
	}
	t.mu.Unlock()

	refresh := func() ([]string, error) {
		ips, err := torGuardIPs(pid)
		if err != nil {
			return nil, err
		}
		t.mu.Lock()
		for _, ip := range ips {
			t.ksSet[ip] = true
		}
		guards := make([]string, 0, len(t.ksSet))
		for ip := range t.ksSet {
			guards = append(guards, ip)
		}
		t.mu.Unlock()
		return guards, nil
	}

	// Quelques tentatives : les connexions gardes peuvent mettre
	// quelques secondes a apparaitre apres le bootstrap.
	var guards []string
	var err error
	for i := 0; i < 6; i++ {
		guards, err = refresh()
		if err == nil && len(guards) > 0 {
			break
		}
		time.Sleep(5 * time.Second)
		t.mu.Lock()
		dead := t.state == "desactive" || t.torCmd == nil
		t.mu.Unlock()
		if dead {
			return
		}
	}
	t.mu.Lock()
	if err != nil || len(guards) == 0 || t.state == "desactive" || t.torCmd == nil {
		t.mu.Unlock()
		if err != nil {
			logEvent(t.dir, "Tor : coupe-circuit impossible, gardes introuvables ("+err.Error()+")")
		}
		return
	}
	if err := netcfg.TorProtect(context.Background(), guards); err != nil {
		t.mu.Unlock()
		logEvent(t.dir, "Tor : coupe-circuit impossible ("+err.Error()+")")
		return
	}
	t.ksOn = true
	t.ksGuards = guards
	t.mu.Unlock()
	logEvent(t.dir, fmt.Sprintf("Tor : coupe-circuit actif (%d gardes)", len(guards)))

	for {
		time.Sleep(60 * time.Second)
		t.mu.Lock()
		alive := t.ksOn && t.state != "desactive" && t.torCmd != nil
		t.mu.Unlock()
		if !alive {
			return
		}
		if g, err := refresh(); err == nil && len(g) > 0 {
			_ = netcfg.TorProtect(context.Background(), g)
			t.mu.Lock()
			t.ksGuards = g
			t.mu.Unlock()
		}
	}
}

// torGuardIPs retourne les IPs distantes IPv4 des connexions établies du
// processus tor : ce sont ses gardes (Tor ne sort que par eux).
func torGuardIPs(pid int) ([]string, error) {
	// Established + SynSent : un garde fraîchement choisi apparaît en
	// SynSent AVANT d'être Established — sans ça il serait bloqué le
	// temps qu'on le découvre.
	ps := fmt.Sprintf(`Get-NetTCPConnection -OwningProcess %d -ErrorAction SilentlyContinue | `+
		`Where-Object { $_.State -in @('Established','SynSent') -and $_.RemoteAddress -notmatch '^(127\\.|::1|0\\.0\\.0\\.0)' } | `+
		`Select-Object -ExpandProperty RemoteAddress -Unique`, pid)
	out, err := netcfg.HiddenCmd(context.Background(), "powershell", "-NoProfile", "-Command", ps).Output()
	if err != nil {
		return nil, err
	}
	return parseNames(out), nil
}

// addTorRoutes installe les routes fourre-tout IPv4 via l'adaptateur TUN.
func addTorRoutes() {
	for _, p := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		_ = netcfg.HiddenCmd(context.Background(), "netsh", "interface", "ipv4", "add", "route",
			p, "vicotor0", "0.0.0.0").Run()
	}
}

// verifyTorRoutes confirme que les deux routes /1 passent par vicotor0.
func verifyTorRoutes() error {
	out, err := netcfg.HiddenCmd(context.Background(), "powershell", "-NoProfile", "-NonInteractive", "-Command",
		`@(Get-NetRoute -InterfaceAlias 'vicotor0' -AddressFamily IPv4 -ErrorAction SilentlyContinue | `+
			`Where-Object { $_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1') }).Count`).Output()
	if err != nil {
		return fmt.Errorf("routes tunnel non vérifiables: %v", err)
	}
	if strings.TrimSpace(string(out)) != "2" {
		return fmt.Errorf("routes du tunnel absentes (vicotor0 : %s/2)", strings.TrimSpace(string(out)))
	}
	return nil
}

// Routes « mortes » : 0.0.0.0/1 et 128.0.0.0/1 vers l'interface de
// bouclage, métrique très haute. Tant que vicotor0 existe, ses routes
// gagnent (métrique plus basse) ; s'il disparaît (plantage de tun2socks),
// ce sont elles qui gagnent sur la route par défaut de la box (préfixe
// plus long) et le trafic est jeté au lieu de sortir en clair.
// tor.exe et tun2socks, liés à l'adresse de la carte physique, ne sont pas
// concernés (Windows ne retient alors que les routes de cette carte).
const deadRoutesPS = `$lo = (Get-NetIPInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue | ` +
	`Where-Object { $_.InterfaceAlias -like 'Loopback*' } | Select-Object -First 1).ifIndex; `

func addDeadRoutes() {
	_ = netcfg.HiddenCmd(context.Background(), "powershell", "-NoProfile", "-NonInteractive", "-Command",
		deadRoutesPS+`if ($lo) { foreach ($p in '0.0.0.0/1','128.0.0.0/1') { `+
			`New-NetRoute -DestinationPrefix $p -InterfaceIndex $lo -NextHop 0.0.0.0 -RouteMetric 9000 `+
			`-PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null } }`).Run()
}

// delDeadRoutes retire les routes « mortes » (arrêt, démarrage du service).
func delDeadRoutes() {
	_ = netcfg.HiddenCmd(context.Background(), "powershell", "-NoProfile", "-NonInteractive", "-Command",
		deadRoutesPS+`if ($lo) { Get-NetRoute -InterfaceIndex $lo -AddressFamily IPv4 -ErrorAction SilentlyContinue | `+
			`Where-Object { $_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1') } | `+
			`Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue }`).Run()
}

// delTorRoutes retire les routes posees par addTorRoutes.
func delTorRoutes() {
	for _, p := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		_ = netcfg.HiddenCmd(context.Background(), "netsh", "interface", "ipv4", "delete", "route",
			p, "vicotor0").Run()
	}
}

// Stop coupe tun2socks puis tor et restaure le DNS.
func (t *torStack) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stopLocked()
}

// stopLocked : idem Stop mais sans verrouillage (appelé sous t.mu).
func (t *torStack) stopLocked() {
	if t.t2sCmd != nil && t.t2sCmd.Process != nil {
		_ = t.t2sCmd.Process.Kill()
		t.t2sCmd = nil
	}
	t.apiAddr, t.apiToken = "", ""
	if len(t.dnsDone) > 0 {
		resetDNS(t.dnsDone)
		t.dnsDone = nil
	}
	delTorRoutes()
	delDeadRoutes()
	// Le coupe-circuit doit tomber AVANT de rallumer l'IPv6 : sinon la
	// règle TorBlock-V6 bloque la sollicitation de routeur envoyée par
	// Windows au réveil de l'IPv6, la box ne répond pas et la carte reste
	// sans adresse IPv6 publique (jusqu'à la prochaine annonce spontanée
	// de la box, parfois de longues minutes).
	// Toujours (même si ksOn est faux) : des règles d'une session
	// interrompue ne doivent jamais survivre à l'arrêt.
	_ = netcfg.TorUnprotect(context.Background())
	t.ksOn = false
	t.ksGuards = nil
	t.ksSet = nil
	if t.torCmd != nil && t.torCmd.Process != nil {
		_ = t.torCmd.Process.Kill()
		t.torCmd = nil
	}
	if len(t.v6Off) > 0 {
		setIPv6Named(t.v6Off, true)
		t.v6Off = nil
	}
	// Fichier persisté : couvre le cas où v6Off est vide (reboot ou crash
	// pendant que le mode Tor était actif — la liste mémoire est perdue).
	restoreIPv6Off(t.dir)
	if t.state != "desactive" {
		logEvent(t.dir, "Tor : arrêté")
		t.state = "desactive"
		t.info = ""
	}
}

func (t *torStack) Status() (state, info string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.state, t.info
}

// defaultInterface retourne l'alias de l'interface portant la route par
// defaut (doit etre appele AVANT le demarrage de tun2socks).
func defaultInterface() string {
	out, err := netcfg.HiddenCmd(context.Background(), "powershell", "-NoProfile", "-Command",
		"(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object InterfaceMetric,RouteMetric | Select-Object -First 1).InterfaceAlias").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// setAllDNS force le serveur DNS de tous les adaptateurs actfs vers addr
// et retourne la liste des alias modifies.
func setAllDNS(addr string) []string {
	ps := fmt.Sprintf(`Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object { `+
		`Set-DnsClientServerAddress -InterfaceAlias $_.Name -ServerAddresses '%s' -ErrorAction SilentlyContinue; $_.Name }`, addr)
	out, err := netcfg.HiddenCmd(context.Background(), "powershell", "-NoProfile", "-Command", ps).Output()
	if err != nil {
		return nil
	}
	return parseNames(out)
}

// setIPv6 active/desactive la pile IPv6 (ms_tcpip6) des cartes physiques
// actives. Retourne les alias effectivement modifies.
func setIPv6(enable bool) []string {
	verb := "Disable"
	if enable {
		verb = "Enable"
	}
	// Toutes les cartes physiques, meme deconnectees : si le Wi-Fi est
	// active pendant le mode Tor, son IPv6 ne doit pas pouvoir fuiter.
	ps := fmt.Sprintf(`Get-NetAdapter -Physical | ForEach-Object { `+
		`if ((Get-NetAdapterBinding -Name $_.Name -ComponentID ms_tcpip6).Enabled -ne $%s) { `+
		`%s-NetAdapterBinding -Name $_.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue; $_.Name } }`,
		map[bool]string{true: "true", false: "false"}[enable], verb)
	out, err := netcfg.HiddenCmd(context.Background(), "powershell", "-NoProfile", "-Command", ps).Output()
	if err != nil {
		return nil
	}
	return parseNames(out)
}

// setIPv6Named ré-applique l'état IPv6 sur une liste d'alias donnés.
func setIPv6Named(aliases []string, enable bool) {
	verb := "Disable-NetAdapterBinding"
	if enable {
		verb = "Enable-NetAdapterBinding"
	}
	for _, a := range aliases {
		_ = netcfg.HiddenCmd(context.Background(), "powershell", "-NoProfile", "-Command",
			fmt.Sprintf("%s -Name '%s' -ComponentID ms_tcpip6", verb, a)).Run()
	}
}

// parseNames transforme une sortie PowerShell (un nom par ligne) en slice.
func parseNames(out []byte) []string {
	var names []string
	for _, l := range strings.Split(string(out), "\n") {
		if s := strings.TrimSpace(l); s != "" {
			names = append(names, s)
		}
	}
	return names
}

// resetDNS repasse les adaptateurs listes en DNS automatique (DHCP).
func resetDNS(aliases []string) {
	for _, a := range aliases {
		_ = netcfg.HiddenCmd(context.Background(), "powershell", "-NoProfile", "-Command",
			fmt.Sprintf("Set-DnsClientServerAddress -InterfaceAlias '%s' -ResetServerAddresses", a)).Run()
	}
}

// ipv6OffPath : fichier d'état listant les cartes physiques dont le mode
// Tor a coupé la pile IPv6. Persisté pour survivre à un reboot du PC ou
// du service — sans lui, la restauration après redémarrage était
// impossible (la liste t.v6Off est volatile).
func ipv6OffPath(dir string) string { return filepath.Join(dir, "ipv6_off.json") }

func saveIPv6Off(dir string, aliases []string) {
	if len(aliases) == 0 {
		return
	}
	// Fusion avec un fichier déjà présent : des cartes restées coupées
	// d'une session précédente (reboot, crash) ne doivent pas être oubliées
	// — setIPv6(false) ne renvoie que les cartes qu'il vient de couper.
	seen := map[string]bool{}
	var all []string
	if old, err := os.ReadFile(ipv6OffPath(dir)); err == nil {
		var prev []string
		if json.Unmarshal(old, &prev) == nil {
			for _, a := range prev {
				if a != "" && !seen[a] {
					seen[a] = true
					all = append(all, a)
				}
			}
		}
	}
	for _, a := range aliases {
		if a != "" && !seen[a] {
			seen[a] = true
			all = append(all, a)
		}
	}
	b, err := json.Marshal(all)
	if err != nil {
		return
	}
	_ = os.WriteFile(ipv6OffPath(dir), b, 0o644)
}

// restoreIPv6Off réactive l'IPv6 des cartes enregistrées puis supprime
// le fichier. Sans effet si le fichier est absent ou vide.
func restoreIPv6Off(dir string) {
	b, err := os.ReadFile(ipv6OffPath(dir))
	if err != nil {
		return
	}
	var aliases []string
	if json.Unmarshal(b, &aliases) != nil || len(aliases) == 0 {
		_ = os.Remove(ipv6OffPath(dir))
		return
	}
	setIPv6Named(aliases, true)
	// Vérification : une carte encore coupée (commande refusée, carte
	// absente…) reste dans le fichier pour une prochaine tentative.
	var left []string
	for _, a := range aliases {
		out, err := netcfg.HiddenCmd(context.Background(), "powershell", "-NoProfile", "-Command",
			fmt.Sprintf("(Get-NetAdapterBinding -Name '%s' -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue).Enabled", a)).Output()
		if err == nil && strings.EqualFold(strings.TrimSpace(string(out)), "False") {
			left = append(left, a)
		}
	}
	if len(left) > 0 {
		if b, err := json.Marshal(left); err == nil {
			_ = os.WriteFile(ipv6OffPath(dir), b, 0o644)
		}
		logEvent(dir, "IPv6 : réactivation impossible sur "+strings.Join(left, ", "))
	} else {
		_ = os.Remove(ipv6OffPath(dir))
	}
	var done []string
	for _, a := range aliases {
		ok := true
		for _, l := range left {
			if l == a {
				ok = false
			}
		}
		if ok {
			done = append(done, a)
		}
	}
	if len(done) > 0 {
		logEvent(dir, "IPv6 réactivé sur "+strings.Join(done, ", "))
	}
}
