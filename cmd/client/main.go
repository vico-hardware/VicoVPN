// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 vico-hardware (Vico Studio) — https://github.com/vico-hardware/VicoVPN

//go:build windows

// vicovpn-client : moteur VPN côté utilisateur.
//
// Modes :
//   - console (défaut) : ctl + option -enable
//   - service Windows : -service install|uninstall|run (voir service_windows.go)
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vicovpn/vicovpn/internal/config"
	"github.com/vicovpn/vicovpn/internal/ctl"
	"github.com/vicovpn/vicovpn/internal/engine"
	"github.com/vicovpn/vicovpn/internal/netcfg"
)

// runtime regroupe les objets vivants du client.
type runtime struct {
	mu        sync.Mutex
	dir       string
	cli       *engine.Client
	srv       *ctl.Server
	tor       *torStack
	torSel    string   // sélection Tor active ("tor-nl"…) ou ""
	enabled   bool     // protection demandée (peu importe le mode)
	gw        *gateway // mode « Protection Maison »
	gwOwnsTun bool     // le tunnel a été démarré par la passerelle
	lastState string   // dernier état journalisé
}

// logEvent ajoute une ligne horodatée au journal events.log du dossier
// de configuration. Rotation naïve au-delà de 256 Kio.
func logEvent(dir, msg string) {
	p := filepath.Join(dir, "events.log")
	if st, err := os.Stat(p); err == nil && st.Size() > 256*1024 {
		if b, err := os.ReadFile(p); err == nil && len(b) > 128*1024 {
			_ = os.WriteFile(p, b[len(b)-128*1024:], 0o600)
		}
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s\n", time.Now().Format("2006-01-02 15:04:05"), msg)
}

// logTail retourne les n dernières lignes du journal.
func logTail(dir string, n int) string {
	b, err := os.ReadFile(filepath.Join(dir, "events.log"))
	if err != nil {
		return "(journal vide)"
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func main() {
	var (
		cfgDir   = flag.String("config", "", "dossier de configuration (défaut: %ProgramData%\\VicoVPN)")
		noGuard  = flag.Bool("no-firewall", false, "désactive le coupe-circuit (laboratoire)")
		ctlPort  = flag.Int("ctl-port", 0, "port du canal de commande (0 = auto)")
		enable   = flag.Bool("enable", false, "active la protection puis reste en avant-plan")
		genIdent = flag.Bool("gen-identity", false, "génère une identité et quitte")
		service  = flag.String("service", "", "service Windows : install|uninstall|console|svc")
	)
	flag.Parse()

	if *service != "" {
		serviceMain(*service, *cfgDir, *noGuard, *ctlPort)
		return
	}

	dir, err := config.DataDir()
	if *cfgDir != "" {
		dir = *cfgDir
	}
	if err != nil {
		fatal(err)
	}

	if *genIdent {
		if _, err := config.LoadOrCreateIdentity(dir); err != nil {
			fatal(err)
		}
		fmt.Println("identité générée dans", dir)
		return
	}

	rt, err := startRuntime(dir, *noGuard, *ctlPort)
	if err != nil {
		fatal(err)
	}
	defer rt.stop()
	fmt.Println("ctl:", filepath.Join(dir, ctl.AddrFile))

	if *enable {
		if err := rt.enable(); err != nil {
			fatal(err)
		}
	}

	// Arrêt propre : Ctrl+C / fermeture => restituer la connexion normale.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	rt.stop()
	fmt.Println("Protection désactivée, connexion restaurée.")
}

// startRuntime construit le moteur client et le canal de commande.
func startRuntime(dir string, noGuard bool, ctlPort int) (*runtime, error) {
	var ops engine.ClientNetOps
	if !noGuard {
		ops = netcfg.NewClientNetOps(dir)
	}
	rt := &runtime{dir: dir}
	rt.cli = engine.NewClient(engine.ClientOptions{
		ConfigDir: dir,
		NetOps:    ops,
		WantIPv6:  true,
		OnState: func(s engine.State, info string) {
			fmt.Printf("[etat] %s %s\n", s, info)
			msg := "VPN classique : " + stateLabel(s.String())
			if info != "" {
				msg += " (" + info + ")"
			}
			logEvent(dir, msg)
		},
		Logf: func(format string, args ...any) {
			fmt.Printf("[log] "+format+"\n", args...)
		},
	})

	rt.tor = newTorStack(dir)
	rt.gw = newGateway(dir, rt.tor)
	// Mort de tor/tun2socks => la passerelle coupe son routage aussitôt.
	rt.tor.onDown = rt.gw.Kick
	// Hygiène de démarrage : si un crash/reboot précédent a laissé le
	// forwarding IP actif sans passerelle, on le coupe (la passerelle
	// repart toujours désactivée — l'utilisateur la relance explicitement).
	// Synchrone : sinon il pourrait effacer les règles d'une passerelle
	// activée dans la foulée.
	_ = setForwarding(false)
	removeGatewayRules()
	// Routes du mode Tor (fourre-tout et « mortes ») laissées par un crash :
	// sans tunnel, elles couperaient Internet sur ce PC.
	delTorRoutes()
	delDeadRoutes()
	go restoreBoxAtStartup(dir, rt.gw.On)
	// Si un reboot est survenu pendant le mode Tor, l'IPv6 des cartes
	// physiques est resté coupé (liste t.v6Off perdue) : le fichier
	// d'état permet de le rétablir au démarrage du service.
	go restoreIPv6Off(dir)
	// Box en mode guidé dont le DHCP est coupé : la maison garde le réseau
	// grâce au DHCP « normal » de ce PC, même protection arrêtée.
	if loadGuided(dir).DHCPOff {
		go rt.gw.StartNormalDHCP()
	}
	var handle func(cmd string, args []string) string
	handle = func(cmd string, args []string) string {
		// Commandes DNS : independantes du moteur, ne pas prendre rt.mu
		// (sinon STATUS/RELAY gèlent pendant l'application).
		switch strings.ToUpper(cmd) {
		case "DNS", "DNSSET", "DNSAUTO":
			// IPv6 : ne restaurer que VPN inactif — pendant le mode
			// Tor, ipv6_off.json existe volontairement (coupure anti-fuite).
			ts, _ := rt.tor.Status()
			return dnsCommand(dir, cmd, args, ts == "desactive")
		case "LOG":
			return "OK\n" + logTail(dir, 80)
		case "GWINFO":
			return gatewayInfo()
		case "FBXSTATUS", "FBXPAIR", "FBXRESTORE", "FBXWIFI":
			return freeboxCommand(dir, rt.gw, cmd)
		case "BOXINFO", "BOXGUIDE":
			return boxCommand(dir, rt.gw, cmd, args)
		case "GWAUTO":
			// GWAUTO : état de l'option ; GWAUTO on|off : la régler.
			if len(args) > 0 {
				on := strings.EqualFold(args[0], "on")
				saveMaisonAuto(dir, func(m *maisonAuto) { m.Option = on })
				if on {
					logEvent(dir, "option : protection maison relancée au démarrage du PC")
				} else {
					logEvent(dir, "option : protection maison non relancée au démarrage du PC")
				}
			}
			if loadMaisonAuto(dir).Option {
				return "OK 1"
			}
			return "OK 0"
		}
		rt.mu.Lock()
		defer rt.mu.Unlock()
		// Toute commande qui arrête/relance le tunnel coupe d'abord le
		// routage des appareils (passerelle maison) : aucun paquet ne doit
		// sortir en clair pendant la transition.
		switch strings.ToUpper(cmd) {
		case "ENABLE", "DISABLE", "RETRY", "SELECT", "GWENABLE", "GWDISABLE":
			rt.gw.Hold()
			defer rt.gw.Release()
		}
		switch strings.ToUpper(cmd) {
		case "STATUS":
			return rt.statusLogged(dir)
		case "ENABLE":
			logEvent(dir, "activation demandée (sortie : "+exitLabel(rt.choice())+")")
			if err := rt.enableLocked(); err != nil {
				logEvent(dir, "échec de l'activation : "+err.Error())
				return "ERR " + err.Error()
			}
			return rt.status()
		case "DISABLE":
			logEvent(dir, "désactivation demandée")
			rt.gw.Stop() // coupure complète : passerelle d'abord
			rt.gwOwnsTun = false
			rt.disableLocked()
			return rt.status()
		case "RETRY":
			logEvent(dir, "nouvelle tentative demandée")
			rt.disableLocked()
			if err := rt.enableLocked(); err != nil {
				logEvent(dir, "échec de la nouvelle tentative : "+err.Error())
				return "ERR " + err.Error()
			}
			return "OK"
		case "SELECT":
			if len(args) == 0 {
				return "ERR usage: SELECT <nom-sortie|auto>"
			}
			name := args[0]
			if strings.EqualFold(name, "auto") {
				name = ""
			}
			logEvent(dir, "sortie sélectionnée : "+exitLabel(name))
			rt.selectExitLocked(name)
			return rt.status()
		case "RELAY":
			return relayList(dir, rt.choice())
		case "GWSTATUS":
			return rt.gw.Status()
		case "GWENABLE":
			// Sortie : GWENABLE tor-de. La passerelle ne fonctionne qu'avec
			// les sorties Tor (tun2socks accepte le trafic routé des
			// appareils ; un relais classique n'a qu'une IP tunnel et pas
			// de NAT côté PC). Sans argument : sélection Tor en cours, sinon
			// Pays-Bas.
			exit := ""
			if len(args) > 0 {
				exit = strings.ToLower(args[0])
			} else if rt.torSel != "" {
				exit = rt.torSel
			} else {
				exit = "tor-nl"
			}
			if !isTorExit(exit) {
				return "ERR la protection maison fonctionne uniquement avec une sortie Tor"
			}
			if _, ok := torPays[torExitCode(exit)]; !ok {
				return "ERR pays Tor inconnu: " + exit
			}
			logEvent(dir, "protection maison demandée (sortie : "+exitLabel(exit)+")")
			// Passerelle d'abord (DNS + pare-feu, forwarding coupé) : si
			// elle échoue, le tunnel ne démarre pas.
			if err := rt.gw.Start(); err != nil {
				logEvent(dir, "protection maison : "+err.Error())
				return "ERR " + err.Error()
			}
			owned := !rt.enabled || rt.gwOwnsTun
			rt.selectExitLocked(exit)
			if !rt.enabled {
				if err := rt.enableLocked(); err != nil {
					rt.gw.Stop()
					rt.enabled = false
					logEvent(dir, "protection maison : échec du tunnel : "+err.Error())
					return "ERR tunnel: " + err.Error()
				}
			}
			rt.gwOwnsTun = owned
			return rt.gw.Status()
		case "GWDEVICES":
			return rt.gw.Devices()
		case "GWNAME":
			if len(args) < 1 || net.ParseIP(args[0]).To4() == nil {
				return "ERR usage : GWNAME <ip> [nom]"
			}
			if err := rt.gw.SetName(args[0], strings.Join(args[1:], " ")); err != nil {
				return "ERR " + err.Error()
			}
			return "OK"
		case "GWDISABLE":
			logEvent(dir, "arrêt de la protection maison demandé")
			rt.gw.Stop()
			if rt.gwOwnsTun {
				rt.gwOwnsTun = false
				rt.disableLocked()
			}
			return "OK inactif"
		default:
			return "ERR commande inconnue"
		}
	}
	srv, err := ctl.Listen(dir, ctlPort, func(cmd string, args []string) string {
		r := handle(cmd, args)
		// Option « relancer au démarrage du PC » : mémoriser si la
		// protection maison est voulue (activée / arrêtée par l'utilisateur).
		switch strings.ToUpper(cmd) {
		case "GWENABLE":
			if !strings.HasPrefix(r, "ERR") {
				exit := rt.torSel
				if len(args) > 0 {
					exit = strings.ToLower(args[0])
				}
				saveMaisonAuto(dir, func(m *maisonAuto) { m.Actif, m.Sortie = true, exit })
			}
		case "GWDISABLE":
			saveMaisonAuto(dir, func(m *maisonAuto) { m.Actif = false })
		}
		return r
	})
	if err != nil {
		return nil, err
	}
	rt.srv = srv
	if m := loadMaisonAuto(dir); m.Option && m.Actif {
		go autoStartMaison(dir, m.Sortie, handle)
	}
	// L'interface graphique tourne sous compte standard : elle doit
	// pouvoir lire ctl.addr/ctl.token (BUILTIN\Users, lecture seule).
	relaxCtlACL(dir)
	return rt, nil
}

// dnsCommand traite les commandes DNS hors du verrou runtime.
// torIdle : vrai si le mode Tor est désactivé (autorise la restauration
// de l'IPv6 coupée — jamais pendant le tunnel, ce serait une fuite).
func dnsCommand(dir, cmd string, args []string, torIdle bool) string {
	switch strings.ToUpper(cmd) {
	case "DNS":
		out, err := netcfg.DNSList()
		if err != nil {
			return "ERR " + err.Error()
		}
		return "OK\n" + out
	case "DNSSET":
		if len(args) < 1 {
			return "ERR usage: DNSSET <ipv4[,ipv4]> [ipv6[,ipv6]]"
		}
		v4 := strings.Split(args[0], ",")
		var v6 []string
		if len(args) > 1 {
			v6 = strings.Split(args[1], ",")
		}
		done, err := netcfg.ApplyDNS(dir, v4, v6, false)
		if err != nil {
			logEvent(dir, "échec du réglage DNS : "+err.Error())
			return "ERR " + err.Error()
		}
		logEvent(dir, "DNS appliqué sur "+cartes(done))
		return "OK appliqué sur " + cartes(done)
	case "DNSAUTO":
		done, err := netcfg.RestoreDNS(dir)
		if err != nil {
			logEvent(dir, "échec de la restauration DNS : "+err.Error())
			return "ERR " + err.Error()
		}
		logEvent(dir, "DNS automatique restauré sur "+cartes(done))
		// « Restaurer » = tout remettre : l'IPv6 coupée par le mode Tor
		// l'est aussi (notamment après un reboot à chaud) — mais jamais
		// pendant que le tunnel est actif.
		if torIdle {
			restoreIPv6Off(dir)
		}
		return "OK restauré sur " + cartes(done)
	}
	return "ERR commande inconnue"
}

// stateLabel traduit un code d'état en français pour le journal.
func stateLabel(code string) string {
	switch code {
	case "protege":
		return "protégé"
	case "connexion":
		return "connexion en cours"
	case "bloque":
		return "bloqué"
	case "desactive":
		return "désactivé"
	}
	return code
}

// exitLabel affiche une sortie : « Tor · Pays-Bas », nom du relais, ou
// « automatique ».
func exitLabel(name string) string {
	if name == "" || strings.EqualFold(name, "auto") {
		return "automatique"
	}
	if isTorExit(name) {
		if p, ok := torPays[torExitCode(name)]; ok {
			return "Tor · " + p
		}
	}
	return name
}

// cartes : « 1 carte : Ethernet » / « 2 cartes : Ethernet, Wi-Fi ».
func cartes(done []string) string {
	if len(done) == 0 {
		return "aucune carte"
	}
	w := "carte"
	if len(done) > 1 {
		w = "cartes"
	}
	return fmt.Sprintf("%d %s : %s", len(done), w, strings.Join(done, ", "))
}

// choice retourne la sélection effective (Tor ou relais classique).
func (r *runtime) choice() string {
	if r.torSel != "" {
		return r.torSel
	}
	return r.cli.ExitChoice()
}

// statusLogged retourne le statut et journalise les transitions d'état
// (connexion, protégé, bloqué, désactivé) même sans commande explicite.
func (r *runtime) statusLogged(dir string) string {
	resp := r.status()
	f := strings.Fields(resp)
	if len(f) >= 2 && f[0] == "OK" {
		st := f[1]
		if st != r.lastState {
			r.lastState = st
			info := strings.TrimSpace(strings.TrimPrefix(resp, "OK "+st))
			logEvent(dir, "état → "+stateLabel(st)+(map[bool]string{true: " (" + info + ")", false: ""}[info != ""]))
		}
	}
	return resp
}

// status retourne l'état courant au format « OK <etat> <info> ».
func (r *runtime) status() string {
	if r.torSel != "" {
		if r.tor != nil {
			if st, info := r.tor.Status(); st != "desactive" {
				return "OK " + st + " " + info
			}
		}
		return "OK desactive"
	}
	return "OK " + r.cli.Status()
}

// enable active la protection dans le mode sélectionné.
func (r *runtime) enable() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.enableLocked()
}

func (r *runtime) enableLocked() error {
	r.enabled = true
	if r.torSel != "" {
		if r.tor == nil {
			r.tor = newTorStack(r.dir)
		}
		return r.tor.Start(torExitCode(r.torSel))
	}
	return r.cli.Enable()
}

func (r *runtime) disableLocked() {
	r.enabled = false
	if r.torSel != "" && r.tor != nil {
		r.tor.Stop()
		return
	}
	r.cli.Disable()
}

// selectExitLocked applique un changement de sortie à chaud.
func (r *runtime) selectExitLocked(name string) {
	if isTorExit(name) {
		r.torSel = strings.ToLower(name)
		if r.tor == nil {
			r.tor = newTorStack(r.dir)
		}
		if r.enabled {
			r.cli.Disable()
			_ = r.tor.Start(torExitCode(r.torSel))
		}
		return
	}
	// Retour à un relais classique.
	if r.torSel != "" {
		r.torSel = ""
		if r.tor != nil {
			r.tor.Stop()
		}
		r.cli.SelectExit(name)
		if r.enabled {
			_ = r.cli.Enable()
		}
		return
	}
	r.cli.SelectExit(name)
}

// relayList retourne une ligne par sortie : nom|pays|choisie.
func relayList(dir, choice string) string {
	cfg, err := config.Load(dir)
	if err != nil {
		return "ERR " + err.Error()
	}
	var b strings.Builder
	for _, r := range cfg.Relays {
		if !r.IsExit() {
			continue
		}
		mark := "0"
		if r.Name == choice || (choice == "" && cfg.SelectedExit == r.Name) || (choice == "" && cfg.SelectedExit == "" && isFirstExit(cfg, r)) {
			mark = "1"
		}
		fmt.Fprintf(&b, "%s|%s|%s\n", r.Name, r.Country, mark)
	}
	// Sorties Tor : pseudo-relais gérés localement (nom tor-<pays>).
	codes := make([]string, 0, len(torPays))
	for c := range torPays {
		codes = append(codes, c)
	}
	sort.Strings(codes)
	for _, c := range codes {
		mark := "0"
		if "tor-"+c == choice {
			mark = "1"
		}
		fmt.Fprintf(&b, "tor-%s|Tor · %s|%s\n", c, torPays[c], mark)
	}
	return strings.TrimRight(b.String(), "\n")
}

func isFirstExit(cfg *config.Config, r config.Relay) bool {
	for _, x := range cfg.Relays {
		if x.IsExit() {
			return x.Name == r.Name
		}
	}
	return false
}

// relaxCtlACL donne la lecture des fichiers du canal de commande au
// groupe Utilisateurs (SID S-1-5-32-545, indépendant de la langue).
// Seuls ctl.addr et ctl.token sont exposés — pas relays.json (clé privée).
func relaxCtlACL(dir string) {
	for _, f := range []string{ctl.AddrFile, ctl.TokenFile} {
		p := filepath.Join(dir, f)
		if _, err := os.Stat(p); err != nil {
			continue
		}
		_ = netcfg.HiddenCmd(context.Background(), "icacls", p, "/grant", "*S-1-5-32-545:R").Run()
	}
}

// stop désactive la protection et ferme le canal de commande.
func (r *runtime) stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.gw != nil {
		r.gw.Stop()
	}
	if r.torSel != "" && r.tor != nil {
		r.tor.Stop()
	}
	if r.cli != nil {
		r.cli.Disable()
	}
	if r.srv != nil {
		_ = r.srv.Close()
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "vicovpn-client:", err)
	os.Exit(1)
}

// --- Option : relancer la protection maison au démarrage du PC ---

type maisonAuto struct {
	Option bool   `json:"option"` // case cochée dans l'appli
	Actif  bool   `json:"actif"`  // protection maison active au dernier arrêt
	Sortie string `json:"sortie"` // sortie Tor utilisée
}

var maisonAutoMu sync.Mutex

func maisonAutoPath(dir string) string { return filepath.Join(dir, "maison-auto.json") }

func loadMaisonAuto(dir string) maisonAuto {
	var m maisonAuto
	if b, err := os.ReadFile(maisonAutoPath(dir)); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

func saveMaisonAuto(dir string, edit func(*maisonAuto)) {
	maisonAutoMu.Lock()
	defer maisonAutoMu.Unlock()
	m := loadMaisonAuto(dir)
	edit(&m)
	if b, err := json.Marshal(m); err == nil {
		_ = os.WriteFile(maisonAutoPath(dir), b, 0o644)
	}
}

// autoStartMaison relance la protection maison au démarrage du service
// (option cochée et protection active au dernier arrêt). Attend que la
// restauration de la box au démarrage soit faite et que le réseau soit là.
func autoStartMaison(dir, exit string, handle func(string, []string) string) {
	// Dès que le réseau est là (carte et route par défaut), au plus 3 min.
	time.Sleep(3 * time.Second)
	for i := 0; i < 90 && defaultInterface() == ""; i++ {
		time.Sleep(2 * time.Second)
	}
	time.Sleep(2 * time.Second)
	logEvent(dir, "démarrage du PC : relance automatique de la protection maison")
	args := []string{}
	if exit != "" {
		args = append(args, exit)
	}
	if r := handle("GWENABLE", args); strings.HasPrefix(r, "ERR") {
		logEvent(dir, "relance automatique impossible : "+strings.TrimPrefix(r, "ERR "))
	}
}
