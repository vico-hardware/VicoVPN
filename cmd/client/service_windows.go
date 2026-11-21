// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 vico-hardware (Vico Studio) — https://github.com/vico-hardware/VicoVPN

//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/vicovpn/vicovpn/internal/config"
)

// serviceName est le nom du service Windows.
const serviceName = "VicoVPN"

// serviceMain gère les sous-commandes du mode service.
//
//	install / uninstall : gestion du service (admin requis)
//	console : même moteur en avant-plan (débogage)
//	svc : appelé par le gestionnaire de services Windows
func serviceMain(mode, cfgDir string, noGuard bool, ctlPort int) {
	dir, err := config.DataDir()
	if cfgDir != "" {
		dir = cfgDir
	}
	if err != nil {
		fatal(err)
	}
	switch mode {
	case "install":
		installService(dir, noGuard, ctlPort)
	case "uninstall":
		uninstallService()
	case "console":
		runServiceConsole(dir, noGuard, ctlPort)
	case "repair":
		repairService(dir)
	default:
		runService(dir, noGuard, ctlPort)
	}
}

// svcParams transporte la configuration figée à l'installation.
type svcParams struct {
	dir     string
	noGuard bool
	ctlPort int
}

// svcHandler exécute le runtime client en tant que service Windows.
type svcHandler struct {
	p    svcParams
	rt   *runtime
	done chan struct{}
}

func (h *svcHandler) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	rt, err := startRuntime(h.p.dir, h.p.noGuard, h.p.ctlPort)
	if err != nil {
		// stderr est perdu pour un service : le journal est la seule trace
		// visible (UI « Journal » / diagnostic).
		logEvent(h.p.dir, "service : démarrage impossible : "+err.Error())
		fmt.Fprintln(os.Stderr, "vicovpn-client:", err)
		return false, 1
	}
	logEvent(h.p.dir, "service : démarré")
	h.rt = rt
	// L'intention de protection est persistante : le service active le
	// tunnel dès son démarrage (y compris au boot). Mais uniquement s'il
	// existe une sortie enrôlée — les installs « Tor uniquement » n'ont
	// aucun relais classique et ne doivent pas afficher « bloqué ».
	if cfg, err := config.Load(h.p.dir); err == nil {
		hasExit := false
		for _, r := range cfg.Relays {
			if r.IsExit() {
				hasExit = true
				break
			}
		}
		if hasExit {
			if err := rt.cli.Enable(); err != nil {
				fmt.Fprintln(os.Stderr, "vicovpn-client:", err)
			}
		}
	}
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				rt.stop()
				return false, 0
			}
		case <-h.done:
			rt.stop()
			return false, 0
		}
	}
}

func runService(dir string, noGuard bool, ctlPort int) {
	isSvc, err := svc.IsWindowsService()
	if err != nil {
		fatal(err)
	}
	if !isSvc {
		fmt.Fprintln(os.Stderr, "vicovpn-client: -service svc doit être lancé par le gestionnaire de services")
		os.Exit(1)
	}
	h := &svcHandler{p: svcParams{dir: dir, noGuard: noGuard, ctlPort: ctlPort}, done: make(chan struct{})}
	if err := svc.Run(serviceName, h); err != nil {
		fatal(err)
	}
}

// runServiceConsole exécute le même moteur en console (débogage).
func runServiceConsole(dir string, noGuard bool, ctlPort int) {
	rt, err := startRuntime(dir, noGuard, ctlPort)
	if err != nil {
		fatal(err)
	}
	defer rt.stop()
	if err := rt.cli.Enable(); err != nil {
		fatal(err)
	}
	fmt.Println("service (console) actif, ctl:", filepath.Join(dir, "ctl.addr"))
	select {}
}

func exePath() string {
	p, err := os.Executable()
	if err != nil {
		fatal(err)
	}
	return p
}

func installService(dir string, noGuard bool, ctlPort int) {
	if err := installServiceErr(dir, noGuard, ctlPort); err != nil {
		fatal(err)
	}
	fmt.Println("service", serviceName, "installé (démarrage automatique, compte SYSTEM).")
}

// repairService (lancé en administrateur par le bouton « Réparer » de
// l'interface) réinstalle le service puis le démarre. Le résultat va dans
// le journal, seule sortie visible (l'exe est une application GUI).
func repairService(dir string) {
	logEvent(dir, "réparation du service demandée")
	if err := installServiceErr(dir, false, 0); err != nil {
		logEvent(dir, "réparation : "+err.Error())
		os.Exit(1)
	}
	m, err := mgr.Connect()
	if err != nil {
		logEvent(dir, "réparation : SCM : "+err.Error())
		os.Exit(1)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		logEvent(dir, "réparation : "+err.Error())
		os.Exit(1)
	}
	defer s.Close()
	if err := s.Start(); err != nil {
		logEvent(dir, "réparation : démarrage refusé : "+err.Error())
		os.Exit(1)
	}
	for i := 0; i < 40; i++ {
		st, err := s.Query()
		if err == nil && st.State == svc.Running {
			logEvent(dir, "réparation : service réinstallé et démarré")
			return
		}
		if err == nil && st.State == svc.Stopped {
			logEvent(dir, fmt.Sprintf("réparation : le service s'est arrêté au démarrage (code %d/%d)", st.Win32ExitCode, st.ServiceSpecificExitCode))
			os.Exit(1)
		}
		time.Sleep(500 * time.Millisecond)
	}
	logEvent(dir, "réparation : le service ne répond pas (toujours en démarrage)")
}

func installServiceErr(dir string, noGuard bool, ctlPort int) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service: connexion SCM (admin requis): %w", err)
	}
	defer m.Disconnect()

	// Supprimer une installation précédente : arrêter proprement d'abord,
	// Windows refuse de supprimer un service encore en cours d'exécution.
	if s, err := m.OpenService(serviceName); err == nil {
		if st, err := s.Query(); err == nil && st.State != svc.Stopped {
			_, _ = s.Control(svc.Stop)
		}
		for i := 0; i < 60; i++ {
			st, err := s.Query()
			if err != nil || st.State == svc.Stopped {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		_ = s.Delete()
		s.Close()
		time.Sleep(time.Second)
	}

	args := []string{"-service=svc"}
	if dd, err := config.DataDir(); err == nil && dir != dd {
		args = append(args, "-config", dir)
	}
	if noGuard {
		args = append(args, "-no-firewall")
	}
	if ctlPort != 0 {
		args = append(args, fmt.Sprintf("-ctl-port=%d", ctlPort))
	}

	s, err := m.CreateService(serviceName, exePath(), mgr.Config{
		DisplayName:  "VicoVPN",
		Description:  "VPN système VicoVPN : protection de la connexion Internet.",
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
	}, args...)
	if err != nil {
		return fmt.Errorf("service: installation: %w", err)
	}
	defer s.Close()
	// Redémarrage automatique si le service plante (5 s, 3 fois/jour).
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}, 86400)
	return nil
}

func uninstallService() {
	m, err := mgr.Connect()
	if err != nil {
		fatal(fmt.Errorf("service: connexion SCM (admin requis): %w", err))
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		fatal(fmt.Errorf("service: %w", err))
	}
	defer s.Close()
	// Demander l'arrêt propre d'abord.
	_, _ = s.Control(svc.Stop)
	time.Sleep(2 * time.Second)
	if err := s.Delete(); err != nil {
		fatal(fmt.Errorf("service: désinstallation: %w", err))
	}
	fmt.Println("service", serviceName, "désinstallé.")
}
