// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 vico-hardware (Vico Studio) — https://github.com/vico-hardware/VicoVPN

//go:build windows

// vicovpn-recover : outil de récupération hors ligne. Il retire
// EXCLUSIVEMENT les objets créés par VicoVPN (règles pare-feu préfixées,
// routes enregistrées dans l'état, configuration DNS de l'interface) sans
// dépendre du service ni d'Internet.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/vicovpn/vicovpn/internal/freebox"
)

var cfgDir = flag.String("config", "", "dossier de configuration du client")

// stateFile mémorise ce que Protect a installé.
type stateFile struct {
	Routes    []string `json:"routes"`
	Protected bool     `json:"protected"`
}

func statePath(dir string) string { return filepath.Join(dir, "netcfg-state.json") }

func main() {
	flag.Parse()
	dir := os.Getenv("VICOVPN_HOME")
	if *cfgDir != "" {
		dir = *cfgDir
	}
	if dir == "" {
		if pd := os.Getenv("ProgramData"); pd != "" {
			dir = filepath.Join(pd, "VicoVPN")
		} else {
			home, _ := os.UserHomeDir()
			dir = filepath.Join(home, ".vicovpn")
		}
	}
	fmt.Println("Récupération VicoVPN dans", dir)

	// 1. Routes enregistrées.
	if b, err := os.ReadFile(statePath(dir)); err == nil {
		var st stateFile
		if json.Unmarshal(b, &st) == nil {
			for _, r := range st.Routes {
				if strings.HasPrefix(r, "HOST/") {
					run("route", "delete", strings.TrimPrefix(r, "HOST/"))
				} else {
					run("route", "delete", r, "mask", "128.0.0.0")
				}
			}
		}
	}
	// Routes /1 génériques même si l'état a été perdu (supprime toutes les
	// routes 0.0.0.0/1 et 128.0.0.0/1, metrics quelconques — documenté).
	run("route", "delete", "0.0.0.0", "mask", "128.0.0.0")
	run("route", "delete", "128.0.0.0", "mask", "128.0.0.0")

	// 2. Règles pare-feu du produit.
	ps(`Get-NetFirewallRule -DisplayName 'VicoVPN-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule`)

	// 3. DNS et métrique de l'interface tunnel si elle existe encore.
	ps(`if (Get-NetAdapter -Name 'VicoVPN' -ErrorAction SilentlyContinue) { Set-DnsClientServerAddress -InterfaceAlias 'VicoVPN' -ResetServerAddresses -ErrorAction SilentlyContinue; Set-NetIPInterface -InterfaceAlias 'VicoVPN' -InterfaceMetric 0 -ErrorAction SilentlyContinue }`)

	// 4. Mode passerelle : couper le forwarding IP sur les cartes physiques
	// (sinon il reste actif après un crash du service ou un reboot).
	ps(`Get-NetAdapter -Physical -ErrorAction SilentlyContinue | ForEach-Object { Set-NetIPInterface -InterfaceAlias $_.Name -AddressFamily IPv4 -Forwarding Disabled -ErrorAction SilentlyContinue }`)

	// 5. Processus Tor orphelins : UNIQUEMENT ceux de VicoVPN (chemin
	// contenant « VicoVPN ») — ne jamais toucher au Tor Browser de
	// l'utilisateur.
	ps(`Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { ($_.Name -in @('tor.exe','tun2socks.exe')) -and ($_.ExecutablePath -like '*VicoVPN*' -or $_.CommandLine -like '*vicotor0*' -or $_.CommandLine -like '*client-torrc*' -or $_.CommandLine -like '*VicoVPN*') } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }`)

	// 6. Adaptateur TUN vicotor0 résiduel.
	ps(`Get-NetAdapter -Name 'vicotor0' -ErrorAction SilentlyContinue | Remove-NetAdapter -Confirm:$false -ErrorAction SilentlyContinue`)

	// 7. Freebox : remettre l'IPv6 et le DHCP de la box s'ils avaient été
	// coupés par la protection maison.
	if freebox.LoadSaved(dir) != nil {
		if err := freebox.Restore(dir); err != nil {
			fmt.Println("  Freebox : restauration impossible :", err)
		} else {
			fmt.Println("  ok: Freebox restaurée (IPv6 + DHCP)")
		}
	}

	// 8. IPv6 des cartes coupée par le mode Tor (liste persistée).
	if b, err := os.ReadFile(filepath.Join(dir, "ipv6_off.json")); err == nil {
		var aliases []string
		if json.Unmarshal(b, &aliases) == nil {
			for _, a := range aliases {
				ps(`Enable-NetAdapterBinding -Name '` + strings.ReplaceAll(a, "'", "''") + `' -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue`)
			}
		}
		_ = os.Remove(filepath.Join(dir, "ipv6_off.json"))
	}

	// 9. Supprimer l'état.
	_ = os.Remove(statePath(dir))

	fmt.Println("Terminé. Redémarrez si des routespersistent.")
}

func run(name string, args ...string) {
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("  %s %s : %v (%s)\n", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	} else {
		fmt.Printf("  ok: %s %s\n", name, strings.Join(args, " "))
	}
}

func ps(script string) {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("  powershell: %v (%s)\n", err, strings.TrimSpace(string(out)))
	} else {
		fmt.Println("  ok: powershell")
	}
}
