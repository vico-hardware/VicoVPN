// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 vico-hardware (Vico Studio) — https://github.com/vico-hardware/VicoVPN

// vicovpn-ctl : outil de ligne de commande pour piloter le client
// (Activer / Désactiver / Réessayer / Status) via le canal local.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/vicovpn/vicovpn/internal/config"
	"github.com/vicovpn/vicovpn/internal/ctl"
)

func main() {
	var cfgDir = flag.String("config", "", "dossier de configuration")
	flag.Parse()
	dir, err := config.DataDir()
	if *cfgDir != "" {
		dir = *cfgDir
	}
	if err != nil {
		fatal(err)
	}
	args := flag.Args()
	if len(args) == 0 {
		usage()
	}
	cmd := strings.ToUpper(args[0])
	var ctlArgs []string
	switch cmd {
	case "ACTIVER", "ENABLE":
		cmd = "ENABLE"
	case "DESACTIVER", "DISABLE":
		cmd = "DISABLE"
	case "REESSAYER", "RETRY":
		cmd = "RETRY"
	case "STATUS", "ETAT":
		cmd = "STATUS"
	case "RELAY", "SORTIES":
		cmd = "RELAY"
	case "SELECT", "SORTIE":
		cmd = "SELECT"
		ctlArgs = args[1:]
	case "DNS":
		cmd = "DNS"
	case "DNSSET":
		cmd = "DNSSET"
		ctlArgs = args[1:]
	case "DNSAUTO", "DNSRESTAURE":
		cmd = "DNSAUTO"
	case "LOG", "JOURNAL":
		cmd = "LOG"
	case "GWSTATUS", "MAISON":
		cmd = "GWSTATUS"
	case "GWENABLE", "MAISONON":
		cmd = "GWENABLE"
		ctlArgs = args[1:]
	case "GWDISABLE", "MAISONOFF":
		cmd = "GWDISABLE"
	case "GWINFO", "MAISONINFO":
		cmd = "GWINFO"
	case "FBXSTATUS", "FREEBOX":
		cmd = "FBXSTATUS"
	case "FBXPAIR", "ASSOCIER":
		cmd = "FBXPAIR"
	case "FBXRESTORE", "RESTAURERBOX":
		cmd = "FBXRESTORE"
	case "GWDEVICES", "APPAREILS":
		cmd = "GWDEVICES"
	case "GWNAME", "NOMMER":
		cmd = "GWNAME"
		ctlArgs = args[1:]
	default:
		usage()
	}
	resp, err := ctl.Command(dir, cmd, ctlArgs...)
	if err != nil {
		fatal(err)
	}
	fmt.Println(resp)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: vicovpn-ctl [ACTIVER|DESACTIVER|REESSAYER|STATUS|SORTIES|SORTIE <nom>|JOURNAL|MAISON|MAISONON [tor-xx]|MAISONOFF|MAISONINFO]")
	os.Exit(2)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "vicovpn-ctl:", err)
	os.Exit(1)
}
