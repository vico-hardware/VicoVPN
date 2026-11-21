// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 vico-hardware (Vico Studio) — https://github.com/vico-hardware/VicoVPN

//go:build !windows

package netcfg

import "fmt"

// DNSBackupPath : non supporté hors Windows.
func DNSBackupPath(dir string) string { return "" }

// BackupDNS : non supporté hors Windows.
func BackupDNS(dir string) error { return fmt.Errorf("dns: non supporté sur cette plateforme") }

// ApplyDNS : non supporté hors Windows.
func ApplyDNS(dir string, v4, v6 []string, skipBackup bool) ([]string, error) {
	return nil, fmt.Errorf("dns: non supporté sur cette plateforme")
}

// RestoreDNS : non supporté hors Windows.
func RestoreDNS(dir string) ([]string, error) {
	return nil, fmt.Errorf("dns: non supporté sur cette plateforme")
}

// DNSList : non supporté hors Windows.
func DNSList() (string, error) { return "", fmt.Errorf("dns: non supporté") }
