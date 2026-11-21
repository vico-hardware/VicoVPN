// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 vico-hardware (Vico Studio) — https://github.com/vico-hardware/VicoVPN

//go:build !windows && !linux

package netcfg

import "fmt"

// RelayTunSetup n'est pas implémenté sur cet OS.
func RelayTunSetup(tunName, tunAddr, tunAddr6 string, mtu int) error {
	return fmt.Errorf("netcfg: configuration relais non supportée sur cet OS")
}

// RelayTunTeardown n'est pas implémenté sur cet OS.
func RelayTunTeardown(tunName, tunAddr, tunAddr6 string) error { return nil }
