// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 vico-hardware (Vico Studio) — https://github.com/vico-hardware/VicoVPN

//go:build linux

package tun

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	iffTun    = 0x0001
	iffNoPi   = 0x1000
	tunSetIFF = 0x400454ca
)

type ifreq struct {
	name  [unix.IFNAMSIZ]byte
	flags uint16
	_     [22]byte // padding vers union
}

// deviceLinux encapsule un descripteur /dev/net/tun sans PI.
type deviceLinux struct {
	f    *os.File
	name string
	mtu  int
}

func create(name string, mtu int) (Device, error) {
	if name == "" {
		name = "vicovpn"
	}
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("tun: /dev/net/tun: %w", err)
	}
	req := ifreq{flags: iffTun | iffNoPi}
	copy(req.name[:], name)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), tunSetIFF, uintptr(unsafe.Pointer(&req))); errno != 0 {
		f.Close()
		return nil, fmt.Errorf("tun: TUNSETIFF: %w", errno)
	}
	return &deviceLinux{f: f, name: name, mtu: mtu}, nil
}

func (d *deviceLinux) Name() string { return d.name }
func (d *deviceLinux) MTU() int     { return d.mtu }

func (d *deviceLinux) Read(buf []byte) (int, error) {
	n, err := d.f.Read(buf)
	if n == 0 && err == nil {
		return 0, ErrClosed
	}
	return n, err
}

func (d *deviceLinux) Write(pkt []byte) (int, error) {
	return d.f.Write(pkt)
}

func (d *deviceLinux) Close() error {
	if d.f == nil {
		return nil
	}
	err := d.f.Close()
	d.f = nil
	_ = errors.Is(err, os.ErrClosed)
	return err
}
