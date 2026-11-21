// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 vico-hardware (Vico Studio) — https://github.com/vico-hardware/VicoVPN

//go:build windows

package tun

import (
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

// deviceWindows encapsule une session wintun.
type deviceWindows struct {
	adapter *wintun.Adapter
	session wintun.Session
	name    string
	mtu     int

	mu     sync.Mutex
	closed bool
	wait   windows.Handle
}

func create(name string, mtu int) (Device, error) {
	if name == "" {
		name = "VicoVPN"
	}
	adapter, err := wintun.CreateAdapter(name, "VicoVPN", nil)
	if err != nil {
		return nil, err
	}
	session, err := adapter.StartSession(0x400000) // ring de 4 Mio
	if err != nil {
		adapter.Close()
		return nil, err
	}
	return &deviceWindows{
		adapter: adapter,
		session: session,
		name:    name,
		mtu:     mtu,
		wait:    session.ReadWaitEvent(),
	}, nil
}

func (d *deviceWindows) Name() string { return d.name }
func (d *deviceWindows) MTU() int     { return d.mtu }

// Read attend un paquet via l'événement de session wintun.
func (d *deviceWindows) Read(buf []byte) (int, error) {
	for {
		d.mu.Lock()
		closed := d.closed
		d.mu.Unlock()
		if closed {
			return 0, ErrClosed
		}
		pkt, err := d.session.ReceivePacket()
		if err != nil {
			// ERROR_NO_MORE_ITEMS : ring vide, équivalent à (nil, nil).
			if errno, ok := err.(syscall.Errno); ok && errno == windows.ERROR_NO_MORE_ITEMS {
				pkt = nil
			} else {
				return 0, err
			}
		}
		if pkt != nil {
			n := copy(buf, pkt)
			d.session.ReleaseReceivePacket(pkt)
			return n, nil
		}
		// Pas de paquet : attendre l'événement (ou la fermeture).
		if d.wait == 0 {
			time.Sleep(time.Millisecond)
			continue
		}
		ret, _ := windows.WaitForSingleObject(d.wait, 500)
		if ret == uint32(windows.WAIT_FAILED) {
			return 0, windows.GetLastError()
		}
	}
}

// Write alloue un paquet dans le ring d'émission wintun.
func (d *deviceWindows) Write(pkt []byte) (int, error) {
	d.mu.Lock()
	closed := d.closed
	d.mu.Unlock()
	if closed {
		return 0, ErrClosed
	}
	out, err := d.session.AllocateSendPacket(len(pkt))
	if err != nil {
		return 0, err
	}
	copy(out, pkt)
	d.session.SendPacket(out)
	return len(pkt), nil
}

func (d *deviceWindows) Close() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	d.mu.Unlock()
	d.session.End()
	err := d.adapter.Close()
	return err
}
