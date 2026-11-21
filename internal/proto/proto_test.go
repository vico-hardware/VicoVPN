// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 vico-hardware (Vico Studio) — https://github.com/vico-hardware/VicoVPN

package proto_test

import (
	"bytes"
	"testing"

	"github.com/vicovpn/vicovpn/internal/proto"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte("paquet-ip-de-test")
	if err := proto.EncodeFrame(&buf, proto.TypeData, payload); err != nil {
		t.Fatal(err)
	}
	typ, got, err := proto.ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if typ != proto.TypeData || !bytes.Equal(got, payload) {
		t.Fatalf("typ=%d got=%q", typ, got)
	}
}

func TestHelloRoundTrip(t *testing.T) {
	h := proto.ClientHello{Version: proto.Version, MTU: 1280, WantIPv6: true}
	b := proto.MarshalClientHello(h)
	got, err := proto.UnmarshalClientHello(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != h.Version || got.MTU != h.MTU || !got.WantIPv6 {
		t.Fatalf("got=%+v", got)
	}

	sh := proto.ServerHello{Version: proto.Version, MTU: 1200, Country: "FR", PolicyFlags: proto.PolicyDatagram}
	sb := proto.MarshalServerHello(sh)
	gs, err := proto.UnmarshalServerHello(sb)
	if err != nil {
		t.Fatal(err)
	}
	if gs.MTU != 1200 || gs.Country != "FR" || gs.PolicyFlags != proto.PolicyDatagram {
		t.Fatalf("got=%+v", gs)
	}
}

func TestFrameTooLarge(t *testing.T) {
	var buf bytes.Buffer
	if err := proto.EncodeFrame(&buf, proto.TypeData, make([]byte, proto.MaxFrameSize+1)); err == nil {
		t.Fatal("aurait dû échouer")
	}
}
