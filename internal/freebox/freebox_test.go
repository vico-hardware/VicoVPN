// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 vico-hardware (Vico Studio) — https://github.com/vico-hardware/VicoVPN

package freebox

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeBox simule l'API Freebox OS.
type fakeBox struct {
	mu       sync.Mutex
	status   string // pending / granted
	settings bool
	dhcp     bool
	ipv6     bool
	puts     []string
	profile  int
	blocked  map[string]any
}

const fakeToken = "dyNYgfK0Ya6FWGqq83sBHa7TwzWo+pg4fDFUJHShcjVYzTfaRrZzm93p7OTAfH/0"

func (f *fakeBox) handler(t *testing.T) http.Handler {
	ok := func(w http.ResponseWriter, v any) {
		b, _ := json.Marshal(map[string]any{"success": true, "result": v})
		_, _ = w.Write(b)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		p := r.URL.Path
		switch {
		case p == "/api_version":
			_, _ = w.Write([]byte(`{"api_base_url":"/api/","api_version":"16.1","box_model_name":"Freebox v9 (r1)","uid":"abc"}`))
		case p == "/api/v16/login/authorize/" && r.Method == http.MethodPost:
			ok(w, map[string]any{"app_token": fakeToken, "track_id": 7})
		case p == "/api/v16/login/authorize/7":
			ok(w, map[string]any{"status": f.status, "challenge": "x"})
		case p == "/api/v16/login/":
			ok(w, map[string]any{"logged_in": false, "challenge": "CHAL"})
		case p == "/api/v16/login/session/":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			m := hmac.New(sha1.New, []byte(fakeToken))
			m.Write([]byte("CHAL"))
			if body["password"] != hex.EncodeToString(m.Sum(nil)) {
				w.WriteHeader(403)
				_, _ = w.Write([]byte(`{"success":false,"error_code":"invalid_token","msg":"bad"}`))
				return
			}
			ok(w, map[string]any{"session_token": "SESS", "permissions": map[string]bool{"settings": f.settings, "profile": f.settings}})
		default:
			if r.Header.Get("X-Fbx-App-Auth") != "SESS" {
				w.WriteHeader(403)
				_, _ = w.Write([]byte(`{"success":false,"error_code":"auth_required","msg":"auth"}`))
				return
			}
			switch {
			case p == "/api/v16/dhcp/config/" && r.Method == http.MethodGet:
				ok(w, map[string]any{"enabled": f.dhcp, "ip_range_start": "192.168.1.1", "ip_range_end": "192.168.1.50", "gateway": "192.168.1.254", "netmask": "255.255.255.0"})
			case p == "/api/v16/dhcp/config/" && r.Method == http.MethodPut:
				b, _ := io.ReadAll(r.Body)
				f.puts = append(f.puts, "dhcp "+string(b))
				var v map[string]bool
				_ = json.Unmarshal(b, &v)
				f.dhcp = v["enabled"]
				ok(w, nil)
			case p == "/api/v16/connection/ipv6/config/" && r.Method == http.MethodGet:
				ok(w, map[string]any{"ipv6_enabled": f.ipv6})
			case p == "/api/v16/connection/ipv6/config/" && r.Method == http.MethodPut:
				b, _ := io.ReadAll(r.Body)
				f.puts = append(f.puts, "ipv6 "+string(b))
				var v map[string]bool
				_ = json.Unmarshal(b, &v)
				f.ipv6 = v["ipv6_enabled"]
				ok(w, nil)
			case p == "/api/v16/dhcp/dynamic_lease/":
				ok(w, []map[string]any{{"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.20", "hostname": "iPhone"}})
			case p == "/api/v16/dhcp/static_lease/":
				ok(w, []map[string]any{})
			case p == "/api/v16/profile/" && r.Method == http.MethodGet:
				var l []map[string]any
				if f.profile > 0 {
					l = append(l, map[string]any{"id": f.profile, "name": ProfileName})
				}
				ok(w, l)
			case p == "/api/v16/profile/" && r.Method == http.MethodPost:
				f.profile = 9
				ok(w, map[string]any{"id": 9})
			case p == "/api/v16/network_control/9" && r.Method == http.MethodPut:
				var v map[string]any
				_ = json.NewDecoder(r.Body).Decode(&v)
				f.blocked = v
				ok(w, v)
			case p == "/api/v16/profile/9" && r.Method == http.MethodDelete:
				f.profile = 0
				ok(w, nil)
			default:
				w.WriteHeader(404)
				_, _ = w.Write([]byte(`{"success":false,"error_code":"invalid_api_version"}`))
			}
		}
	})
}

func TestFlow(t *testing.T) {
	fb := &fakeBox{status: "pending", dhcp: true, ipv6: true}
	srv := httptest.NewServer(fb.handler(t))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	dir := t.TempDir()

	c := New(dir, host)
	if st, _ := c.State(); st != "non_associee" {
		t.Fatalf("état initial = %s", st)
	}
	if err := c.Pair("PC test"); err != nil {
		t.Fatal(err)
	}
	if st, _ := c.State(); st != "attente" {
		t.Fatalf("après Pair = %s", st)
	}
	fb.mu.Lock()
	fb.status = "granted"
	fb.mu.Unlock()
	if st, _ := c.State(); st != "droits" {
		t.Fatalf("sans droit settings = %s", st)
	}
	fb.mu.Lock()
	fb.settings = true
	fb.mu.Unlock()
	c2 := New(dir, host) // jeton relu depuis le disque
	if st, err := c2.State(); st != "prete" {
		t.Fatalf("avec droit settings = %s (%v)", st, err)
	}

	s, err := c2.Takeover()
	if err != nil {
		t.Fatal(err)
	}
	if !s.DHCPEnabled || !s.IPv6Enabled || len(s.Leases) != 1 || s.DHCP.RangeEnd != "192.168.1.50" {
		t.Fatalf("sauvegarde incorrecte : %+v", s)
	}
	if fb.dhcp || fb.ipv6 {
		t.Fatalf("box non coupée : dhcp=%v ipv6=%v", fb.dhcp, fb.ipv6)
	}
	// Deuxième prise de main (plantage) : la sauvegarde d'origine reste.
	if s2, _ := c2.Takeover(); !s2.DHCPEnabled || !s2.IPv6Enabled {
		t.Fatal("la sauvegarde d'origine a été écrasée")
	}
	// Profil de blocage des appareils basculés.
	id, err := c2.CreateBlockProfile()
	if err != nil || id != 9 {
		t.Fatalf("profil: %d %v", id, err)
	}
	if err := c2.SetBlocked(id, []string{"AA:BB:CC:DD:EE:FF"}); err != nil {
		t.Fatal(err)
	}
	if fb.blocked["override_mode"] != "denied" || fb.blocked["override"] != true {
		t.Fatalf("blocage: %v", fb.blocked)
	}
	if again, _ := c2.CreateBlockProfile(); again != 9 {
		t.Fatal("profil existant non réutilisé")
	}
	s.ProfileID = id
	_ = SaveSaved(dir, s)
	if err := Restore(dir); err != nil {
		t.Fatal(err)
	}
	if !fb.dhcp || !fb.ipv6 {
		t.Fatalf("box non restaurée : dhcp=%v ipv6=%v", fb.dhcp, fb.ipv6)
	}
	if LoadSaved(dir) != nil {
		t.Fatal("sauvegarde non effacée")
	}
	if fb.profile != 0 {
		t.Fatal("profil de blocage non supprimé")
	}
	_ = net.IPv4zero
}
