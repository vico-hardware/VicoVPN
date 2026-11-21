// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 vico-hardware (Vico Studio) — https://github.com/vico-hardware/VicoVPN

// Package freebox pilote une Freebox par son API officielle (Freebox OS),
// sur le réseau local : association de l'application (validation sur
// l'écran de la box), session HMAC, IPv6 de la box, serveur DHCP de la
// box, baux DHCP et noms des appareils.
//
// Le jeton d'application (freebox.json) donne le droit de modifier les
// réglages de la box : il reste dans le dossier de données du service
// (%ProgramData%\VicoVPN), comme les autres secrets du produit.
package freebox

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	AppID      = "fr.vicostudio.vicovpn"
	AppName    = "VicoVPN"
	AppVersion = "1.1.0"

	tokenFile = "freebox.json"
	savedFile = "freebox-sauvegarde.json"
)

// ErrNotPaired : aucune association avec la box.
var ErrNotPaired = errors.New("Freebox non associée")

// ErrNoSettings : association valide mais sans le droit « Modification
// des réglages de la Freebox ».
var ErrNoSettings = errors.New("droit « Modification des réglages de la Freebox » non accordé")

// ErrNoProfile : droit « Gestion des profils » non accordé.
var ErrNoProfile = errors.New("droit « Gestion des profils » non accordé")

// Client parle à une Freebox. Sûr pour un usage concurrent.
type Client struct {
	mu      sync.Mutex
	dir     string
	box     string // IP LAN de la box
	base    string // http://<ip>/api/vNN/
	model   string
	uid     string
	tok     tokenState
	session string
	perms   map[string]bool
	http    *http.Client
}

type tokenState struct {
	AppToken string `json:"app_token"`
	TrackID  int    `json:"track_id"`
	UID      string `json:"uid"`
	Granted  bool   `json:"granted"`
}

// New prépare un client pour la box d'adresse LAN boxIP.
func New(dir, boxIP string) *Client {
	c := &Client{dir: dir, box: boxIP, http: &http.Client{Timeout: 8 * time.Second}}
	if b, err := os.ReadFile(filepath.Join(dir, tokenFile)); err == nil {
		_ = json.Unmarshal(b, &c.tok)
	}
	return c
}

// Box retourne l'adresse de la box.
func (c *Client) Box() string { return c.box }

// Model retourne le modèle détecté (« Freebox v9 (r1) »).
func (c *Client) Model() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.model
}

// ModelOrDefault retourne le modèle (« Freebox v9 (r1) ») ou « Freebox ».
func (c *Client) ModelOrDefault() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.detectLocked()
	if c.model == "" {
		return "Freebox"
	}
	return c.model
}

// Detect vérifie qu'une Freebox répond à cette adresse et retient la
// version de l'API.
func (c *Client) Detect() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.detectLocked()
}

func (c *Client) detectLocked() error {
	if c.base != "" {
		return nil
	}
	req, _ := http.NewRequest(http.MethodGet, "http://"+c.box+"/api_version", nil)
	req.Host = "mafreebox.freebox.fr"
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("aucune Freebox ne répond sur %s", c.box)
	}
	defer resp.Body.Close()
	var v struct {
		APIBaseURL string `json:"api_base_url"`
		APIVersion string `json:"api_version"`
		Model      string `json:"box_model_name"`
		DeviceName string `json:"device_name"`
		UID        string `json:"uid"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil || v.APIVersion == "" {
		return fmt.Errorf("la box %s n'est pas une Freebox", c.box)
	}
	major := strings.SplitN(v.APIVersion, ".", 2)[0]
	if v.APIBaseURL == "" {
		v.APIBaseURL = "/api/"
	}
	c.base = "http://" + c.box + v.APIBaseURL + "v" + major + "/"
	c.model = v.Model
	if c.model == "" {
		c.model = v.DeviceName
	}
	c.uid = v.UID
	return nil
}

type apiResp struct {
	Success   bool            `json:"success"`
	Result    json.RawMessage `json:"result"`
	ErrorCode string          `json:"error_code"`
	Msg       string          `json:"msg"`
}

// call exécute une requête brute (sans session).
func (c *Client) call(method, path string, body any, session string, out any) (string, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return "", err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		return "", err
	}
	req.Host = "mafreebox.freebox.fr"
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	if session != "" {
		req.Header.Set("X-Fbx-App-Auth", session)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("Freebox injoignable : %w", err)
	}
	defer resp.Body.Close()
	var r apiResp
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", fmt.Errorf("réponse Freebox illisible (HTTP %d)", resp.StatusCode)
	}
	if !r.Success {
		msg := r.Msg
		if msg == "" {
			msg = r.ErrorCode
		}
		return r.ErrorCode, fmt.Errorf("Freebox : %s", msg)
	}
	if out != nil && len(r.Result) > 0 {
		if err := json.Unmarshal(r.Result, out); err != nil {
			return "", fmt.Errorf("réponse Freebox inattendue : %w", err)
		}
	}
	return "", nil
}

func (c *Client) saveTokenLocked() {
	b, _ := json.MarshalIndent(c.tok, "", "  ")
	_ = os.WriteFile(filepath.Join(c.dir, tokenFile), b, 0o600)
}

// Pair lance une demande d'association : l'utilisateur doit la valider
// sur l'écran de la Freebox.
func (c *Client) Pair(deviceName string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.detectLocked(); err != nil {
		return err
	}
	var res struct {
		AppToken string `json:"app_token"`
		TrackID  int    `json:"track_id"`
	}
	_, err := c.call(http.MethodPost, "login/authorize/", map[string]string{
		"app_id": AppID, "app_name": AppName, "app_version": AppVersion, "device_name": deviceName,
	}, "", &res)
	if err != nil {
		return err
	}
	c.tok = tokenState{AppToken: res.AppToken, TrackID: res.TrackID, UID: c.uid}
	c.session = ""
	c.saveTokenLocked()
	return nil
}

// State résume l'association :
//
//	absente | non_associee | attente | refusee | droits | prete
func (c *Client) State() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.detectLocked(); err != nil {
		return "absente", err
	}
	if c.tok.AppToken == "" || (c.tok.UID != "" && c.uid != "" && c.tok.UID != c.uid) {
		return "non_associee", nil
	}
	if !c.tok.Granted {
		var st struct {
			Status string `json:"status"`
		}
		if _, err := c.call(http.MethodGet, fmt.Sprintf("login/authorize/%d", c.tok.TrackID), nil, "", &st); err != nil {
			return "non_associee", err
		}
		switch st.Status {
		case "pending":
			return "attente", nil
		case "granted":
			c.tok.Granted = true
			c.saveTokenLocked()
		case "denied":
			return "refusee", nil
		default: // timeout, unknown
			c.tok = tokenState{}
			c.saveTokenLocked()
			return "non_associee", nil
		}
	}
	if err := c.loginLocked(); err != nil {
		if errors.Is(err, ErrNotPaired) {
			return "non_associee", nil
		}
		return "non_associee", err
	}
	if !c.perms["settings"] {
		return "droits", nil
	}
	if !c.perms["profile"] {
		return "droits_profil", nil
	}
	return "prete", nil
}

// Perm indique si l'association dispose d'une permission (session ouverte
// au besoin).
func (c *Client) Perm(name string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session == "" {
		if err := c.detectLocked(); err != nil {
			return false
		}
		if err := c.loginLocked(); err != nil {
			return false
		}
	}
	return c.perms[name]
}

// loginLocked ouvre une session (mot de passe = HMAC-SHA1(app_token,
// challenge)).
func (c *Client) loginLocked() error {
	if c.tok.AppToken == "" || !c.tok.Granted {
		return ErrNotPaired
	}
	var ch struct {
		Challenge string `json:"challenge"`
	}
	if _, err := c.call(http.MethodGet, "login/", nil, "", &ch); err != nil {
		return err
	}
	m := hmac.New(sha1.New, []byte(c.tok.AppToken))
	m.Write([]byte(ch.Challenge))
	var s struct {
		SessionToken string          `json:"session_token"`
		Permissions  map[string]bool `json:"permissions"`
	}
	code, err := c.call(http.MethodPost, "login/session/", map[string]string{
		"app_id": AppID, "app_version": AppVersion, "password": hex.EncodeToString(m.Sum(nil)),
	}, "", &s)
	if err != nil {
		if code == "invalid_token" || code == "pending_token" {
			c.tok = tokenState{}
			c.saveTokenLocked()
			return ErrNotPaired
		}
		return err
	}
	c.session = s.SessionToken
	c.perms = s.Permissions
	return nil
}

// do appelle l'API avec session (ouverte ou renouvelée au besoin).
func (c *Client) do(method, path string, body, out any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.detectLocked(); err != nil {
		return err
	}
	if c.session == "" {
		if err := c.loginLocked(); err != nil {
			return err
		}
	}
	code, err := c.call(method, path, body, c.session, out)
	if err != nil && (code == "auth_required" || code == "invalid_session") {
		if err := c.loginLocked(); err != nil {
			return err
		}
		code, err = c.call(method, path, body, c.session, out)
	}
	if code == "insufficient_rights" {
		if strings.HasPrefix(path, "profile") || strings.HasPrefix(path, "network_control") {
			return ErrNoProfile
		}
		return ErrNoSettings
	}
	return err
}

// RestartWifi éteint puis rallume le Wi-Fi de la box : tous les appareils
// Wi-Fi se reconnectent et redemandent leurs réglages (DHCP) aussitôt.
// Plusieurs tentatives pour le rallumage : le Wi-Fi ne doit jamais rester
// éteint.
func (c *Client) RestartWifi() error {
	var cur struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.do(http.MethodGet, "wifi/config/", nil, &cur); err != nil {
		return err
	}
	if !cur.Enabled {
		return fmt.Errorf("le Wi-Fi de la box est déjà éteint")
	}
	if err := c.do(http.MethodPut, "wifi/config/", map[string]bool{"enabled": false}, nil); err != nil {
		return err
	}
	time.Sleep(5 * time.Second)
	var last error
	for i := 0; i < 8; i++ {
		if last = c.do(http.MethodPut, "wifi/config/", map[string]bool{"enabled": true}, nil); last == nil {
			return nil
		}
		time.Sleep(3 * time.Second)
	}
	return fmt.Errorf("le Wi-Fi n'a pas pu être rallumé (%v) : rallume-le dans Freebox OS", last)
}

// Get lit un point d'API de la box (lecture seule, diagnostic).
func (c *Client) Get(path string, out any) error { return c.do(http.MethodGet, path, nil, out) }

// ---------------------------------------------------------------------
// Profils (contrôle d'accès Internet par adresse MAC)
// ---------------------------------------------------------------------

// ProfileName : profil créé par VicoVPN pendant la protection maison.
const ProfileName = "VicoVPN"

// CreateBlockProfile crée le profil qui coupe l'accès Internet direct
// (par la box) des appareils basculés sur le PC.
func (c *Client) CreateBlockProfile() (int, error) {
	// Un profil du même nom laissé par un plantage est réutilisé.
	var list []struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	}
	if err := c.do(http.MethodGet, "profile/", nil, &list); err == nil {
		for _, p := range list {
			if p.Name == ProfileName {
				return p.ID, nil
			}
		}
	}
	var res struct {
		ID int `json:"id"`
	}
	if err := c.do(http.MethodPost, "profile/", map[string]string{
		"name": ProfileName, "icon": "/resources/images/profile/profile_01.png",
	}, &res); err != nil {
		return 0, err
	}
	if res.ID == 0 {
		return 0, fmt.Errorf("profil Freebox non créé")
	}
	return res.ID, nil
}

// SetBlocked interdit l'accès Internet direct aux adresses MAC données
// (blocage permanent du profil, IPv4 et IPv6).
func (c *Client) SetBlocked(profileID int, macs []string) error {
	if macs == nil {
		macs = []string{}
	}
	return c.do(http.MethodPut, fmt.Sprintf("network_control/%d", profileID), map[string]any{
		"override": true, "override_mode": "denied", "override_until": 0, "macs": macs,
	}, nil)
}

// DeleteProfile supprime le profil (les appareils retrouvent l'accès).
func (c *Client) DeleteProfile(profileID int) error {
	err := c.do(http.MethodDelete, fmt.Sprintf("profile/%d", profileID), nil, nil)
	if err != nil {
		// Déjà supprimé à la main dans Freebox OS : rien à faire.
		var list []struct {
			ID int `json:"id"`
		}
		if c.do(http.MethodGet, "profile/", nil, &list) == nil {
			for _, p := range list {
				if p.ID == profileID {
					return err
				}
			}
			return nil
		}
	}
	return err
}

// ---------------------------------------------------------------------
// Réglages de la box
// ---------------------------------------------------------------------

// DHCPConfig : configuration du serveur DHCP de la box.
type DHCPConfig struct {
	Enabled      bool     `json:"enabled"`
	StickyAssign bool     `json:"sticky_assign"`
	Gateway      string   `json:"gateway"`
	Netmask      string   `json:"netmask"`
	RangeStart   string   `json:"ip_range_start"`
	RangeEnd     string   `json:"ip_range_end"`
	DNS          []string `json:"dns"`
}

func (c *Client) DHCP() (DHCPConfig, error) {
	var d DHCPConfig
	err := c.do(http.MethodGet, "dhcp/config/", nil, &d)
	return d, err
}

func (c *Client) SetDHCPEnabled(on bool) error {
	return c.do(http.MethodPut, "dhcp/config/", map[string]bool{"enabled": on}, nil)
}

func (c *Client) IPv6Enabled() (bool, error) {
	var v struct {
		Enabled bool `json:"ipv6_enabled"`
	}
	err := c.do(http.MethodGet, "connection/ipv6/config/", nil, &v)
	return v.Enabled, err
}

// SetIPv6Enabled change l'IPv6 de la box. La Freebox répond parfois
// « Impossible de récupérer l'état de la connexion » : nouvel essai avec
// l'objet complet, jusqu'à 4 fois, puis vérification de l'état réel.
func (c *Client) SetIPv6Enabled(on bool) error {
	var last error
	for i := 0; i < 4; i++ {
		if i > 0 {
			time.Sleep(time.Duration(i) * 2 * time.Second)
		}
		var body any = map[string]bool{"ipv6_enabled": on}
		if i%2 == 1 {
			var cur map[string]any
			if err := c.do(http.MethodGet, "connection/ipv6/config/", nil, &cur); err == nil {
				delete(cur, "ipv6ll")
				cur["ipv6_enabled"] = on
				body = cur
			}
		}
		last = c.do(http.MethodPut, "connection/ipv6/config/", body, nil)
		if last == nil {
			return nil
		}
		if errors.Is(last, ErrNoSettings) || errors.Is(last, ErrNotPaired) {
			return last
		}
		if v, err := c.IPv6Enabled(); err == nil && v == on {
			return nil // appliqué malgré l'erreur
		}
	}
	return last
}

// Lease : bail DHCP de la box (dynamique ou statique).
type Lease struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	Static   bool   `json:"is_static"`
}

// Leases retourne les baux dynamiques et statiques de la box.
func (c *Client) Leases() ([]Lease, error) {
	var dyn, sta []Lease
	if err := c.do(http.MethodGet, "dhcp/dynamic_lease/", nil, &dyn); err != nil {
		return nil, err
	}
	_ = c.do(http.MethodGet, "dhcp/static_lease/", nil, &sta)
	for i := range sta {
		sta[i].Static = true
	}
	return append(sta, dyn...), nil
}

// Host : appareil connu de la box.
type Host struct {
	Name   string
	Type   string
	MAC    string
	IPs    []string
	Active bool
}

// Hosts retourne les appareils connus du réseau local (noms donnés par
// la box ou par l'utilisateur dans Freebox OS).
func (c *Client) Hosts() ([]Host, error) {
	var raw []struct {
		PrimaryName string `json:"primary_name"`
		HostType    string `json:"host_type"`
		Active      bool   `json:"active"`
		L2          struct {
			ID string `json:"id"`
		} `json:"l2ident"`
		L3 []struct {
			Addr string `json:"addr"`
			AF   string `json:"af"`
		} `json:"l3connectivities"`
	}
	if err := c.do(http.MethodGet, "lan/browser/pub/", nil, &raw); err != nil {
		return nil, err
	}
	out := make([]Host, 0, len(raw))
	for _, h := range raw {
		x := Host{Name: h.PrimaryName, Type: h.HostType, MAC: strings.ToUpper(h.L2.ID), Active: h.Active}
		for _, l := range h.L3 {
			if l.AF == "ipv4" && l.Addr != "" {
				x.IPs = append(x.IPs, l.Addr)
			}
		}
		out = append(out, x)
	}
	return out, nil
}

// ---------------------------------------------------------------------
// Sauvegarde / restauration (survit à un plantage ou un redémarrage)
// ---------------------------------------------------------------------

// Saved mémorise l'état de la box avant la protection maison.
type Saved struct {
	Box         string     `json:"box"`
	DHCPEnabled bool       `json:"dhcp_enabled"`
	IPv6Enabled bool       `json:"ipv6_enabled"`
	DHCP        DHCPConfig `json:"dhcp"`
	Leases      []Lease    `json:"leases"`
	SavedAt     time.Time  `json:"saved_at"`
	IPv6Kept    bool       `json:"ipv6_kept,omitempty"`  // la box a refusé de couper l'IPv6
	ProfileID   int        `json:"profile_id,omitempty"` // profil de blocage créé par VicoVPN
}

// SaveSaved réécrit la sauvegarde (ajout du profil de blocage).
func SaveSaved(dir string, s *Saved) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, savedFile), b, 0o600)
}

// LoadSaved lit la sauvegarde (nil s'il n'y en a pas).
func LoadSaved(dir string) *Saved {
	b, err := os.ReadFile(filepath.Join(dir, savedFile))
	if err != nil {
		return nil
	}
	var s Saved
	if json.Unmarshal(b, &s) != nil || s.Box == "" {
		return nil
	}
	return &s
}

// Takeover sauvegarde l'état de la box puis coupe son IPv6 et son DHCP.
// Une sauvegarde déjà présente (plantage précédent) est conservée : c'est
// elle qui décrit l'état normal de la box.
func (c *Client) Takeover() (*Saved, error) {
	s := LoadSaved(c.dir)
	if s == nil {
		d, err := c.DHCP()
		if err != nil {
			return nil, err
		}
		v6, err := c.IPv6Enabled()
		if err != nil {
			return nil, err
		}
		leases, _ := c.Leases()
		s = &Saved{Box: c.box, DHCPEnabled: d.Enabled, IPv6Enabled: v6, DHCP: d, Leases: leases, SavedAt: time.Now()}
		b, _ := json.MarshalIndent(s, "", "  ")
		if err := os.WriteFile(filepath.Join(c.dir, savedFile), b, 0o600); err != nil {
			return nil, fmt.Errorf("sauvegarde des réglages de la box impossible : %w", err)
		}
	}
	// L'IPv6 qui refuse de se couper n'empêche pas la bascule (le DHCP est
	// l'essentiel) : c'est signalé par s.IPv6Kept.
	s.IPv6Kept = false
	if s.IPv6Enabled {
		if err := c.SetIPv6Enabled(false); err != nil {
			s.IPv6Kept = true
		}
	}
	if s.DHCPEnabled {
		if err := c.SetDHCPEnabled(false); err != nil {
			if !s.IPv6Kept {
				_ = c.SetIPv6Enabled(s.IPv6Enabled)
			}
			return s, fmt.Errorf("coupure du DHCP de la box : %w", err)
		}
	}
	return s, nil
}

// Restore remet la box dans l'état sauvegardé puis efface la sauvegarde.
func Restore(dir string) error {
	s := LoadSaved(dir)
	if s == nil {
		return nil
	}
	c := New(dir, s.Box)
	var errs []string
	// Profil de blocage d'abord : les appareils doivent retrouver l'accès
	// direct avant de revenir sur le DHCP de la box.
	if s.ProfileID > 0 {
		if err := c.DeleteProfile(s.ProfileID); err != nil {
			errs = append(errs, "profil : "+err.Error())
		} else {
			s.ProfileID = 0
			_ = SaveSaved(dir, s)
		}
	}
	if err := c.SetDHCPEnabled(s.DHCPEnabled); err != nil {
		errs = append(errs, "DHCP : "+err.Error())
	}
	if err := c.SetIPv6Enabled(s.IPv6Enabled); err != nil {
		errs = append(errs, "IPv6 : "+err.Error())
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, " ; "))
	}
	return os.Remove(filepath.Join(dir, savedFile))
}
