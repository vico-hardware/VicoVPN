// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 vico-hardware (Vico Studio) — https://github.com/vico-hardware/VicoVPN

//go:build windows

// vicovpn-ui : interface graphique VicoVPN (WebView2, style VicoMedia).
// Fenêtre standard-user qui pilote le client via le canal de commande
// local ctl — aucun privilège requis.
package main

import (
	"embed"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	webview2 "github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/vicovpn/vicovpn/internal/config"
	"github.com/vicovpn/vicovpn/internal/ctl"
)

//go:embed assets/index.html assets/vico-wallpaper.jpg assets/icon.ico assets/pubs
var assets embed.FS

// pubsJSON construit la liste des bannières Vico (assets/pubs/pubs.json +
// vidéos MP4 encodées en base64) injectée dans la page à la place de
// __PUBS__. En cas de problème : liste vide, la page s'affiche sans pub.
func pubsJSON() string {
	type entry struct {
		Nom     string `json:"nom"`
		Fichier string `json:"fichier,omitempty"`
		Lien    string `json:"lien"`
		MP4     string `json:"mp4,omitempty"`
	}
	raw, err := assets.ReadFile("assets/pubs/pubs.json")
	if err != nil {
		return "[]"
	}
	var list []entry
	if json.Unmarshal(raw, &list) != nil {
		return "[]"
	}
	out := make([]entry, 0, len(list))
	for _, e := range list {
		b, err := assets.ReadFile("assets/pubs/" + e.Fichier)
		if err != nil {
			continue
		}
		out = append(out, entry{Nom: e.Nom, Lien: e.Lien, MP4: base64.StdEncoding.EncodeToString(b)})
	}
	j, err := json.Marshal(out)
	if err != nil {
		return "[]"
	}
	return string(j)
}

// serviceDiag explique pourquoi le client (service VicoVPN) est
// injoignable. Fonctionne sous compte standard : lecture seule du
// gestionnaire de services. Réponse : « <code> <texte> » où code vaut
// absent | arrete | demarrage | marche | exe | inconnu.
func serviceDiag(dir string) string {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return "inconnu Gestionnaire de services inaccessible : " + err.Error()
	}
	defer windows.CloseServiceHandle(scm)
	name, _ := windows.UTF16PtrFromString("VicoVPN")
	h, err := windows.OpenService(scm, name, windows.SERVICE_QUERY_STATUS|windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		if err == windows.ERROR_SERVICE_DOES_NOT_EXIST {
			return "absent Le service VicoVPN n'est pas installé (case « Service » décochée à l'installation, ou installation interrompue)."
		}
		return "inconnu Service illisible : " + err.Error()
	}
	s := &mgr.Service{Name: "VicoVPN", Handle: h}
	defer s.Close()

	exeOK := true
	if cfg, err := s.Config(); err == nil {
		exe := strings.Trim(strings.SplitN(cfg.BinaryPathName, `" `, 2)[0], `"`)
		if i := strings.Index(strings.ToLower(exe), ".exe"); i > 0 {
			exe = exe[:i+4]
		}
		if _, err := os.Stat(exe); err != nil {
			exeOK = false
		}
	}
	if !exeOK {
		return "exe Le programme du service a disparu (souvent supprimé par l'antivirus) : réinstalle VicoVPN et ajoute une exclusion pour C:\\Program Files\\VicoVPN dans l'antivirus."
	}
	st, err := s.Query()
	if err != nil {
		return "inconnu État du service illisible : " + err.Error()
	}
	last := lastServiceError(dir)
	switch st.State {
	case svc.Running:
		return "marche Le service tourne mais ne répond pas encore — patiente quelques secondes." + last
	case svc.StartPending:
		return "demarrage Le service démarre…"
	default:
		msg := "Le service VicoVPN est arrêté"
		if st.Win32ExitCode != 0 && st.Win32ExitCode != 1077 {
			msg += fmt.Sprintf(" (erreur %d", st.Win32ExitCode)
			if st.ServiceSpecificExitCode != 0 {
				msg += fmt.Sprintf("/%d", st.ServiceSpecificExitCode)
			}
			msg += ")"
		}
		return "arrete " + msg + "." + last
	}
}

// lastServiceError retourne la dernière erreur de démarrage du service
// trouvée dans events.log (lisible ou non selon les droits du dossier).
func lastServiceError(dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, "events.log"))
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	for i := len(lines) - 1; i >= 0 && i >= len(lines)-200; i-- {
		l := lines[i]
		if strings.Contains(l, "service : démarré") || strings.Contains(l, "réinstallé et démarré") {
			return ""
		}
		if strings.Contains(l, "démarrage impossible") || strings.Contains(l, "réparation :") {
			return " Dernière erreur : " + strings.TrimSpace(l)
		}
	}
	return ""
}

// repairService relance « vicovpn-client.exe -service repair » en
// administrateur (invite UAC) : réinstalle et démarre le service.
func repairService() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	exe := filepath.Join(filepath.Dir(self), "vicovpn-client.exe")
	if _, err := os.Stat(exe); err != nil {
		return fmt.Errorf("vicovpn-client.exe introuvable à côté de l'interface (supprimé par l'antivirus ?) : réinstalle VicoVPN")
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	args, _ := windows.UTF16PtrFromString("-service repair")
	cwd, _ := windows.UTF16PtrFromString(filepath.Dir(exe))
	if err := windows.ShellExecute(0, verb, file, args, cwd, windows.SW_HIDE); err != nil {
		if err == windows.ERROR_CANCELLED {
			return fmt.Errorf("autorisation administrateur refusée")
		}
		return err
	}
	return nil
}

// prefPath : préférences de l'interface (par utilisateur Windows).
func prefPath() string {
	base, err := os.UserConfigDir()
	if err != nil {
		base = os.TempDir()
	}
	return filepath.Join(base, "VicoVPN", "interface.json")
}

// pref lit (value == "") ou écrit une préférence de l'interface.
func pref(key, value string) string {
	m := map[string]string{}
	if b, err := os.ReadFile(prefPath()); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	if value == "" {
		return m[key]
	}
	m[key] = value
	_ = os.MkdirAll(filepath.Dir(prefPath()), 0o700)
	if b, err := json.MarshalIndent(m, "", "  "); err == nil {
		_ = os.WriteFile(prefPath(), b, 0o600)
	}
	return value
}

// setAutorun ajoute ou retire VicoVPN du démarrage de la session Windows
// (HKCU\...\Run, propre à l'utilisateur, sans droits administrateur).
func setAutorun(on bool) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if !on {
		if err := k.DeleteValue("VicoVPN"); err != nil && err != registry.ErrNotExist {
			return err
		}
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return k.SetStringValue("VicoVPN", `"`+exe+`"`)
}

// openURL ouvre un lien https dans le navigateur par défaut.
func openURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("lien refusé: %q", raw)
	}
	// https partout ; http seulement vers une adresse locale (interface
	// d'administration de la box).
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || ip == nil || !ip.IsPrivate() {
			return fmt.Errorf("lien refusé: %q", raw)
		}
	}
	verb, _ := windows.UTF16PtrFromString("open")
	file, err := windows.UTF16PtrFromString(u.String())
	if err != nil {
		return err
	}
	return windows.ShellExecute(0, verb, file, nil, nil, windows.SW_SHOWNORMAL)
}

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

	htmlRaw, err := assets.ReadFile("assets/index.html")
	if err != nil {
		fatal(err)
	}
	wall, err := assets.ReadFile("assets/vico-wallpaper.jpg")
	if err != nil {
		fatal(err)
	}
	html := strings.ReplaceAll(string(htmlRaw), "__WALLPAPER_B64__",
		base64.StdEncoding.EncodeToString(wall))
	html = strings.Replace(html, "__PUBS__", pubsJSON(), 1)

	w := webview2.NewWithOptions(webview2.WebViewOptions{
		WindowOptions: webview2.WindowOptions{
			Title:  "VicoVPN",
			Width:  1060,
			Height: 1040,
			Center: true,
		},
	})
	if w == nil {
		fatal(fmt.Errorf("webview2 indisponible (runtime WebView2 requis)"))
	}
	defer w.Destroy()
	setWindowIcon(w.Window())
	fitToScreen(w.Window())

	// Pont JS -> ctl : window.vicocmd("STATUS") etc.
	if err := w.Bind("vicocmd", func(arg string) (string, error) {
		parts := strings.Fields(arg)
		if len(parts) == 0 {
			return "ERR commande vide", nil
		}
		resp, err := ctl.Command(dir, parts[0], parts[1:]...)
		if err != nil {
			return "ERR " + err.Error(), nil
		}
		return resp, nil
	}); err != nil {
		fatal(err)
	}

	// Préférences de l'interface (guide déjà vu…).
	if err := w.Bind("vicopref", func(key, value string) (string, error) {
		return pref(key, value), nil
	}); err != nil {
		fatal(err)
	}

	// Ouverture de l'appli à l'ouverture de session Windows (option
	// « relancer la protection maison au démarrage du PC »).
	if err := w.Bind("vicoautorun", func(on bool) (string, error) {
		if err := setAutorun(on); err != nil {
			return "ERR " + err.Error(), nil
		}
		return "OK", nil
	}); err != nil {
		fatal(err)
	}

	// Diagnostic / réparation quand le service est injoignable.
	if err := w.Bind("vicodiag", func() (string, error) {
		return serviceDiag(dir), nil
	}); err != nil {
		fatal(err)
	}
	if err := w.Bind("vicorepair", func() (string, error) {
		if err := repairService(); err != nil {
			return "ERR " + err.Error(), nil
		}
		return "OK", nil
	}); err != nil {
		fatal(err)
	}

	// Clic sur une bannière : ouverture dans le navigateur par défaut.
	if err := w.Bind("vicoopen", func(link string) (string, error) {
		if err := openURL(link); err != nil {
			return "ERR " + err.Error(), nil
		}
		return "OK", nil
	}); err != nil {
		fatal(err)
	}

	w.SetHtml(html)
	w.Run()
}

var (
	user32                = windows.NewLazySystemDLL("user32.dll")
	procLoadImageW        = user32.NewProc("LoadImageW")
	procSendMessageW      = user32.NewProc("SendMessageW")
	procGetDpiForWindow   = user32.NewProc("GetDpiForWindow")
	procMonitorFromWindow = user32.NewProc("MonitorFromWindow")
	procGetMonitorInfoW   = user32.NewProc("GetMonitorInfoW")
	procSetWindowPos      = user32.NewProc("SetWindowPos")
)

// setWindowIcon charge l'icône embarquée depuis un fichier temporaire et
// l'applique à la fenêtre (grande + petite icône de la barre de titre).
func setWindowIcon(hwnd unsafe.Pointer) {
	ico, err := assets.ReadFile("assets/icon.ico")
	if err != nil || hwnd == nil {
		return
	}
	tmp := filepath.Join(os.TempDir(), "vicovpn-icon.ico")
	if b, err := os.ReadFile(tmp); err != nil || string(b) != string(ico) {
		_ = os.WriteFile(tmp, ico, 0o600)
	}
	name, err := windows.UTF16PtrFromString(tmp)
	if err != nil {
		return
	}
	// LoadImageW(NULL, path, IMAGE_ICON=1, 0, 0, LR_LOADFROMFILE=0x10)
	h, _, _ := procLoadImageW.Call(0, uintptr(unsafe.Pointer(name)), 1, 0, 0, 0x10)
	if h == 0 {
		return
	}
	const wmSetIcon = 0x0080
	for _, iconType := range []uintptr{1, 0} { // ICON_BIG, ICON_SMALL
		procSendMessageW.Call(uintptr(hwnd), wmSetIcon, iconType, h)
	}
}

// Taille idéale de la fenêtre (en pixels « logiques » à 100 %) : colonne
// principale + journal à droite, sans défilement sur l'onglet Système.
const (
	winW = 1060
	winH = 1040
)

type rect32 struct{ L, T, R, B int32 }

type monitorInfo struct {
	Size      uint32
	Mon, Work rect32
	Flags     uint32
}

// fitToScreen dimensionne et centre la fenêtre selon l'écran où elle
// s'ouvre : taille idéale mise à l'échelle Windows (DPI), réduite à 95 %
// de la zone utile si l'écran est plus petit. La page s'adapte ensuite
// d'elle-même (mise à l'échelle automatique).
func fitToScreen(hwnd unsafe.Pointer) {
	if hwnd == nil {
		return
	}
	h := uintptr(hwnd)
	dpi := int32(96)
	if procGetDpiForWindow.Find() == nil {
		if r, _, _ := procGetDpiForWindow.Call(h); r != 0 {
			dpi = int32(r)
		}
	}
	mon, _, _ := procMonitorFromWindow.Call(h, 2) // MONITOR_DEFAULTTONEAREST
	var mi monitorInfo
	mi.Size = uint32(unsafe.Sizeof(mi))
	if r, _, _ := procGetMonitorInfoW.Call(mon, uintptr(unsafe.Pointer(&mi))); r == 0 {
		return
	}
	areaW, areaH := mi.Work.R-mi.Work.L, mi.Work.B-mi.Work.T
	w, ht := winW*dpi/96, winH*dpi/96
	if max := areaW * 95 / 100; w > max {
		w = max
	}
	if max := areaH * 95 / 100; ht > max {
		ht = max
	}
	x, y := mi.Work.L+(areaW-w)/2, mi.Work.T+(areaH-ht)/2
	const swpNoZOrder, swpNoActivate = 0x0004, 0x0010
	procSetWindowPos.Call(h, 0, uintptr(x), uintptr(y), uintptr(w), uintptr(ht), swpNoZOrder|swpNoActivate)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "vicovpn-ui:", err)
	os.Exit(1)
}
