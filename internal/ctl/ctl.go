// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 vico-hardware (Vico Studio) — https://github.com/vico-hardware/VicoVPN

// Package ctl implémente le canal de commande local du client : un petit
// serveur TCP sur 127.0.0.1 protégé par un jeton aléatoire stocké dans le
// dossier de données (ACL NTFS restrictive). V2 : named pipe avec descripteur
// de sécurité — voir docs/LIMITES.md.
package ctl

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// AddrFile / TokenFile : fichiers du canal de commande.
	AddrFile  = "ctl.addr"
	TokenFile = "ctl.token"
	// DefaultPort est le port TCP bouclé par défaut.
	DefaultPort = 47819
)

// TokenPath retourne le chemin du jeton.
func TokenPath(dir string) string { return filepath.Join(dir, TokenFile) }

// AddrPath retourne le chemin du fichier d'adresse.
func AddrPath(dir string) string { return filepath.Join(dir, AddrFile) }

// EnsureToken crée le jeton s'il n'existe pas et retourne son contenu.
func EnsureToken(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	p := TokenPath(dir)
	if b, err := os.ReadFile(p); err == nil && len(b) >= 16 {
		return strings.TrimSpace(string(b)), nil
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(buf)
	if err := os.WriteFile(p, []byte(tok), 0o600); err != nil {
		return "", err
	}
	return tok, nil
}

// Handler est appelé pour chaque commande reçue ; elle retourne la réponse.
type Handler func(cmd string, args []string) string

// Server écoute sur 127.0.0.1:port et dispatche vers h.
type Server struct {
	ln     net.Listener
	token  string
	handle Handler
}

// Listen démarre le serveur de commande.
func Listen(dir string, port int, h Handler) (*Server, error) {
	token, err := EnsureToken(dir)
	if err != nil {
		return nil, err
	}
	auto := port == 0
	if auto {
		port = DefaultPort
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil && auto {
		// Port par défaut occupé ou réservé par Windows (plages exclues
		// Hyper-V/WSL/Docker) : port libre choisi par le système. Les
		// clients lisent l'adresse réelle dans ctl.addr.
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		return nil, fmt.Errorf("ctl: écoute: %w", err)
	}
	if err := os.WriteFile(AddrPath(dir), []byte(ln.Addr().String()), 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	s := &Server{ln: ln, token: token, handle: h}
	go s.acceptLoop()
	return s, nil
}

func (s *Server) acceptLoop() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.serve(c)
	}
}

func (s *Server) serve(c net.Conn) {
	defer c.Close()
	// Les commandes DNS (netsh/PowerShell par carte) peuvent dépasser
	// quelques secondes — deadline large.
	_ = c.SetDeadline(time.Now().Add(60 * time.Second))
	sc := bufio.NewScanner(c)
	if !sc.Scan() {
		return
	}
	line := strings.TrimSpace(sc.Text())
	parts := strings.Fields(line)
	if len(parts) == 0 || parts[0] != s.token {
		fmt.Fprintln(c, "ERR auth")
		return
	}
	if len(parts) < 2 {
		fmt.Fprintln(c, "ERR usage")
		return
	}
	resp := s.handle(parts[1], parts[2:])
	fmt.Fprintln(c, resp)
}

// Close arrête le serveur.
func (s *Server) Close() error { return s.ln.Close() }

// Command envoie une commande au serveur et retourne la réponse.
func Command(dir, cmd string, args ...string) (string, error) {
	addrB, err := os.ReadFile(AddrPath(dir))
	if err != nil {
		return "", fmt.Errorf("ctl: %w (le client tourne-t-il ?)", err)
	}
	token, err := EnsureToken(dir)
	if err != nil {
		return "", err
	}
	conn, err := net.DialTimeout("tcp", strings.TrimSpace(string(addrB)), 3*time.Second)
	if err != nil {
		return "", fmt.Errorf("ctl: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(65 * time.Second))
	line := token + " " + cmd
	if len(args) > 0 {
		line += " " + strings.Join(args, " ")
	}
	fmt.Fprintln(conn, line)
	out, err := io.ReadAll(conn)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
