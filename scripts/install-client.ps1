# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 vico-hardware (Vico Studio)
# Install-client.ps1 — installation du client VicoVPN sur Windows 11.
# À lancer en administrateur :
#   powershell -ExecutionPolicy Bypass -File install-client.ps1 [-ConfigDir <dossier>]
#
# Ce que fait le script :
#   1. Copie les binaires dans %ProgramFiles%\VicoVPN
#   2. Crée %ProgramData%\VicoVPN (config + identité + canal ctl)
#   3. Génère l'identité client si absente
#   4. Installe le service Windows VicoVPN (démarrage automatique)
#   5. Raccourci bureau pour l'interface (optionnel)
#
# Le coupe-circuit n'est PAS désactivé : la protection est réelle.
# Pour un test sans pare-feu : relancer avec -NoFirewall (laboratoire).
param(
    [string]$ConfigDir = "$env:ProgramData\VicoVPN",
    [string]$BinDir = (Join-Path $PSScriptRoot "..\bin"),
    [switch]$NoFirewall,
    [switch]$NoShortcut
)

$ErrorActionPreference = "Stop"
$dst = "$env:ProgramFiles\VicoVPN"
$exe = Join-Path $dst "vicovpn-client.exe"

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Droits administrateur requis."
}

Write-Host "== Installation VicoVPN =="

# 1. Binaires
New-Item -ItemType Directory -Force $dst | Out-Null
foreach ($f in @("vicovpn-client.exe","vicovpn-ctl.exe","vicovpn-recover.exe","vicovpn-ui.exe","wintun.dll")) {
    $src = Join-Path $BinDir $f
    if (-not (Test-Path $src)) { throw "binaire manquant : $src" }
    Copy-Item $src $dst -Force
}
Write-Host "Binaires copiés dans $dst"

# 2. Dossier de configuration
New-Item -ItemType Directory -Force $ConfigDir | Out-Null

# 3. Identité client (si relays.json absent)
$cfgFile = Join-Path $ConfigDir "relays.json"
if (-not (Test-Path $cfgFile)) {
    & $exe -gen-identity -config $ConfigDir | Out-Null
    Write-Host "Identité générée."
    Write-Host "IMPORTANT : copiez testdata\relays.example.json vers $cfgFile"
    Write-Host "           et renseignez les relais enrôlés."
} else {
    Write-Host "Configuration existante conservée : $cfgFile"
}

# 4. Service Windows
$svcArgs = @("-service","install","-config",$ConfigDir)
if ($NoFirewall) { $svcArgs += "-no-firewall" }
& $exe @svcArgs
Start-Service VicoVPN -ErrorAction SilentlyContinue

# 5. Raccourci bureau (interface)
if (-not $NoShortcut) {
    $lnk = "$env:USERPROFILE\Desktop\VicoVPN.lnk"
    $ws = New-Object -ComObject WScript.Shell
    $s = $ws.CreateShortcut($lnk)
    $s.TargetPath = Join-Path $dst "vicovpn-ui.exe"
    $s.Arguments = "-config `"$ConfigDir`""
    $s.Description = "VicoVPN — protection VPN"
    $s.Save()
    Write-Host "Raccourci bureau créé : $lnk"
}

Write-Host ""
Write-Host "Installation terminée."
Write-Host "  Service : Get-Service VicoVPN"
Write-Host "  GUI     : vicovpn-ui.exe (ou raccourci bureau)"
Write-Host "  Récup.  : vicovpn-recover.exe (hors ligne, retire les règles VicoVPN)"
