# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 vico-hardware (Vico Studio)
# Uninstall-client.ps1 — désinstallation propre de VicoVPN.
# À lancer en administrateur.
#
#   powershell -ExecutionPolicy Bypass -File uninstall-client.ps1 [-KeepConfig]
#
# Ordre : arrêt du service -> désinstallation -> récupération des règles
# réseau (uniquement les objets VicoVPN-*) -> suppression des fichiers.
param(
    [string]$InstallDir = "$env:ProgramFiles\VicoVPN",
    [switch]$KeepConfig   # conserver %ProgramData%\VicoVPN (identité, config)
)

$ErrorActionPreference = "Continue"

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Droits administrateur requis."
}

Write-Host "== Désinstallation VicoVPN =="

# 1. Service
$svc = Get-Service VicoVPN -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -eq "Running") { Stop-Service VicoVPN -Force -ErrorAction SilentlyContinue }
    & "$InstallDir\vicovpn-client.exe" -service uninstall 2>$null
    if (-not $?) { sc.exe delete VicoVPN | Out-Null }
    Write-Host "Service supprimé."
} else {
    Write-Host "Service absent."
}

# 2. Règles réseau résiduelles (routes /1, pare-feu VicoVPN-*)
$recover = Join-Path $InstallDir "vicovpn-recover.exe"
if (Test-Path $recover) {
    & $recover
    Write-Host "Récupération réseau effectuée (règles VicoVPN-* retirées)."
} else {
    # Sans le binaire : suppression manuelle des règles pare-feu.
    Get-NetFirewallRule -DisplayName "VicoVPN-*" -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
    route delete 0.0.0.0 mask 128.0.0.0 2>$null | Out-Null
    route delete 128.0.0.0 mask 128.0.0.0 2>$null | Out-Null
    Write-Host "Règles pare-feu VicoVPN-* supprimées (routes à vérifier)."
}

# 3. Fichiers
if (Test-Path $InstallDir) {
    Remove-Item $InstallDir -Recurse -Force
    Write-Host "Binaires supprimés : $InstallDir"
}
if (-not $KeepConfig) {
    $cfg = "$env:ProgramData\VicoVPN"
    if (Test-Path $cfg) {
        Remove-Item $cfg -Recurse -Force
        Write-Host "Configuration supprimée : $cfg"
    }
} else {
    Write-Host "Configuration conservée : $env:ProgramData\VicoVPN"
}

# 4. Raccourci bureau
$lnk = "$env:USERPROFILE\Desktop\VicoVPN.lnk"
if (Test-Path $lnk) { Remove-Item $lnk -Force }

Write-Host "Désinstallation terminée."
