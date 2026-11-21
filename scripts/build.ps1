# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 vico-hardware (Vico Studio)
# VicoVPN — compilation de tous les exécutables dans bin\ (+ installateur).
#
#   powershell -ExecutionPolicy Bypass -File scripts\build.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\build.ps1 -Installer
#
# -Installer : produit aussi dist\VicoVPN-Setup-<version>.exe (Inno Setup 6/7).
param([switch]$Installer)

$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)

# Un exe en cours d'exécution ne peut pas être remplacé : prévenir clairement.
$svc = Get-CimInstance Win32_Service -Filter "Name='VicoVPN'" -ErrorAction SilentlyContinue
if ($svc -and $svc.State -eq 'Running' -and $svc.PathName -like "*$((Resolve-Path bin).Path)*") {
    Write-Host "Le service VicoVPN tourne depuis bin\ : arrête-le d'abord (admin) : net stop VicoVPN" -ForegroundColor Yellow
    exit 1
}

$gui = '-H windowsgui'
$targets = @(
    @{ out = 'bin\vicovpn-client.exe';  pkg = './cmd/client';  flags = $gui },
    @{ out = 'bin\vicovpn-ui.exe';      pkg = './cmd/ui';      flags = $gui },
    @{ out = 'bin\vicovpn-ctl.exe';     pkg = './cmd/ctl';     flags = '' },
    @{ out = 'bin\vicovpn-recover.exe'; pkg = './cmd/recover'; flags = '' }
)
foreach ($t in $targets) {
    Write-Host "go build $($t.pkg) -> $($t.out)"
    $goArgs = @('build', '-trimpath')
    if ($t.flags) { $goArgs += @('-ldflags', $t.flags) }
    $goArgs += @('-o', $t.out, $t.pkg)
    & go @goArgs
    if ($LASTEXITCODE -ne 0) { throw "échec de compilation : $($t.pkg)" }
}

Write-Host "Tests unitaires (protocole, politique)…"
go test ./internal/proto ./internal/engine
if ($LASTEXITCODE -ne 0) { throw "tests en échec" }

if ($Installer) {
    $iscc = @(
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
        "${env:ProgramFiles(x86)}\Inno Setup 7\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 7\ISCC.exe",
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $iscc) { throw "Inno Setup (ISCC.exe) introuvable" }
    & $iscc installer\vicovpn.iss
    if ($LASTEXITCODE -ne 0) { throw "échec de l'installateur" }
}
Write-Host "OK" -ForegroundColor Green
