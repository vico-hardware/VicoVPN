# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 vico-hardware (Vico Studio)
# VicoVPN — télécharge les binaires tiers dans bin\ (utilisé par la CI,
# utilisable aussi en local) :
#   bin\wintun.dll, bin\tor\{tor.exe, tun2socks.exe, wintun.dll, data\geoip, data\geoip6}
#
#   powershell -ExecutionPolicy Bypass -File scripts\fetch-deps.ps1
#
# wintun et tun2socks sont figés et vérifiés par empreinte SHA-256.
# Tor : dernière version stable du « Tor Expert Bundle », vérifiée contre
# le fichier d'empreintes publié par le projet Tor.
param([string]$Dest = 'bin')

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Set-Location (Split-Path -Parent $PSScriptRoot)

$tmp = Join-Path ([IO.Path]::GetTempPath()) 'vicovpn-deps'
if (Test-Path $tmp) { Remove-Item $tmp -Recurse -Force }
New-Item -ItemType Directory -Force $tmp, "$Dest\tor\data" | Out-Null

function Get-File([string]$Url, [string]$Out) {
    Write-Host "  téléchargement $Url"
    Invoke-WebRequest -Uri $Url -OutFile $Out -UseBasicParsing
}
function Assert-Sha256([string]$Path, [string]$Expected) {
    $h = (Get-FileHash $Path -Algorithm SHA256).Hash.ToLower()
    if ($h -ne $Expected.ToLower()) { throw "Empreinte inattendue pour $Path : $h (attendu $Expected)" }
}

# --- wintun 0.14.1 (pilote signé WireGuard LLC) -----------------------------
Write-Host 'wintun 0.14.1'
$wz = Join-Path $tmp 'wintun.zip'
Get-File 'https://www.wintun.net/builds/wintun-0.14.1.zip' $wz
Expand-Archive $wz (Join-Path $tmp 'wintun') -Force
$dll = Join-Path $tmp 'wintun\wintun\bin\amd64\wintun.dll'
Assert-Sha256 $dll 'e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce'
Copy-Item $dll "$Dest\wintun.dll" -Force
Copy-Item $dll "$Dest\tor\wintun.dll" -Force

# --- tun2socks v2.7.0 --------------------------------------------------------
Write-Host 'tun2socks v2.7.0'
$tz = Join-Path $tmp 'tun2socks.zip'
Get-File 'https://github.com/xjasonlyu/tun2socks/releases/download/v2.7.0/tun2socks-windows-amd64.zip' $tz
Expand-Archive $tz (Join-Path $tmp 'tun2socks') -Force
$t2s = Get-ChildItem (Join-Path $tmp 'tun2socks') -Recurse -Filter 'tun2socks*.exe' | Select-Object -First 1
if (-not $t2s) { throw 'tun2socks.exe introuvable dans l''archive' }
Assert-Sha256 $t2s.FullName '076b3c3d6a372bae3f49f2b415a4105f70c30a3ed3caaed7979390e649892559'
Copy-Item $t2s.FullName "$Dest\tor\tun2socks.exe" -Force

# --- Tor Expert Bundle (dernière version stable) ----------------------------
$base = 'https://dist.torproject.org/torbrowser/'
$index = (Invoke-WebRequest -Uri $base -UseBasicParsing).Content
$versions = [regex]::Matches($index, 'href="(\d+\.\d+(?:\.\d+)?)/"') |
    ForEach-Object { $_.Groups[1].Value } | Sort-Object { [version]$_ } -Descending -Unique
$done = $false
foreach ($v in $versions) {
    $name = "tor-expert-bundle-windows-x86_64-$v.tar.gz"
    try { $sums = (Invoke-WebRequest -Uri "$base$v/sha256sums-signed-build.txt" -UseBasicParsing).Content } catch { continue }
    $line = ($sums -split "`n") | Where-Object { $_ -match [regex]::Escape($name) } | Select-Object -First 1
    if (-not $line) { continue }
    Write-Host "Tor Expert Bundle $v"
    $tb = Join-Path $tmp $name
    Get-File "$base$v/$name" $tb
    Assert-Sha256 $tb (($line.Trim() -split '\s+')[0])
    $tx = Join-Path $tmp 'tor'
    New-Item -ItemType Directory -Force $tx | Out-Null
    tar -xzf $tb -C $tx
    if ($LASTEXITCODE -ne 0) { throw 'extraction du Tor Expert Bundle impossible' }
    # l'arborescence du bundle varie selon les versions : chercher les fichiers
    foreach ($f in @(@('tor.exe', "$Dest\tor\tor.exe"), @('geoip', "$Dest\tor\data\geoip"), @('geoip6', "$Dest\tor\data\geoip6"))) {
        $src = Get-ChildItem $tx -Recurse -File -Filter $f[0] | Select-Object -First 1
        if (-not $src) { throw "$($f[0]) introuvable dans le Tor Expert Bundle" }
        Copy-Item $src.FullName $f[1] -Force
    }
    $done = $true
    break
}
if (-not $done) { throw 'aucun Tor Expert Bundle trouvé sur dist.torproject.org' }

Remove-Item $tmp -Recurse -Force
Write-Host 'Dépendances prêtes dans' (Resolve-Path $Dest) -ForegroundColor Green
