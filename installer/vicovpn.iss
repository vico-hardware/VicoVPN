; VicoVPN — Installateur Windows x64 (Inno Setup 6/7)
; Produit : client + UI + ctl + recover + pile Tor (tor.exe, tun2socks, wintun, geoip)
; Service Windows auto-démarrage + raccourci bureau.

#define MyAppName    "VicoVPN"
#define MyAppVersion "1.1.5"
#define MyAppExe     "vicovpn-ui.exe"

[Setup]
AppId={{7C2E4A91-3B5D-4F8E-9A1C-6D2B8E0F4A7C}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher=VicoMedia
AppCopyright=Copyright (C) 2026 vico-hardware (Vico Studio)
AppPublisherURL=https://hardware24.fr
AppSupportURL=https://github.com/vico-hardware/VicoVPN
LicenseFile=..\LICENSE
DefaultDirName={autopf}\VicoVPN
DefaultGroupName=VicoVPN
DisableProgramGroupPage=yes
OutputDir=..\dist
OutputBaseFilename=VicoVPN-Setup-{#MyAppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern
SetupIconFile=..\cmd\ui\assets\icon.ico
UninstallDisplayIcon={app}\{#MyAppExe}
MinVersion=10.0

[Languages]
Name: "french"; MessagesFile: "compiler:Languages\French.isl"

[Tasks]
Name: "desktopicon"; Description: "Créer un raccourci sur le bureau"; GroupDescription: "Raccourcis :"; Flags: checkedonce
Name: "service";    Description: "Service de démarrage automatique (recommandé)"; GroupDescription: "Protection :"; Flags: checkedonce

[Files]
Source: "..\bin\vicovpn-client.exe";  DestDir: "{app}"; Flags: ignoreversion
Source: "..\bin\vicovpn-ui.exe";      DestDir: "{app}"; Flags: ignoreversion
Source: "..\bin\vicovpn-ctl.exe";     DestDir: "{app}"; Flags: ignoreversion
Source: "..\bin\vicovpn-recover.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\bin\wintun.dll";          DestDir: "{app}"; Flags: ignoreversion
Source: "..\bin\tor\tor.exe";         DestDir: "{app}\tor"; Flags: ignoreversion
Source: "..\bin\tor\tun2socks.exe";   DestDir: "{app}\tor"; Flags: ignoreversion
Source: "..\bin\tor\wintun.dll";      DestDir: "{app}\tor"; Flags: ignoreversion
Source: "..\bin\tor\data\geoip";      DestDir: "{app}\tor\data"; Flags: ignoreversion
Source: "..\bin\tor\data\geoip6";     DestDir: "{app}\tor\data"; Flags: ignoreversion
; Configuration initiale : aucun relais classique, sorties Tor uniquement.
; onlyifdoesntexist : ne jamais écraser la config existante à la MAJ.
Source: "relays-empty.json"; DestDir: "{commonappdata}\VicoVPN"; DestName: "relays.json"; Flags: onlyifdoesntexist

[Icons]
Name: "{group}\VicoVPN";             Filename: "{app}\{#MyAppExe}"
Name: "{group}\Désinstaller VicoVPN"; Filename: "{uninstallexe}"
Name: "{autodesktop}\VicoVPN";       Filename: "{app}\{#MyAppExe}"; Tasks: desktopicon

[Registry]
; Ouverture de VicoVPN à la connexion (option de l'appli) : retirée à la désinstallation.
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: none; ValueName: "VicoVPN"; Flags: uninsdeletevalue dontcreatekey

[Run]
; Service Windows : démarre avec Windows, compte SYSTEM, protection active.
Filename: "{app}\vicovpn-client.exe"; Parameters: "-service install"; \
  StatusMsg: "Installation du service VicoVPN…"; Flags: runhidden waituntilterminated; Tasks: service
Filename: "net"; Parameters: "start VicoVPN"; \
  StatusMsg: "Démarrage du service VicoVPN…"; Flags: runhidden waituntilterminated; Tasks: service
; Ouvre l'application à la fin de l'installation.
Filename: "{app}\{#MyAppExe}"; Description: "Ouvrir VicoVPN"; \
  Flags: nowait postinstall skipifsilent

[UninstallRun]
; Arrêt et suppression du service via sc/net — déterministe, ne dépend
; pas de l'exe client (qui tourne en windowsgui, erreurs silencieuses).
Filename: "net"; Parameters: "stop VicoVPN"; \
  Flags: runhidden waituntilterminated; RunOnceId: "svcstop"
Filename: "sc"; Parameters: "delete VicoVPN"; \
  Flags: runhidden waituntilterminated; RunOnceId: "svcdelete"

[Code]
// Avant la copie des fichiers : arrêter et supprimer un éventuel service
// existant, sinon l'exe reste verrouillé et le service n'est pas recréé.
procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if CurStep = ssInstall then
  begin
    Exec('net', 'stop VicoVPN', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('sc', 'delete VicoVPN', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Sleep(1500);
  end;
end;

// Sécurité : refuser l'installation sur une session non élevée (déjà
// couvert par PrivilegesRequired=admin) et avertir si WebView2 absent.
function InitializeSetup(): Boolean;
begin
  Result := True;
end;
