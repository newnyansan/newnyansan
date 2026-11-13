; Inno Setup script for SafeSweep. Build with:  ISCC /DAppVersion=0.3.0 installer.iss
#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{8F3C2B71-5E4A-4C1D-9B6F-2A7E0D5C9E14}
AppName=SafeSweep
AppVersion={#AppVersion}
AppPublisher=SafeSweep
AppComments=Virus scanner and junk cleaner with a Review folder
DefaultDirName={localappdata}\Programs\SafeSweep
DefaultGroupName=SafeSweep
DisableProgramGroupPage=yes
; Installs for the current user only: no administrator rights needed.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=..\..\dist
OutputBaseFilename=SafeSweep-Setup-{#AppVersion}
SetupIconFile=..\..\assets\icon.ico
UninstallDisplayIcon={app}\SafeSweep.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "autocheck"; Description: "Check for threats &automatically every day (recommended)"; GroupDescription: "Protection:"
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"

[Files]
Source: "..\..\dist\SafeSweep\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\SafeSweep"; Filename: "{app}\SafeSweep.exe"; AppUserModelID: "SafeSweep.App"
Name: "{group}\SafeSweep self-test"; Filename: "{app}\safesweep-cli.exe"; Parameters: "selftest"
Name: "{group}\Uninstall SafeSweep"; Filename: "{uninstallexe}"
Name: "{autodesktop}\SafeSweep"; Filename: "{app}\SafeSweep.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\safesweep-cli.exe"; Parameters: "schedule on --quiet"; Flags: runhidden; Tasks: autocheck
Filename: "{app}\SafeSweep.exe"; Description: "Start SafeSweep now"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{app}\safesweep-cli.exe"; Parameters: "schedule off --quiet"; Flags: runhidden; RunOnceId: "RemoveDailyCheck"

; Your settings and the Review folder (%LOCALAPPDATA%\SafeSweep) are kept on uninstall,
; so nothing waiting in review is lost. Delete that folder yourself if you want it gone.
