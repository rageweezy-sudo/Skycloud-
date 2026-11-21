#ifndef PackageDir
  #define PackageDir "..\build\windows\app\AccountPrivacy"
#endif
#ifndef InstallerOutput
  #define InstallerOutput "..\dist"
#endif

[Setup]
AppId={{E3F4CC3B-3EF8-4F71-A738-137F42D00259}
AppName=Account Privacy
AppVersion=0.1.0
DefaultDirName={localappdata}\Programs\AccountPrivacy
DefaultGroupName=Account Privacy
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
MinVersion=10.0.22000
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#InstallerOutput}
OutputBaseFilename=AccountPrivacy-Setup-x64
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\AccountPrivacy.exe

[Files]
Source: "{#PackageDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\Account Privacy"; Filename: "{app}\AccountPrivacy.exe"; AppUserModelID: "AccountPrivacy.Desktop"

[Run]
Filename: "{app}\AccountPrivacy.exe"; Description: "Open Account Privacy"; Flags: nowait postinstall skipifsilent unchecked
