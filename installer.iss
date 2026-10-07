; Inno Setup Script for GameTracker
; Generates GameTracker_Setup.exe for 1-click Windows installation

#define MyAppName "GameTracker"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "GameTracker Project"
#define MyAppExeName "GameTrackerService.exe"
#define MyCliExeName "gametracker.exe"

[Setup]
AppId={{E2481489-A28D-4F5B-9A74-7221BC22B8C1}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputBaseFilename=GameTracker_Setup_v{#MyAppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=force

[Files]
Source: "dist\GameTrackerService.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "dist\gametracker.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "README.md"; DestDir: "{app}"; Flags: isreadme

[Icons]
Name: "{group}\GameTracker Status"; Filename: "{cmd}"; Parameters: "/K ""{app}\gametracker.exe"" status"
Name: "{group}\GameTracker List Games"; Filename: "{cmd}"; Parameters: "/K ""{app}\gametracker.exe"" list-games"
Name: "{group}\GameTracker Set Password"; Filename: "{cmd}"; Parameters: "/K ""{app}\gametracker.exe"" set-password"
Name: "{group}\Uninstall GameTracker"; Filename: "{uninstallexe}"

[Run]
; Register and start Windows Task running on system boot with SYSTEM privileges
Filename: "schtasks"; Parameters: "/Create /F /SC ONSTART /TN ""GameTrackerService"" /TR """"{app}\GameTrackerService.exe"""" /RU ""SYSTEM"" /RL ""HIGHEST"""; Flags: runhidden
Filename: "schtasks"; Parameters: "/Run /TN ""GameTrackerService"""; Flags: runhidden
; Show status to user upon finishing
Filename: "{cmd}"; Parameters: "/C ""{app}\gametracker.exe"" status & pause"; Description: "Перевірити статус служби зараз"; Flags: postinstall nowait skipifsilent

[UninstallRun]
; Stop and delete the service task before removing files
Filename: "taskkill"; Parameters: "/F /IM GameTrackerService.exe"; Flags: runhidden
Filename: "schtasks"; Parameters: "/Delete /F /TN ""GameTrackerService"""; Flags: runhidden
