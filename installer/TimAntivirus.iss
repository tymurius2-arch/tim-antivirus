; Установщик Tim Antivirus (Inno Setup 6)
; Сборка: build.ps1 или ISCC.exe installer\TimAntivirus.iss
; Подпись: build.ps1 передаёт /DSIGN и /Ssigntool=… при заданном сертификате.

#define AppName "Tim Antivirus"
#define AppVersion "1.1.3"
#define AppExe "TimAntivirus.exe"

[Setup]
AppId={{6B1E7C1A-3F0D-4E55-9A3C-7D0B2C8F4A11}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=Tim Antivirus
VersionInfoVersion={#AppVersion}
DefaultDirName={autopf}\TimAntivirus
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
OutputDir=..\dist
OutputBaseFilename=TimAntivirus-Setup-{#AppVersion}
SetupIconFile=..\timav\resources\app.ico
UninstallDisplayIcon={app}\{#AppExe}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
LicenseFile=..\installer\license_ru.txt
CloseApplications=no
RestartApplications=no
#ifdef SIGN
SignTool=signtool
SignedUninstaller=yes
#endif

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
russian.TaskAutostart=Запускать Tim Antivirus при входе в Windows (защита в реальном времени)
english.TaskAutostart=Start Tim Antivirus at Windows sign-in (real-time protection)
russian.TaskUpdateDb=Загрузить антивирусные базы сразу после установки (~300 МБ)
english.TaskUpdateDb=Download virus databases right after installation (~300 MB)
russian.TaskContext=Добавить «Проверить в Tim Antivirus» в меню Проводника
english.TaskContext=Add “Scan with Tim Antivirus” to the File Explorer menu
russian.GroupProtection=Защита:
english.GroupProtection=Protection:
russian.DownloadingDb=Загрузка антивирусных баз ClamAV…
english.DownloadingDb=Downloading ClamAV virus databases…
russian.ContextVerb=Проверить в Tim Antivirus
english.ContextVerb=Scan with Tim Antivirus
russian.AskDeleteData=Удалить пользовательские данные (антивирусные базы, журнал, карантин)?
english.AskDeleteData=Delete user data (virus databases, log, quarantine)?

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "autostart"; Description: "{cm:TaskAutostart}"; GroupDescription: "{cm:GroupProtection}"
Name: "contextmenu"; Description: "{cm:TaskContext}"; GroupDescription: "{cm:GroupProtection}"
Name: "updatedb"; Description: "{cm:TaskUpdateDb}"; GroupDescription: "{cm:GroupProtection}"

[Files]
Source: "..\dist\TimAntivirus\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\vendor\clamav\*"; DestDir: "{app}\clamav"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{group}\{cm:UninstallProgram,{#AppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "TimAntivirus"; \
  ValueData: """{app}\{#AppExe}"" --minimized"; Flags: uninsdeletevalue; Tasks: autostart
Root: HKCU; Subkey: "Software\Classes\*\shell\TimAntivirus.Scan"; ValueType: string; ValueName: "MUIVerb"; ValueData: "{cm:ContextVerb}"; Flags: uninsdeletekey; Tasks: contextmenu
Root: HKCU; Subkey: "Software\Classes\*\shell\TimAntivirus.Scan"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#AppExe}"; Tasks: contextmenu
Root: HKCU; Subkey: "Software\Classes\*\shell\TimAntivirus.Scan\command"; ValueType: string; ValueData: """{app}\{#AppExe}"" --scan ""%1"""; Tasks: contextmenu
Root: HKCU; Subkey: "Software\Classes\Directory\shell\TimAntivirus.Scan"; ValueType: string; ValueName: "MUIVerb"; ValueData: "{cm:ContextVerb}"; Flags: uninsdeletekey; Tasks: contextmenu
Root: HKCU; Subkey: "Software\Classes\Directory\shell\TimAntivirus.Scan"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#AppExe}"; Tasks: contextmenu
Root: HKCU; Subkey: "Software\Classes\Directory\shell\TimAntivirus.Scan\command"; ValueType: string; ValueData: """{app}\{#AppExe}"" --scan ""%1"""; Tasks: contextmenu
Root: HKCU; Subkey: "Software\TimAntivirus"; Flags: uninsdeletekeyifempty

[Run]
Filename: "{app}\{#AppExe}"; Parameters: "--update-db"; StatusMsg: "{cm:DownloadingDb}"; \
  Flags: runasoriginaluser waituntilterminated; Tasks: updatedb
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent runasoriginaluser
; после тихого обновления из самой программы — перезапуск
Filename: "{app}\{#AppExe}"; Flags: nowait runasoriginaluser; Check: WizardSilent

[UninstallRun]
Filename: "{cmd}"; Parameters: "/C taskkill /F /IM {#AppExe} /T"; Flags: runhidden; RunOnceId: "KillApp"
Filename: "{cmd}"; Parameters: "/C taskkill /F /IM clamd.exe /T"; Flags: runhidden; RunOnceId: "KillClamd"
Filename: "{app}\{#AppExe}"; Parameters: "--cleanup"; Flags: runhidden waituntilterminated; RunOnceId: "Cleanup"

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Code]
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
begin
  // программа сворачивается в трей вместо закрытия, поэтому завершаем её и движок явно
  Exec(ExpandConstant('{cmd}'), '/C taskkill /F /IM {#AppExe} /T', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Exec(ExpandConstant('{cmd}'), '/C taskkill /F /IM clamd.exe /T', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Sleep(800);
  Result := '';
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    if SuppressibleMsgBox(CustomMessage('AskDeleteData'), mbConfirmation, MB_YESNO, IDNO) = IDYES then
      DelTree(ExpandConstant('{localappdata}\TimAntivirus'), True, True, True);
end;
