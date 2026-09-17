; FailKeep.iss — Inno Setup script for FailKeep (Windows Server)
;
; Build (repo root):
;   cargo build --release
;   optional UI:  cd ui\FailKeep.Ui && dotnet publish -c Release -r win-x64 --self-contained false -o publish
;   ISCC.exe installer\FailKeep.iss
;
; Silent uninstall keeps data by default:
;   unins000.exe /SILENT
;
; Uninstall always:
;   - stops & deletes Windows service FailKeep
;   - removes FailKeep:* firewall rules
;   - asks whether to keep lists (state.json) and logs

#define MyAppName "FailKeep"
#define MyAppVersion "0.2.0"
#define MyAppPublisher "FailKeep"
#define MyAppExeName "failkeep.exe"
#define ServiceName "FailKeep"

#ifndef AppSourceDir
  #define AppSourceDir "..\target\release"
#endif
#ifndef UiSourceDir
  #define UiSourceDir "..\ui\FailKeep.Ui\publish"
#endif

[Setup]
AppId={{A7C3E9F1-2B4D-4E6A-9C8B-1D2E3F4A5B6C}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\FailKeep
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible
OutputBaseFilename=FailKeep-setup-{#MyAppVersion}
OutputDir=..\dist
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
UninstallDisplayName={#MyAppName}
; Log install for support
SetupLogging=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
; If ChineseSimplified.isl is missing, remove the next line or install Inno language files
Name: "chinesesimplified"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"

[Types]
Name: "full"; Description: "完整安装（服务 + CLI + UI）"
Name: "compact"; Description: "精简安装（仅服务 + CLI）"
Name: "custom"; Description: "自定义"; Flags: iscustom

[Components]
Name: "core"; Description: "FailKeep 服务与 CLI（必需）"; Types: full compact custom; Flags: fixed
Name: "ui"; Description: "管理界面（WinUI，可选）"; Types: full

[Files]
Source: "{#AppSourceDir}\{#MyAppExeName}"; DestDir: "{app}"; Components: core; Flags: ignoreversion
Source: "..\config.example.toml"; DestDir: "{app}"; Components: core; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Components: core; Flags: ignoreversion
Source: "..\PLAN.md"; DestDir: "{app}"; Components: core; Flags: ignoreversion skipifsourcedoesntexist
; UI (from `dotnet publish -o publish`); skipped if folder absent
Source: "{#UiSourceDir}\*"; DestDir: "{app}\ui"; Components: ui; \
    Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist

[Icons]
Name: "{group}\FailKeep 帮助"; Filename: "{app}\{#MyAppExeName}"; Parameters: "--help"; Components: core
Name: "{group}\打开数据目录"; Filename: "{commonappdata}\FailKeep"; Components: core
Name: "{group}\FailKeep UI"; Filename: "{app}\ui\FailKeep.Ui.exe"; Components: ui; Flags: createonlyiffileexists
Name: "{group}\卸载 {#MyAppName}"; Filename: "{uninstallexe}"

[Run]
Filename: "{app}\{#MyAppExeName}"; \
  Parameters: "check-config --config ""{commonappdata}\FailKeep\config.toml"""; \
  StatusMsg: "校验配置..."; Flags: runhidden skipifsilent; Components: core
Filename: "sc.exe"; Parameters: "start {#ServiceName}"; \
  StatusMsg: "启动 FailKeep 服务..."; Flags: runhidden; Components: core

[UninstallDelete]
; Leftovers under app dir
Type: filesandordirs; Name: "{app}\ui"
Type: files; Name: "{app}\uninstall\*"

[Code]
const
  SvcName = '{#ServiceName}';

var
  KeepLists: Boolean;
  KeepLogs: Boolean;

function GetDataDir(): String;
begin
  Result := ExpandConstant('{commonappdata}\FailKeep');
end;

function ConfigPath(): String;
begin
  Result := GetDataDir() + '\config.toml';
end;

procedure SeedConfig();
var
  Cfg, Example: String;
begin
  Cfg := ConfigPath();
  Example := ExpandConstant('{app}\config.example.toml');
  ForceDirectories(GetDataDir());
  if (not FileExists(Cfg)) and FileExists(Example) then
    FileCopy(Example, Cfg, False);
end;

procedure InstallService();
var
  ResultCode: Integer;
  Exe, Args: String;
begin
  Exe := ExpandConstant('{app}\{#MyAppExeName}');
  if not FileExists(Exe) then
    Exit;

  Args := 'install --config "' + ConfigPath() + '"';
  if Exec(Exe, Args, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    if ResultCode = 0 then
      Exit;

  // Fallback: sc create (AUTO_START)
  Args := 'create ' + SvcName +
          ' binPath= "\"' + Exe + '\" --config \"' + ConfigPath() + '\" service-run"' +
          ' start= auto' +
          ' DisplayName= "FailKeep Lightweight Ban Service"';
  Exec('sc.exe', Args, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure StopAndDeleteService();
var
  ResultCode: Integer;
  Exe: String;
begin
  Exec('sc.exe', 'stop ' + SvcName, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  Exe := ExpandConstant('{app}\{#MyAppExeName}');
  if FileExists(Exe) then
  begin
    // FailKeep uninstall --purge-rules: SCM delete + firewall cleanup
    Exec(Exe, 'uninstall --purge-rules', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end
  else
  begin
    Exec('sc.exe', 'delete ' + SvcName, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;

  // If still present (binary already gone mid-uninstall), force sc delete
  Exec('sc.exe', 'query ' + SvcName, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  if ResultCode <> 0 then
    Exit; // already gone
  Exec('sc.exe', 'delete ' + SvcName, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure PurgeFirewallRulesFallback();
var
  ResultCode: Integer;
  PS: String;
begin
  // Best-effort if FailKeep.exe was already removed
  PS :=
    '$ErrorActionPreference="SilentlyContinue"; ' +
    '$out = netsh advfirewall firewall show rule name=all; ' +
    'foreach ($line in $out) { ' +
    '  if ($line -match "Rule Name:\s+(FailKeep:.+)$" -or $line -match "规则名:\s+(FailKeep:.+)$") { ' +
    '    $n = $Matches[1].Trim(); ' +
    '    netsh advfirewall firewall delete rule name=$n | Out-Null ' +
    '  } ' +
    '}';
  Exec('powershell.exe',
       '-NoProfile -NonInteractive -Command "' + PS + '"',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure AskKeepData();
begin
  KeepLists := True;
  KeepLogs := True;

  if UninstallSilent() then
    Exit; // silent: keep both (safe default)

  if MsgBox(
       '卸载时是否保留黑白名单与统计状态？' + #13#10 + #13#10 +
       '文件：' + GetDataDir() + '\state.json' + #13#10 +
       '（白名单 / 临时黑名单 / 黑名单 / 封禁历史）' + #13#10 + #13#10 +
       '是 = 保留' + #13#10 +
       '否 = 删除',
       mbConfirmation, MB_YESNO or MB_DEFBUTTON1) = IDNO then
    KeepLists := False;

  if MsgBox(
       '卸载时是否保留日志文件？' + #13#10 + #13#10 +
       '文件：' + GetDataDir() + '\FailKeep.log（及轮转 .log.1 等）' + #13#10 + #13#10 +
       '是 = 保留' + #13#10 +
       '否 = 删除',
       mbConfirmation, MB_YESNO or MB_DEFBUTTON1) = IDNO then
    KeepLogs := False;
end;

procedure CleanupDataDir();
var
  DataDir: String;
begin
  DataDir := GetDataDir();
  if not DirExists(DataDir) then
    Exit;

  // Always drop live IPC endpoint (stale port/token)
  DeleteFile(DataDir + '\ipc.json');
  DeleteFile(DataDir + '\state.json.tmp');

  if not KeepLists then
    DeleteFile(DataDir + '\state.json');

  if not KeepLogs then
  begin
    DelTree(DataDir + '\FailKeep.log', False, True, False);
    DelTree(DataDir + '\FailKeep.log.1', False, True, False);
    DelTree(DataDir + '\FailKeep.log.2', False, True, False);
    DelTree(DataDir + '\FailKeep.log.3', False, True, False);
  end;

  // Config: remove only when user keeps neither lists nor logs (full wipe)
  if (not KeepLists) and (not KeepLogs) then
  begin
    DelTree(DataDir + '\geo', True, True, True);
    DelTree(DataDir + '\config.toml', False, True, False);
    DelTree(DataDir, True, True, True);
    Exit;
  end;

  // Partial keep: remove empty geo helper dir; leave config if lists kept
  DelTree(DataDir + '\geo', True, True, True);
  if not KeepLists then
    DeleteFile(DataDir + '\config.toml');

  // Remove directory if nothing left
  RemoveDir(DataDir);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    SeedConfig();
    if IsComponentSelected('core') then
      InstallService();
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  case CurUninstallStep of
    usUninstall:
      begin
        StopAndDeleteService();
        PurgeFirewallRulesFallback();
      end;
    usPostUninstall:
      begin
        AskKeepData();
        CleanupDataDir();
      end;
  end;
end;
