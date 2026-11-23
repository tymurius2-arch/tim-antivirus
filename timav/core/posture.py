"""Проверка настроек безопасности Windows (только чтение; изменения делает пользователь)."""
from __future__ import annotations

import json
import subprocess
import time
import winreg
from dataclasses import dataclass

from timav.core.clamav import CREATE_NO_WINDOW
from timav.i18n import tr


@dataclass
class Check:
    id: str
    title: str
    status: str          # ok | warn | bad | info
    detail: str
    advice: str = ""
    open_cmd: str = ""   # URI или команда для открытия нужных настроек

    def __post_init__(self):
        self.title, self.detail, self.advice = tr(self.title), tr(self.detail), tr(self.advice)


def _reg(hive, key, name, default=None):
    try:
        with winreg.OpenKey(hive, key) as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return default


PS_SCRIPT = r"""
$o = @{}
try { $m = Get-MpComputerStatus; $o.rtp = $m.RealTimeProtectionEnabled; $o.av = $m.AntivirusEnabled;
      $o.sigage = $m.AntivirusSignatureAge; $o.tamper = $m.IsTamperProtected } catch {}
try { $o.cfa = (Get-MpPreference).EnableControlledFolderAccess } catch {}
try { $o.fw = @(Get-NetFirewallProfile | ForEach-Object { @{n=$_.Name; e=[bool]$_.Enabled} }) } catch {}
try { $h = Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1;
      if ($h) { $o.hotfix = $h.InstalledOn.ToString('yyyy-MM-dd') } } catch {}
try { $o.bitlocker = (New-Object -ComObject Shell.Application).NameSpace($env:SystemDrive + '\').Self.ExtendedProperty('System.Volume.BitLockerProtection') } catch {}
try { $g = Get-LocalUser | Where-Object { $_.SID -like '*-501' }; if ($g) { $o.guest = [bool]$g.Enabled } } catch {}
try { $o.execpol = [string](Get-ExecutionPolicy) } catch {}
$o | ConvertTo-Json -Compress -Depth 4
"""


def run_checks() -> list[Check]:
    HKLM = winreg.HKEY_LOCAL_MACHINE
    data: dict = {}
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", PS_SCRIPT],
                           capture_output=True, text=True, timeout=60, creationflags=CREATE_NO_WINDOW)
        data = json.loads(r.stdout.strip() or "{}")
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    out: list[Check] = []

    rtp = data.get("rtp")
    out.append(Check("defender", "Microsoft Defender", "ok" if rtp else "bad" if rtp is False else "info",
                     "Защита в реальном времени включена" if rtp else "Защита в реальном времени выключена"
                     if rtp is False else "Статус недоступен",
                     "" if rtp else "Включите защиту в реальном времени в «Безопасность Windows»", "windowsdefender://threat"))
    tamper = data.get("tamper")
    if tamper is not None:
        out.append(Check("tamper", "Защита от подделки (Tamper Protection)", "ok" if tamper else "warn",
                         "Включена" if tamper else "Выключена — вредонос может отключить Defender",
                         "" if tamper else "Включите в «Защита от вирусов и угроз» → «Управление настройками»",
                         "windowsdefender://threatsettings"))
    fw = data.get("fw") or []
    if isinstance(fw, dict):
        fw = [fw]
    if fw:
        off = [p["n"] for p in fw if not p.get("e")]
        out.append(Check("firewall", "Брандмауэр Windows", "ok" if not off else "bad",
                         "Включён для всех профилей" if not off else tr("Выключен для: ") + ", ".join(off),
                         "" if not off else "Включите брандмауэр для всех сетевых профилей", "windowsdefender://network"))
    lua = _reg(HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", 1)
    consent = _reg(HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin", 5)
    if not lua:
        out.append(Check("uac", "Контроль учётных записей (UAC)", "bad", "UAC отключён",
                         "Включите UAC — без него любая программа получает права администратора", "UserAccountControlSettings.exe"))
    else:
        out.append(Check("uac", "Контроль учётных записей (UAC)", "warn" if consent == 0 else "ok",
                         "Включён, но запросы подтверждения отключены" if consent == 0 else "Включён",
                         "Верните уровень уведомлений по умолчанию" if consent == 0 else "", "UserAccountControlSettings.exe"))
    sb = _reg(HKLM, r"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled")
    out.append(Check("secureboot", "Безопасная загрузка (Secure Boot)",
                     "ok" if sb == 1 else "warn" if sb == 0 else "info",
                     "Включена" if sb == 1 else "Выключена" if sb == 0 else "Не поддерживается или BIOS в режиме Legacy",
                     "Включите Secure Boot в настройках UEFI/BIOS" if sb == 0 else ""))
    hvci = _reg(HKLM, r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled", 0)
    out.append(Check("hvci", "Изоляция ядра (целостность памяти)", "ok" if hvci == 1 else "warn",
                     "Включена" if hvci == 1 else "Выключена",
                     "" if hvci == 1 else "Включите «Целостность памяти» в разделе «Безопасность устройства»",
                     "windowsdefender://coreisolation"))
    bl = data.get("bitlocker")
    if bl in (1, 3, 5):
        out.append(Check("bitlocker", "Шифрование диска (BitLocker)", "ok", "Системный диск зашифрован"))
    elif bl in (2, 6):
        out.append(Check("bitlocker", "Шифрование диска (BitLocker)", "warn", "Системный диск не зашифрован",
                         "Включите BitLocker или шифрование устройства, особенно на ноутбуке", "ms-settings:deviceencryption"))
    else:
        out.append(Check("bitlocker", "Шифрование диска (BitLocker)", "info", "Недоступно в этой редакции Windows или статус неизвестен"))
    hf = data.get("hotfix")
    if hf:
        days = int((time.time() - time.mktime(time.strptime(hf, "%Y-%m-%d"))) // 86400)
        out.append(Check("updates", "Обновления Windows", "ok" if days <= 40 else "warn" if days <= 90 else "bad",
                         tr("Последнее обновление установлено {d} дн. назад ({h})", d=days, h=hf),
                         "" if days <= 40 else "Установите обновления Windows", "ms-settings:windowsupdate"))
    rdp = _reg(HKLM, r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections", 1)
    out.append(Check("rdp", "Удалённый рабочий стол", "warn" if rdp == 0 else "ok",
                     "Входящие подключения разрешены" if rdp == 0 else "Выключен",
                     "Отключите, если не пользуетесь — частая цель атак" if rdp == 0 else "", "ms-settings:remotedesktop"))
    smb1 = _reg(HKLM, r"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start")
    out.append(Check("smb1", "Протокол SMBv1", "bad" if smb1 is not None and smb1 != 4 else "ok",
                     "Включён (уязвим, использовался WannaCry)" if smb1 is not None and smb1 != 4 else "Отключён",
                     "Отключите SMB 1.0 в «Компонентах Windows»" if smb1 is not None and smb1 != 4 else "", "optionalfeatures.exe"))
    auto = _reg(HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoAdminLogon", "0")
    out.append(Check("autologon", "Автоматический вход без пароля", "warn" if str(auto) == "1" else "ok",
                     "Включён" if str(auto) == "1" else "Выключен",
                     "Отключите автоматический вход" if str(auto) == "1" else "", "netplwiz.exe"))
    guest = data.get("guest")
    if guest is not None:
        out.append(Check("guest", "Учётная запись «Гость»", "warn" if guest else "ok", "Включена" if guest else "Отключена",
                         "Отключите гостевую учётную запись" if guest else ""))
    ep = data.get("execpol", "")
    if ep:
        risky = ep in ("Unrestricted", "Bypass")
        out.append(Check("execpol", "Политика выполнения PowerShell", "warn" if risky else "ok", ep,
                         "Установите RemoteSigned: Set-ExecutionPolicy RemoteSigned -Scope CurrentUser" if risky else ""))
    ss = _reg(HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled", "")
    out.append(Check("smartscreen", "SmartScreen", "bad" if str(ss).lower() == "off" else "ok",
                     "Выключен" if str(ss).lower() == "off" else "Включён",
                     "Включите проверку приложений SmartScreen" if str(ss).lower() == "off" else "", "windowsdefender://smartscreen"))
    cfa = data.get("cfa")
    if cfa is not None:
        out.append(Check("cfa", "Контролируемый доступ к папкам (Defender)", "ok" if cfa == 1 else "info",
                         "Включён" if cfa == 1 else "Выключен (Tim Antivirus защищает от шифровальщиков сам)",
                         "", "windowsdefender://ransomwareprotection"))
    return out


def summary(checks: list[Check]) -> tuple[int, int, int]:
    return (sum(c.status == "ok" for c in checks), sum(c.status == "warn" for c in checks),
            sum(c.status == "bad" for c in checks))
