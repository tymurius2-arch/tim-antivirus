"""Состояние Microsoft Defender и брандмауэра (только чтение — ничего не изменяет)
и расчёт индикатора безопасности системы."""
from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass, field

from timav.core.clamav import CREATE_NO_WINDOW


@dataclass
class DefenderStatus:
    available: bool = False
    antivirus_enabled: bool | None = None
    realtime_enabled: bool | None = None
    signatures_age_days: int | None = None
    firewall_enabled: bool | None = None
    error: str = ""


def _ps(script: str, timeout: float = 25) -> str:
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                       capture_output=True, text=True, timeout=timeout, creationflags=CREATE_NO_WINDOW)
    return r.stdout.strip()


def query_defender() -> DefenderStatus:
    st = DefenderStatus()
    try:
        out = _ps("Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,"
                  "AntivirusSignatureAge | ConvertTo-Json -Compress")
        if out:
            d = json.loads(out)
            st.available = True
            st.antivirus_enabled = bool(d.get("AntivirusEnabled"))
            st.realtime_enabled = bool(d.get("RealTimeProtectionEnabled"))
            st.signatures_age_days = d.get("AntivirusSignatureAge")
    except (OSError, subprocess.SubprocessError, ValueError) as e:
        st.error = str(e)
    try:
        out = _ps("(Get-NetFirewallProfile | Where-Object Enabled -eq $true | Measure-Object).Count")
        if out.isdigit():
            st.firewall_enabled = int(out) > 0
    except (OSError, subprocess.SubprocessError):
        pass
    return st


@dataclass
class SecurityScore:
    score: int
    level: str                        # good | warning | danger
    title: str
    issues: list[str] = field(default_factory=list)


def compute_score(*, engine_ok: bool, db_age_hours: float | None, realtime: bool, unresolved: int,
                  last_scan_ts: float, defender: DefenderStatus | None) -> SecurityScore:
    score = 100
    issues: list[str] = []
    from timav.i18n import tr
    if not engine_ok:
        score -= 35
        issues.append(tr("Движок ClamAV не найден"))
    if db_age_hours is None:
        score -= 30
        issues.append(tr("Антивирусные базы не загружены"))
    elif db_age_hours > 72:
        score -= 20
        issues.append(tr("Базы устарели ({d} дн.)", d=int(db_age_hours // 24)))
    elif db_age_hours > 30:
        score -= 8
        issues.append(tr("Базы давно не обновлялись"))
    if not realtime:
        score -= 20
        issues.append(tr("Защита в реальном времени выключена"))
    if unresolved:
        score -= min(40, 20 * unresolved)
        issues.append(tr("Необработанных угроз: {n}", n=unresolved))
    days = (time.time() - last_scan_ts) / 86400 if last_scan_ts else None
    if days is None:
        score -= 10
        issues.append(tr("Сканирование ещё не выполнялось"))
    elif days > 7:
        score -= 8
        issues.append(tr("Последнее сканирование {d} дн. назад", d=int(days)))
    if defender and defender.available:
        if defender.realtime_enabled is False:
            score -= 15
            issues.append(tr("Защита Microsoft Defender в реальном времени выключена"))
        if defender.firewall_enabled is False:
            score -= 10
            issues.append(tr("Брандмауэр Windows выключен"))
    score = max(0, min(100, score))
    if unresolved or score < 50:
        return SecurityScore(score, "danger", tr("Требуется действие"), issues)
    if score < 85:
        return SecurityScore(score, "warning", tr("Есть рекомендации"), issues)
    return SecurityScore(score, "good", tr("Компьютер защищён"), issues)
