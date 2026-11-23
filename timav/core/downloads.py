"""Сведения о скачанных файлах: источник из метки Mark-of-the-Web (поток Zone.Identifier)."""
from __future__ import annotations

import os

from timav.core import paths

ZONES = {0: "компьютер", 1: "локальная сеть", 2: "доверенные сайты", 3: "Интернет", 4: "опасные сайты"}
WATCH_EXT = {".exe", ".msi", ".zip", ".rar", ".7z", ".iso", ".img", ".js", ".vbs", ".ps1", ".bat", ".cmd",
             ".scr", ".jar", ".docm", ".xlsm", ".doc", ".xls", ".pdf", ".apk", ".dll", ".lnk", ".hta", ".cab"}


def zone_info(path: str) -> dict:
    """{'zone': 3, 'host_url': ..., 'referrer': ...} или {} если метки нет."""
    try:
        with open(path + ":Zone.Identifier", "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return {}
    info: dict = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            k = k.strip().lower()
            if k == "zoneid":
                try:
                    info["zone"] = int(v)
                except ValueError:
                    pass
            elif k == "hosturl":
                info["host_url"] = v.strip()
            elif k == "referrerurl":
                info["referrer"] = v.strip()
    return info


def is_download(path: str) -> bool:
    dl = os.path.normcase(str(paths.user_folder("Downloads")))
    return os.path.normcase(path).startswith(dl + os.sep)


def worth_reporting(path: str) -> bool:
    return os.path.splitext(path)[1].lower() in WATCH_EXT


def describe_source(info: dict) -> str:
    if not info:
        return ""
    from timav.i18n import tr
    src = info.get("host_url") or info.get("referrer") or ""
    if src:
        from urllib.parse import urlparse
        host = urlparse(src).netloc or src[:60]
        return tr("источник: {h}", h=host)
    return tr("зона: {z}", z=tr(ZONES.get(info.get("zone", -1), "?")))
