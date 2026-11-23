"""Пункт «Проверить в Tim Antivirus» в контекстном меню Проводника (HKCU, без прав администратора).
В Windows 11 пункт находится в «Показать дополнительные параметры» (Shift+F10)."""
from __future__ import annotations

import sys
import winreg

KEYS = [r"Software\Classes\*\shell\TimAntivirus.Scan", r"Software\Classes\Directory\shell\TimAntivirus.Scan",
        r"Software\Classes\Drive\shell\TimAntivirus.Scan"]


def launch_command() -> tuple[str, str]:
    """(команда, иконка)"""
    if getattr(sys, "frozen", False):
        exe = sys.executable
        return f'"{exe}" --scan "%1"', exe
    py = sys.executable.replace("python.exe", "pythonw.exe")
    return f'"{py}" -m timav --scan "%1"', py


def register(label: str = "Проверить в Tim Antivirus") -> None:
    cmd, icon = launch_command()
    for k in KEYS:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, k) as key:
            winreg.SetValueEx(key, "MUIVerb", 0, winreg.REG_SZ, label)
            winreg.SetValueEx(key, "Icon", 0, winreg.REG_SZ, icon)
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, k + r"\command") as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, cmd)


def unregister() -> None:
    for k in KEYS:
        for sub in (k + r"\command", k):
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, sub)
            except OSError:
                pass


def is_registered() -> bool:
    try:
        winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEYS[0] + r"\command").Close()
        return True
    except OSError:
        return False
