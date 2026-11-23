"""Расположение файлов приложения, данных и движка ClamAV."""
from __future__ import annotations

import os
import sys
from pathlib import Path

from timav import APP_ID


def app_dir() -> Path:
    """Каталог установленного приложения (или корень проекта при разработке)."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]


def resource_dir() -> Path:
    """Каталог ресурсов (иконки и т.п.)."""
    base = Path(getattr(sys, "_MEIPASS", app_dir()))
    cand = base / "timav" / "resources"
    if cand.exists():
        return cand
    return Path(__file__).resolve().parents[1] / "resources"


def data_dir() -> Path:
    """Пользовательские данные: базы, карантин, журнал, настройки."""
    override = os.environ.get("TIMAV_DATA_DIR")
    if override:
        root = Path(override)
    else:
        root = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / APP_ID
    root.mkdir(parents=True, exist_ok=True)
    return root


def db_dir() -> Path:
    p = data_dir() / "db"
    p.mkdir(parents=True, exist_ok=True)
    return p


def quarantine_dir() -> Path:
    p = data_dir() / "quarantine"
    p.mkdir(parents=True, exist_ok=True)
    return p


def logs_dir() -> Path:
    p = data_dir() / "logs"
    p.mkdir(parents=True, exist_ok=True)
    return p


def clamav_dir() -> Path | None:
    """Поиск бинарников ClamAV: рядом с приложением, в vendor/ или в системе."""
    candidates = [
        app_dir() / "clamav",
        app_dir() / "vendor" / "clamav",
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "ClamAV",
    ]
    env = os.environ.get("TIMAV_CLAMAV_DIR")
    if env:
        candidates.insert(0, Path(env))
    for c in candidates:
        if (c / "clamscan.exe").exists():
            return c
    return None


def user_folder(name: str) -> Path:
    """Известные папки пользователя (Downloads и т.д.)."""
    home = Path.home()
    if name == "Downloads":
        try:
            import ctypes
            from ctypes import wintypes
            import uuid

            guid = uuid.UUID("{374DE290-123F-4565-9164-39C4925E467B}")

            class GUID(ctypes.Structure):
                _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                            ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]

            g = GUID(guid.fields[0], guid.fields[1], guid.fields[2],
                     (ctypes.c_ubyte * 8).from_buffer_copy(guid.bytes[8:]))
            ptr = ctypes.c_wchar_p()
            if ctypes.windll.shell32.SHGetKnownFolderPath(ctypes.byref(g), 0, None, ctypes.byref(ptr)) == 0:
                path = Path(ptr.value)
                ctypes.windll.ole32.CoTaskMemFree(ptr)
                return path
        except Exception:
            pass
    return home / name
