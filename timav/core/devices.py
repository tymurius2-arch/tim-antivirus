"""Отслеживание подключения съёмных носителей (USB-флешки, карты памяти)."""
from __future__ import annotations

import ctypes
import os
import threading
from typing import Callable

DRIVE_REMOVABLE = 2


def removable_drives() -> set[str]:
    out = set()
    try:
        mask = ctypes.windll.kernel32.GetLogicalDrives()
    except Exception:
        return out
    for i in range(26):
        if mask & (1 << i):
            root = f"{chr(65 + i)}:\\"
            if ctypes.windll.kernel32.GetDriveTypeW(root) == DRIVE_REMOVABLE and os.path.exists(root):
                out.add(root)
    return out


def volume_label(root: str) -> str:
    buf = ctypes.create_unicode_buffer(261)
    try:
        if ctypes.windll.kernel32.GetVolumeInformationW(root, buf, 261, None, None, None, None, 0):
            return buf.value
    except Exception:
        pass
    return ""


class UsbWatcher:
    def __init__(self, on_inserted: Callable[[str, str], None], interval: float = 2.0):
        self.on_inserted = on_inserted
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.known: set[str] = set()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self):
        if self.running:
            return
        self._stop.clear()
        self.known = removable_drives()   # уже подключённые при запуске не сканируем
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._thread = None

    def _loop(self):
        while not self._stop.wait(self.interval):
            cur = removable_drives()
            for root in sorted(cur - self.known):
                self.on_inserted(root, volume_label(root))
            self.known = cur
