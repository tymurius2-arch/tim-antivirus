"""Настройки приложения (JSON в каталоге данных)."""
from __future__ import annotations

import json
import threading
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

from timav.core import paths


def _default_watch() -> list[str]:
    import os
    folders = [paths.user_folder("Downloads"), paths.user_folder("Desktop"), paths.user_folder("Documents")]
    tmp = os.environ.get("TEMP")
    if tmp:
        folders.append(Path(tmp))
    return [str(f) for f in folders if f.exists()]


def _default_protected() -> list[str]:
    folders = [paths.user_folder(n) for n in ("Documents", "Desktop", "Pictures")]
    return [str(f) for f in folders if f.exists()]


def _default_trusted() -> list[str]:
    from timav.core.signer import DEFAULT_TRUSTED
    return list(DEFAULT_TRUSTED)


@dataclass
class Settings:
    theme: str = "system"                 # system | light | dark
    realtime_enabled: bool = True
    watch_folders: list[str] = field(default_factory=_default_watch)
    auto_quarantine: bool = True
    use_daemon: bool = True               # резидентный движок clamd (быстрее)
    auto_update: bool = True
    update_interval_hours: int = 4
    max_file_size_mb: int = 100
    scan_archives: bool = True
    heuristics_enabled: bool = True       # локальный AI-анализ при сканировании
    heuristic_threshold: float = 0.75
    notifications: bool = True
    minimize_to_tray: bool = True
    autostart: bool = False
    claude_api_key: str = ""
    cloud_ai_enabled: bool = False
    last_scan_ts: float = 0.0
    last_scan_kind: str = ""
    last_update_ts: float = 0.0
    excluded_paths: list[str] = field(default_factory=list)
    # защита
    process_guard: bool = True             # проверка запускаемых программ
    ransomware_guard: bool = True          # защита от шифровальщиков
    protected_folders: list[str] = field(default_factory=_default_protected)
    usb_autoscan: bool = True              # проверка флешек при подключении
    downloads_guard: bool = True           # уведомления о проверке загрузок
    trusted_publishers: list[str] = field(default_factory=_default_trusted)
    # интеграции
    virustotal_api_key: str = ""
    context_menu: bool = True
    language: str = "ru"                   # ru | en
    update_feed_url: str = ""              # JSON-манифест или github:owner/repo
    check_app_updates: bool = True
    last_app_update_check: float = 0.0

    _lock = threading.Lock()

    @classmethod
    def path(cls) -> Path:
        return paths.data_dir() / "settings.json"

    @classmethod
    def load(cls) -> "Settings":
        s = cls()
        try:
            raw = json.loads(cls.path().read_text(encoding="utf-8-sig"))
            names = {f.name for f in fields(cls)}
            for k, v in raw.items():
                if k in names:
                    setattr(s, k, v)
        except (OSError, ValueError):
            pass
        return s

    def save(self) -> None:
        with self._lock:
            tmp = self.path().with_suffix(".tmp")
            tmp.write_text(json.dumps(asdict(self), ensure_ascii=False, indent=2), encoding="utf-8")
            tmp.replace(self.path())
