"""Контроль запуска программ.

Без драйвера ядра Python-приложение не может остановить процесс ДО запуска, поэтому новые процессы
обнаруживаются опросом (~0,5 с), их исполняемый файл проверяется ClamAV и эвристикой, а заражённый
процесс немедленно завершается и файл изолируется.
"""
from __future__ import annotations

import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

import psutil

from timav.core.ai_analyzer import LocalAnalyzer
from timav.core.clamav import ClamAVEngine
from timav.core.signer import signature

SYSTEM_DIRS = (os.path.normcase(os.environ.get("SystemRoot", r"C:\Windows")) + os.sep,)


class ProcessGuard:
    """on_event(kind, exe, name, pid, action): kind = threat | suspicious."""

    def __init__(self, engine: ClamAVEngine, on_event: Callable[[str, str, str, int, str], None],
                 heuristics: bool = True, threshold: float = 0.75, trusted: list[str] | None = None,
                 interval: float = 0.5):
        self.engine = engine
        self.on_event = on_event
        self.heuristics = heuristics
        self.threshold = threshold
        self.analyzer = LocalAnalyzer(trusted)
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._pool = ThreadPoolExecutor(max_workers=3)
        self._verdicts: dict[tuple, tuple[str, str]] = {}   # (path,size,mtime) -> (kind,name)
        self._lock = threading.Lock()
        self.checked = 0
        self.blocked = 0
        self._dirty = 0
        self.load_cache()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self):
        if self.running:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        self.save_cache()
        if self._thread:
            self._thread.join(timeout=2)
        self._thread = None

    def _loop(self):
        known = set(psutil.pids())
        while not self._stop.wait(self.interval):
            try:
                pids = set(psutil.pids())
            except Exception:
                continue
            for pid in pids - known:
                self._pool.submit(self._check_pid, pid)
            known = pids

    def _check_pid(self, pid: int):
        try:
            proc = psutil.Process(pid)
            exe = proc.exe()
        except (psutil.Error, OSError):
            return
        if not exe or not os.path.isfile(exe) or pid == os.getpid():
            return
        kind, name = self.check_file(exe)
        if kind == "clean":
            return
        action = "обнаружено"
        if kind == "threat":
            try:
                for child in proc.children(recursive=True):
                    child.kill()
                proc.kill()
                action = "процесс остановлен"
                self.blocked += 1
            except psutil.Error:
                action = "не удалось остановить процесс"
        self.on_event(kind, exe, name, pid, action)

    def check_file(self, exe: str) -> tuple[str, str]:
        try:
            st = os.stat(exe)
        except OSError:
            return "clean", ""
        key = (os.path.normcase(exe), st.st_size, st.st_mtime_ns)
        with self._lock:
            if key in self._verdicts:
                return self._verdicts[key]
        self.checked += 1
        v = self.engine.scan_file(exe)
        res = ("clean", "")
        if v.infected:
            res = ("threat", v.signature)
        elif self.heuristics and not os.path.normcase(exe).startswith(SYSTEM_DIRS) \
                and not signature(exe)[0]:
            # программы с действительной подписью эвристикой не проверяем (ClamAV проверил выше)
            try:
                rep = self.analyzer.analyze(exe, quick=True)
                if rep.score >= self.threshold:
                    res = ("suspicious", f"AI.Heuristic.{rep.verdict.capitalize()}")
            except (OSError, ValueError):
                pass
        with self._lock:
            self._verdicts[key] = res
            self._dirty += 1
        if self._dirty >= 25:
            self.save_cache()
        return res

    # ---------- кэш проверенных программ между перезапусками ----------
    def _cache_path(self):
        from timav.core import paths
        return paths.data_dir() / "process_cache.json"

    def load_cache(self):
        import json
        try:
            raw = json.loads(self._cache_path().read_text(encoding="utf-8"))
            if raw.get("db") != self._db_stamp():
                return          # базы обновились — проверим заново
            with self._lock:
                for k, v in raw.get("items", {}).items():
                    path, size, mt = k.rsplit("|", 2)
                    self._verdicts[(path, int(size), int(mt))] = tuple(v)
        except (OSError, ValueError, KeyError):
            pass

    def save_cache(self):
        import json
        with self._lock:
            items = {f"{k[0]}|{k[1]}|{k[2]}": list(v) for k, v in list(self._verdicts.items())[-5000:]
                     if v[0] == "clean"}
            self._dirty = 0
        try:
            self._cache_path().write_text(json.dumps({"db": self._db_stamp(), "items": items}), encoding="utf-8")
        except OSError:
            pass

    def _db_stamp(self) -> str:
        try:
            return ",".join(f"{i.name}:{i.version}" for i in self.engine.db_info())
        except Exception:
            return ""
