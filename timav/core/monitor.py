"""Мониторинг файловой системы в реальном времени (watchdog / ReadDirectoryChangesW)."""
from __future__ import annotations

import os
import queue
import threading
import time
from typing import Callable

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from timav.core.ai_analyzer import LocalAnalyzer, is_analyzable
from timav.core.clamav import ClamAVEngine, ScanVerdict

TEMP_DIRS = tuple(os.path.normcase(os.path.abspath(d)) + os.sep for d in
                  {os.environ.get("TEMP", ""), os.environ.get("TMP", ""),
                   os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Temp")} if d)
RISKY_EXT = {".exe", ".dll", ".scr", ".sys", ".com", ".cpl", ".msi", ".pif", ".ps1", ".vbs", ".vbe", ".js",
             ".jse", ".wsf", ".bat", ".cmd", ".hta", ".lnk", ".jar", ".zip", ".rar", ".7z", ".iso", ".docm",
             ".xlsm", ".doc", ".xls", ".rtf", ".pdf"}
IGNORED_EXT = {".tmp", ".crdownload", ".part", ".partial", ".download", ".log", ".etl", ".lock"}


class _Handler(FileSystemEventHandler):
    def __init__(self, monitor: "RealtimeMonitor"):
        self.m = monitor

    def on_created(self, event: FileSystemEvent):
        if not event.is_directory:
            self.m.enqueue(event.src_path)

    def on_modified(self, event: FileSystemEvent):
        if not event.is_directory:
            self.m.enqueue(event.src_path)

    def on_moved(self, event: FileSystemEvent):
        if not event.is_directory:
            self.m.enqueue(event.dest_path)


class RealtimeMonitor:
    """Следит за папками; новые и изменённые файлы проверяются ClamAV + эвристикой.

    on_threat(path, name, kind, score) вызывается из рабочего потока.
    """

    SETTLE = 1.2  # секунды тишины после последней записи, прежде чем сканировать

    def __init__(self, engine: ClamAVEngine, on_threat: Callable[[str, str, str, float], None],
                 on_scanned: Callable[[ScanVerdict], None] | None = None,
                 heuristics: bool = True, threshold: float = 0.75, excluded: list[str] | None = None,
                 trusted: list[str] | None = None):
        self.engine = engine
        self.on_threat = on_threat
        self.on_scanned = on_scanned
        self.heuristics = heuristics
        self.threshold = threshold
        self.analyzer = LocalAnalyzer(trusted)
        self.excluded = [os.path.normcase(os.path.abspath(e)) for e in (excluded or [])]
        self._observer: Observer | None = None
        self._pending: dict[str, float] = {}
        self._lock = threading.Lock()
        self._q: queue.Queue[str] = queue.Queue()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self.folders: list[str] = []
        self.files_checked = 0
        self._recent: dict[str, float] = {}

    @property
    def running(self) -> bool:
        return self._observer is not None and self._observer.is_alive()

    def enqueue(self, path: str) -> None:
        ext = os.path.splitext(path)[1].lower()
        if ext in IGNORED_EXT:
            return
        n = os.path.normcase(path)
        if any(n.startswith(t) for t in TEMP_DIRS) and ext not in RISKY_EXT:
            return          # во временных папках огромный поток служебных файлов — только исполняемое и скрипты
        if any(n.startswith(e) for e in self.excluded):
            return
        with self._lock:
            self._pending[path] = time.time()

    def start(self, folders: list[str]) -> list[str]:
        self.stop()
        self._stop.clear()
        self.folders = [f for f in folders if os.path.isdir(f)]
        obs = Observer()
        handler = _Handler(self)
        for f in self.folders:
            try:
                obs.schedule(handler, f, recursive=True)
            except OSError:
                pass
        obs.daemon = True
        obs.start()
        self._observer = obs
        self._threads = [threading.Thread(target=self._settler, daemon=True)]
        self._threads += [threading.Thread(target=self._worker, daemon=True) for _ in range(2)]
        for t in self._threads:
            t.start()
        return self.folders

    def stop(self) -> None:
        self._stop.set()
        if self._observer:
            try:
                self._observer.stop()
                self._observer.join(timeout=3)
            except RuntimeError:
                pass
        self._observer = None
        self._threads = []

    def _settler(self):
        while not self._stop.is_set():
            time.sleep(0.3)
            now = time.time()
            ready = []
            with self._lock:
                for p, t in list(self._pending.items()):
                    if now - t >= self.SETTLE:
                        ready.append(p)
                        del self._pending[p]
            for p in ready:
                # не сканировать один и тот же файл чаще раза в 3 с
                if now - self._recent.get(p, 0) > 3:
                    self._recent[p] = now
                    self._q.put(p)
            if len(self._recent) > 5000:
                self._recent = {k: v for k, v in self._recent.items() if now - v < 60}

    def _worker(self):
        while not self._stop.is_set():
            try:
                path = self._q.get(timeout=0.5)
            except queue.Empty:
                continue
            if not os.path.isfile(path):
                continue
            v = None
            for _ in range(3):  # файл может быть занят записывающим процессом
                v = self.engine.scan_file(path)
                if v.status != "error" or not os.path.exists(path):
                    break
                time.sleep(1.0)
            self.files_checked += 1
            if v is None:
                continue
            if self.on_scanned:
                try:
                    self.on_scanned(v)
                except Exception:
                    pass
            if v.infected:
                self.on_threat(path, v.signature, "threat", 1.0)
            elif v.status == "clean" and self.heuristics and is_analyzable(path):
                try:
                    rep = self.analyzer.analyze(path, quick=True)
                    if rep.score >= self.threshold:
                        self.on_threat(path, f"AI.Heuristic.{rep.verdict.capitalize()}", "suspicious", rep.score)
                except (OSError, ValueError):
                    pass
