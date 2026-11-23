"""Быстрое, полное и выборочное сканирование."""
from __future__ import annotations

import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator

from timav.core import paths
from timav.core.ai_analyzer import LocalAnalyzer, is_analyzable
from timav.core.clamav import ClamAVEngine, ScanVerdict

QUICK_EXT = {
    ".exe", ".dll", ".scr", ".sys", ".com", ".cpl", ".ocx", ".msi", ".pif", ".ps1", ".vbs", ".vbe", ".js",
    ".jse", ".wsf", ".bat", ".cmd", ".hta", ".lnk", ".jar", ".zip", ".rar", ".7z", ".iso", ".img", ".doc",
    ".docm", ".xls", ".xlsm", ".pptm", ".rtf", ".pdf", ".html", ".htm", ".svg", ".reg", ".inf", ".chm",
}
SKIP_DIRS = {"$recycle.bin", "system volume information", "winsxs", "$windows.~bt", "$windows.~ws",
             "windowsapps", "node_modules", ".git", "__pycache__"}


@dataclass
class Detection:
    path: str
    name: str
    kind: str                 # threat | suspicious
    score: float = 1.0
    action: str = "обнаружено"
    event_id: int = 0


@dataclass
class ScanStats:
    mode: str
    started: float = field(default_factory=time.time)
    finished: float = 0.0
    total: int = 0
    total_final: bool = False
    scanned: int = 0
    skipped: int = 0
    errors: int = 0
    current: str = ""
    detections: list[Detection] = field(default_factory=list)
    cancelled: bool = False

    @property
    def elapsed(self) -> float:
        return (self.finished or time.time()) - self.started

    @property
    def percent(self) -> float:
        if not self.total:
            return 0.0
        p = self.scanned / self.total * 100
        return min(p, 100.0 if self.total_final else 99.0)


def quick_targets() -> list[Path]:
    env = os.environ
    t = [paths.user_folder("Downloads"), paths.user_folder("Desktop"), paths.user_folder("Documents")]
    for var in ("TEMP", "TMP"):
        if env.get(var):
            t.append(Path(env[var]))
    appdata = Path(env.get("APPDATA", ""))
    progdata = Path(env.get("ProgramData", r"C:\ProgramData"))
    t += [
        appdata / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
        progdata / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "StartUp",
        Path(env.get("SystemRoot", r"C:\Windows")) / "Temp",
        Path(env.get("LOCALAPPDATA", "")) / "Temp",
    ]
    uniq, seen = [], set()
    for p in t:
        k = os.path.normcase(str(p))
        if p and p.exists() and k not in seen:
            seen.add(k)
            uniq.append(p)
    return uniq


def running_process_files() -> list[str]:
    """Исполняемые файлы запущенных процессов (входят в быстрое сканирование)."""
    out = set()
    try:
        import psutil
        for p in psutil.process_iter(["exe"]):
            exe = p.info.get("exe")
            if exe and os.path.isfile(exe):
                out.add(exe)
    except Exception:
        pass
    return sorted(out)


def fixed_drives() -> list[Path]:
    try:
        import psutil
        return [Path(p.mountpoint) for p in psutil.disk_partitions(all=False)
                if "fixed" in p.opts or (p.fstype and "cdrom" not in p.opts)]
    except Exception:
        return [Path("C:\\")]


class Scanner:
    def __init__(self, engine: ClamAVEngine, heuristics: bool = True, threshold: float = 0.75,
                 excluded: list[str] | None = None, workers: int = 4,
                 trusted: list[str] | None = None):
        self.engine = engine
        self.heuristics = heuristics
        self.threshold = threshold
        self.analyzer = LocalAnalyzer(trusted)
        self.workers = workers
        excl = [str(paths.data_dir())] + list(excluded or [])
        if engine.clam_dir:
            excl.append(str(engine.clam_dir))
        self.excluded = [os.path.normcase(os.path.abspath(e)) for e in excl]
        self._stop = threading.Event()
        self._pause = threading.Event()
        self._pause.set()

    # ---------- управление ----------
    def cancel(self) -> None:
        self._stop.set()
        self._pause.set()

    def pause(self, paused: bool) -> None:
        if paused:
            self._pause.clear()
        else:
            self._pause.set()

    @property
    def paused(self) -> bool:
        return not self._pause.is_set()

    # ---------- обход файлов ----------
    def _is_excluded(self, path: str) -> bool:
        n = os.path.normcase(path)
        return any(n == e or n.startswith(e + os.sep) for e in self.excluded)

    def iter_files(self, roots: list[Path | str], ext_filter: set[str] | None) -> Iterator[str]:
        stack = [str(r) for r in roots]
        while stack and not self._stop.is_set():
            cur = stack.pop()
            if os.path.isfile(cur):
                if not self._is_excluded(cur):
                    yield cur
                continue
            try:
                with os.scandir(cur) as it:
                    for e in it:
                        if self._stop.is_set():
                            return
                        try:
                            if e.is_symlink():
                                continue
                            if e.is_dir(follow_symlinks=False):
                                if e.name.lower() not in SKIP_DIRS and not self._is_excluded(e.path):
                                    stack.append(e.path)
                            elif e.is_file(follow_symlinks=False):
                                if ext_filter is None or os.path.splitext(e.name)[1].lower() in ext_filter:
                                    if not self._is_excluded(e.path):
                                        yield e.path
                        except OSError:
                            continue
            except OSError:
                continue

    # ---------- сканирование ----------
    def run(self, mode: str, custom: list[str] | None = None,
            on_progress: Callable[[ScanStats], None] | None = None,
            on_detection: Callable[[Detection], None] | None = None) -> ScanStats:
        self._stop.clear()
        stats = ScanStats(mode)
        if mode == "quick":
            roots: list = quick_targets() + running_process_files()
            ext = QUICK_EXT
        elif mode == "full":
            roots, ext = fixed_drives(), None
        else:
            roots, ext = [Path(c) for c in (custom or [])], None

        # подсчёт файлов параллельно со сканированием
        def counter():
            n = 0
            for _ in self.iter_files(roots, ext):
                n += 1
                if n % 500 == 0:
                    stats.total = max(stats.total, n)
            stats.total = n
            stats.total_final = True

        cthread = threading.Thread(target=counter, daemon=True)
        cthread.start()

        lock = threading.Lock()
        last_emit = [0.0]

        def emit(force=False):
            now = time.time()
            if on_progress and (force or now - last_emit[0] > 0.15):
                last_emit[0] = now
                on_progress(stats)

        def handle(v: ScanVerdict):
            det = None
            if v.infected:
                det = Detection(v.path, v.signature, "threat", 1.0)
            elif v.status == "clean" and self.heuristics and is_analyzable(v.path):
                try:
                    rep = self.analyzer.analyze(v.path, quick=True)
                    if rep.score >= self.threshold:
                        det = Detection(v.path, f"AI.Heuristic.{rep.verdict.capitalize()}", "suspicious", rep.score)
                except (OSError, ValueError):
                    pass
            with lock:
                stats.scanned += 1
                stats.current = v.path
                if v.status == "skipped":
                    stats.skipped += 1
                elif v.status == "error":
                    stats.errors += 1
                if det:
                    stats.detections.append(det)
            if det and on_detection:
                on_detection(det)
            emit()

        files = self.iter_files(roots, ext)
        if self.engine.daemon_alive():
            with ThreadPoolExecutor(max_workers=self.workers) as pool:
                pending = set()
                for f in files:
                    self._pause.wait()
                    if self._stop.is_set():
                        break
                    pending.add(pool.submit(lambda p=f: handle(self.engine.scan_file(p))))
                    if len(pending) >= self.workers * 4:
                        done = {p for p in pending if p.done()}
                        while not done:
                            time.sleep(0.005)
                            done = {p for p in pending if p.done()}
                        pending -= done
                for p in pending:
                    p.result()
        else:
            # пакетами через clamscan
            batch: list[str] = []
            for f in files:
                if self._stop.is_set():
                    break
                batch.append(f)
                if len(batch) >= 5000:
                    self.engine.scan_files_clamscan(batch, handle, self._stop)
                    batch = []
            if batch and not self._stop.is_set():
                self.engine.scan_files_clamscan(batch, handle, self._stop)

        stats.cancelled = self._stop.is_set()
        self._stop.set()  # останавливаем счётчик
        cthread.join(timeout=2)
        if not stats.cancelled:
            stats.total = stats.scanned
            stats.total_final = True
        stats.finished = time.time()
        stats.current = ""
        emit(force=True)
        return stats
