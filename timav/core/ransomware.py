"""Защита от программ-шифровальщиков.

1. Файлы-ловушки: в защищаемых папках создаются скрытые документы, которые обычные программы не трогают.
   Изменение, удаление или переименование ловушки — сильный признак шифровальщика.
2. Массовые изменения: десятки файлов за несколько секунд переписываются данными с высокой энтропией
   или переименовываются в новые расширения.
Реакция: определяется процесс с наибольшей записью на диск за последние секунды, он приостанавливается
(suspend), пользователь решает — завершить его или продолжить.
"""
from __future__ import annotations

import math
import os
import random
import threading
import time
from collections import deque
from typing import Callable

import psutil
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from timav.i18n import tr

CANARY_NAMES = ["~$tim_000_backup.docx", "~$tim_001_budget.xlsx", "~$tim_002_photo.jpg"]
LOW_ENTROPY_EXT = {".txt", ".csv", ".doc", ".xls", ".rtf", ".html", ".htm", ".xml", ".json", ".md", ".log",
                   ".bmp", ".ini", ".cfg", ".py", ".js", ".cs", ".cpp", ".c", ".h", ".java", ".sql", ".svg", ".tex"}
NEVER_SUSPEND = {"system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
                 "lsass.exe", "svchost.exe", "msmpeng.exe", "explorer.exe", "dwm.exe", "searchindexer.exe",
                 "mssense.exe", "nissrv.exe", "clamd.exe", "timantivirus.exe", "memory compression"}
WINDOW = 10.0
RECENT_PROCESS = 180.0   # процесс считается «новым», если запущен не раньше чем 3 мин назад
MASS_THRESHOLD = 20


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in (data.count(bytes((b,))) for b in range(256)) if c)


def _canary_content(name: str) -> bytes:
    rnd = random.Random(name)
    words = ["отчёт", "бюджет", "договор", "проект", "счёт", "план", "итоги", "квартал", "смета"]
    text = " ".join(rnd.choice(words) for _ in range(800))
    return text.encode("utf-8")


class RansomwareGuard:
    """on_alert(reason, suspect: dict | None) вызывается из рабочего потока."""

    def __init__(self, folders: list[str], on_alert: Callable[[str, dict | None], None],
                 trusted_check: Callable[[str], bool] | None = None):
        self.folders = [f for f in folders if os.path.isdir(f)]
        self.on_alert = on_alert
        self.trusted_check = trusted_check or (lambda exe: False)
        self.canaries: dict[str, bytes] = {}
        self._obs: Observer | None = None
        self._events: deque[tuple[float, str, str]] = deque()
        self._lock = threading.Lock()
        self._io_prev: dict[int, int] = {}
        self._io_delta: dict[int, deque] = {}
        self._stop = threading.Event()
        self._last_alert = 0.0
        self.suspended: dict[int, str] = {}
        self._io_lock = threading.Lock()
        self._no_access: set[int] = set()
        self._t0 = time.time()

    @property
    def running(self) -> bool:
        return self._obs is not None and self._obs.is_alive()

    # ---------- ловушки ----------
    def plant_canaries(self):
        import ctypes
        for folder in self.folders:
            for name in CANARY_NAMES:
                p = os.path.join(folder, name)
                data = _canary_content(name)
                try:
                    if not os.path.exists(p) or open(p, "rb").read() != data:
                        if os.path.exists(p):
                            ctypes.windll.kernel32.SetFileAttributesW(p, 0x80)
                        with open(p, "wb") as f:
                            f.write(data)
                    ctypes.windll.kernel32.SetFileAttributesW(p, 0x2)  # hidden
                    self.canaries[os.path.normcase(p)] = data
                except OSError:
                    continue

    def remove_canaries(self):
        import ctypes
        for p in list(self.canaries):
            try:
                ctypes.windll.kernel32.SetFileAttributesW(p, 0x80)
                os.remove(p)
            except OSError:
                pass
        self.canaries.clear()

    # ---------- запуск ----------
    def start(self):
        self.stop()
        self._stop.clear()
        self._t0 = time.time()
        self.plant_canaries()
        obs = Observer()
        h = _Handler(self)
        for f in self.folders:
            try:
                obs.schedule(h, f, recursive=True)
            except OSError:
                pass
        obs.daemon = True
        obs.start()
        self._obs = obs
        threading.Thread(target=self._watch_loop, daemon=True).start()

    def stop(self):
        self._stop.set()
        if self._obs:
            try:
                self._obs.stop()
                self._obs.join(timeout=3)
            except RuntimeError:
                pass
        self._obs = None

    # ---------- события ----------
    def on_fs(self, kind: str, path: str, dest: str = ""):
        n = os.path.normcase(path)
        if n in self.canaries:
            if kind == "modified":
                try:
                    if open(path, "rb").read() == self.canaries[n]:
                        return  # содержимое не изменилось (например, событие от антивируса)
                except OSError:
                    pass
            self._trigger(tr("Изменён файл-ловушка: {n} ({k})", n=os.path.basename(path), k=kind))
            return
        now = time.time()
        suspicious = False
        if kind == "moved" and dest:
            old_ext, new_ext = os.path.splitext(path)[1].lower(), os.path.splitext(dest)[1].lower()
            suspicious = old_ext != new_ext and new_ext not in (".tmp", ".bak", "")
        elif kind == "modified" and os.path.splitext(path)[1].lower() in LOW_ENTROPY_EXT:
            try:
                with open(path, "rb") as f:
                    suspicious = entropy(f.read(65536)) > 7.5
            except OSError:
                pass
        elif kind == "deleted":
            suspicious = False
        if not suspicious:
            return
        try:
            size = os.path.getsize(dest or path)
        except OSError:
            size = 0
        with self._lock:
            self._events.append((now, kind, path, size))
            while self._events and now - self._events[0][0] > WINDOW:
                self._events.popleft()
            count = len({e[2] for e in self._events})
        if count >= MASS_THRESHOLD:
            self._trigger(tr("Массовое шифрование/переименование файлов: {n} за {s} с", n=count, s=int(WINDOW)))

    # ---------- поиск виновника ----------
    def _watch_loop(self):
        """Фоновая работа — только дешёвая проверка ловушек раз в 2 с.
        Счётчики записи процессов снимаются лишь во время тревоги (это дорого — сотни процессов)."""
        while not self._stop.wait(2.0):
            self._poll_canaries()

    def _poll_canaries(self):
        """Прямая проверка ловушек: уведомления ФС о перезаписи «на месте» приходят не всегда."""
        for path, data in list(self.canaries.items()):
            try:
                with open(path, "rb") as f:
                    same = f.read(len(data) + 1) == data
            except FileNotFoundError:
                same = False
            except OSError:
                continue          # временно занят (например, проверяется антивирусом)
            if not same:
                self._trigger(tr("Изменён файл-ловушка: {n} ({k})", n=os.path.basename(path), k="modified"))
                return

    def _sample_once(self):
        """Снимок счётчиков записи. Для процессов, запущенных после старта защиты, начальное значение 0 —
        иначе быстрый шифровальщик успел бы всё записать до первого замера."""
        recent = time.time() - RECENT_PROCESS
        with self._io_lock:
            seen = set()
            for p in psutil.process_iter(["pid", "create_time"]):
                pid = p.info["pid"]
                if pid in self._no_access:
                    continue
                try:
                    wb = p.io_counters().write_bytes
                except (psutil.Error, AttributeError):
                    self._no_access.add(pid)
                    continue
                seen.add(pid)
                prev = self._io_prev.get(pid)
                if prev is None and (p.info.get("create_time") or 0) >= recent:
                    prev = 0   # недавно запущенный процесс: всё записанное — «свежее»
                self._io_prev[pid] = wb
                if prev is not None:
                    dq = self._io_delta.setdefault(pid, deque(maxlen=20))
                    dq.append(max(0, wb - prev))
            for pid in list(self._io_prev):
                if pid not in seen:
                    self._io_prev.pop(pid, None)
                    self._io_delta.pop(pid, None)

    def changed_bytes(self) -> int:
        now = time.time()
        with self._lock:
            return sum(e[3] for e in self._events if now - e[0] <= WINDOW)

    def candidates(self, min_bytes: int) -> list[dict]:
        """Процессы, записавшие за последние секунды не меньше min_bytes (без системных процессов)."""
        out = []
        windir = os.path.normcase(os.environ.get("SystemRoot", r"C:\Windows")) + os.sep
        for pid, dq in list(self._io_delta.items()):
            total = sum(dq)
            if pid == os.getpid() or total < min_bytes:
                continue
            try:
                p = psutil.Process(pid)
                name, exe, created = p.name(), p.exe(), p.create_time()
            except psutil.Error:
                continue
            if name.lower() in NEVER_SUSPEND or os.path.normcase(exe).startswith(windir):
                continue
            out.append({"pid": pid, "name": name, "exe": exe, "written": total,
                        "new": created >= time.time() - RECENT_PROCESS})
        out.sort(key=lambda c: -c["written"])
        return out[:8]

    def _touches_protected(self, pid: int) -> bool:
        roots = [os.path.normcase(f) + os.sep for f in self.folders]
        try:
            return any(any(os.path.normcase(f.path).startswith(r) for r in roots)
                       for f in psutil.Process(pid).open_files())
        except psutil.Error:
            return False

    def find_culprit(self, min_bytes: int, wait: float = 3.0) -> tuple[dict | None, str]:
        """Возвращает (подозреваемый, доказательство).

        Доказательства (по убыванию надёжности):
          handle  — процесс держит открытыми файлы в защищаемых папках (проверяется несколько раз за wait секунд);
          new     — процесс запущен после старта защиты, не подписан и записал больше всех;
          io      — просто записал больше всех (НЕ основание для приостановки: так «выигрывают» браузеры и др.).
        """
        deadline = time.time() + wait
        cands: list[dict] = []
        while True:
            self._sample_once()
            cands = self.candidates(min_bytes)
            for c in cands:
                if self._touches_protected(c["pid"]):
                    return c, "handle"
            if time.time() >= deadline:
                break
            time.sleep(0.5)
        if not cands:
            return None, ""
        from timav.core.signer import signature
        for c in cands:
            if c["new"] and not signature(c["exe"])[0]:
                return c, "new"
        return cands[0], "io"

    def _trigger(self, reason: str):
        now = time.time()
        if now - self._last_alert < 5:
            return
        self._last_alert = now
        need = max(64 * 1024, self.changed_bytes() // 2)
        suspect, evidence = self.find_culprit(need)
        if suspect:
            suspect["evidence"] = evidence
            suspect["trusted"] = self.trusted_check(suspect["exe"])
            suspect["suspended"] = False
            if evidence in ("handle", "new") and not suspect["trusted"]:
                try:
                    psutil.Process(suspect["pid"]).suspend()
                    suspect["suspended"] = True
                    self.suspended[suspect["pid"]] = suspect["exe"]
                except psutil.Error:
                    pass
        self.on_alert(reason, suspect)
        self.plant_canaries()

    def resolve(self, pid: int, kill: bool) -> bool:
        try:
            p = psutil.Process(pid)
            if kill:
                for c in p.children(recursive=True):
                    c.kill()
                p.kill()
            else:
                p.resume()
            self.suspended.pop(pid, None)
            return True
        except psutil.Error:
            self.suspended.pop(pid, None)
            return False


class _Handler(FileSystemEventHandler):
    def __init__(self, g: RansomwareGuard):
        self.g = g

    def on_modified(self, e):
        if not e.is_directory:
            self.g.on_fs("modified", e.src_path)

    def on_deleted(self, e):
        if not e.is_directory:
            self.g.on_fs("deleted", e.src_path)

    def on_moved(self, e):
        if not e.is_directory:
            self.g.on_fs("moved", e.src_path, e.dest_path)
