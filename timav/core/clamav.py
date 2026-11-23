"""Обёртка над движком ClamAV: резидентный clamd (INSTREAM по TCP) и clamscan как запасной вариант."""
from __future__ import annotations

import os
import re
import socket
import struct
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

from timav.core import paths

CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0
BELOW_NORMAL = 0x00004000 if os.name == "nt" else 0   # не мешать играм и работе
CLAMD_PORT = int(os.environ.get("TIMAV_CLAMD_PORT", "33110"))
CHUNK = 1 << 16


@dataclass
class ScanVerdict:
    path: str
    status: str            # clean | infected | error | skipped
    signature: str = ""
    detail: str = ""

    @property
    def infected(self) -> bool:
        return self.status == "infected"


@dataclass
class DbInfo:
    name: str
    version: int
    signatures: int
    built: datetime | None


def read_cvd_header(path: Path) -> DbInfo | None:
    """Заголовок .cvd/.cld: 'ClamAV-VDB:build time:version:sigs:...'."""
    try:
        with open(path, "rb") as f:
            head = f.read(512).decode("latin-1", "replace")
    except OSError:
        return None
    if not head.startswith("ClamAV-VDB:"):
        return None
    parts = head.split(":")
    built = None
    try:
        built = datetime.strptime(parts[1].strip(), "%d %b %Y %H-%M %z")
    except (ValueError, IndexError):
        pass
    try:
        return DbInfo(path.stem, int(parts[2]), int(parts[3]), built)
    except (ValueError, IndexError):
        return DbInfo(path.stem, 0, 0, built)


class ClamAVEngine:
    def __init__(self, clam_dir: Path | None = None, db: Path | None = None, port: int = CLAMD_PORT,
                 max_file_mb: int = 100, scan_archives: bool = True):
        self.clam_dir = clam_dir or paths.clamav_dir()
        self.db = db or paths.db_dir()
        self.port = port
        self.max_file_mb = max_file_mb
        self.scan_archives = scan_archives
        self._proc: subprocess.Popen | None = None
        self._lock = threading.Lock()

    # ---------- информация ----------
    def exe(self, name: str) -> Path | None:
        if not self.clam_dir:
            return None
        p = self.clam_dir / f"{name}.exe"
        return p if p.exists() else None

    @property
    def available(self) -> bool:
        return self.exe("clamscan") is not None

    def db_files(self) -> list[Path]:
        exts = {".cvd", ".cld", ".cud", ".hdb", ".hsb", ".ndb", ".ldb", ".cdb", ".mdb", ".msb", ".yar", ".yara", ".ign2"}
        return sorted(p for p in self.db.glob("*") if p.suffix.lower() in exts)

    def db_ready(self) -> bool:
        return bool(self.db_files())

    def db_info(self) -> list[DbInfo]:
        out = []
        for p in self.db_files():
            if p.suffix.lower() in (".cvd", ".cld", ".cud"):
                info = read_cvd_header(p)
                if info:
                    out.append(info)
        return out

    def db_newest(self) -> datetime | None:
        dates = [i.built for i in self.db_info() if i.built]
        return max(dates) if dates else None

    def db_signatures(self) -> int:
        return sum(i.signatures for i in self.db_info())

    def version(self) -> str:
        if self.daemon_alive():
            v = self._command(b"zVERSION\0")
            if v:
                return v
        exe = self.exe("clamscan")
        if not exe:
            return "ClamAV не найден"
        try:
            r = subprocess.run([str(exe), "--version"], capture_output=True, text=True, timeout=20,
                               creationflags=CREATE_NO_WINDOW)
            return r.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return "ClamAV"

    # ---------- конфиги ----------
    def write_configs(self) -> tuple[Path, Path]:
        d = paths.data_dir()
        logs = paths.logs_dir()
        clamd_conf = d / "clamd.conf"
        clamd_conf.write_text("\n".join([
            f"DatabaseDirectory {self.db}",
            f"TCPSocket {self.port}",
            "TCPAddr 127.0.0.1",
            f"LogFile {logs / 'clamd.log'}",
            "LogFileMaxSize 5M",
            "LogTime yes",
            "MaxThreads 8",
            f"MaxFileSize {self.max_file_mb}M",
            f"MaxScanSize {self.max_file_mb * 4}M",
            f"StreamMaxLength {self.max_file_mb}M",
            f"ScanArchive {'yes' if self.scan_archives else 'no'}",
            "ScanPE yes",
            "ScanOLE2 yes",
            "ScanPDF yes",
            "ScanHTML yes",
            "AlertBrokenExecutables no",
            "SelfCheck 3600",
            "",
        ]), encoding="utf-8")
        fresh_conf = d / "freshclam.conf"
        fresh_conf.write_text("\n".join([
            f"DatabaseDirectory {self.db}",
            f"UpdateLogFile {logs / 'freshclam.log'}",
            "LogTime yes",
            "DatabaseMirror database.clamav.net",
            "ConnectTimeout 30",
            "ReceiveTimeout 0",
            "",
        ]), encoding="utf-8")
        return clamd_conf, fresh_conf

    # ---------- демон ----------
    def _connect(self, timeout: float = 5.0) -> socket.socket:
        s = socket.create_connection(("127.0.0.1", self.port), timeout=timeout)
        return s

    def _command(self, cmd: bytes, timeout: float = 5.0) -> str | None:
        try:
            with self._connect(timeout) as s:
                s.sendall(cmd)
                data = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if data.endswith(b"\0"):
                        break
            return data.rstrip(b"\0\n").decode("utf-8", "replace")
        except OSError:
            return None

    def daemon_alive(self) -> bool:
        return self._command(b"zPING\0", timeout=1.5) == "PONG"

    def start_daemon(self, wait: float = 180.0, stop: threading.Event | None = None) -> bool:
        """Запускает clamd (загрузка баз ~20–60 с). Возвращает True, когда отвечает PONG."""
        if self.daemon_alive():
            return True
        exe = self.exe("clamd")
        if not exe or not self.db_ready():
            return False
        conf, _ = self.write_configs()
        with self._lock:
            if self._proc is None or self._proc.poll() is not None:
                self._proc = subprocess.Popen(
                    [str(exe), f"--config-file={conf}"], cwd=str(self.clam_dir),
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    creationflags=CREATE_NO_WINDOW | BELOW_NORMAL)
        deadline = time.time() + wait
        while time.time() < deadline:
            if stop is not None and stop.is_set():
                return False
            if self._proc.poll() is not None:
                return False
            if self.daemon_alive():
                return True
            time.sleep(1.0)
        return False

    def reload_daemon(self) -> None:
        self._command(b"zRELOAD\0")

    def stop_daemon(self) -> None:
        self._command(b"zSHUTDOWN\0", timeout=2)
        with self._lock:
            if self._proc and self._proc.poll() is None:
                try:
                    self._proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
            self._proc = None

    # ---------- сканирование ----------
    def scan_file(self, path: str | Path) -> ScanVerdict:
        """Сканирование одного файла: через clamd (INSTREAM) или clamscan."""
        path = str(path)
        try:
            size = os.path.getsize(path)
        except OSError as e:
            return ScanVerdict(path, "error", detail=str(e))
        if size > self.max_file_mb * 1024 * 1024:
            return ScanVerdict(path, "skipped", detail="файл слишком большой")
        if self.daemon_alive():
            return self._scan_instream(path)
        res = self.scan_files_clamscan([path])
        return res[0] if res else ScanVerdict(path, "error", detail="нет ответа clamscan")

    def _scan_instream(self, path: str) -> ScanVerdict:
        try:
            with open(path, "rb") as f, self._connect(timeout=120) as s:
                s.sendall(b"zINSTREAM\0")
                while True:
                    buf = f.read(CHUNK)
                    if not buf:
                        break
                    s.sendall(struct.pack("!L", len(buf)) + buf)
                s.sendall(struct.pack("!L", 0))
                data = b""
                while not data.endswith(b"\0"):
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
        except PermissionError as e:
            return ScanVerdict(path, "skipped", detail=f"нет доступа: {e.strerror}")
        except OSError as e:
            return ScanVerdict(path, "error", detail=str(e))
        reply = data.rstrip(b"\0").decode("utf-8", "replace")
        return self._parse_reply(path, reply)

    def scan_bytes(self, data: bytes, label: str = "stream") -> ScanVerdict:
        """Проверка буфера в памяти через clamd (без записи на диск)."""
        try:
            with self._connect(timeout=60) as s:
                s.sendall(b"zINSTREAM\0")
                for i in range(0, len(data), CHUNK):
                    part = data[i:i + CHUNK]
                    s.sendall(struct.pack("!L", len(part)) + part)
                s.sendall(struct.pack("!L", 0))
                reply = b""
                while not reply.endswith(b"\0"):
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    reply += chunk
        except OSError as e:
            return ScanVerdict(label, "error", detail=str(e))
        return self._parse_reply(label, reply.rstrip(b"\0").decode("utf-8", "replace"))

    @staticmethod
    def _parse_reply(path: str, reply: str) -> ScanVerdict:
        # "stream: OK" | "stream: Eicar-Signature FOUND" | "... ERROR"
        body = reply.split(": ", 1)[-1]
        if body.endswith("FOUND"):
            return ScanVerdict(path, "infected", signature=body[:-5].strip())
        if body.strip() == "OK":
            return ScanVerdict(path, "clean")
        if "size limit" in body.lower():
            return ScanVerdict(path, "skipped", detail=body)
        return ScanVerdict(path, "error", detail=body)

    _line_re = re.compile(r"^(?P<path>.+): (?P<body>.+?)$")

    def scan_files_clamscan(self, files: Iterable[str], on_result: Callable[[ScanVerdict], None] | None = None,
                            stop: threading.Event | None = None) -> list[ScanVerdict]:
        """Пакетное сканирование clamscan (без демона). Базы загружаются один раз на пакет."""
        exe = self.exe("clamscan")
        files = list(files)
        if not exe:
            return [ScanVerdict(f, "error", detail="ClamAV не найден") for f in files]
        if not self.db_ready():
            return [ScanVerdict(f, "error", detail="нет антивирусных баз") for f in files]
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".lst", encoding="utf-8") as lst:
            lst.write("\n".join(files))
            list_path = lst.name
        cmd = [str(exe), "--no-summary", f"--database={self.db}", f"--file-list={list_path}",
               f"--max-filesize={self.max_file_mb}M", f"--max-scansize={self.max_file_mb * 4}M",
               f"--scan-archive={'yes' if self.scan_archives else 'no'}", "--stdout"]
        results: dict[str, ScanVerdict] = {}
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    creationflags=CREATE_NO_WINDOW, cwd=str(self.clam_dir))
            assert proc.stdout
            for raw in proc.stdout:
                if stop is not None and stop.is_set():
                    proc.kill()
                    break
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                m = self._line_re.match(line)
                if not m:
                    continue
                v = self._parse_reply(m["path"], m["path"] + ": " + m["body"])
                v.path = m["path"]
                results[os.path.normcase(v.path)] = v
                if on_result:
                    on_result(v)
            proc.wait()
        finally:
            try:
                os.unlink(list_path)
            except OSError:
                pass
        out = []
        for f in files:
            v = results.get(os.path.normcase(f))
            if v is None:
                v = ScanVerdict(f, "clean")
                if on_result:
                    on_result(v)
            out.append(v)
        return out


def db_age_hours(engine: ClamAVEngine) -> float | None:
    newest = engine.db_newest()
    if not newest:
        return None
    return (datetime.now(timezone.utc) - newest).total_seconds() / 3600
