"""Обновление антивирусных баз через freshclam."""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Callable

from timav.core import paths
from timav.core.clamav import CREATE_NO_WINDOW, ClamAVEngine


@dataclass
class UpdateResult:
    ok: bool
    updated: bool
    message: str
    log: str


def update_databases(engine: ClamAVEngine, on_line: Callable[[str], None] | None = None,
                     timeout: float = 1800) -> UpdateResult:
    exe = engine.exe("freshclam")
    if not exe:
        return UpdateResult(False, False, "freshclam не найден", "")
    _, conf = engine.write_configs()
    cmd = [str(exe), f"--config-file={conf}", "--stdout", "--show-progress"]
    lines: list[str] = []
    logfile = paths.logs_dir() / "freshclam.log"
    log_start = logfile.stat().st_size if logfile.exists() else 0
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                cwd=str(engine.clam_dir), creationflags=CREATE_NO_WINDOW)
        assert proc.stdout
        buf = b""
        while True:
            ch = proc.stdout.read(1)
            if not ch:
                break
            if ch in (b"\n", b"\r"):
                if buf.strip():
                    line = buf.decode("utf-8", "replace").strip()
                    if ch == b"\n":
                        lines.append(line)
                    if on_line:
                        on_line(line)
                buf = b""
            else:
                buf += ch
        proc.wait(timeout=timeout)
        code = proc.returncode
    except (OSError, subprocess.SubprocessError) as e:
        return UpdateResult(False, False, f"Ошибка запуска freshclam: {e}", "\n".join(lines))
    try:
        with open(logfile, "rb") as f:
            f.seek(log_start)
            tail = f.read().decode("utf-8", "replace")
        for line in tail.splitlines():
            line = line.split("-> ", 1)[-1].strip()
            if line and line.strip("-") and line not in lines:
                lines.append(line)
                if on_line:
                    on_line(line)
    except OSError:
        pass
    log = "\n".join(lines)
    low = log.lower()
    updated = "updated (version" in low or ".cdiff" in low or "database updated" in low
    if code == 0:
        if updated:
            engine.reload_daemon()
        msg = "Базы обновлены" if updated else "Базы актуальны"
        return UpdateResult(True, updated, msg, log)
    if "cool-down" in low or "rate limit" in low or "429" in low:
        return UpdateResult(False, False, "Сервер обновлений ограничил частоту запросов, повтор позже", log)
    return UpdateResult(False, False, f"freshclam завершился с кодом {code}", log)
