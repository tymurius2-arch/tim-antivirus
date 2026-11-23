"""Обновление самой программы.

Канал обновлений (settings.update_feed_url):
  • URL JSON-манифеста: {"version": "1.2.0", "url": "https://…/TimAntivirus-Setup-1.2.0.exe",
                         "sha256": "…", "notes": "…"}
  • github:owner/repo — последний релиз GitHub; установщик *Setup*.exe, хеш из файла *.sha256 или поля digest.
Загруженный установщик проверяется по SHA-256 и запускается в тихом режиме.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import urllib.request
from dataclasses import dataclass
from typing import Callable

from timav import __version__

UA = {"User-Agent": f"TimAntivirus/{__version__}"}


@dataclass
class Release:
    version: str
    url: str
    sha256: str
    notes: str = ""


def vtuple(v: str) -> tuple:
    out = []
    for p in v.strip().lstrip("vV").split("."):
        num = "".join(ch for ch in p if ch.isdigit())
        out.append(int(num) if num else 0)
    return tuple(out + [0] * (4 - len(out)))


def _get_json(url: str) -> dict:
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=20) as r:
        return json.loads(r.read().decode("utf-8-sig"))


def fetch_release(feed: str) -> Release:
    feed = feed.strip()
    if feed.startswith("github:"):
        repo = feed.split(":", 1)[1].strip("/")
        d = _get_json(f"https://api.github.com/repos/{repo}/releases/latest")
        assets = d.get("assets", [])
        inst = next((a for a in assets if a["name"].lower().endswith(".exe") and "setup" in a["name"].lower()), None)
        if not inst:
            raise ValueError("В релизе нет установщика *Setup*.exe")
        sha = (inst.get("digest") or "").replace("sha256:", "")
        if not sha:
            sh = next((a for a in assets if a["name"].lower().endswith(".sha256")), None)
            if sh:
                with urllib.request.urlopen(urllib.request.Request(sh["browser_download_url"], headers=UA), timeout=20) as r:
                    sha = r.read().decode().split()[0]
        if not sha:
            raise ValueError("В релизе нет контрольной суммы SHA-256")
        return Release(d.get("tag_name", "0"), inst["browser_download_url"], sha.lower(), d.get("body", "") or "")
    d = _get_json(feed)
    return Release(str(d["version"]), d["url"], str(d["sha256"]).lower(), d.get("notes", ""))


def check(feed: str, current: str = __version__) -> Release | None:
    """Release, если доступна более новая версия, иначе None."""
    if not feed:
        raise ValueError("Канал обновлений не настроен")
    rel = fetch_release(feed)
    return rel if vtuple(rel.version) > vtuple(current) else None


def download(rel: Release, on_progress: Callable[[int, int], None] | None = None, dest_dir: str | None = None) -> str:
    dest_dir = dest_dir or tempfile.mkdtemp(prefix="timav_update_")
    os.makedirs(dest_dir, exist_ok=True)
    dest = os.path.join(dest_dir, f"TimAntivirus-Setup-{rel.version}.exe")
    h = hashlib.sha256()
    with urllib.request.urlopen(urllib.request.Request(rel.url, headers=UA), timeout=60) as r, open(dest, "wb") as f:
        total = int(r.headers.get("Content-Length") or 0)
        done = 0
        while True:
            buf = r.read(1 << 16)
            if not buf:
                break
            f.write(buf)
            h.update(buf)
            done += len(buf)
            if on_progress:
                on_progress(done, total)
    if h.hexdigest() != rel.sha256:
        os.remove(dest)
        raise ValueError("Контрольная сумма не совпадает — загрузка повреждена или подменена")
    return dest


def install(installer: str) -> None:
    """Запускает установщик в тихом режиме; приложение должно сразу завершиться."""
    subprocess.Popen([installer, "/SILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/CLOSEAPPLICATIONS"],
                     close_fds=True)
