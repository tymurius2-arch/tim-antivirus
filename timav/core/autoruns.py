"""Автозагрузка: ключи Run/RunOnce, папки «Автозагрузка», задачи планировщика и службы сторонних
производителей. Отключение записей реестра и ярлыков обратимо (резервная копия)."""
from __future__ import annotations

import csv
import io
import json
import os
import re
import shutil
import subprocess
import winreg
from dataclasses import asdict, dataclass

from timav.core import paths
from timav.core.clamav import CREATE_NO_WINDOW

RUN_KEYS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run (32-bit)"),
]
HIVES = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
BACKUP_KEY = r"Software\TimAntivirus\DisabledAutoruns"


@dataclass
class AutorunEntry:
    id: str
    kind: str               # registry | startup | task | service
    location: str
    name: str
    command: str
    path: str = ""
    enabled: bool = True
    signer: str = ""
    signed: bool = False
    verdict: str = ""       # clean | threat:<name> | suspicious | missing
    can_toggle: bool = True


def exe_from_command(cmd: str) -> str:
    cmd = os.path.expandvars(cmd.strip())
    if not cmd:
        return ""
    if cmd.startswith('"'):
        p = cmd[1:].split('"', 1)[0]
    else:
        m = re.match(r"(.+?\.(exe|com|bat|cmd|vbs|js|ps1|scr|dll|lnk))(\s|,|\"|$)", cmd, re.I)
        p = m.group(1) if m else cmd.split(" ")[0]
    if p.lower().startswith("rundll32") or os.path.basename(p).lower() in ("rundll32.exe", "rundll32"):
        rest = cmd.split(None, 1)[1] if " " in cmd else ""
        p = exe_from_command(rest.split(",")[0]) if rest else p
    if not os.path.isabs(p):
        for d in os.environ.get("PATH", "").split(os.pathsep):
            c = os.path.join(d, p)
            if os.path.isfile(c):
                return c
    return p


def _reg_entries() -> list[AutorunEntry]:
    out = []
    for hive, key, label in RUN_KEYS:
        try:
            with winreg.OpenKey(hive, key) as k:
                i = 0
                while True:
                    try:
                        name, val, _ = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    i += 1
                    out.append(AutorunEntry(f"reg|{label}|{name}", "registry", label, name, str(val),
                                            exe_from_command(str(val)),
                                            can_toggle=True))
        except OSError:
            continue
    # отключённые нами записи
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, BACKUP_KEY) as k:
            i = 0
            while True:
                try:
                    vid, data, _ = winreg.EnumValue(k, i)
                except OSError:
                    break
                i += 1
                try:
                    d = json.loads(data)
                    out.append(AutorunEntry(vid, "registry", d["location"], d["name"], d["command"],
                                            exe_from_command(d["command"]), enabled=False))
                except (ValueError, KeyError):
                    pass
    except OSError:
        pass
    return out


def startup_folders() -> list[tuple[str, str]]:
    appdata = os.environ.get("APPDATA", "")
    progdata = os.environ.get("ProgramData", r"C:\ProgramData")
    return [(os.path.join(appdata, r"Microsoft\Windows\Start Menu\Programs\Startup"), "Автозагрузка (пользователь)"),
            (os.path.join(progdata, r"Microsoft\Windows\Start Menu\Programs\StartUp"), "Автозагрузка (все)")]


def _disabled_dir() -> str:
    d = paths.data_dir() / "disabled_startup"
    d.mkdir(exist_ok=True)
    return str(d)


def _lnk_target(lnk: str) -> str:
    try:
        ps = f"(New-Object -ComObject WScript.Shell).CreateShortcut('{lnk.replace(chr(39), chr(39) * 2)}').TargetPath"
        r = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True,
                           timeout=10, creationflags=CREATE_NO_WINDOW)
        return r.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def _startup_entries() -> list[AutorunEntry]:
    out = []
    for folder, label in startup_folders():
        if not os.path.isdir(folder):
            continue
        for fn in os.listdir(folder):
            if fn.lower() == "desktop.ini":
                continue
            full = os.path.join(folder, fn)
            target = _lnk_target(full) if fn.lower().endswith(".lnk") else full
            out.append(AutorunEntry(f"file|{full}", "startup", label, fn, target or full, target or full))
    meta = os.path.join(_disabled_dir(), "index.json")
    try:
        idx = json.loads(open(meta, encoding="utf-8").read())
    except (OSError, ValueError):
        idx = {}
    for stored, orig in idx.items():
        out.append(AutorunEntry(f"filedis|{stored}", "startup", "Автозагрузка (отключено)", os.path.basename(orig),
                                orig, os.path.join(_disabled_dir(), stored), enabled=False))
    return out


def _task_entries() -> list[AutorunEntry]:
    out = []
    try:
        r = subprocess.run(["schtasks", "/query", "/fo", "csv", "/v"], capture_output=True, timeout=60,
                           creationflags=CREATE_NO_WINDOW)
        text = r.stdout.decode("cp866", "replace") if r.stdout else ""
    except (OSError, subprocess.SubprocessError):
        return out
    rows = list(csv.reader(io.StringIO(text)))
    if not rows:
        return out
    header = rows[0]
    try:
        i_name = header.index("TaskName") if "TaskName" in header else 1
        i_run = next(i for i, h in enumerate(header) if h in ("Task To Run", "Выполняемая задача", "Задача для выполнения"))
        i_state = next((i for i, h in enumerate(header) if h in ("Scheduled Task State", "Состояние назначенного задания")), None)
    except StopIteration:
        i_name, i_run, i_state = 1, 8, None
    seen = set()
    for row in rows[1:]:
        if len(row) <= i_run or row[0] == header[0]:
            continue
        name = row[i_name]
        if name in seen or name.startswith("\\Microsoft\\"):
            continue
        seen.add(name)
        cmd = row[i_run]
        if not cmd or cmd.upper() in ("COM HANDLER", "ОБРАБОТЧИК COM"):
            continue
        enabled = True
        if i_state is not None and len(row) > i_state:
            enabled = row[i_state].lower() not in ("disabled", "отключено")
        out.append(AutorunEntry(f"task|{name}", "task", "Планировщик заданий", name, cmd, exe_from_command(cmd),
                                enabled=enabled))
    return out


def _service_entries() -> list[AutorunEntry]:
    out = []
    try:
        import psutil
        windir = os.path.normcase(os.environ.get("SystemRoot", r"C:\Windows"))
        for s in psutil.win_service_iter():
            try:
                info = s.as_dict()
            except Exception:
                continue
            if info.get("start_type") != "automatic":
                continue
            bp = info.get("binpath") or ""
            exe = exe_from_command(bp)
            if os.path.normcase(exe).startswith(windir) or not exe:
                continue
            out.append(AutorunEntry(f"svc|{info['name']}", "service", "Службы", info.get("display_name") or info["name"],
                                    bp, exe, can_toggle=False))
    except Exception:
        pass
    return out


def collect(include_tasks: bool = True, include_services: bool = True) -> list[AutorunEntry]:
    items = _reg_entries() + _startup_entries()
    if include_tasks:
        items += _task_entries()
    if include_services:
        items += _service_entries()
    return items


def _catalog_signers(files: list[str]) -> dict[str, str]:
    """Подписи из каталогов Windows (системные файлы без встроенной подписи) — один вызов PowerShell."""
    if not files:
        return {}
    lst = ",".join("'" + f.replace("'", "''") + "'" for f in files)
    ps = (f"@({lst}) | ForEach-Object {{ $s = Get-AuthenticodeSignature -LiteralPath $_; "
          "if ($s.Status -eq 'Valid') { $_ + '|' + $s.SignerCertificate.GetNameInfo('SimpleName', $false) } }")
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, timeout=60,
                           creationflags=CREATE_NO_WINDOW)
        out = r.stdout.decode("utf-8", "replace") if r.stdout else ""
    except (OSError, subprocess.SubprocessError):
        return {}
    res = {}
    for line in out.splitlines():
        if "|" in line:
            path, name = line.rsplit("|", 1)
            res[os.path.normcase(path.strip())] = name.strip()
    return res


def evaluate(entries: list[AutorunEntry], engine, analyzer) -> None:
    """Подпись, ClamAV и (для неподписанных) AI-оценка; файлы проверяются параллельно."""
    from concurrent.futures import ThreadPoolExecutor

    from timav.core.signer import signature

    def check(p: str) -> tuple:
        valid, signer = signature(p)
        verdict = "clean"
        try:
            v = engine.scan_file(p) if engine and engine.db_ready() else None
            if v and v.infected:
                verdict = "threat:" + v.signature
            elif analyzer and not valid:
                rep = analyzer.analyze(p)
                if rep.score >= 0.75:
                    verdict = "suspicious"
        except (OSError, ValueError):
            pass
        return valid, signer, verdict

    paths_ = {os.path.normcase(e.path): e.path for e in entries if e.path and os.path.isfile(e.path)}
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = dict(zip(paths_, pool.map(check, paths_.values())))
    unsigned = [paths_[k] for k, r in results.items() if not r[0]]
    cat = _catalog_signers(unsigned)
    for k, name in cat.items():
        if k in results:
            results[k] = (True, name, results[k][2])
    for e in entries:
        r = results.get(os.path.normcase(e.path)) if e.path else None
        if r is None:
            e.verdict = "missing"
        else:
            e.signed, e.signer, e.verdict = r


def set_enabled(e: AutorunEntry, enable: bool) -> None:
    """Включение/отключение. Бросает PermissionError, если нужны права администратора."""
    if e.kind == "registry":
        if not enable:
            hive_name, rest = e.location.split("\\", 1)
            key = next(k for h, k, lbl in RUN_KEYS if lbl == e.location)
            with winreg.OpenKey(HIVES[hive_name], key, 0, winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, e.name)
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, BACKUP_KEY) as b:
                vid = f"dis|{e.location}|{e.name}"
                winreg.SetValueEx(b, vid, 0, winreg.REG_SZ,
                                  json.dumps({"location": e.location, "name": e.name, "command": e.command}))
        else:
            d_key = next(k for h, k, lbl in RUN_KEYS if lbl == e.location)
            hive_name = e.location.split("\\", 1)[0]
            with winreg.OpenKey(HIVES[hive_name], d_key, 0, winreg.KEY_SET_VALUE) as k:
                winreg.SetValueEx(k, e.name, 0, winreg.REG_SZ, e.command)
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, BACKUP_KEY, 0, winreg.KEY_SET_VALUE) as b:
                winreg.DeleteValue(b, e.id)
    elif e.kind == "startup":
        meta = os.path.join(_disabled_dir(), "index.json")
        try:
            idx = json.loads(open(meta, encoding="utf-8").read())
        except (OSError, ValueError):
            idx = {}
        if not enable:
            src = e.id.split("|", 1)[1]
            stored = f"{len(idx)}_{os.path.basename(src)}"
            shutil.move(src, os.path.join(_disabled_dir(), stored))
            idx[stored] = src
        else:
            stored = e.id.split("|", 1)[1]
            orig = idx.pop(stored)
            shutil.move(os.path.join(_disabled_dir(), stored), orig)
        with open(meta, "w", encoding="utf-8") as f:
            json.dump(idx, f, ensure_ascii=False)
    elif e.kind == "task":
        r = subprocess.run(["schtasks", "/change", "/tn", e.name, "/enable" if enable else "/disable"],
                           capture_output=True, timeout=30, creationflags=CREATE_NO_WINDOW)
        if r.returncode != 0:
            raise PermissionError("Нужны права администратора для изменения этой задачи")
    else:
        raise PermissionError("Службы меняются в оснастке «Службы» (services.msc)")


def to_dict(e: AutorunEntry) -> dict:
    return asdict(e)
