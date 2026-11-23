"""Тесты функций версии 1.1: контроль запуска, шифровальщики, загрузки, автозагрузка, система,
VirusTotal, описания угроз, отчёты, меню Проводника, самообновление, ML, локализация."""
import hashlib
import http.server
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import winreg
from pathlib import Path

import pytest

from timav.core import paths
from timav.core.clamav import ClamAVEngine

needs_clam = pytest.mark.skipif(paths.clamav_dir() is None, reason="ClamAV не найден")


# ---------------- 1. Контроль запуска ----------------
@needs_clam
def test_process_guard_kills_infected_process(tmp_path):
    from timav.core.process_guard import ProcessGuard
    exe = tmp_path / "evil_ping.exe"
    shutil.copy(r"C:\Windows\System32\PING.EXE", exe)
    db = tmp_path / "db"
    db.mkdir()
    data = exe.read_bytes()
    (db / "t.hdb").write_text(f"{hashlib.md5(data).hexdigest()}:{len(data)}:Tim.Test.Process\n")
    eng = ClamAVEngine(db=db, port=33191)
    events = []
    ev = threading.Event()
    try:
        assert eng.start_daemon(wait=60)
        g = ProcessGuard(eng, lambda *a: (events.append(a), ev.set()), heuristics=False, interval=0.2)
        g.start()
        time.sleep(0.5)
        proc = subprocess.Popen([str(exe), "-n", "30", "127.0.0.1"], stdout=subprocess.DEVNULL,
                                creationflags=0x08000000)
        assert ev.wait(15), "контроль запуска не сработал"
        proc.wait(timeout=10)
        g.stop()
    finally:
        eng.stop_daemon()
    kind, path, name, pid, action = events[0]
    assert kind == "threat" and name.startswith("Tim.Test.Process") and pid == proc.pid
    assert action == "процесс остановлен" and proc.returncode is not None


# ---------------- 2. Шифровальщики ----------------
RANSOM_SIM = r"""
import os, sys, time
folder = sys.argv[1]
canary = [n for n in os.listdir(folder) if n.startswith("~$tim_")][0]
with open(os.path.join(folder, canary), "r+b") as f:
    f.write(os.urandom(4096))
# like real ransomware: file by file, each one kept open while being "encrypted"
for i in range(400):
    path = os.path.join(folder, f"doc{i % 30}.txt")
    with open(path, "r+b") as f:
        for _ in range(8):
            f.seek(0)
            f.write(os.urandom(8192))
            time.sleep(0.02)
"""


def test_ransomware_guard_suspends_encryptor(tmp_path):
    from timav.core.ransomware import RansomwareGuard
    folder = tmp_path / "Documents"
    folder.mkdir()
    for i in range(30):
        (folder / f"doc{i}.txt").write_text("обычный текст " * 300, encoding="utf-8")
    alerts = []
    ev = threading.Event()
    g = RansomwareGuard([str(folder)], lambda r, s: (alerts.append((r, s)), ev.set()), trusted_check=lambda e: False)
    g.start()
    assert len(g.canaries) == 3
    script = tmp_path / "sim.py"
    script.write_text(RANSOM_SIM)
    time.sleep(1.5)
    proc = subprocess.Popen([sys.executable, str(script), str(folder)])
    try:
        assert ev.wait(20), "защита не сработала"
        reason, suspect = alerts[0]
        assert "ловушка" in reason or "Массов" in reason
        import psutil
        family = {proc.pid} | {c.pid for c in psutil.Process(proc.pid).children(recursive=True)}
        assert suspect and suspect["pid"] in family and suspect["suspended"], suspect
        assert suspect["evidence"] == "handle"
        assert g.resolve(suspect["pid"], kill=True)
        proc.wait(timeout=10)
    finally:
        if proc.poll() is None:
            proc.kill()
        g.stop()
        g.remove_canaries()
    assert not any(n.startswith("~$tim_") for n in os.listdir(folder))


def test_ransomware_never_suspends_unrelated_writers(tmp_path):
    """Тревога без процесса, работающего с защищаемой папкой, не должна приостанавливать посторонние процессы."""
    import psutil
    from timav.core.ransomware import RansomwareGuard
    folder = tmp_path / "Docs"
    folder.mkdir()
    alerts = []
    g = RansomwareGuard([str(folder)], lambda r, s: alerts.append(s), trusted_check=lambda e: False)
    g.start()
    try:
        time.sleep(1.2)
        g._last_alert = 0
        g._trigger("тест")
        suspect = alerts[-1]
        assert not suspect or not suspect["suspended"], suspect
        assert not any(p.info["status"] == psutil.STATUS_STOPPED and p.info["pid"] in g.suspended
                       for p in psutil.process_iter(["pid", "status"]))
    finally:
        g.stop()
        g.remove_canaries()


def test_ransomware_guard_idle_is_cheap(tmp_path):
    """В покое защита не опрашивает процессы (раньше это съедало до 75% CPU)."""
    from timav.core.ransomware import RansomwareGuard
    g = RansomwareGuard([str(tmp_path)], lambda r, s: None)
    calls = []
    orig = g._sample_once
    g._sample_once = lambda: (calls.append(1), orig())
    g.start()
    try:
        time.sleep(4.5)
        assert calls == []
    finally:
        g.stop()
        g.remove_canaries()


def test_canaries_ignore_unchanged_touch(tmp_path):
    from timav.core.ransomware import RansomwareGuard
    alerts = []
    g = RansomwareGuard([str(tmp_path)], lambda r, s: alerts.append(r))
    g.plant_canaries()
    c = next(iter(g.canaries))
    g.on_fs("modified", c)            # содержимое не менялось
    assert not alerts
    g.remove_canaries()


# ---------------- 3. USB, 4. загрузки ----------------
def test_usb_enumeration():
    from timav.core.devices import UsbWatcher, removable_drives
    assert isinstance(removable_drives(), set)
    w = UsbWatcher(lambda r, l: None, interval=0.1)
    w.start()
    assert w.running
    w.stop()


def test_zone_identifier(tmp_path):
    from timav.core import downloads
    f = tmp_path / "setup.exe"
    f.write_bytes(b"MZ")
    with open(str(f) + ":Zone.Identifier", "w") as z:
        z.write("[ZoneTransfer]\nZoneId=3\nReferrerUrl=https://example.org/\nHostUrl=https://cdn.example.org/setup.exe\n")
    info = downloads.zone_info(str(f))
    assert info == {"zone": 3, "referrer": "https://example.org/", "host_url": "https://cdn.example.org/setup.exe"}
    assert downloads.describe_source(info) == "источник: cdn.example.org"
    assert downloads.worth_reporting(str(f))


# ---------------- 5. Автозагрузка ----------------
def test_exe_from_command():
    from timav.core.autoruns import exe_from_command
    assert exe_from_command(r'"C:\Program Files\App\app.exe" --min') == r"C:\Program Files\App\app.exe"
    assert exe_from_command(r"C:\Tools\tool.exe -x") == r"C:\Tools\tool.exe"
    assert exe_from_command(r"%SystemRoot%\system32\cmd.exe /c x").lower().endswith(r"system32\cmd.exe")


def test_autoruns_toggle_roundtrip():
    from timav.core import autoruns
    key = r"Software\Microsoft\Windows\CurrentVersion\Run"
    name = "TimAVTestEntry"
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, name, 0, winreg.REG_SZ, r'"C:\nonexistent\x.exe" /q')
    try:
        items = autoruns.collect(include_tasks=False, include_services=False)
        e = next(i for i in items if i.name == name and i.enabled)
        autoruns.evaluate([e], None, None)
        assert e.verdict == "missing"
        autoruns.set_enabled(e, False)
        items = autoruns.collect(include_tasks=False, include_services=False)
        d = next(i for i in items if i.name == name)
        assert not d.enabled
        autoruns.set_enabled(d, True)
        items = autoruns.collect(include_tasks=False, include_services=False)
        assert next(i for i in items if i.name == name).enabled
    finally:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, name)
        except OSError:
            pass


def test_autoruns_full_collect():
    from timav.core import autoruns
    items = autoruns.collect()
    assert all(i.kind in ("registry", "startup", "task", "service") for i in items)


# ---------------- 19. Проверка системы ----------------
def test_posture_checks():
    from timav.core.posture import run_checks, summary
    checks = run_checks()
    ids = {c.id for c in checks}
    assert {"defender", "uac", "secureboot", "rdp", "smb1"} <= ids
    assert all(c.status in ("ok", "warn", "bad", "info") for c in checks)
    assert sum(summary(checks)) <= len(checks)


# ---------------- 10. VirusTotal ----------------
def test_virustotal_parse():
    from timav.core.virustotal import parse
    data = {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 3, "suspicious": 1, "harmless": 0, "undetected": 60},
        "last_analysis_results": {"A": {"category": "malicious", "result": "Trojan.X"},
                                  "B": {"category": "undetected", "result": None}},
        "popular_threat_classification": {"suggested_threat_label": "trojan.x"}}}}
    r = parse(data, "ab" * 32)
    assert r["malicious"] == 3 and r["total"] == 64 and r["names"] == ["Trojan.X"] and r["label"] == "trojan.x"


# ---------------- 13. Описания угроз ----------------
@pytest.mark.parametrize("sig,cat,danger", [
    ("Win.Trojan.Emotet-9953920-0", "Троян", "high"),
    ("Win.Ransomware.WannaCry-6313787-0", "Шифровальщик", "critical"),
    ("PUA.Win.Adware.OpenCandy-1", "Нежелательная программа", "low"),
    ("Eicar-Signature", "Тестовый файл", "info"),
    ("Html.Phishing.Bank-123-0", "Фишинг", "high"),
    ("AI.Heuristic.Suspicious", "Эвристика Tim Antivirus", "medium"),
])
def test_threat_info(sig, cat, danger):
    from timav.core.threat_info import describe
    ti = describe(sig)
    assert ti.category == cat and ti.danger == danger and ti.advice


def test_threat_family_note():
    from timav.core.threat_info import describe
    assert "Emotet" in describe("Doc.Downloader.Emotet-123-0").family_note


# ---------------- 7. Меню Проводника ----------------
def test_context_menu_register():
    from timav.core import shell
    was = shell.is_registered()
    shell.register("Проверить в Tim Antivirus")
    try:
        assert shell.is_registered()
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, shell.KEYS[0] + r"\command") as k:
            assert "--scan" in winreg.QueryValueEx(k, "")[0]
    finally:
        if not was:
            shell.unregister()


# ---------------- 17. Самообновление ----------------
def test_selfupdate_check_and_download(tmp_path):
    from timav.core import selfupdate
    payload = os.urandom(200_000)
    (tmp_path / "TimAntivirus-Setup-9.9.9.exe").write_bytes(payload)
    handler = lambda *a, **k: http.server.SimpleHTTPRequestHandler(*a, directory=str(tmp_path), **k)  # noqa: E731
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        (tmp_path / "latest.json").write_text(json.dumps({
            "version": "9.9.9", "url": base + "/TimAntivirus-Setup-9.9.9.exe",
            "sha256": hashlib.sha256(payload).hexdigest(), "notes": "Новое"}))
        rel = selfupdate.check(base + "/latest.json", "1.1.0")
        assert rel and rel.version == "9.9.9"
        assert selfupdate.check(base + "/latest.json", "9.9.9") is None
        got = selfupdate.download(rel, dest_dir=str(tmp_path / "dl"))
        assert Path(got).read_bytes() == payload
        rel.sha256 = "0" * 64
        with pytest.raises(ValueError):
            selfupdate.download(rel, dest_dir=str(tmp_path / "dl2"))
    finally:
        srv.shutdown()
    assert selfupdate.vtuple("v1.10.0") > selfupdate.vtuple("1.9.9")


# ---------------- 11. ML-модель ----------------
def test_ml_model_loaded_and_benign():
    import pefile
    from timav.core.ml_model import load_model, predict
    m = load_model()
    assert m is not None and len(m.trees) >= 50 and m.meta["cv_accuracy"] > 0.95
    pe = pefile.PE(getattr(sys, "_base_executable", sys.executable), fast_load=True)
    assert predict(pe) < 0.5


# ---------------- 18. Локализация ----------------
def test_english_translation():
    from timav import i18n
    try:
        i18n.set_language("en")
        assert i18n.tr("Сканирование") == "Scan"
        assert i18n.tr("Необработанных угроз: {n}", n=2) == "Unresolved threats: 2"
    finally:
        i18n.set_language("ru")
    assert i18n.tr("Сканирование") == "Сканирование"


def test_all_ui_strings_translated():
    """Каждая строка tr("…") в коде имеет английский перевод."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    from extract_strings import missing
    m = missing()
    assert not m, m[:20]
