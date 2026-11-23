import base64
import os
import sys
import threading
import time
from pathlib import Path

import pytest

from timav.core import paths
from timav.core.ai_analyzer import LocalAnalyzer
from timav.core.clamav import ClamAVEngine
from timav.core.journal import Journal
from timav.core.monitor import RealtimeMonitor
from timav.core.quarantine import Quarantine
from timav.core.scanner import Scanner
from timav.core.settings import Settings
from timav.core.system_status import compute_score, query_defender

needs_clam = pytest.mark.skipif(paths.clamav_dir() is None, reason="ClamAV не найден")


# ---------------- ClamAV ----------------
@needs_clam
def test_clamscan_detects_custom_signature(sample):
    eng = ClamAVEngine(db=sample["db"])
    res = eng.scan_files_clamscan([str(sample["file"]), str(sample["clean"])])
    assert res[0].infected and res[0].signature.startswith("Tim.Test.Signature")
    assert res[1].status == "clean"


@needs_clam
def test_clamd_instream(sample):
    eng = ClamAVEngine(db=sample["db"], port=33199)
    try:
        assert eng.start_daemon(wait=60), "clamd не запустился"
        assert eng.daemon_alive()
        v = eng.scan_file(sample["file"])
        assert v.infected and "Tim.Test.Signature" in v.signature
        assert eng.scan_file(sample["clean"]).status == "clean"
        # имя файла с кириллицей и пробелами — INSTREAM не зависит от кодировки пути
        ru = sample["dir"] / "Документ с пробелами.bin"
        ru.write_bytes(sample["file"].read_bytes())
        assert eng.scan_file(ru).infected
        assert "ClamAV" in eng.version()
    finally:
        eng.stop_daemon()
    assert not eng.daemon_alive()


@needs_clam
def test_real_databases_info():
    eng = ClamAVEngine(db=Path(os.environ["LOCALAPPDATA"]) / "TimAntivirus" / "db")
    if not eng.db_ready():
        pytest.skip("официальные базы ещё не загружены")
    names = {i.name for i in eng.db_info()}
    assert {"main", "daily"} <= names
    assert eng.db_signatures() > 1_000_000


# ---------------- Сканер ----------------
@needs_clam
def test_scanner_custom_scan(sample):
    eng = ClamAVEngine(db=sample["db"])
    sc = Scanner(eng, heuristics=False)
    progress = []
    found = []
    st = sc.run("custom", [str(sample["dir"])], on_progress=progress.append, on_detection=found.append)
    assert st.scanned == 2 and not st.cancelled
    assert len(found) == 1 and found[0].name.startswith("Tim.Test.Signature")
    assert found[0].path == str(sample["file"])
    assert progress and progress[-1].percent == 100


@needs_clam
def test_scanner_cancel(sample, tmp_path):
    many = tmp_path / "many"
    many.mkdir()
    for i in range(300):
        (many / f"f{i}.txt").write_text(str(i))
    eng = ClamAVEngine(db=sample["db"], port=33198)
    try:
        assert eng.start_daemon(wait=60)
        sc = Scanner(eng, heuristics=False)
        threading.Timer(0.05, sc.cancel).start()
        st = sc.run("custom", [str(many)])
        assert st.cancelled or st.scanned == 300
    finally:
        eng.stop_daemon()


def test_scanner_excludes_data_dir(sample, data_dir):
    (data_dir / "x.exe").write_bytes(b"MZ")
    sc = Scanner(ClamAVEngine(db=sample["db"]), heuristics=False)
    files = list(sc.iter_files([data_dir, sample["dir"]], None))
    assert all(not f.startswith(str(data_dir)) for f in files)
    assert len(files) == 2


# ---------------- Мониторинг ----------------
@needs_clam
def test_realtime_monitor_detects_new_file(sample, tmp_path):
    watch = tmp_path / "watch"
    watch.mkdir()
    eng = ClamAVEngine(db=sample["db"], port=33197)
    hits = []
    ev = threading.Event()
    try:
        assert eng.start_daemon(wait=60)
        mon = RealtimeMonitor(eng, lambda p, n, k, s: (hits.append((p, n, k)), ev.set()), heuristics=False)
        mon.start([str(watch)])
        time.sleep(0.5)
        (watch / "dropped.bin").write_bytes(sample["file"].read_bytes())
        (watch / "ok.txt").write_text("fine")
        assert ev.wait(20), "монитор не сработал"
        mon.stop()
    finally:
        eng.stop_daemon()
    assert hits[0][1].startswith("Tim.Test.Signature") and hits[0][2] == "threat"
    assert len(hits) == 1


# ---------------- Карантин ----------------
def test_quarantine_roundtrip(tmp_path):
    f = tmp_path / "evil.exe"
    data = os.urandom(3_000_000)
    f.write_bytes(data)
    q = Quarantine()
    item = q.add(f, "Test.Threat")
    assert not f.exists() and q.count() == 1
    blob = (q.root / f"{item.id}.qbin").read_bytes()
    assert blob != data and len(blob) == len(data)          # хранится в обфусцированном виде
    restored = q.restore(item.id)
    assert restored.read_bytes() == data and q.count() == 0


def test_quarantine_delete(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x" * 10)
    q = Quarantine()
    it = q.add(f, "T")
    q.delete(it.id)
    assert q.list() == []


# ---------------- Журнал ----------------
def test_journal(tmp_path):
    j = Journal()
    calls = []
    j.listeners.append(calls.append)
    eid = j.add("threat", "high", "scan", "C:/x.exe", "Win.Trojan.X")
    j.add("scan", "info", "scan", details="Быстрое сканирование завершено")
    assert j.unresolved_threats() == 1
    j.update_action(eid, "в карантине")
    assert j.unresolved_threats() == 0
    assert [e.kind for e in j.query()] == ["scan", "threat"]
    assert len(j.query("threat", "Trojan")) == 1
    n = j.export_csv(tmp_path / "j.csv")
    assert n == 2 and "Win.Trojan.X" in (tmp_path / "j.csv").read_text(encoding="utf-8-sig")
    assert len(calls) == 2
    j.close()


# ---------------- AI-анализ ----------------
def test_ai_benign_files():
    rep = LocalAnalyzer().analyze(sys.executable)          # подписанный python.exe
    assert rep.file_type.startswith("PE")
    assert rep.score < 0.5, rep.indicators
    assert rep.pe_info.get("imports_count", 0) > 0


def test_ai_trusted_signature_lowers_risk():
    from timav.core.ai_analyzer import verify_signature
    exe = getattr(sys, "_base_executable", sys.executable)
    assert verify_signature(exe)                              # python.exe подписан PSF
    rep = LocalAnalyzer().analyze(exe)
    assert rep.pe_info["signature_valid"] and rep.verdict == "clean"
    assert any(i.name == "trusted_publisher" and i.weight < 0 for i in rep.indicators)
    assert rep.pe_info["signer"] == "Python Software Foundation"
    rep2 = LocalAnalyzer(trusted_publishers=[]).analyze(exe)     # без списка доверенных — просто подпись
    assert any(i.name == "trusted_signature" for i in rep2.indicators)


def test_ai_unsigned_installer_not_flagged(tmp_path):
    # неподписанный «установщик»: копия заголовка PE + большой сжатый оверлей, лежит во Temp
    exe = getattr(sys, "_base_executable", sys.executable)
    import pefile
    pe = pefile.PE(exe, fast_load=True)
    end = max(s.PointerToRawData + s.SizeOfRawData for s in pe.sections)
    head = bytearray(Path(exe).read_bytes()[:end])
    sec = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
    off = pe.OPTIONAL_HEADER.get_file_offset() + (0x70 if pe.OPTIONAL_HEADER.Magic == 0x20B else 0x60) + 8 * sec
    head[off:off + 8] = b"\0" * 8                            # убираем подпись
    pe.close()
    f = tmp_path / "Temp" / "app-setup.exe"
    f.parent.mkdir()
    f.write_bytes(bytes(head) + os.urandom(3 * 1024 * 1024))
    rep = LocalAnalyzer().analyze(f)
    assert rep.pe_info.get("installer") and not rep.pe_info["signed"]
    assert rep.score < 0.5, [(i.name, i.weight) for i in rep.indicators]


def test_ai_suspicious_script(tmp_path):
    f = tmp_path / "Temp" / "invoice.pdf.vbs"
    f.parent.mkdir()
    blob = base64.b64encode(os.urandom(600)).decode()
    f.write_text(
        'Set sh = CreateObject("WScript.Shell")\n'
        'sh.RegWrite "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\upd", "x"\n'
        f'data = "{blob}"\n'
        "' FromBase64String\n")
    rep = LocalAnalyzer().analyze(f)
    names = {i.name for i in rep.indicators}
    assert {"double_ext", "run_key", "wscript_shell", "long_b64"} <= names
    assert rep.score >= 0.75 and rep.verdict in ("suspicious", "malicious")


def test_ai_plain_text_clean(tmp_path):
    f = tmp_path / "notes.txt"
    f.write_text("Список покупок: хлеб, молоко\n" * 20, encoding="utf-8")
    rep = LocalAnalyzer().analyze(f)
    assert rep.verdict == "clean" and not rep.indicators


# ---------------- Индикатор безопасности ----------------
def test_security_score():
    good = compute_score(engine_ok=True, db_age_hours=5, realtime=True, unresolved=0,
                         last_scan_ts=time.time() - 3600, defender=None)
    assert good.score == 100 and good.level == "good"
    bad = compute_score(engine_ok=True, db_age_hours=200, realtime=False, unresolved=1,
                        last_scan_ts=0, defender=None)
    assert bad.level == "danger" and bad.score < 50 and len(bad.issues) == 4


def test_settings_roundtrip():
    s = Settings.load()
    s.theme = "dark"
    s.watch_folders = ["C:/x"]
    s.save()
    s2 = Settings.load()
    assert s2.theme == "dark" and s2.watch_folders == ["C:/x"]


@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
def test_defender_query_is_readonly_and_works():
    st = query_defender()
    # только чтение статуса; Defender должен оставаться включённым
    assert st.available
    assert st.antivirus_enabled is True
