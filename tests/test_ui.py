import os
import shutil
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QEventLoop, QTimer  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from timav.core import paths  # noqa: E402

pytestmark = pytest.mark.skipif(paths.clamav_dir() is None, reason="ClamAV не найден")


@pytest.fixture(scope="module")
def qapp():
    return QApplication.instance() or QApplication([])


def wait_signal(sig, timeout=60):
    loop = QEventLoop()
    got = []
    sig.connect(lambda *a: (got.append(a), loop.quit()))
    QTimer.singleShot(timeout * 1000, loop.quit)
    loop.exec()
    assert got, "сигнал не пришёл"
    return got[0]


def test_controller_scan_quarantine_flow(qapp, sample):
    from timav.core.settings import Settings
    from timav.ui.controller import Controller
    from timav.ui.main_window import MainWindow
    from timav.app import make_icon

    shutil.copy(sample["db"] / "tim_test.hdb", paths.db_dir() / "tim_test.hdb")
    s = Settings()
    s.use_daemon = False
    s.realtime_enabled = False
    s.auto_update = False
    s.heuristics_enabled = True
    ctrl = Controller(s)
    win = MainWindow(ctrl, make_icon())        # все страницы создаются без ошибок
    for key in win.pages:
        win.go(key)
    for th in ("light", "dark", "system"):
        win.apply_theme(th)

    assert ctrl.start_scan("custom", [str(sample["dir"])])
    (stats,) = wait_signal(ctrl.scan_finished)
    assert stats.scanned == 2 and len(stats.detections) == 1
    assert ctrl.journal.unresolved_threats() == 1
    assert ctrl.security().level == "danger"

    # кнопка «Показать в Проводнике» у каждой угрозы
    from PySide6.QtWidgets import QPushButton
    import timav.ui.pages_main as pm
    page = win.pages["scan"]
    assert page.table.rowCount() == 1
    btn = page.table.cellWidget(0, 4).findChild(QPushButton)
    assert btn is not None
    calls = []
    orig_popen = pm.subprocess.Popen
    pm.subprocess.Popen = lambda args, **kw: calls.append(args)
    try:
        btn.click()
        assert calls[-1][:2] == ["explorer", "/select,"] and calls[-1][2] == os.path.normpath(str(sample["file"]))
    finally:
        pm.subprocess.Popen = orig_popen

    det = stats.detections[0]
    assert ctrl.resolve_detection(det, "quarantine") == "в карантине"
    assert not sample["file"].exists() and ctrl.quarantine.count() == 1
    # после карантина файла нет — открывается папка, где он был
    calls = []
    pm.subprocess.Popen = lambda args, **kw: calls.append(args)
    try:
        assert pm.open_location(str(sample["file"])) == "folder"
        assert calls[-1] == ["explorer", os.path.normpath(str(sample["dir"]))]
    finally:
        pm.subprocess.Popen = orig_popen
    assert ctrl.journal.unresolved_threats() == 0
    assert ctrl.settings.last_scan_ts > time.time() - 60

    win.pages["journal"].reload()
    assert win.pages["journal"].table.rowCount() >= 3
    win.pages["quarantine"].reload()
    assert win.pages["quarantine"].table.rowCount() == 1

    # переключение защиты не блокирует окно
    t = time.perf_counter()
    ctrl.set_realtime(True)
    ctrl.settings.ransomware_guard = True
    ctrl.settings.protected_folders = [str(sample["dir"])]
    ctrl.apply_protection()
    ctrl.set_realtime(False)
    assert time.perf_counter() - t < 0.3
    time.sleep(1.5)
    with ctrl._prot_lock:
        pass
    win.quit_app()


def test_single_instance_mutex():
    from timav import app
    name = f"Local\\TimAVTest.{os.getpid()}"
    assert app.acquire_single_instance(name) is True
    k32 = __import__("ctypes").windll.kernel32
    k32.CreateMutexW.restype = __import__("ctypes").c_void_p
    h = k32.CreateMutexW(None, False, name)
    assert k32.GetLastError() == 183          # вторая копия увидит, что первая уже запущена
    k32.CloseHandle(__import__("ctypes").c_void_p(h))
