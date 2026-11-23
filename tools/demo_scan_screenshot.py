"""Скриншот страницы сканирования с найденными «угрозами» (безопасные файлы + тестовая сигнатура).
Работает в отдельном каталоге данных и на отдельном порту движка — установленную программу не трогает."""
import hashlib
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
work = Path(tempfile.mkdtemp(prefix="timav_demo_"))
os.environ["TIMAV_DATA_DIR"] = str(work / "data")
os.environ["TIMAV_CLAMD_PORT"] = "33188"

from PySide6.QtCore import QTimer  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from timav.app import make_icon  # noqa: E402
from timav.core import paths  # noqa: E402
from timav.core.settings import Settings  # noqa: E402
from timav.ui import theme  # noqa: E402
from timav.ui.controller import Controller  # noqa: E402
from timav.ui.main_window import MainWindow  # noqa: E402

victims = work / "Загрузки"
victims.mkdir()
sigs = []
for i, name in enumerate(["invoice_2026.pdf.exe", "crack_setup.exe", "photo.scr"]):
    data = f"TIM-DEMO-{i}-".encode() + os.urandom(4096)
    (victims / name).write_bytes(data)
    sigs.append(f"{hashlib.md5(data).hexdigest()}:{len(data)}:Win.Trojan.Demo{i}-{1000 + i}-0")
(victims / "readme.txt").write_text("обычный файл", encoding="utf-8")
(paths.db_dir() / "demo.hdb").write_text("\n".join(sigs) + "\n")

app = QApplication([])
app.setFont(theme.base_font())
app.setStyle("Fusion")
s = Settings()
s.realtime_enabled = s.process_guard = s.ransomware_guard = s.usb_autoscan = False
s.auto_update = s.context_menu = s.minimize_to_tray = False
s.save = lambda: None
ctrl = Controller(s)
win = MainWindow(ctrl, make_icon())
win.apply_theme(sys.argv[1] if len(sys.argv) > 1 else "dark")
win.show()
out = ROOT / "docs" / "screenshots" / "scan_explorer_buttons.png"


def done(_stats):
    QTimer.singleShot(800, lambda: (win.grab().save(str(out)), print("saved", out), win.quit_app()))


ctrl.scan_finished.connect(done)
QTimer.singleShot(500, lambda: (ctrl.start_scan("custom", [str(victims)]), win.go("scan")))
app.exec()
shutil.rmtree(work, ignore_errors=True)
