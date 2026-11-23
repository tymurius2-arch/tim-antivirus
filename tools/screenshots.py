"""Запускает окно и сохраняет снимки всех страниц в docs/screenshots (для проверки UI)."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from PySide6.QtCore import QTimer  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from timav.app import make_icon  # noqa: E402
from timav.core.settings import Settings  # noqa: E402
from timav.ui import theme  # noqa: E402
from timav.ui.controller import Controller  # noqa: E402
from timav.ui.main_window import MainWindow  # noqa: E402

out = ROOT / "docs" / "screenshots"
out.mkdir(parents=True, exist_ok=True)
mode = sys.argv[1] if len(sys.argv) > 1 else "dark"
wait = int(sys.argv[2]) if len(sys.argv) > 2 else 8000
lang = sys.argv[3] if len(sys.argv) > 3 else "ru"
from timav.i18n import set_language  # noqa: E402
set_language(lang)

app = QApplication([])
app.setFont(theme.base_font())
app.setStyle("Fusion")
s = Settings.load()
s.minimize_to_tray = False
s.save = lambda: None  # не сохранять временные изменения
ctrl = Controller(s)
win = MainWindow(ctrl, make_icon())
win.apply_theme(mode)
win.show()
ctrl.startup()
pages = ["home", "scan", "protection", "journal", "quarantine", "ai", "autoruns", "system", "updates", "settings"]


def shoot(i=0):
    if i >= len(pages):
        win.quit_app()
        return
    win.go(pages[i])
    delay = 9000 if pages[i] in ("autoruns", "system") else 700
    QTimer.singleShot(delay, lambda: (win.grab().save(str(out / f"{lang}_{mode}_{pages[i]}.png")), shoot(i + 1)))


QTimer.singleShot(wait, shoot)
app.exec()
print("saved to", out)
