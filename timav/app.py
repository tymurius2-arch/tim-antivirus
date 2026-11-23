"""Точка входа Tim Antivirus."""
from __future__ import annotations

import ctypes
import sys

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QIcon, QPainter, QPainterPath, QPixmap, QLinearGradient
from PySide6.QtNetwork import QLocalServer, QLocalSocket
from PySide6.QtWidgets import QApplication

from timav import APP_ID, APP_NAME, __version__
from timav.core import paths
from timav.core.settings import Settings


def make_icon() -> QIcon:
    ico = paths.resource_dir() / "app.ico"
    if ico.exists():
        return QIcon(str(ico))
    return QIcon(render_icon(256))


def render_icon(size: int) -> QPixmap:
    """Рисует иконку-щит (используется и для генерации app.ico)."""
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    s = size
    path = QPainterPath()
    path.moveTo(s * 0.5, s * 0.06)
    path.cubicTo(s * 0.66, s * 0.16, s * 0.80, s * 0.18, s * 0.90, s * 0.18)
    path.cubicTo(s * 0.90, s * 0.55, s * 0.78, s * 0.80, s * 0.5, s * 0.95)
    path.cubicTo(s * 0.22, s * 0.80, s * 0.10, s * 0.55, s * 0.10, s * 0.18)
    path.cubicTo(s * 0.20, s * 0.18, s * 0.34, s * 0.16, s * 0.5, s * 0.06)
    g = QLinearGradient(0, 0, s, s)
    g.setColorAt(0, QColor("#4cc2ff"))
    g.setColorAt(1, QColor("#0050b3"))
    p.fillPath(path, g)
    # галочка
    pen_path = QPainterPath()
    pen_path.moveTo(s * 0.32, s * 0.50)
    pen_path.lineTo(s * 0.45, s * 0.63)
    pen_path.lineTo(s * 0.69, s * 0.37)
    from PySide6.QtGui import QPen
    p.setPen(QPen(QColor("white"), s * 0.085, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
    p.drawPath(pen_path)
    p.end()
    return pm


_MUTEX = None


def acquire_single_instance(name: str = "") -> bool:
    """True, если это первая копия в сеансе пользователя."""
    global _MUTEX
    if sys.platform != "win32":
        return True
    k32 = ctypes.windll.kernel32
    k32.CreateMutexW.restype = ctypes.c_void_p
    _MUTEX = k32.CreateMutexW(None, False, name or f"Local\\{APP_ID}.SingleInstance")
    err = k32.GetLastError()
    return not (err == 183 or (not _MUTEX and err == 5))   # ALREADY_EXISTS / ACCESS_DENIED (копия с правами админа)


def install_error_log() -> None:
    """Необработанные исключения (в т.ч. в потоках и слотах Qt) пишутся в logs/app.log вместо тихого сбоя."""
    import logging
    import threading
    import traceback
    from logging.handlers import RotatingFileHandler

    log = logging.getLogger("timav")
    h = RotatingFileHandler(paths.logs_dir() / "app.log", maxBytes=1_000_000, backupCount=2, encoding="utf-8")
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    log.addHandler(h)
    log.setLevel(logging.INFO)

    def hook(et, ev, tb):
        log.error("Необработанное исключение:\n%s", "".join(traceback.format_exception(et, ev, tb)))

    sys.excepthook = hook
    threading.excepthook = lambda a: hook(a.exc_type, a.exc_value, a.exc_traceback)
    log.info("Запуск Tim Antivirus %s", __version__)


def autostart_registered() -> bool:
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run") as k:
            winreg.QueryValueEx(k, "TimAntivirus")
            return True
    except OSError:
        return False


def update_db_mode(app: QApplication) -> int:
    """Режим первичной загрузки баз (вызывается установщиком)."""
    import threading

    from PySide6.QtWidgets import QProgressDialog

    from timav.core.clamav import ClamAVEngine
    from timav.core.updater import update_databases
    from timav.ui import theme

    p = theme.resolve("system")
    theme.set_current(p)
    app.setFont(theme.base_font())
    app.setStyle("Fusion")
    app.setStyleSheet(theme.stylesheet(p))
    dlg = QProgressDialog("Загрузка антивирусных баз ClamAV…", None, 0, 0)
    dlg.setWindowTitle(APP_NAME)
    dlg.setWindowIcon(make_icon())
    dlg.setMinimumWidth(460)
    dlg.show()
    theme.apply_titlebar(dlg.winId(), p)
    result = {}

    def run():
        result["r"] = update_databases(ClamAVEngine(), on_line=lambda l: result.__setitem__("line", l))

    t = threading.Thread(target=run, daemon=True)
    t.start()
    from PySide6.QtCore import QTimer
    timer = QTimer()

    def tick():
        if "line" in result:
            dlg.setLabelText("Загрузка антивирусных баз ClamAV…\n" + result["line"][:80])
        if not t.is_alive():
            timer.stop()
            dlg.close()
            app.quit()
    timer.timeout.connect(tick)
    timer.start(200)
    app.exec()
    r = result.get("r")
    if r and r.ok:
        s = Settings.load()
        import time as _t
        s.last_update_ts = _t.time()
        s.save()
    return 0 if r and r.ok else 1


def cleanup_mode(settings: Settings) -> int:
    """Вызывается деинсталлятором: удаляет файлы-ловушки и пункт контекстного меню."""
    import ctypes
    import os

    from timav.core import shell
    from timav.core.ransomware import CANARY_NAMES
    for folder in settings.protected_folders:
        for name in CANARY_NAMES:
            p = os.path.join(folder, name)
            try:
                ctypes.windll.kernel32.SetFileAttributesW(p, 0x80)
                os.remove(p)
            except OSError:
                pass
    shell.unregister()
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv if argv is None else argv)
    if sys.platform == "win32":
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(f"{APP_ID}.App")
        except Exception:
            pass
    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication(argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(__version__)
    app.setOrganizationName(APP_ID)
    app.setQuitOnLastWindowClosed(False)

    settings = Settings.load()
    from timav.i18n import set_language, tr
    set_language(settings.language)

    if "--update-db" in argv:
        return update_db_mode(app)
    if "--cleanup" in argv:
        return cleanup_mode(settings)

    scan_targets = []
    if "--scan" in argv:
        i = argv.index("--scan")
        scan_targets = [a for a in argv[i + 1:] if not a.startswith("--")]

    # один экземпляр: мьютекс видят и обычные, и запущенные от администратора копии
    if not acquire_single_instance():
        sock = QLocalSocket()
        sock.connectToServer(APP_ID)
        if sock.waitForConnected(1500):
            sock.write(("scan\n" + "\n".join(scan_targets)).encode("utf-8") if scan_targets else b"show")
            sock.flush()
            sock.waitForBytesWritten(500)
        else:
            from PySide6.QtWidgets import QMessageBox
            QMessageBox.information(None, APP_NAME, tr("Tim Antivirus уже запущен — откройте его через значок в трее."))
        return 0
    install_error_log()
    sock = QLocalSocket()
    sock.connectToServer(APP_ID)
    if sock.waitForConnected(300):
        sock.write(("scan\n" + "\n".join(scan_targets)).encode("utf-8") if scan_targets else b"show")
        sock.flush()
        sock.waitForBytesWritten(300)
        return 0
    server = QLocalServer()
    server.setSocketOptions(QLocalServer.WorldAccessOption)   # доступно и из копии без прав администратора
    QLocalServer.removeServer(APP_ID)
    server.listen(APP_ID)

    from timav.ui import theme
    from timav.ui.controller import Controller
    from timav.ui.main_window import MainWindow

    app.setFont(theme.base_font())
    app.setStyle("Fusion")
    icon = make_icon()
    app.setWindowIcon(icon)
    settings.autostart = autostart_registered()
    ctrl = Controller(settings)
    win = MainWindow(ctrl, icon)

    def on_conn():
        c = server.nextPendingConnection()
        if c:
            def read():
                msg = bytes(c.readAll()).decode("utf-8", "replace")
                if msg.startswith("scan\n"):
                    win.scan_paths([x for x in msg.split("\n")[1:] if x])
                else:
                    win.restore_window()
            c.readyRead.connect(read)
    server.newConnection.connect(on_conn)

    if "--minimized" not in argv:
        win.show()
    ctrl.startup()
    if scan_targets:
        from PySide6.QtCore import QTimer
        QTimer.singleShot(1500, lambda: win.scan_paths(scan_targets))
    code = app.exec()
    return code


if __name__ == "__main__":
    sys.exit(main())
