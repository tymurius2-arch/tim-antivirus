"""Главное окно: навигационная панель Windows 11, страницы, трей и уведомления."""
from __future__ import annotations

from PySide6.QtCore import QEvent, Qt, QTimer
from PySide6.QtGui import QAction, QFont, QGuiApplication, QIcon
from PySide6.QtWidgets import (QApplication, QButtonGroup, QHBoxLayout, QLabel, QMainWindow, QMenu,
                               QPushButton, QStackedWidget, QSystemTrayIcon, QVBoxLayout, QWidget)

from timav import APP_NAME
from timav.core import paths
from timav.ui import theme
from timav.ui.controller import Controller
from timav.ui.pages_extra import AIPage, JournalPage, QuarantinePage, SettingsPage, UpdatesPage
from timav.ui.pages_main import HomePage, ProtectionPage, ScanPage
from timav.ui.pages_tools import AutorunsPage, SystemPage
from timav.i18n import tr
from timav.ui.theme import GLYPH

def nav_items():
    return [
        ("home", "home", tr("Главная")),
        ("scan", "scan", tr("Сканирование")),
        ("protection", "shield", tr("Защита")),
        ("journal", "journal", tr("Журнал угроз")),
        ("quarantine", "quarantine", tr("Карантин")),
        ("ai", "ai", tr("AI-анализ")),
        ("autoruns", "play", tr("Автозагрузка")),
        ("system", "defender", tr("Проверка системы")),
        ("updates", "update", tr("Обновления")),
    ]


class NavButton(QPushButton):
    def __init__(self, glyph: str, text: str):
        super().__init__()
        self.setObjectName("Nav")
        self.setCheckable(True)
        self.setCursor(Qt.PointingHandCursor)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(12, 0, 8, 0)
        lay.setSpacing(12)
        self.ind = QWidget()
        self.ind.setFixedSize(3, 16)
        ic = QLabel(GLYPH[glyph])
        f = QFont(theme.icon_font_family())
        f.setPixelSize(16)
        ic.setFont(f)
        ic.setFixedWidth(20)
        tx = QLabel(text)
        lay.addWidget(ic)
        lay.addWidget(tx, 1)
        self.ic, self.tx = ic, tx
        self.setMinimumHeight(38)
        for w in (ic, tx):
            w.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.toggled.connect(self._t)

    def _t(self, on):
        f = self.tx.font()
        f.setBold(on)
        self.tx.setFont(f)
        p = theme.current()
        self.ic.setStyleSheet(f"color: {p.accent};" if on else "")

    def paintEvent(self, e):
        super().paintEvent(e)
        if self.isChecked():
            from PySide6.QtGui import QColor, QPainter
            qp = QPainter(self)
            qp.setRenderHint(QPainter.Antialiasing)
            qp.setPen(Qt.NoPen)
            qp.setBrush(QColor(theme.current().accent))
            h = 16
            qp.drawRoundedRect(0, (self.height() - h) // 2, 3, h, 1.5, 1.5)


class MainWindow(QMainWindow):
    def __init__(self, ctrl: Controller, icon: QIcon):
        super().__init__()
        self.ctrl = ctrl
        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(icon)
        self.resize(1180, 780)
        self.setMinimumSize(980, 640)
        self._really_quit = False

        root = QWidget()
        root.setObjectName("Root")
        self.setCentralWidget(root)
        h = QHBoxLayout(root)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)

        # навигация
        nav = QWidget()
        nav.setFixedWidth(250)
        nl = QVBoxLayout(nav)
        nl.setContentsMargins(8, 14, 8, 10)
        nl.setSpacing(2)
        brand = QHBoxLayout()
        bi = QLabel()
        bi.setPixmap(icon.pixmap(24, 24))
        bt = QLabel(APP_NAME)
        bt.setStyleSheet("font-size: 11pt; font-weight: 600;")
        brand.setContentsMargins(12, 0, 0, 12)
        brand.addWidget(bi)
        brand.addSpacing(6)
        brand.addWidget(bt, 1)
        nl.addLayout(brand)
        self.group = QButtonGroup(self)
        self.group.setExclusive(True)
        self.buttons: dict[str, NavButton] = {}
        for key, g, text in nav_items():
            b = NavButton(g, text)
            b.clicked.connect(lambda _=False, k=key: self.go(k))
            self.group.addButton(b)
            self.buttons[key] = b
            nl.addWidget(b)
        nl.addStretch()
        b = NavButton("settings", tr("Параметры"))
        b.clicked.connect(lambda: self.go("settings"))
        self.group.addButton(b)
        self.buttons["settings"] = b
        nl.addWidget(b)
        h.addWidget(nav)

        # содержимое
        content = QWidget()
        content.setObjectName("Content")
        cl = QVBoxLayout(content)
        cl.setContentsMargins(0, 0, 0, 0)
        self.stack = QStackedWidget()
        cl.addWidget(self.stack)
        h.addWidget(content, 1)
        self.content = content

        self.pages = {
            "home": HomePage(ctrl), "scan": ScanPage(ctrl), "protection": ProtectionPage(ctrl),
            "journal": JournalPage(ctrl), "quarantine": QuarantinePage(ctrl), "ai": AIPage(ctrl),
            "autoruns": AutorunsPage(ctrl), "system": SystemPage(ctrl),
            "updates": UpdatesPage(ctrl), "settings": SettingsPage(ctrl),
        }
        for p in self.pages.values():
            self.stack.addWidget(p)
        self.pages["home"].navigate.connect(self.go)
        self.pages["settings"].theme_changed.connect(self.apply_theme)

        self._make_tray(icon)
        from timav.ui.flyout import TrayFlyout
        self.flyout = TrayFlyout(ctrl, self, icon)
        ctrl.notify.connect(self.show_notification)
        ctrl.ransom_alert.connect(self._ransom)
        ctrl.scan_started.connect(lambda _m: self.go("scan") if self.isVisible() else None)
        ctrl.realtime_threat.connect(lambda *_: self._tray_state())
        ctrl.security_changed.connect(lambda _: self._tray_state())
        ctrl.scan_progress.connect(self._scan_tray)
        self.apply_theme(ctrl.settings.theme)
        self.go("home")
        try:
            QGuiApplication.styleHints().colorSchemeChanged.connect(
                lambda _: self.ctrl.settings.theme == "system" and self.apply_theme("system"))
        except AttributeError:
            pass

    # ---------- навигация ----------
    def go(self, key: str):
        self.buttons[key].setChecked(True)
        page = self.pages[key]
        self.stack.setCurrentWidget(page)
        page.on_show()

    def open_ai(self, path: str):
        self.go("ai")
        self.pages["ai"].analyze(path)

    # ---------- тема ----------
    def apply_theme(self, name: str):
        p = theme.resolve(name)
        theme.set_current(p)
        QApplication.instance().setStyleSheet(theme.stylesheet(p))
        for pg in self.pages.values():
            pg.apply_palette(p)
        for b in self.buttons.values():
            b._t(b.isChecked())
        theme.apply_titlebar(self.winId(), p)

    def showEvent(self, e):
        super().showEvent(e)
        theme.apply_titlebar(self.winId(), theme.current())

    # ---------- трей ----------
    def _make_tray(self, icon: QIcon):
        self.tray = QSystemTrayIcon(icon, self)
        self.tray.setToolTip(APP_NAME)
        m = QMenu()
        a_open = QAction(tr("Открыть Tim Antivirus"), m)
        a_open.triggered.connect(self.restore_window)
        a_quick = QAction(tr("Быстрое сканирование"), m)
        a_quick.triggered.connect(lambda: (self.restore_window(), self.ctrl.start_scan("quick"), self.go("scan")))
        self.a_rt = QAction(tr("Защита в реальном времени"), m)
        self.a_rt.setCheckable(True)
        self.a_rt.setChecked(self.ctrl.settings.realtime_enabled)
        self.a_rt.toggled.connect(self.ctrl.set_realtime)
        self.ctrl.realtime_state.connect(lambda on: (self.a_rt.blockSignals(True), self.a_rt.setChecked(on),
                                                     self.a_rt.blockSignals(False)))
        a_upd = QAction(tr("Обновить базы"), m)
        a_upd.triggered.connect(self.ctrl.start_update)
        a_quit = QAction(tr("Выход"), m)
        a_quit.triggered.connect(self.quit_app)
        for a in (a_open, a_quick, self.a_rt, a_upd):
            m.addAction(a)
        m.addSeparator()
        m.addAction(a_quit)
        self.tray.setContextMenu(m)
        self.tray.activated.connect(self._tray_activated)
        self.tray.messageClicked.connect(lambda: (self.restore_window(), self.go("journal")))
        self.tray.show()
        self._tray_menu = m

    def _tray_activated(self, reason):
        if reason == QSystemTrayIcon.Trigger:
            self.flyout.popup()
        elif reason == QSystemTrayIcon.DoubleClick:
            self.flyout.hide()
            self.restore_window()

    def _ransom(self, reason, suspect):
        from timav.ui.dialogs import RansomDialog
        self.restore_window()
        RansomDialog(reason, suspect, self.ctrl, self).show()

    def scan_paths(self, paths_: list[str]):
        """Запрос из контекстного меню Проводника."""
        self.restore_window()
        self.ctrl.start_scan("custom", paths_)
        self.go("scan")

    def _tray_state(self):
        sec = self.ctrl.security()
        self.tray.setToolTip(f"{APP_NAME} — {sec.title} ({sec.score}/100)")

    def _scan_tray(self, st):
        self.tray.setToolTip(f"{APP_NAME} — " + tr("сканирование {p}% ({n} файлов)", p=f"{st.percent:.0f}", n=st.scanned))

    def show_notification(self, title: str, text: str, level: str):
        if not self.ctrl.settings.notifications:
            return
        ic = {"danger": QSystemTrayIcon.Critical, "warning": QSystemTrayIcon.Warning}.get(level, QSystemTrayIcon.Information)
        self.tray.showMessage(title, text, ic, 8000)

    def restore_window(self):
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def closeEvent(self, e):
        if self.ctrl.settings.minimize_to_tray and not self._really_quit:
            e.ignore()
            self.hide()
            if not getattr(self, "_hint_shown", False):
                self._hint_shown = True
                self.tray.showMessage(APP_NAME, tr("Защита продолжает работать в фоне. Управление — через значок в трее."),
                                      QSystemTrayIcon.Information, 4000)
            return
        self.quit_app()

    def quit_app(self):
        self._really_quit = True
        self.tray.hide()
        self.ctrl.shutdown()
        QApplication.instance().quit()
