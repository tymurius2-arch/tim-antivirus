"""Мини-окно из трея в стиле всплывающих панелей Windows 11."""
from __future__ import annotations

import time

from PySide6.QtCore import QPoint, Qt
from PySide6.QtGui import QColor, QGuiApplication
from PySide6.QtWidgets import (QFrame, QGraphicsDropShadowEffect, QHBoxLayout, QLabel, QPushButton, QVBoxLayout,
                               QWidget)

from timav import APP_NAME
from timav.i18n import tr
from timav.ui import theme
from timav.ui.widgets import SecurityGauge, ToggleSwitch


class TrayFlyout(QWidget):
    def __init__(self, ctrl, window, icon):
        super().__init__(None, Qt.Popup | Qt.FramelessWindowHint | Qt.NoDropShadowWindowHint)
        self.ctrl, self.win = ctrl, window
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setFixedWidth(360)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(12, 12, 12, 12)
        self.frame = QFrame()
        self.frame.setObjectName("Flyout")
        sh = QGraphicsDropShadowEffect(self)
        sh.setBlurRadius(24)
        sh.setOffset(0, 4)
        sh.setColor(QColor(0, 0, 0, 90))
        self.frame.setGraphicsEffect(sh)
        outer.addWidget(self.frame)
        lay = QVBoxLayout(self.frame)
        lay.setContentsMargins(18, 16, 18, 16)
        lay.setSpacing(10)

        top = QHBoxLayout()
        ic = QLabel()
        ic.setPixmap(icon.pixmap(20, 20))
        t = QLabel(APP_NAME)
        t.setStyleSheet("font-weight: 600;")
        top.addWidget(ic)
        top.addWidget(t, 1)
        lay.addLayout(top)

        mid = QHBoxLayout()
        self.gauge = SecurityGauge(size=110)
        mid.addWidget(self.gauge)
        col = QVBoxLayout()
        self.title = QLabel("")
        self.title.setStyleSheet("font-size: 13pt; font-weight: 600;")
        self.title.setWordWrap(True)
        self.sub = QLabel("")
        self.sub.setObjectName("Caption")
        self.sub.setWordWrap(True)
        col.addStretch()
        col.addWidget(self.title)
        col.addWidget(self.sub)
        col.addStretch()
        mid.addLayout(col, 1)
        lay.addLayout(mid)

        self.sw_rt = ToggleSwitch()
        self.sw_rt.toggled.connect(self.ctrl.set_realtime)
        self.sw_rg = ToggleSwitch()
        self.sw_rg.toggled.connect(lambda v: self._set("ransomware_guard", v))
        self.sw_pg = ToggleSwitch()
        self.sw_pg.toggled.connect(lambda v: self._set("process_guard", v))
        for text, sw in ((tr("Защита в реальном времени"), self.sw_rt), (tr("Защита от шифровальщиков"), self.sw_rg),
                         (tr("Контроль запуска программ"), self.sw_pg)):
            r = QHBoxLayout()
            r.addWidget(QLabel(text), 1)
            r.addWidget(sw)
            lay.addLayout(r)

        self.events = QLabel("")
        self.events.setObjectName("Caption")
        self.events.setWordWrap(True)
        lay.addWidget(self.events)

        btns = QHBoxLayout()
        b1 = QPushButton(tr("Быстрая проверка"))
        b1.setObjectName("Accent")
        b1.clicked.connect(lambda: (self.hide(), self.ctrl.start_scan("quick"), self.win.restore_window(), self.win.go("scan")))
        b2 = QPushButton(tr("Открыть"))
        b2.clicked.connect(lambda: (self.hide(), self.win.restore_window()))
        btns.addWidget(b1, 1)
        btns.addWidget(b2)
        lay.addLayout(btns)

    def _set(self, key, v):
        setattr(self.ctrl.settings, key, v)
        self.ctrl.settings.save()
        self.ctrl.apply_protection()

    def refresh(self):
        p = theme.current()
        self.frame.setStyleSheet(f"QFrame#Flyout {{ background: {p.surface}; border: 1px solid {p.stroke}; border-radius: 10px; }}")
        for sw in (self.sw_rt, self.sw_rg, self.sw_pg):
            sw.set_palette(p)
        self.gauge.set_palette(p)
        sec = self.ctrl.security()
        self.gauge.set_score(sec.score, sec.level)
        self.title.setText(sec.title)
        self.sub.setText(sec.issues[0] if sec.issues else tr("Все компоненты работают"))
        c = self.ctrl
        for sw, on in ((self.sw_rt, bool(c.monitor and c.monitor.running)), (self.sw_rg, c.settings.ransomware_guard),
                       (self.sw_pg, c.settings.process_guard)):
            sw.blockSignals(True)
            sw.setChecked(on)
            sw.blockSignals(False)
        ev = [e for e in c.journal.query(limit=50) if e.kind in ("threat", "suspicious", "scan")][:3]
        self.events.setText("\n".join(f"{time.strftime('%d.%m %H:%M', time.localtime(e.ts))} · "
                                      + (e.threat or e.details)[:60] for e in ev) or tr("Событий пока нет"))

    def popup(self):
        self.refresh()
        self.adjustSize()
        scr = QGuiApplication.primaryScreen().availableGeometry()
        self.move(QPoint(scr.right() - self.width() + 4, scr.bottom() - self.height() + 4))
        self.show()
        self.activateWindow()
