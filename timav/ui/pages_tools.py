"""Автозагрузка и проверка безопасности системы."""
from __future__ import annotations

import os
import subprocess
import threading
import time

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QCheckBox, QHBoxLayout, QLabel, QMenu, QMessageBox, QPushButton, QTableWidgetItem,
                               QVBoxLayout)

from timav import APP_NAME
from timav.i18n import tr
from timav.ui import theme
from timav.ui.pages_extra import make_table
from timav.ui.pages_main import Page, open_location
from timav.ui.widgets import Card, icon_label, page_header


class _Bridge(QObject):
    done = Signal(object)


KIND = {"registry": "Реестр", "startup": "Папка автозагрузки", "task": "Планировщик", "service": "Служба"}


class AutorunsPage(Page):
    def __init__(self, ctrl, parent=None):
        super().__init__(ctrl, parent)
        self.root.addWidget(page_header(tr("Автозагрузка"), tr("Программы, которые запускаются вместе с Windows. "
                                                             "Незнакомые и неподписанные записи подсвечены.")))
        bar = QHBoxLayout()
        self.cb_ms = QCheckBox(tr("Скрыть доверенных издателей"))
        self.cb_ms.setChecked(True)
        self.cb_ms.toggled.connect(self._fill)
        self.status = QLabel("")
        self.status.setObjectName("Caption")
        self.b_refresh = QPushButton(tr("Проверить автозагрузку"))
        self.b_refresh.setObjectName("Accent")
        self.b_refresh.clicked.connect(self.reload)
        bar.addWidget(self.cb_ms)
        bar.addWidget(self.status, 1)
        bar.addWidget(self.b_refresh)
        self.root.addLayout(bar)
        self.table = make_table([tr("Имя"), tr("Где"), tr("Издатель"), tr("Проверка"), tr("Состояние"), tr("Команда")], stretch=5)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._menu)
        self.root.addWidget(self.table, 1)
        hint = QLabel(tr("Правый щелчок — отключить/включить, открыть расположение, проверить файл. Отключение записей реестра "
                         "и папки автозагрузки обратимо."))
        hint.setObjectName("Caption")
        hint.setWordWrap(True)
        self.root.addWidget(hint)
        self.items = []
        self.shown = []
        self.loaded = False
        self.bridge = _Bridge()
        self.bridge.done.connect(self._loaded)

    def on_show(self):
        if not self.loaded:
            self.reload()

    def reload(self):
        self.b_refresh.setEnabled(False)
        self.status.setText(tr("Сбор и проверка записей автозагрузки…"))
        ctrl = self.ctrl

        def run():
            from timav.core import autoruns
            from timav.core.ai_analyzer import LocalAnalyzer
            try:
                items = autoruns.collect()
                autoruns.evaluate(items, ctrl.engine, LocalAnalyzer(ctrl.settings.trusted_publishers))
            except RuntimeError:      # приложение закрывается
                return
            self.bridge.done.emit(items)
        threading.Thread(target=run, daemon=True).start()

    def _loaded(self, items):
        self.loaded = True
        self.items = items
        self.b_refresh.setEnabled(True)
        self._fill()

    def _fill(self):
        from timav.core.signer import is_trusted
        p = theme.current()
        trusted = self.ctrl.settings.trusted_publishers
        self.shown = [e for e in self.items if not (self.cb_ms.isChecked() and e.signed and is_trusted(e.signer, trusted)
                                                    and e.verdict == "clean")]
        bad = sum(e.verdict.startswith("threat") for e in self.items)
        susp = sum(e.verdict == "suspicious" for e in self.items)
        unsigned = sum(not e.signed and e.verdict != "missing" for e in self.items)
        self.status.setText(tr("Записей: {n} · угроз: {b} · подозрительных: {s} · без подписи: {u}",
                               n=len(self.items), b=bad, s=susp, u=unsigned) + f" · {time.strftime('%H:%M')}")
        self.table.setRowCount(len(self.shown))
        for r, e in enumerate(self.shown):
            if e.verdict.startswith("threat"):
                ver, col = tr("Угроза: ") + e.verdict.split(":", 1)[1], p.danger
            elif e.verdict == "suspicious":
                ver, col = tr("Подозрительный"), p.warn
            elif e.verdict == "missing":
                ver, col = tr("Файл не найден"), p.text2
            else:
                ver, col = tr("Чисто"), p.good
            vals = [e.name, tr(KIND.get(e.kind, e.kind)) + " · " + tr(e.location), e.signer or (tr("нет подписи") if e.verdict != "missing" else "—"),
                    ver, tr("Включено") if e.enabled else tr("Отключено"), e.command]
            for c, v in enumerate(vals):
                it = QTableWidgetItem(v)
                if c == 3:
                    it.setForeground(QColor(col))
                if c == 2 and not e.signed and e.verdict != "missing":
                    it.setForeground(QColor(p.warn))
                if c == 5:
                    it.setToolTip(e.command)
                self.table.setItem(r, c, it)

    def _menu(self, pos):
        row = self.table.rowAt(pos.y())
        if row < 0:
            return
        e = self.shown[row]
        m = QMenu(self)
        a_t = m.addAction(tr("Включить") if not e.enabled else tr("Отключить"))
        a_t.setEnabled(e.can_toggle)
        a_o = m.addAction(tr("Открыть расположение"))
        a_ai = m.addAction(tr("AI-анализ файла"))
        a_q = m.addAction(tr("Поместить файл в карантин"))
        for a in (a_o, a_ai, a_q):
            a.setEnabled(bool(e.path) and os.path.isfile(e.path))
        act = m.exec(self.table.viewport().mapToGlobal(pos))
        if act == a_t:
            from timav.core import autoruns
            try:
                autoruns.set_enabled(e, not e.enabled)
                self.ctrl.journal.add("info", "info", "system", e.path, "", tr("автозагрузка включена") if not e.enabled
                                      else tr("автозагрузка отключена"), e.name)
                self.reload()
            except (PermissionError, OSError) as ex:
                QMessageBox.warning(self, APP_NAME, tr("Не удалось изменить запись: ") + str(ex) + "\n\n" +
                                    tr("Для системных записей (HKLM, задачи) запустите Tim Antivirus от имени администратора."))
        elif act == a_o:
            open_location(e.path)
        elif act == a_ai:
            self.window().open_ai(e.path)
        elif act == a_q:
            if QMessageBox.question(self, APP_NAME, tr("Поместить в карантин «{n}»?", n=e.path)) == QMessageBox.Yes:
                try:
                    self.ctrl.quarantine.add(e.path, tr("Автозагрузка: ") + e.name)
                    self.ctrl.quarantine_changed.emit()
                    self.reload()
                except OSError as ex:
                    QMessageBox.warning(self, APP_NAME, str(ex))


class SystemPage(Page):
    def __init__(self, ctrl, parent=None):
        super().__init__(ctrl, parent)
        self.root.addWidget(page_header(tr("Проверка системы"), tr("Настройки безопасности Windows. Tim Antivirus только проверяет "
                                                                  "их и подсказывает, что исправить — изменения вносите вы.")))
        bar = QHBoxLayout()
        self.summary = QLabel("")
        self.summary.setObjectName("Subtitle")
        self.b_run = QPushButton(tr("Проверить снова"))
        self.b_run.setObjectName("Accent")
        self.b_run.clicked.connect(self.reload)
        self.b_rep = QPushButton(tr("Отчёт"))
        self.b_rep.clicked.connect(self._report)
        bar.addWidget(self.summary, 1)
        bar.addWidget(self.b_rep)
        bar.addWidget(self.b_run)
        self.root.addLayout(bar)
        self.list_lay = QVBoxLayout()
        self.list_lay.setSpacing(6)
        body = self.scroll_body()
        body.addLayout(self.list_lay)
        body.addStretch()
        self.checks = []
        self.loaded = False
        self.bridge = _Bridge()
        self.bridge.done.connect(self._loaded)

    def on_show(self):
        if not self.loaded:
            self.reload()

    def reload(self):
        self.b_run.setEnabled(False)
        self.summary.setText(tr("Проверка…"))

        def run():
            from timav.core.posture import run_checks
            self.bridge.done.emit(run_checks())
        threading.Thread(target=run, daemon=True).start()

    def _loaded(self, checks):
        from timav.core.posture import summary
        self.loaded = True
        self.checks = checks
        self.b_run.setEnabled(True)
        ok, warn, bad = summary(checks)
        self.summary.setText(tr("В порядке: {o} · рекомендации: {w} · проблемы: {b}", o=ok, w=warn, b=bad))
        while self.list_lay.count():
            w = self.list_lay.takeAt(0).widget()
            if w:
                w.deleteLater()
        p = theme.current()
        order = {"bad": 0, "warn": 1, "info": 2, "ok": 3}
        for c in sorted(checks, key=lambda c: order.get(c.status, 9)):
            card = Card()
            row = QHBoxLayout()
            g, col = {"ok": ("check", p.good), "warn": ("warning", p.warn), "bad": ("error", p.danger)}.get(c.status, ("info", p.text2))
            row.addWidget(icon_label(g, 16, col))
            v = QVBoxLayout()
            v.setSpacing(1)
            v.addWidget(QLabel(f"<b>{c.title}</b>"))
            d = QLabel(c.detail + (f"<br><span style='color:{p.text2}'>{c.advice}</span>" if c.advice else ""))
            d.setWordWrap(True)
            v.addWidget(d)
            row.addLayout(v, 1)
            if c.open_cmd and c.status != "ok":
                b = QPushButton(tr("Открыть настройки"))
                b.clicked.connect(lambda _=False, cmd=c.open_cmd: self._open(cmd))
                row.addWidget(b, 0, Qt.AlignVCenter)
            card.lay.addLayout(row)
            self.list_lay.addWidget(card)

    @staticmethod
    def _open(cmd: str):
        if ":" in cmd and not cmd.lower().endswith(".exe"):
            os.startfile(cmd)
        else:
            subprocess.Popen([cmd], shell=False)

    def _report(self):
        if not self.checks:
            return
        from timav.core.report import posture_report
        from timav.ui.dialogs import save_report
        save_report(self, posture_report(self.checks), f"TimAntivirus_system_{time.strftime('%Y%m%d')}.pdf")
