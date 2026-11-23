"""Главная, сканирование и защита."""
from __future__ import annotations

import os
import subprocess
import time

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFontMetrics
from PySide6.QtWidgets import (QAbstractItemView, QFileDialog, QGridLayout, QHBoxLayout, QHeaderView, QLabel,
                               QListWidget, QMenu, QProgressBar, QPushButton, QScrollArea, QTableWidget,
                               QTableWidgetItem, QVBoxLayout, QWidget)

from timav.core.clamav import db_age_hours
from timav.core.scanner import Detection, ScanStats
from timav.i18n import tr
from timav.ui import theme
from timav.ui.controller import kind_ru
from timav.ui.widgets import (Card, ClickCard, InfoBar, SecurityGauge, SettingRow, StatusTile, ToggleSwitch,
                              human_duration, icon_label, page_header)


def _fmt_ts(ts: float) -> str:
    if not ts:
        return tr("никогда")
    d = time.time() - ts
    if d < 60:
        return tr("только что")
    if d < 3600:
        return tr("{n} мин. назад", n=int(d // 60))
    if d < 86400:
        return tr("{n} ч. назад", n=int(d // 3600))
    return time.strftime("%d.%m.%Y %H:%M", time.localtime(ts))


def open_location(path: str) -> str:
    """Открывает Проводник с выделенным файлом. Если файла уже нет (карантин/удалён) — открывает его папку.
    Возвращает: selected | folder | missing."""
    path = os.path.normpath(path)
    if os.path.exists(path):
        subprocess.Popen(["explorer", "/select,", path])
        return "selected"
    folder = os.path.dirname(path)
    if os.path.isdir(folder):
        subprocess.Popen(["explorer", folder])
        return "folder"
    return "missing"


class Page(QWidget):
    def __init__(self, ctrl, parent=None):
        super().__init__(parent)
        self.ctrl = ctrl
        self.root = QVBoxLayout(self)
        self.root.setContentsMargins(36, 28, 36, 28)
        self.root.setSpacing(10)

    def apply_palette(self, p: theme.Palette):
        for t in self.findChildren(ToggleSwitch):
            t.set_palette(p)

    def on_show(self):
        pass

    def scroll_body(self) -> QVBoxLayout:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        body = QWidget()
        lay = QVBoxLayout(body)
        lay.setContentsMargins(0, 0, 8, 0)
        lay.setSpacing(6)
        scroll.setWidget(body)
        self.root.addWidget(scroll, 1)
        return lay


def section(lay: QVBoxLayout, text: str):
    lab = QLabel(text)
    lab.setObjectName("Subtitle")
    lay.addSpacing(10)
    lay.addWidget(lab)


# ===================================================================== Главная
class HomePage(Page):
    navigate = Signal(str)

    def __init__(self, ctrl, parent=None):
        super().__init__(ctrl, parent)
        self.root.addWidget(page_header(tr("Безопасность"), tr("Состояние защиты вашего компьютера")))
        hero = Card()
        h = QHBoxLayout()
        h.setSpacing(28)
        self.gauge = SecurityGauge()
        h.addWidget(self.gauge)
        col = QVBoxLayout()
        col.setSpacing(6)
        self.status_title = QLabel(tr("Проверка состояния…"))
        self.status_title.setObjectName("Title")
        self.status_issues = QLabel("")
        self.status_issues.setObjectName("Caption")
        self.status_issues.setWordWrap(True)
        col.addStretch()
        col.addWidget(self.status_title)
        col.addWidget(self.status_issues)
        btns = QHBoxLayout()
        self.btn_quick = QPushButton(tr("Быстрое сканирование"))
        self.btn_quick.setObjectName("Accent")
        self.btn_quick.clicked.connect(self._quick)
        self.btn_update = QPushButton(tr("Обновить базы"))
        self.btn_update.clicked.connect(self.ctrl.start_update)
        self.btn_sys = QPushButton(tr("Проверить систему"))
        self.btn_sys.clicked.connect(lambda: self.navigate.emit("system"))
        for b in (self.btn_quick, self.btn_update, self.btn_sys):
            btns.addWidget(b)
        btns.addStretch()
        col.addSpacing(8)
        col.addLayout(btns)
        col.addStretch()
        h.addLayout(col, 1)
        hero.lay.addLayout(h)
        self.root.addWidget(hero)
        self.info = InfoBar()
        self.root.addWidget(self.info)

        grid = QGridLayout()
        grid.setSpacing(10)
        self.t_rt = StatusTile("shield", tr("Защита в реальном времени"))
        self.t_guard = StatusTile("bolt", tr("Контроль запуска и шифровальщиков"))
        self.t_db = StatusTile("db", tr("Антивирусные базы"))
        self.t_scan = StatusTile("scan", tr("Последнее сканирование"))
        self.t_def = StatusTile("defender", tr("Microsoft Defender"))
        self.t_q = StatusTile("quarantine", tr("Карантин"))
        for i, t in enumerate([self.t_rt, self.t_guard, self.t_db, self.t_scan, self.t_def, self.t_q]):
            grid.addWidget(t, i // 3, i % 3)
        self.root.addLayout(grid)
        self.root.addStretch()

        c = self.ctrl
        c.security_changed.connect(self._on_security)
        for sig in (c.defender_changed, c.engine_state, c.realtime_state, c.update_finished, c.scan_finished):
            sig.connect(lambda *_: self.refresh())
        c.quarantine_changed.connect(self.refresh)
        c.protection_changed.connect(self.refresh)

    def _quick(self):
        if self.ctrl.start_scan("quick"):
            self.navigate.emit("scan")

    def apply_palette(self, p):
        super().apply_palette(p)
        self.gauge.set_palette(p)
        self.refresh()

    def on_show(self):
        self.refresh()
        self.ctrl.refresh_security()

    def _on_security(self, sec):
        p = theme.current()
        self.gauge.set_score(sec.score, sec.level)
        self.status_title.setText(sec.title)
        self.status_issues.setText("\n".join("• " + i for i in sec.issues) if sec.issues else
                                   tr("Все компоненты защиты работают. Microsoft Defender и Tim Antivirus защищают систему вместе."))
        if sec.level == "danger":
            self.info.show_message(tr("Обнаружены необработанные угрозы или критические проблемы. Откройте журнал или выполните сканирование."), "danger", p)
        else:
            self.info.hide()

    def refresh(self):
        p = theme.current()
        c = self.ctrl
        rt = bool(c.monitor and c.monitor.running)
        self.t_rt.set(tr("Включена") if rt else tr("Выключена"),
                      tr("Папок под наблюдением: {n}", n=len(c.monitor.folders)) if rt else tr("Рекомендуется включить"),
                      p.good if rt else p.danger)
        parts = []
        if c.pguard and c.pguard.running:
            parts.append(tr("запуск программ"))
        if c.rguard and c.rguard.running:
            parts.append(tr("шифровальщики"))
        if c.usb.running:
            parts.append("USB")
        self.t_guard.set(tr("Активен") if parts else tr("Выключен"), ", ".join(parts), p.good if len(parts) >= 2 else p.warn)
        if c.engine.db_ready():
            age = db_age_hours(c.engine)
            sigs = c.engine.db_signatures()
            ver = next((i.version for i in c.engine.db_info() if i.name == "daily"), 0)
            ok = age is not None and age < 48
            self.t_db.set(tr("{n} сигнатур", n=f"{sigs:,}".replace(",", " ")),
                          f"daily v{ver} · " + tr("{n} ч. назад", n=int(age)) if age is not None else "",
                          p.good if ok else p.warn)
        else:
            self.t_db.set(tr("Не загружены"), tr("Идёт загрузка…") if c.updating else tr("Нажмите «Обновить базы»"), p.danger)
        s = c.settings
        self.t_scan.set(_fmt_ts(s.last_scan_ts), (kind_ru(s.last_scan_kind) + " " + tr("сканирование")) if s.last_scan_kind else "",
                        p.good if s.last_scan_ts and time.time() - s.last_scan_ts < 7 * 86400 else p.warn)
        d = c.defender
        if d is None:
            self.t_def.set(tr("Проверка…"))
        elif not d.available:
            self.t_def.set(tr("Нет данных"), tr("Статус недоступен"), p.text2)
        else:
            on = d.realtime_enabled
            self.t_def.set(tr("Активен") if on else tr("Защита выключена"),
                           tr("Работает совместно с Tim Antivirus") + (tr(" · брандмауэр включён") if d.firewall_enabled else ""),
                           p.good if on else p.danger)
        self.t_q.set(tr("{n} объект(ов)", n=c.quarantine.count()), tr("Изолированные файлы"), p.accent)
        self.btn_update.setEnabled(not c.updating)
        self.btn_update.setText(tr("Обновление…") if c.updating else tr("Обновить базы"))


# ===================================================================== Сканирование
class ScanPage(Page):
    def __init__(self, ctrl, parent=None):
        super().__init__(ctrl, parent)
        self.root.addWidget(page_header(tr("Сканирование"), tr("Проверка файлов движком ClamAV и AI-эвристикой")))
        self.detections: list[Detection] = []
        self.stats: ScanStats | None = None
        modes = QHBoxLayout()
        modes.setSpacing(10)
        self.cards = []
        for mode, glyph, title, desc in [
            ("quick", "bolt", tr("Быстрое"), tr("Загрузки, рабочий стол, документы, автозагрузка, временные папки и запущенные процессы")),
            ("full", "drive", tr("Полное"), tr("Все файлы на всех локальных дисках. Может занять продолжительное время")),
            ("custom", "folder", tr("Выборочное"), tr("Выберите папку или файлы для проверки")),
        ]:
            card = ClickCard()
            card.setMinimumHeight(120)
            top = QHBoxLayout()
            top.addWidget(icon_label(glyph, 20))
            t = QLabel(title)
            t.setObjectName("Subtitle")
            top.addWidget(t, 1)
            card.lay.addLayout(top)
            d = QLabel(desc)
            d.setObjectName("Caption")
            d.setWordWrap(True)
            card.lay.addWidget(d)
            card.lay.addStretch()
            card.clicked.connect(lambda m=mode, c=card: self._start(m, c))
            modes.addWidget(card)
            self.cards.append(card)
        self.root.addLayout(modes)

        self.prog_card = Card()
        r1 = QHBoxLayout()
        self.prog_title = QLabel(tr("Сканирование не выполняется"))
        self.prog_title.setObjectName("Subtitle")
        r1.addWidget(self.prog_title, 1)
        self.btn_pause = QPushButton(tr("Пауза"))
        self.btn_pause.clicked.connect(self._pause)
        self.btn_cancel = QPushButton(tr("Остановить"))
        self.btn_cancel.clicked.connect(self.ctrl.cancel_scan)
        self.btn_report = QPushButton(tr("Отчёт"))
        self.btn_report.clicked.connect(self._report)
        for b in (self.btn_pause, self.btn_cancel, self.btn_report):
            r1.addWidget(b)
        self.prog_card.lay.addLayout(r1)
        self.bar = QProgressBar()
        self.bar.setRange(0, 1000)
        self.bar.setTextVisible(False)
        self.prog_card.lay.addWidget(self.bar)
        self.cur = QLabel("")
        self.cur.setObjectName("Caption")
        self.prog_card.lay.addWidget(self.cur)
        st = QHBoxLayout()
        self.lbl_files = QLabel(tr("Проверено: {n}", n=0))
        self.lbl_threats = QLabel(tr("Найдено: {n}", n=0))
        self.lbl_time = QLabel(tr("Время: {t}", t="00:00"))
        self.lbl_speed = QLabel("")
        for w in (self.lbl_files, self.lbl_threats, self.lbl_time, self.lbl_speed):
            st.addWidget(w)
        st.addStretch()
        self.prog_card.lay.addLayout(st)
        self.root.addWidget(self.prog_card)

        hdr = QHBoxLayout()
        lab = QLabel(tr("Обнаруженные объекты"))
        lab.setObjectName("Subtitle")
        hdr.addWidget(lab, 1)
        self.btn_q_all = QPushButton(tr("Поместить все в карантин"))
        self.btn_q_all.setObjectName("Accent")
        self.btn_q_all.clicked.connect(self._quarantine_all)
        hdr.addWidget(self.btn_q_all)
        self.root.addLayout(hdr)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels([tr("Объект"), tr("Угроза"), tr("Тип"), tr("Действие"), ""])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Fixed)
        probe = QPushButton(tr("Показать в Проводнике"))
        self.table.setColumnWidth(4, probe.sizeHint().width() + 44)
        self.table.verticalHeader().setDefaultSectionSize(42)
        self.table.setWordWrap(False)
        self.table.setTextElideMode(Qt.ElideMiddle)
        self.table.verticalHeader().hide()
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._menu)
        self.table.doubleClicked.connect(lambda idx: self._details(idx.row()))
        self.table.setShowGrid(False)
        self.root.addWidget(self.table, 1)
        hint = QLabel(tr("Двойной щелчок — описание угрозы; правый щелчок — действия"))
        hint.setObjectName("Caption")
        self.root.addWidget(hint)

        c = self.ctrl
        c.scan_started.connect(self._on_started)
        c.scan_progress.connect(self._on_progress)
        c.scan_detection.connect(self._on_detection)
        c.scan_finished.connect(self._on_finished)
        self._set_running(False)
        self.btn_report.setVisible(False)

    def _start(self, mode: str, card=None):
        custom = None
        if mode == "custom":
            m = QMenu(self)
            a_dir = m.addAction(tr("Выбрать папку…"))
            a_files = m.addAction(tr("Выбрать файлы…"))
            act = m.exec(card.mapToGlobal(card.rect().center()) if card else self.cursor().pos())
            if act == a_dir:
                d = QFileDialog.getExistingDirectory(self, tr("Папка для сканирования"))
                custom = [d] if d else None
            elif act == a_files:
                fs, _ = QFileDialog.getOpenFileNames(self, tr("Файлы для сканирования"))
                custom = fs or None
            if not custom:
                return
        self.start(mode, custom)

    def start(self, mode: str, custom=None):
        self.ctrl.start_scan(mode, custom)

    def _on_started(self, mode: str):
        self.detections.clear()
        self.table.setRowCount(0)
        self.prog_title.setText(tr("{k} сканирование…", k=kind_ru(mode)))
        self._set_running(True)
        self.btn_report.setVisible(False)

    def _set_running(self, on: bool):
        for c in self.cards:
            c.setEnabled(not on)
        self.btn_pause.setVisible(on)
        self.btn_cancel.setVisible(on)
        self.btn_pause.setText(tr("Пауза"))
        self.btn_q_all.setEnabled(any(d.action == tr("обнаружено") for d in self.detections))

    def _pause(self):
        sc = self.ctrl.scanner
        if not sc:
            return
        paused = not sc.paused
        self.ctrl.pause_scan(paused)
        self.btn_pause.setText(tr("Продолжить") if paused else tr("Пауза"))

    def _on_progress(self, st: ScanStats):
        self.bar.setRange(0, 1000 if st.total else 0)
        if st.total:
            self.bar.setValue(int(st.percent * 10))
        fm = QFontMetrics(self.cur.font())
        self.cur.setText(fm.elidedText(st.current, Qt.ElideMiddle, max(200, self.cur.width() - 10)))
        tot = (" / " + str(st.total) + ("" if st.total_final else "+")) if st.total else ""
        self.lbl_files.setText(tr("Проверено: {n}", n=f"{st.scanned}{tot}"))
        self.lbl_threats.setText(tr("Найдено: {n}", n=len(st.detections)))
        self.lbl_time.setText(tr("Время: {t}", t=human_duration(st.elapsed)))
        if st.elapsed > 1:
            self.lbl_speed.setText(tr("{n} файлов/с", n=f"{st.scanned / st.elapsed:.0f}"))

    def _on_detection(self, d: Detection):
        self.detections.append(d)
        r = self.table.rowCount()
        self.table.insertRow(r)
        p = theme.current()
        items = [QTableWidgetItem(d.path), QTableWidgetItem(d.name),
                 QTableWidgetItem(tr("Угроза") if d.kind == "threat" else tr("Подозрительный ({p})", p=f"{d.score:.0%}")),
                 QTableWidgetItem(d.action)]
        items[0].setToolTip(d.path)
        items[2].setForeground(QColor(p.danger if d.kind == "threat" else p.warn))
        for i, it in enumerate(items):
            self.table.setItem(r, i, it)
        btn = QPushButton(tr("Показать в Проводнике"))
        btn.setMinimumWidth(btn.sizeHint().width() + 8)
        btn.setToolTip(tr("Открыть папку с этим файлом"))
        btn.setCursor(Qt.PointingHandCursor)
        btn.clicked.connect(lambda _=False, path=d.path: self._show_in_explorer(path))
        cell = QWidget()
        lay = QHBoxLayout(cell)
        lay.setContentsMargins(6, 3, 14, 3)
        lay.addWidget(btn)
        self.table.setCellWidget(r, 4, cell)
        self.btn_q_all.setEnabled(True)

    def _show_in_explorer(self, path: str):
        res = open_location(path)
        if res == "folder":
            self.window().show_notification(tr("Файла уже нет на месте"),
                                            tr("Он перемещён в карантин или удалён — открыта папка, где он был."), "info")
        elif res == "missing":
            self.window().show_notification(tr("Папка не найдена"), path, "warning")

    def _on_finished(self, st: ScanStats):
        self.stats = st
        self._set_running(False)
        self.btn_report.setVisible(True)
        self.bar.setRange(0, 1000)
        self.bar.setValue(1000 if not st.cancelled else self.bar.value())
        n = len(st.detections)
        state = tr("прервано") if st.cancelled else tr("завершено")
        self.prog_title.setText(tr("Сканирование {s}: ", s=state) +
                                (tr("найдено объектов — {n}", n=n) if n else tr("угроз не найдено")))
        self.cur.setText(tr("Проверено {n} файлов за {t}; пропущено {s}, ошибок доступа {e}",
                            n=st.scanned, t=human_duration(st.elapsed), s=st.skipped, e=st.errors))

    def _details(self, row: int):
        if 0 <= row < len(self.detections):
            from timav.ui.dialogs import ThreatDialog
            d = self.detections[row]
            ThreatDialog(d.name, d.path, self.ctrl, self).exec()

    def _report(self):
        if not self.stats:
            return
        from timav.core.report import scan_report
        from timav.ui.dialogs import save_report
        e = self.ctrl.engine
        db = ", ".join(f"{i.name} v{i.version}" for i in e.db_info())
        html = scan_report(self.stats, kind_ru(self.stats.mode), e.version(), tr("Базы: ") + db)
        save_report(self, html, f"TimAntivirus_scan_{time.strftime('%Y%m%d_%H%M')}.pdf")

    def _menu(self, pos):
        row = self.table.rowAt(pos.y())
        if row < 0:
            return
        d = self.detections[row]
        m = QMenu(self)
        aq = m.addAction(tr("Поместить в карантин"))
        ad = m.addAction(tr("Удалить файл"))
        ai = m.addAction(tr("Пропустить"))
        m.addSeparator()
        ainfo = m.addAction(tr("Описание угрозы"))
        aa = m.addAction(tr("AI-анализ файла"))
        ao = m.addAction(tr("Открыть расположение"))
        act = m.exec(self.table.viewport().mapToGlobal(pos))
        if act in (aq, ad, ai):
            res = self.ctrl.resolve_detection(d, {aq: "quarantine", ad: "delete", ai: "ignore"}[act])
            self.table.item(row, 3).setText(res)
        elif act == ainfo:
            self._details(row)
        elif act == aa:
            self.window().open_ai(d.path)
        elif act == ao:
            open_location(d.path)

    def _quarantine_all(self):
        for row, d in enumerate(self.detections):
            if d.action == tr("обнаружено"):
                self.table.item(row, 3).setText(self.ctrl.resolve_detection(d, "quarantine"))
        self.btn_q_all.setEnabled(False)


# ===================================================================== Защита
class ProtectionPage(Page):
    def __init__(self, ctrl, parent=None):
        super().__init__(ctrl, parent)
        s = ctrl.settings
        self.root.addWidget(page_header(tr("Защита"), tr("Компоненты защиты, работающие в фоне. Microsoft Defender при этом остаётся включённым.")))
        lay = self.scroll_body()

        section(lay, tr("Файловый монитор"))
        self.sw_rt = ToggleSwitch(checked=s.realtime_enabled)
        self.sw_rt.toggled.connect(self.ctrl.set_realtime)
        lay.addWidget(SettingRow("shield", tr("Мониторинг файлов"),
                                 tr("Проверять файлы в отслеживаемых папках при создании и изменении"), self.sw_rt))
        lay.addWidget(self._toggle("auto_quarantine", "quarantine", tr("Автоматический карантин"),
                                   tr("Сразу изолировать файлы, в которых ClamAV нашёл угрозу"), restart=False))
        lay.addWidget(self._toggle("heuristics_enabled", "ai", tr("AI-эвристика"),
                                   tr("Оценивать исполняемые файлы и скрипты локальной моделью и предупреждать о подозрительных")))
        lay.addWidget(self._toggle("downloads_guard", "export", tr("Проверка загрузок"),
                                   tr("Следить за папкой «Загрузки» и сообщать, что скачанный файл проверен и откуда он получен")))
        hdr = QHBoxLayout()
        lab = QLabel(tr("Отслеживаемые папки"))
        hdr.addWidget(lab, 1)
        b_add = QPushButton(tr("Добавить папку"))
        b_add.clicked.connect(lambda: self._add(self.list, "watch_folders"))
        b_del = QPushButton(tr("Удалить"))
        b_del.clicked.connect(lambda: self._remove(self.list, "watch_folders"))
        hdr.addWidget(b_add)
        hdr.addWidget(b_del)
        lay.addLayout(hdr)
        self.list = QListWidget()
        self.list.setMaximumHeight(130)
        self.list.addItems(s.watch_folders)
        lay.addWidget(self.list)

        section(lay, tr("Контроль запуска программ"))
        lay.addWidget(self._toggle("process_guard", "play", tr("Проверять запускаемые программы"),
                                   tr("Каждая новая программа проверяется при запуске; заражённая — сразу останавливается и изолируется")))

        section(lay, tr("Защита от шифровальщиков"))
        lay.addWidget(self._toggle("ransomware_guard", "lock", tr("Защита от шифровальщиков"),
                                   tr("Файлы-ловушки и контроль массового шифрования; подозрительный процесс приостанавливается")))
        hdr2 = QHBoxLayout()
        hdr2.addWidget(QLabel(tr("Защищаемые папки")), 1)
        b2 = QPushButton(tr("Добавить папку"))
        b2.clicked.connect(lambda: self._add(self.plist, "protected_folders"))
        b3 = QPushButton(tr("Удалить"))
        b3.clicked.connect(lambda: self._remove(self.plist, "protected_folders"))
        hdr2.addWidget(b2)
        hdr2.addWidget(b3)
        lay.addLayout(hdr2)
        self.plist = QListWidget()
        self.plist.setMaximumHeight(110)
        self.plist.addItems(s.protected_folders)
        lay.addWidget(self.plist)

        section(lay, tr("Съёмные носители"))
        lay.addWidget(self._toggle("usb_autoscan", "drive", tr("Проверять флешки при подключении"),
                                   tr("Автоматически сканировать USB-накопители и карты памяти")))
        self.stats = QLabel("")
        self.stats.setObjectName("Caption")
        self.stats.setWordWrap(True)
        lay.addSpacing(6)
        lay.addWidget(self.stats)
        lay.addStretch()
        ctrl.realtime_state.connect(self._state)
        ctrl.protection_changed.connect(self.on_show)

    def _toggle(self, key, glyph, title, desc, restart=True):
        sw = ToggleSwitch(checked=getattr(self.ctrl.settings, key))

        def changed(v):
            setattr(self.ctrl.settings, key, v)
            self.ctrl.settings.save()
            if restart:
                if key in ("heuristics_enabled", "downloads_guard"):
                    self.ctrl.restart_realtime()
                self.ctrl.apply_protection()
        sw.toggled.connect(changed)
        return SettingRow(glyph, title, desc, sw)

    def _state(self, on):
        self.sw_rt.blockSignals(True)
        self.sw_rt.setChecked(on)
        self.sw_rt.blockSignals(False)
        self.on_show()

    def on_show(self):
        c = self.ctrl
        parts = []
        if c.monitor and c.monitor.running:
            parts.append(tr("Файлов проверено монитором: {n}", n=c.monitor.files_checked))
        if c.pguard and c.pguard.running:
            parts.append(tr("программ проверено при запуске: {n}, остановлено: {b}", n=c.pguard.checked, b=c.pguard.blocked))
        if c.rguard and c.rguard.running:
            parts.append(tr("файлов-ловушек: {n}", n=len(c.rguard.canaries)))
        self.stats.setText(" · ".join(parts) if parts else tr("Компоненты защиты выключены"))

    def _add(self, lst: QListWidget, key: str):
        d = QFileDialog.getExistingDirectory(self, tr("Выберите папку"))
        if d and os.path.normpath(d) not in getattr(self.ctrl.settings, key):
            lst.addItem(os.path.normpath(d))
            self._sync(lst, key)

    def _remove(self, lst: QListWidget, key: str):
        for it in lst.selectedItems():
            lst.takeItem(lst.row(it))
        self._sync(lst, key)

    def _sync(self, lst: QListWidget, key: str):
        setattr(self.ctrl.settings, key, [lst.item(i).text() for i in range(lst.count())])
        self.ctrl.settings.save()
        if key == "watch_folders":
            self.ctrl.restart_realtime()
        else:
            self.ctrl.apply_protection()
