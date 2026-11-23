"""Журнал, карантин, AI-анализ, обновления, параметры."""
from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

from PySide6.QtCore import QObject, Qt, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QFileDialog, QHBoxLayout, QHeaderView, QLabel,
                               QLineEdit, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QScrollArea,
                               QSpinBox, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from timav import APP_NAME, __version__
from timav.core.ai_analyzer import AnalysisReport, CloudAnalyzer, LocalAnalyzer
from timav.core.clamav import db_age_hours
from timav.i18n import tr
from timav.ui import theme
from timav.ui.pages_main import Page, _fmt_ts, open_location, section
from timav.ui.widgets import Card, InfoBar, SecurityGauge, SettingRow, ToggleSwitch, human_size, page_header


def kind_label(k: str) -> str:
    return {"threat": tr("Угроза"), "suspicious": tr("Подозрительный"), "scan": tr("Сканирование"),
            "update": tr("Обновление"), "info": tr("Информация"), "error": tr("Ошибка")}.get(k, k)


def source_label(s: str) -> str:
    return {"scan": tr("Сканер"), "realtime": tr("Монитор"), "ai": "AI", "updater": tr("Обновление"),
            "system": tr("Система"), "process": tr("Запуск"), "ransomware": tr("Шифровальщики"), "usb": "USB"}.get(s, s)


def make_table(cols: list[str], stretch: int = 0) -> QTableWidget:
    t = QTableWidget(0, len(cols))
    t.setHorizontalHeaderLabels(cols)
    t.horizontalHeader().setSectionResizeMode(stretch, QHeaderView.Stretch)
    for i in range(len(cols)):
        if i != stretch:
            t.horizontalHeader().setSectionResizeMode(i, QHeaderView.ResizeToContents)
    t.verticalHeader().hide()
    t.setSelectionBehavior(QAbstractItemView.SelectRows)
    t.setEditTriggers(QAbstractItemView.NoEditTriggers)
    t.setShowGrid(False)
    t.setWordWrap(False)
    return t


# ===================================================================== Журнал
class JournalPage(Page):
    def __init__(self, ctrl, parent=None):
        super().__init__(ctrl, parent)
        self.root.addWidget(page_header(tr("Журнал угроз"), tr("История обнаружений, сканирований и обновлений")))
        bar = QHBoxLayout()
        self.filter = QComboBox()
        self.filter.addItem(tr("Все события"), None)
        for k in ("threat", "suspicious", "scan", "update", "info"):
            self.filter.addItem(kind_label(k), k)
        self.filter.currentIndexChanged.connect(self.reload)
        self.search = QLineEdit()
        self.search.setPlaceholderText(tr("Поиск по пути или названию угрозы"))
        self.search.textChanged.connect(self.reload)
        b_rep = QPushButton(tr("Отчёт"))
        b_rep.clicked.connect(self._report)
        b_exp = QPushButton(tr("Экспорт CSV"))
        b_exp.clicked.connect(self._export)
        b_clr = QPushButton(tr("Очистить"))
        b_clr.clicked.connect(self._clear)
        bar.addWidget(self.filter)
        bar.addWidget(self.search, 1)
        for b in (b_rep, b_exp, b_clr):
            bar.addWidget(b)
        self.root.addLayout(bar)
        self.table = make_table([tr("Время"), tr("Тип"), tr("Источник"), tr("Объект / событие"), tr("Угроза"), tr("Действие")], stretch=3)
        self.table.doubleClicked.connect(lambda i: self._details(i.row()))
        self.root.addWidget(self.table, 1)
        hint = QLabel(tr("Двойной щелчок по угрозе — подробное описание"))
        hint.setObjectName("Caption")
        self.root.addWidget(hint)
        self.rows = []
        self._dirty = True
        ctrl.journal_changed.connect(self._changed)

    def _changed(self):
        self._dirty = True
        if self.isVisible():
            self.reload()

    def on_show(self):
        if self._dirty:
            self.reload()

    def reload(self):
        self._dirty = False
        p = theme.current()
        self.rows = self.ctrl.journal.query(self.filter.currentData(), self.search.text().strip(), limit=3000)
        self.table.setRowCount(len(self.rows))
        for r, e in enumerate(self.rows):
            vals = [time.strftime("%d.%m.%Y %H:%M:%S", time.localtime(e.ts)), kind_label(e.kind), source_label(e.source),
                    e.path or e.details, e.threat, e.action]
            for c, v in enumerate(vals):
                it = QTableWidgetItem(v)
                if c == 3:
                    it.setToolTip((e.path + "\n" + e.details).strip())
                if c == 1 and e.kind in ("threat", "suspicious"):
                    it.setForeground(QColor(p.danger if e.kind == "threat" else p.warn))
                self.table.setItem(r, c, it)

    def _details(self, row: int):
        if 0 <= row < len(self.rows) and self.rows[row].threat:
            from timav.ui.dialogs import ThreatDialog
            e = self.rows[row]
            ThreatDialog(e.threat, e.path, self.ctrl, self).exec()

    def _report(self):
        from timav.core.report import journal_report
        from timav.ui.dialogs import save_report
        save_report(self, journal_report(self.rows, tr("Журнал угроз"), self.ctrl.engine.version()),
                    f"TimAntivirus_journal_{time.strftime('%Y%m%d')}.pdf")

    def _export(self):
        fn, _ = QFileDialog.getSaveFileName(self, tr("Экспорт журнала"), str(Path.home() / "tim_antivirus_journal.csv"), "CSV (*.csv)")
        if fn:
            n = self.ctrl.journal.export_csv(Path(fn))
            QMessageBox.information(self, APP_NAME, tr("Экспортировано записей: {n}", n=n))

    def _clear(self):
        if QMessageBox.question(self, APP_NAME, tr("Очистить весь журнал событий? Это действие нельзя отменить.")) == QMessageBox.Yes:
            self.ctrl.journal.clear()
            self.reload()
            self.ctrl.refresh_security()


# ===================================================================== Карантин
class QuarantinePage(Page):
    def __init__(self, ctrl, parent=None):
        super().__init__(ctrl, parent)
        self.root.addWidget(page_header(tr("Карантин"), tr("Изолированные файлы хранятся в зашифрованном виде и не могут быть запущены")))
        bar = QHBoxLayout()
        self.b_restore = QPushButton(tr("Восстановить"))
        self.b_restore.clicked.connect(self._restore)
        self.b_delete = QPushButton(tr("Удалить навсегда"))
        self.b_delete.setObjectName("Danger")
        self.b_delete.clicked.connect(self._delete)
        bar.addStretch()
        bar.addWidget(self.b_restore)
        bar.addWidget(self.b_delete)
        self.root.addLayout(bar)
        self.table = make_table([tr("Исходный путь"), tr("Угроза"), tr("Размер"), tr("Дата"), "SHA-256"], stretch=0)
        self.root.addWidget(self.table, 1)
        self.items = []
        ctrl.quarantine_changed.connect(self.reload)

    def on_show(self):
        self.reload()

    def reload(self):
        self.items = self.ctrl.quarantine.list()
        self.table.setRowCount(len(self.items))
        for r, it in enumerate(self.items):
            vals = [it.original_path, it.threat, human_size(it.size), time.strftime("%d.%m.%Y %H:%M", time.localtime(it.ts)),
                    it.sha256[:16] + "…"]
            for c, v in enumerate(vals):
                cell = QTableWidgetItem(v)
                if c == 4:
                    cell.setToolTip(it.sha256)
                self.table.setItem(r, c, cell)

    def _selected(self):
        return [self.items[r] for r in sorted({i.row() for i in self.table.selectedIndexes()})]

    def _restore(self):
        sel = self._selected()
        if not sel or QMessageBox.warning(self, APP_NAME, tr("Восстановленный файл может навредить компьютеру. Восстановить?"),
                                          QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
            return
        for it in sel:
            try:
                dst = self.ctrl.quarantine.restore(it.id)
                self.ctrl.journal.add("info", "low", "system", str(dst), it.threat, tr("восстановлено из карантина"))
            except OSError as e:
                QMessageBox.critical(self, APP_NAME, tr("Не удалось восстановить: ") + str(e))
        self.reload()
        self.ctrl.refresh_security()

    def _delete(self):
        sel = self._selected()
        if not sel or QMessageBox.question(self, APP_NAME, tr("Удалить без возможности восстановления объектов: {n}?", n=len(sel))) != QMessageBox.Yes:
            return
        for it in sel:
            self.ctrl.quarantine.delete(it.id)
            self.ctrl.journal.add("info", "info", "system", it.original_path, it.threat, tr("удалено из карантина"))
        self.reload()


# ===================================================================== AI-анализ
class _AIWorker(QObject):
    local_done = Signal(object)
    cloud_done = Signal(object)
    vt_done = Signal(object)
    failed = Signal(str)


class AIPage(Page):
    def __init__(self, ctrl, parent=None):
        super().__init__(ctrl, parent)
        self.setAcceptDrops(True)
        self.root.addWidget(page_header(tr("AI-анализ файлов"),
                                        tr("ML-модель и эвристика оценивают файл локально. VirusTotal и Claude — по желанию, сам файл не отправляется.")))
        pick = Card()
        row = QHBoxLayout()
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText(tr("Перетащите файл сюда или выберите его"))
        b = QPushButton(tr("Выбрать файл…"))
        b.clicked.connect(self._pick)
        self.b_go = QPushButton(tr("Анализировать"))
        self.b_go.setObjectName("Accent")
        self.b_go.clicked.connect(lambda: self.analyze(self.path_edit.text()))
        row.addWidget(self.path_edit, 1)
        row.addWidget(b)
        row.addWidget(self.b_go)
        pick.lay.addLayout(row)
        self.root.addWidget(pick)
        self.info = InfoBar()
        self.root.addWidget(self.info)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        body = QWidget()
        self.body = QVBoxLayout(body)
        self.body.setContentsMargins(0, 0, 8, 0)
        scroll.setWidget(body)
        self.root.addWidget(scroll, 1)

        res = Card()
        rl = QHBoxLayout()
        self.gauge = SecurityGauge(size=150)
        rl.addWidget(self.gauge)
        col = QVBoxLayout()
        self.v_title = QLabel(tr("Файл не выбран"))
        self.v_title.setObjectName("Title")
        self.v_title.setWordWrap(True)
        self.v_meta = QLabel("")
        self.v_meta.setObjectName("Caption")
        self.v_meta.setWordWrap(True)
        self.v_meta.setTextInteractionFlags(Qt.TextSelectableByMouse)
        col.addStretch()
        col.addWidget(self.v_title)
        col.addWidget(self.v_meta)
        btns = QHBoxLayout()
        self.b_vt = QPushButton(tr("Проверить в VirusTotal"))
        self.b_vt.clicked.connect(self._vt)
        self.b_cloud = QPushButton(tr("Глубокий анализ Claude"))
        self.b_cloud.clicked.connect(self._cloud)
        self.b_info = QPushButton(tr("Описание угрозы"))
        self.b_info.clicked.connect(self._threat_info)
        self.b_quar = QPushButton(tr("В карантин"))
        self.b_quar.clicked.connect(self._quarantine)
        for b in (self.b_vt, self.b_cloud, self.b_info, self.b_quar):
            b.setEnabled(False)
            btns.addWidget(b)
        btns.addStretch()
        col.addLayout(btns)
        col.addStretch()
        rl.addLayout(col, 1)
        res.lay.addLayout(rl)
        self.body.addWidget(res)

        ind = Card()
        t = QLabel(tr("Признаки"))
        t.setObjectName("Subtitle")
        ind.lay.addWidget(t)
        self.ind_table = make_table([tr("Признак"), tr("Вклад")], stretch=0)
        self.ind_table.setMinimumHeight(200)
        ind.lay.addWidget(self.ind_table)
        self.body.addWidget(ind)

        vt = Card()
        t3 = QLabel("VirusTotal")
        t3.setObjectName("Subtitle")
        vt.lay.addWidget(t3)
        self.vt_text = QLabel(tr("Проверка по хешу SHA-256 в базе 70+ антивирусов. Укажите бесплатный API-ключ VirusTotal в параметрах."))
        self.vt_text.setWordWrap(True)
        self.vt_text.setOpenExternalLinks(True)
        self.vt_text.setTextInteractionFlags(Qt.TextBrowserInteraction)
        vt.lay.addWidget(self.vt_text)
        self.body.addWidget(vt)

        cl = Card()
        t2 = QLabel(tr("Заключение Claude"))
        t2.setObjectName("Subtitle")
        cl.lay.addWidget(t2)
        self.cloud_text = QLabel(tr("Облачный анализ не выполнялся. Включите его и укажите API-ключ в параметрах. "
                                    "В облако отправляются только признаки и выборка строк, но не сам файл."))
        self.cloud_text.setWordWrap(True)
        self.cloud_text.setTextInteractionFlags(Qt.TextSelectableByMouse)
        cl.lay.addWidget(self.cloud_text)
        self.body.addWidget(cl)
        self.body.addStretch()

        self.report: AnalysisReport | None = None
        self.w = _AIWorker()
        self.w.local_done.connect(self._show_local)
        self.w.cloud_done.connect(self._show_cloud)
        self.w.vt_done.connect(self._show_vt)
        self.w.failed.connect(lambda m: (self.info.show_message(m, "danger", theme.current()), self.b_go.setEnabled(True)))

    def apply_palette(self, p):
        super().apply_palette(p)
        self.gauge.set_palette(p)

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e):
        urls = e.mimeData().urls()
        if urls:
            self.analyze(urls[0].toLocalFile())

    def _pick(self):
        fn, _ = QFileDialog.getOpenFileName(self, tr("Файл для анализа"))
        if fn:
            self.analyze(fn)

    def analyze(self, path: str):
        path = path.strip().strip('"')
        if not path or not os.path.isfile(path):
            self.info.show_message(tr("Укажите существующий файл"), "warning", theme.current())
            return
        self.path_edit.setText(os.path.normpath(path))
        self.info.hide()
        self.v_title.setText(tr("Анализ…"))
        self.b_go.setEnabled(False)
        trusted = self.ctrl.settings.trusted_publishers

        def run():
            try:
                rep = LocalAnalyzer(trusted).analyze(path)
                v = self.ctrl.engine.scan_file(path) if self.ctrl.engine.db_ready() else None
                rep.pe_info["clamav"] = (v.signature if v and v.infected else tr("чисто") if v and v.status == "clean"
                                         else (v.detail if v else tr("нет баз")))
                rep.pe_info["clamav_hit"] = bool(v and v.infected)
                self.w.local_done.emit(rep)
            except Exception as e:  # noqa: BLE001
                self.w.failed.emit(tr("Ошибка анализа: ") + str(e))
        threading.Thread(target=run, daemon=True).start()

    def _show_local(self, rep: AnalysisReport):
        p = theme.current()
        self.report = rep
        self.b_go.setEnabled(True)
        cav = rep.pe_info.get("clamav", "")
        infected = bool(rep.pe_info.get("clamav_hit"))
        score = 100 if infected else int(rep.score * 100)
        level = "danger" if infected or rep.verdict == "malicious" else "warning" if rep.verdict == "suspicious" else "good"
        self.gauge.set_score(100 - score, level)
        self.v_title.setText((tr("Угроза: ") + cav) if infected else f"{rep.verdict_ru} · {tr('риск')} {score}%")
        signer = rep.pe_info.get("signer")
        sig_txt = ""
        if rep.pe_info.get("signed") is not None:
            sig_txt = " · " + (tr("подпись: ") + signer if signer else tr("подпись: есть") if rep.pe_info["signed"] else tr("подпись: нет"))
        ml = rep.pe_info.get("ml_probability")
        self.v_meta.setText(
            f"{Path(rep.path).name} · {human_size(rep.size)} · {tr(rep.file_type)} · {tr('энтропия')} {rep.entropy:.2f}\n"
            f"SHA-256: {rep.sha256}\nClamAV: {cav}{sig_txt}" + (f" · ML: {ml:.0%}" if ml is not None else ""))
        self.ind_table.setRowCount(max(1, len(rep.indicators)))
        if not rep.indicators:
            self.ind_table.setItem(0, 0, QTableWidgetItem(tr("Подозрительных признаков не обнаружено")))
            self.ind_table.setItem(0, 1, QTableWidgetItem(""))
        for r, i in enumerate(rep.indicators):
            self.ind_table.setItem(r, 0, QTableWidgetItem(i.description))
            w = QTableWidgetItem(f"{i.weight:+.2f}")
            w.setForeground(QColor(p.good if i.weight < 0 else p.danger if i.weight >= 1.2 else p.warn if i.weight >= 0.6 else p.text2))
            self.ind_table.setItem(r, 1, w)
        s = self.ctrl.settings
        self.b_cloud.setEnabled(bool(s.cloud_ai_enabled and (s.claude_api_key or os.environ.get("ANTHROPIC_API_KEY"))))
        self.b_cloud.setToolTip("" if self.b_cloud.isEnabled() else tr("Включите облачный анализ и укажите ключ в параметрах"))
        self.b_vt.setEnabled(bool(s.virustotal_api_key))
        self.b_vt.setToolTip("" if s.virustotal_api_key else tr("Укажите API-ключ VirusTotal в параметрах"))
        self.b_info.setEnabled(infected or rep.verdict in ("suspicious", "malicious"))
        self.b_quar.setEnabled(True)
        self.vt_text.setText(tr("Нажмите «Проверить в VirusTotal».") if s.virustotal_api_key else self.vt_text.text())
        if rep.verdict in ("suspicious", "malicious") or infected:
            self.ctrl.journal.add("threat" if infected else "suspicious", "high" if infected else "medium", "ai",
                                  rep.path, cav if infected else f"AI.Heuristic.{rep.verdict.capitalize()}",
                                  tr("обнаружено"), tr("AI-оценка риска: {p}", p=f"{rep.score:.0%}"))

    def _threat_info(self):
        if not self.report:
            return
        from timav.ui.dialogs import ThreatDialog
        r = self.report
        name = r.pe_info["clamav"] if r.pe_info.get("clamav_hit") else f"AI.Heuristic.{r.verdict.capitalize()}"
        ThreatDialog(name, r.path, self.ctrl, self).exec()

    def _vt(self):
        if not self.report:
            return
        self.b_vt.setEnabled(False)
        self.vt_text.setText(tr("Запрос к VirusTotal…"))
        sha, key = self.report.sha256, self.ctrl.settings.virustotal_api_key

        def run():
            from timav.core.virustotal import lookup
            self.w.vt_done.emit(lookup(sha, key))
        threading.Thread(target=run, daemon=True).start()

    def _show_vt(self, r: dict):
        self.b_vt.setEnabled(True)
        p = theme.current()
        if "error" in r:
            self.vt_text.setText(tr(r["error"]))
            return
        if not r.get("found"):
            self.vt_text.setText(tr("Файл не встречался VirusTotal — его никто не загружал для проверки. "
                                    "Это не означает, что он безопасен."))
            return
        m, total = r["malicious"], r["total"]
        col = p.danger if m >= 5 else p.warn if m else p.good
        names = ", ".join(r["names"][:6])
        txt = (f"<b style='color:{col}'>{m} / {total}</b> " + tr("антивирусов считают файл вредоносным") +
               (f"<br>{tr('Подозрительный')}: {r['suspicious']}" if r["suspicious"] else "") +
               (f"<br>{tr('Классификация')}: {r['label']}" if r["label"] else "") +
               (f"<br>{tr('Названия')}: {names}" if names else "") +
               f"<br><a href='{r['link']}'>{tr('Открыть отчёт на virustotal.com')}</a>")
        self.vt_text.setText(txt)
        if self.report:
            self.ctrl.journal.add("info", "info", "ai", self.report.path, r.get("label", ""), "VirusTotal",
                                  f"VirusTotal: {m}/{total}")

    def _cloud(self):
        if not self.report:
            return
        self.b_cloud.setEnabled(False)
        self.cloud_text.setText(tr("Claude анализирует признаки файла…"))
        rep, key = self.report, self.ctrl.settings.claude_api_key

        def run():
            try:
                self.w.cloud_done.emit(CloudAnalyzer(key).analyze(rep))
            except Exception as e:  # noqa: BLE001
                self.w.cloud_done.emit({"error": str(e)})
        threading.Thread(target=run, daemon=True).start()

    def _show_cloud(self, res: dict):
        self.b_cloud.setEnabled(True)
        if "error" in res:
            self.cloud_text.setText(tr("Ошибка: ") + tr(res["error"]))
            return
        verdict = {"clean": tr("Чистый"), "low": tr("Низкий риск"), "suspicious": tr("Подозрительный"),
                   "malicious": tr("Вредоносный")}.get(res.get("verdict"), res.get("verdict", "?"))
        recs = "".join(f"<li>{r}</li>" for r in res.get("recommendations", []))
        self.cloud_text.setText(f"<b>{verdict}</b> · {tr('риск')} {res.get('risk_score', '?')}/100 · {tr('семейство')}: "
                                f"{res.get('family_guess', '—')}<p>{res.get('explanation', '')}</p><ul>{recs}</ul>")
        if self.report:
            self.ctrl.journal.add("info", "info", "ai", self.report.path, res.get("family_guess", ""), tr("облачный анализ"),
                                  f"Claude: {verdict}, {tr('риск')} {res.get('risk_score')}")

    def _quarantine(self):
        if not self.report:
            return
        try:
            self.ctrl.quarantine.add(self.report.path, tr("AI-анализ: ") + self.report.verdict_ru)
            self.ctrl.quarantine_changed.emit()
            self.ctrl.journal.add("suspicious", "medium", "ai", self.report.path, tr("AI-анализ"), tr("в карантине"))
            self.info.show_message(tr("Файл помещён в карантин"), "good", theme.current())
            self.b_quar.setEnabled(False)
        except OSError as e:
            self.info.show_message(tr("Не удалось: ") + str(e), "danger", theme.current())


# ===================================================================== Обновления
class _UpdBridge(QObject):
    progress = Signal(int, int)
    done = Signal(str)
    failed = Signal(str)


class UpdatesPage(Page):
    def __init__(self, ctrl, parent=None):
        super().__init__(ctrl, parent)
        s = ctrl.settings
        self.root.addWidget(page_header(tr("Обновления"), tr("Антивирусные базы ClamAV и сама программа")))
        card = Card()
        row = QHBoxLayout()
        col = QVBoxLayout()
        self.lbl_state = QLabel("")
        self.lbl_state.setObjectName("Subtitle")
        self.lbl_info = QLabel("")
        self.lbl_info.setObjectName("Caption")
        self.lbl_info.setWordWrap(True)
        col.addWidget(self.lbl_state)
        col.addWidget(self.lbl_info)
        row.addLayout(col, 1)
        self.b_upd = QPushButton(tr("Обновить базы"))
        self.b_upd.setObjectName("Accent")
        self.b_upd.clicked.connect(self._update)
        row.addWidget(self.b_upd)
        card.lay.addLayout(row)
        self.root.addWidget(card)

        app = Card()
        ar = QHBoxLayout()
        ac = QVBoxLayout()
        self.app_state = QLabel(tr("Tim Antivirus {v}", v=__version__))
        self.app_state.setObjectName("Subtitle")
        self.app_info = QLabel(tr("Канал обновлений не настроен (Параметры → Обновление программы)") if not s.update_feed_url
                               else tr("Канал: ") + s.update_feed_url)
        self.app_info.setObjectName("Caption")
        self.app_info.setWordWrap(True)
        ac.addWidget(self.app_state)
        ac.addWidget(self.app_info)
        self.app_bar = QProgressBar()
        self.app_bar.setTextVisible(False)
        self.app_bar.hide()
        ac.addWidget(self.app_bar)
        ar.addLayout(ac, 1)
        self.b_app = QPushButton(tr("Проверить обновления программы"))
        self.b_app.clicked.connect(self._check_app)
        self.b_install = QPushButton(tr("Скачать и установить"))
        self.b_install.setObjectName("Accent")
        self.b_install.hide()
        self.b_install.clicked.connect(self._install)
        ar.addWidget(self.b_app)
        ar.addWidget(self.b_install)
        app.lay.addLayout(ar)
        self.root.addWidget(app)

        self.sw_auto = ToggleSwitch(checked=s.auto_update)
        self.sw_auto.toggled.connect(lambda v: self._set("auto_update", v))
        self.root.addWidget(SettingRow("update", tr("Автоматическое обновление баз"), tr("Регулярно проверять наличие новых сигнатур"), self.sw_auto))
        self.spin = QSpinBox()
        self.spin.setRange(1, 24)
        self.spin.setSuffix(tr(" ч"))
        self.spin.setValue(s.update_interval_hours)
        self.spin.valueChanged.connect(lambda v: self._set("update_interval_hours", v))
        self.root.addWidget(SettingRow("clock", tr("Интервал проверки"), tr("Как часто проверять обновления баз"), self.spin))
        lab = QLabel(tr("Журнал обновления"))
        lab.setObjectName("Subtitle")
        self.root.addWidget(lab)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.root.addWidget(self.log, 1)
        self.release = None
        self.bridge = _UpdBridge()
        self.bridge.progress.connect(lambda d, t: (self.app_bar.setRange(0, t or 0), self.app_bar.setValue(d)))
        self.bridge.done.connect(self._downloaded)
        self.bridge.failed.connect(lambda m: (self.app_info.setText(tr("Ошибка: ") + m), self.app_bar.hide(),
                                              self.b_install.setEnabled(True)))
        ctrl.update_line.connect(self._line)
        ctrl.update_finished.connect(self._done)
        ctrl.app_update.connect(self._app_update)

    def _set(self, k, v):
        setattr(self.ctrl.settings, k, v)
        self.ctrl.settings.save()

    def _update(self):
        self.log.appendPlainText(time.strftime("[%H:%M:%S] ") + tr("Запуск freshclam…"))
        self.ctrl.start_update()
        self.on_show()

    def _line(self, line: str):
        if not ("%" in line and "[" in line):
            self.log.appendPlainText(line)

    def _done(self, ok: bool, msg: str):
        self.log.appendPlainText(time.strftime("[%H:%M:%S] ") + msg)
        self.on_show()

    def on_show(self):
        e = self.ctrl.engine
        upd = self.ctrl.updating
        self.b_upd.setEnabled(not upd)
        self.b_upd.setText(tr("Обновление…") if upd else tr("Обновить базы"))
        if e.db_ready():
            age = db_age_hours(e)
            self.lbl_state.setText(tr("Базы актуальны") if age is not None and age < 48 else tr("Базы требуют обновления"))
            parts = [f"{i.name} v{i.version} ({i.signatures:,})".replace(",", " ") for i in e.db_info()]
            self.lbl_info.setText(" · ".join(parts) + "\n" + tr("Последняя проверка: ") + _fmt_ts(self.ctrl.settings.last_update_ts))
        else:
            self.lbl_state.setText(tr("Базы не загружены"))
            self.lbl_info.setText(tr("Первая загрузка занимает около 300 МБ"))

    def _check_app(self):
        if not self.ctrl.settings.update_feed_url:
            self.app_info.setText(tr("Канал обновлений не настроен (Параметры → Обновление программы)"))
            return
        self.app_info.setText(tr("Проверка…"))
        self.ctrl.check_app_update()

    def _app_update(self, rel):
        if isinstance(rel, str):
            self.app_info.setText(tr("Ошибка: ") + rel)
        elif rel is None:
            self.app_info.setText(tr("Установлена последняя версия"))
            self.b_install.hide()
        else:
            self.release = rel
            self.app_state.setText(tr("Доступна версия {v}", v=rel.version))
            self.app_info.setText(rel.notes[:400] or tr("Новая версия готова к установке"))
            self.b_install.show()
            self.b_install.setEnabled(True)

    def _install(self):
        if not self.release:
            return
        self.b_install.setEnabled(False)
        self.app_bar.show()
        rel = self.release

        def run():
            from timav.core import selfupdate
            try:
                path = selfupdate.download(rel, on_progress=lambda d, t: self.bridge.progress.emit(d, t))
                self.bridge.done.emit(path)
            except Exception as e:  # noqa: BLE001
                self.bridge.failed.emit(str(e))
        threading.Thread(target=run, daemon=True).start()

    def _downloaded(self, path: str):
        if QMessageBox.question(self, APP_NAME, tr("Обновление загружено и проверено. Установить сейчас? Программа будет перезапущена.")) == QMessageBox.Yes:
            from timav.core import selfupdate
            selfupdate.install(path)
            self.window().quit_app()


# ===================================================================== Параметры
class SettingsPage(Page):
    theme_changed = Signal(str)

    def __init__(self, ctrl, parent=None):
        super().__init__(ctrl, parent)
        s = ctrl.settings
        self.root.addWidget(page_header(tr("Параметры")))
        lay = self.scroll_body()

        section(lay, tr("Внешний вид"))
        self.cb_theme = QComboBox()
        for k, v in (("system", tr("Как в системе")), ("light", tr("Светлая")), ("dark", tr("Тёмная"))):
            self.cb_theme.addItem(v, k)
        self.cb_theme.setCurrentIndex(["system", "light", "dark"].index(s.theme))
        self.cb_theme.currentIndexChanged.connect(self._theme)
        lay.addWidget(SettingRow("settings", tr("Тема"), tr("Оформление приложения"), self.cb_theme))
        self.cb_lang = QComboBox()
        self.cb_lang.addItem("Русский", "ru")
        self.cb_lang.addItem("English", "en")
        self.cb_lang.setCurrentIndex(0 if s.language == "ru" else 1)
        self.cb_lang.currentIndexChanged.connect(self._lang)
        lay.addWidget(SettingRow("info", tr("Язык / Language"), tr("Применяется после перезапуска программы"), self.cb_lang))

        section(lay, tr("Система"))
        lay.addWidget(self._toggle("notifications", "info", tr("Уведомления"), tr("Показывать уведомления Windows об угрозах и сканировании")))
        lay.addWidget(self._toggle("minimize_to_tray", "shield", tr("Сворачивать в трей"), tr("При закрытии окна защита продолжит работать в фоне")))
        sw = ToggleSwitch(checked=s.autostart)
        sw.toggled.connect(self._autostart)
        lay.addWidget(SettingRow("play", tr("Запуск вместе с Windows"), tr("Запускать Tim Antivirus при входе в систему (свёрнутым)"), sw))
        cm = ToggleSwitch(checked=s.context_menu)
        cm.toggled.connect(lambda v: (self._set("context_menu", v), self.ctrl.sync_context_menu()))
        lay.addWidget(SettingRow("folder", tr("Пункт в меню Проводника"),
                                 tr("«Проверить в Tim Antivirus» по правому щелчку (в Windows 11 — «Показать дополнительные параметры»)"), cm))

        section(lay, tr("Сканирование"))
        lay.addWidget(self._toggle("use_daemon", "bolt", tr("Резидентный движок"),
                                   tr("Держать базы ClamAV в памяти (clamd) — сканирование в разы быстрее, ~1 ГБ ОЗУ. Требуется перезапуск")))
        lay.addWidget(self._toggle("scan_archives", "folder", tr("Проверять архивы"), tr("Распаковывать ZIP, RAR, 7z и другие архивы при проверке")))
        sp = QSpinBox()
        sp.setRange(10, 2000)
        sp.setSuffix(tr(" МБ"))
        sp.setValue(s.max_file_size_mb)
        sp.valueChanged.connect(lambda v: self._set("max_file_size_mb", v))
        lay.addWidget(SettingRow("file", tr("Максимальный размер файла"), tr("Более крупные файлы пропускаются"), sp))
        sp2 = QSpinBox()
        sp2.setRange(50, 99)
        sp2.setSuffix(" %")
        sp2.setValue(int(s.heuristic_threshold * 100))
        sp2.valueChanged.connect(lambda v: self._set("heuristic_threshold", v / 100))
        lay.addWidget(SettingRow("ai", tr("Порог AI-эвристики"), tr("Файлы с оценкой риска выше порога помечаются как подозрительные"), sp2))
        self.ex_edit = QLineEdit("; ".join(s.excluded_paths))
        self.ex_edit.setPlaceholderText("C:\\Dev; D:\\Games")
        self.ex_edit.setMinimumWidth(260)
        self.ex_edit.editingFinished.connect(
            lambda: self._set("excluded_paths", [x.strip() for x in self.ex_edit.text().split(";") if x.strip()]))
        lay.addWidget(SettingRow("folder", tr("Исключения"), tr("Папки, которые не проверяются (через «;»)"), self.ex_edit))

        section(lay, tr("Доверенные издатели"))
        note = QLabel(tr("Программы с действительной цифровой подписью этих издателей не помечаются эвристикой "
                         "(ClamAV проверяет их как обычно). По одному издателю на строку."))
        note.setObjectName("Caption")
        note.setWordWrap(True)
        lay.addWidget(note)
        self.trusted = QPlainTextEdit("\n".join(s.trusted_publishers))
        self.trusted.setMinimumHeight(150)
        lay.addWidget(self.trusted)
        b_tr = QPushButton(tr("Сохранить список"))
        b_tr.clicked.connect(self._save_trusted)
        lay.addWidget(b_tr, 0, Qt.AlignLeft)

        section(lay, tr("Облачные сервисы"))
        lay.addWidget(self._toggle("cloud_ai_enabled", "cloud", tr("Облачный AI-анализ (Claude)"),
                                   tr("Отправлять признаки подозрительного файла (не сам файл) в Claude для подробного заключения")))
        self.key = QLineEdit(s.claude_api_key)
        self.key.setEchoMode(QLineEdit.Password)
        self.key.setPlaceholderText(tr("sk-ant-… или переменная ANTHROPIC_API_KEY"))
        self.key.setMinimumWidth(260)
        self.key.editingFinished.connect(lambda: self._set("claude_api_key", self.key.text().strip()))
        lay.addWidget(SettingRow("lock", tr("API-ключ Anthropic"), tr("Хранится локально в настройках пользователя"), self.key))
        self.vt = QLineEdit(s.virustotal_api_key)
        self.vt.setEchoMode(QLineEdit.Password)
        self.vt.setPlaceholderText(tr("ключ из профиля virustotal.com"))
        self.vt.setMinimumWidth(260)
        self.vt.editingFinished.connect(lambda: self._set("virustotal_api_key", self.vt.text().strip()))
        lay.addWidget(SettingRow("cloud", tr("API-ключ VirusTotal"),
                                 tr("Бесплатный ключ: 4 запроса в минуту. Отправляется только хеш SHA-256"), self.vt))

        section(lay, tr("Обновление программы"))
        self.feed = QLineEdit(s.update_feed_url)
        self.feed.setPlaceholderText("github:owner/repo  " + tr("или") + "  https://…/latest.json")
        self.feed.setMinimumWidth(300)
        self.feed.editingFinished.connect(lambda: self._set("update_feed_url", self.feed.text().strip()))
        lay.addWidget(SettingRow("update", tr("Канал обновлений"), tr("Откуда проверять новые версии Tim Antivirus"), self.feed))
        lay.addWidget(self._toggle("check_app_updates", "clock", tr("Проверять обновления программы"), tr("Раз в сутки при запуске")))

        section(lay, tr("О программе"))
        about = Card()
        a = QLabel(f"<b>{APP_NAME}</b> {__version__}<br>{tr('Движок')}: {ctrl.engine.version()}<br>"
                   + tr("Антивирусный движок ClamAV® (GPL-2.0), © Cisco Systems.") + "<br>"
                   + tr("ML-модель обучена на открытом датасете ClaMP (5184 PE-файла).") + "<br>"
                   + tr("Tim Antivirus дополняет встроенную защиту Microsoft Defender и никогда не отключает её."))
        a.setWordWrap(True)
        a.setObjectName("Caption")
        about.lay.addWidget(a)
        lay.addWidget(about)
        lay.addStretch()

    def _toggle(self, key, glyph, title, desc):
        sw = ToggleSwitch(checked=getattr(self.ctrl.settings, key))
        sw.toggled.connect(lambda v: self._set(key, v))
        return SettingRow(glyph, title, desc, sw)

    def _set(self, k, v):
        setattr(self.ctrl.settings, k, v)
        self.ctrl.settings.save()
        if k in ("max_file_size_mb", "scan_archives"):
            self.ctrl.engine.max_file_mb = self.ctrl.settings.max_file_size_mb
            self.ctrl.engine.scan_archives = self.ctrl.settings.scan_archives

    def _save_trusted(self):
        items = [x.strip() for x in self.trusted.toPlainText().splitlines() if x.strip()]
        self._set("trusted_publishers", items)
        self.ctrl.restart_realtime()
        if self.ctrl.pguard:
            self.ctrl.pguard.stop()
            self.ctrl.pguard = None
        self.ctrl.apply_protection()
        QMessageBox.information(self, APP_NAME, tr("Список сохранён: {n} издателей", n=len(items)))

    def _theme(self):
        k = self.cb_theme.currentData()
        self._set("theme", k)
        self.theme_changed.emit(k)

    def _lang(self):
        self._set("language", self.cb_lang.currentData())
        QMessageBox.information(self, APP_NAME, "Язык изменится после перезапуска программы.\n"
                                                "The language will change after restarting the app.")

    def _autostart(self, on: bool):
        self._set("autostart", on)
        set_autostart(on)


def set_autostart(on: bool) -> None:
    import winreg
    key = r"Software\Microsoft\Windows\CurrentVersion\Run"
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_SET_VALUE) as k:
        if on:
            if getattr(sys, "frozen", False):
                cmd = f'"{sys.executable}" --minimized'
            else:
                cmd = f'"{sys.executable.replace("python.exe", "pythonw.exe")}" -m timav --minimized'
            winreg.SetValueEx(k, "TimAntivirus", 0, winreg.REG_SZ, cmd)
        else:
            try:
                winreg.DeleteValue(k, "TimAntivirus")
            except FileNotFoundError:
                pass
