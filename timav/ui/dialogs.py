"""Диалоги: описание угрозы, тревога шифровальщика, сохранение отчёта."""
from __future__ import annotations

import os
import threading
from pathlib import Path

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtWidgets import (QDialog, QFileDialog, QHBoxLayout, QLabel, QMessageBox, QPushButton, QVBoxLayout,
                               QWidget)

from timav import APP_NAME
from timav.core.threat_info import describe
from timav.i18n import tr
from timav.ui import theme
from timav.ui.widgets import Card, icon_label


def _style_dialog(d: QDialog):
    d.setStyleSheet(f"QDialog {{ background: {theme.current().bg}; }}")
    theme.apply_titlebar(d.winId(), theme.current())


class _Bridge(QObject):
    done = Signal(str)


class ThreatDialog(QDialog):
    def __init__(self, signature: str, path: str = "", ctrl=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle(tr("Сведения об угрозе"))
        self.setMinimumWidth(560)
        p = theme.current()
        ti = describe(signature)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 20, 24, 20)
        lay.setSpacing(10)
        top = QHBoxLayout()
        col = {"critical": p.danger, "high": p.danger, "medium": p.warn, "low": p.accent, "info": p.good}[ti.danger]
        top.addWidget(icon_label("error" if ti.danger in ("critical", "high") else "warning", 26, col))
        t = QVBoxLayout()
        title = QLabel(ti.category)
        title.setObjectName("Title")
        sig = QLabel(signature)
        sig.setObjectName("Caption")
        sig.setTextInteractionFlags(Qt.TextSelectableByMouse)
        t.addWidget(title)
        t.addWidget(sig)
        top.addLayout(t, 1)
        lay.addLayout(top)
        card = Card()
        rows = [(tr("Опасность"), f"<b style='color:{col}'>{ti.danger_ru}</b>"), (tr("Платформа"), ti.platform),
                (tr("Семейство"), ti.family)]
        if path:
            rows.append((tr("Файл"), path))
        for k, v in rows:
            r = QHBoxLayout()
            a = QLabel(k)
            a.setObjectName("Caption")
            a.setFixedWidth(110)
            b = QLabel(v)
            b.setWordWrap(True)
            b.setTextInteractionFlags(Qt.TextSelectableByMouse)
            r.addWidget(a)
            r.addWidget(b, 1)
            card.lay.addLayout(r)
        lay.addWidget(card)
        d = QLabel(ti.description + (f"<p>{ti.family_note}</p>" if ti.family_note else ""))
        d.setWordWrap(True)
        lay.addWidget(d)
        adv = QLabel(f"<b>{tr('Что делать')}:</b><ul>" + "".join(f"<li>{a}</li>" for a in ti.advice) + "</ul>")
        adv.setWordWrap(True)
        lay.addWidget(adv)
        self.claude_lbl = QLabel("")
        self.claude_lbl.setWordWrap(True)
        self.claude_lbl.hide()
        lay.addWidget(self.claude_lbl)
        btns = QHBoxLayout()
        self.ctrl = ctrl
        self.signature = signature
        if ctrl and ctrl.settings.cloud_ai_enabled and (ctrl.settings.claude_api_key or os.environ.get("ANTHROPIC_API_KEY")):
            b = QPushButton(tr("Объяснить подробнее (Claude)"))
            b.clicked.connect(lambda: self._claude(b))
            btns.addWidget(b)
        btns.addStretch()
        ok = QPushButton(tr("Закрыть"))
        ok.setObjectName("Accent")
        ok.clicked.connect(self.accept)
        btns.addWidget(ok)
        lay.addLayout(btns)
        self.bridge = _Bridge()
        self.bridge.done.connect(self._claude_done)
        _style_dialog(self)

    def _claude(self, btn):
        btn.setEnabled(False)
        self.claude_lbl.setText(tr("Claude готовит объяснение…"))
        self.claude_lbl.show()
        key, sig = self.ctrl.settings.claude_api_key, self.signature

        def run():
            try:
                import anthropic
                from timav.core.ai_analyzer import CLOUD_MODEL
                from timav.i18n import LANG
                client = anthropic.Anthropic(api_key=key or None, timeout=90.0)
                lang = "English" if LANG == "en" else "русском языке"
                resp = client.beta.messages.create(
                    model=CLOUD_MODEL, max_tokens=3000, betas=["server-side-fallback-2026-07-01"],
                    fallbacks="default", output_config={"effort": "low"},
                    system=f"Ты — эксперт по кибербезопасности. Отвечай на {lang}, кратко (до 8 предложений), "
                           "для обычного пользователя.",
                    messages=[{"role": "user", "content": f"Антивирус ClamAV обнаружил угрозу «{sig}». Что это за "
                               "семейство, что оно делает, насколько опасно и что делать пользователю?"}])
                if resp.stop_reason == "refusal":
                    text = tr("Модель отказалась отвечать")
                else:
                    text = "".join(getattr(b, "text", "") for b in resp.content if getattr(b, "type", "") == "text")
            except Exception as e:  # noqa: BLE001
                text = tr("Ошибка: ") + str(e)
            self.bridge.done.emit(text)
        threading.Thread(target=run, daemon=True).start()

    def _claude_done(self, text: str):
        self.claude_lbl.setText("<b>Claude:</b> " + text.replace("\n", "<br>"))


class RansomDialog(QDialog):
    def __init__(self, reason: str, suspect: dict | None, ctrl, parent=None):
        super().__init__(parent)
        self.setWindowTitle(tr("Защита от шифровальщиков"))
        self.setMinimumWidth(560)
        self.setWindowFlag(Qt.WindowStaysOnTopHint)
        p = theme.current()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 20, 24, 20)
        top = QHBoxLayout()
        top.addWidget(icon_label("error", 28, p.danger))
        t = QLabel(tr("Обнаружено поведение шифровальщика"))
        t.setObjectName("Title")
        t.setWordWrap(True)
        top.addWidget(t, 1)
        lay.addLayout(top)
        lay.addWidget(QLabel(reason))
        if suspect:
            card = Card()
            info = QLabel(f"<b>{suspect['name']}</b> (PID {suspect['pid']})<br>{suspect['exe']}<br>"
                          + (tr("Процесс приостановлен — он не может продолжать изменять файлы.")
                             if suspect.get("suspended") else
                             tr("Возможный источник: процесс активно пишет на диск, но прямых доказательств нет — "
                                "он не приостановлен.") if suspect.get("evidence") == "io" else
                             tr("Процесс не приостановлен (доверенный издатель или нет доступа).")))
            info.setWordWrap(True)
            info.setTextInteractionFlags(Qt.TextSelectableByMouse)
            card.lay.addWidget(info)
            lay.addWidget(card)
        else:
            lay.addWidget(QLabel(tr("Не удалось определить процесс-виновник.")))
        btns = QHBoxLayout()
        btns.addStretch()
        if suspect:
            kill = QPushButton(tr("Завершить процесс и изолировать файл"))
            kill.setObjectName("Danger")
            kill.clicked.connect(lambda: (ctrl.resolve_ransom(suspect, True), self.accept()))
            btns.addWidget(kill)
            if suspect.get("suspended"):
                res = QPushButton(tr("Это не угроза — продолжить"))
                res.clicked.connect(lambda: (ctrl.resolve_ransom(suspect, False), self.accept()))
                btns.addWidget(res)
        close = QPushButton(tr("Закрыть"))
        close.clicked.connect(self.reject)
        btns.addWidget(close)
        lay.addLayout(btns)
        _style_dialog(self)


def save_report(parent: QWidget, html_text: str, default_name: str) -> None:
    fn, _ = QFileDialog.getSaveFileName(parent, tr("Сохранить отчёт"), str(Path.home() / "Documents" / default_name),
                                        "PDF (*.pdf);;HTML (*.html)")
    if not fn:
        return
    from timav.core.report import save
    try:
        out = save(html_text, fn)
        QMessageBox.information(parent, APP_NAME, tr("Отчёт сохранён:") + f"\n{out}")
    except OSError as e:
        QMessageBox.critical(parent, APP_NAME, str(e))
