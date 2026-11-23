"""Fluent-виджеты: индикатор безопасности, переключатель, карточки."""
from __future__ import annotations

from PySide6.QtCore import Property, QEasingCurve, QPropertyAnimation, QRectF, QSize, Qt, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import (QAbstractButton, QFrame, QHBoxLayout, QLabel, QSizePolicy, QVBoxLayout,
                               QWidget)

from timav.ui import theme
from timav.ui.theme import GLYPH


class SecurityGauge(QWidget):
    """Кольцевой индикатор уровня безопасности 0–100 с анимацией."""

    def __init__(self, parent=None, size: int = 190):
        super().__init__(parent)
        self.setFixedSize(size, size)
        self._value = 0.0
        self._target = 0
        self.level = "good"
        self.palette_ = theme.LIGHT
        self.glyph = GLYPH["shield"]
        self._anim = QPropertyAnimation(self, b"value", self)
        self._anim.setDuration(900)
        self._anim.setEasingCurve(QEasingCurve.OutCubic)

    def set_palette(self, p: theme.Palette):
        self.palette_ = p
        self.update()

    def getValue(self) -> float:
        return self._value

    def setValue(self, v: float):
        self._value = v
        self.update()

    value = Property(float, getValue, setValue)

    def set_score(self, score: int, level: str):
        self.level = level
        self.glyph = {"good": GLYPH["shield"], "warning": GLYPH["warning"], "danger": GLYPH["error"]}[level]
        self._anim.stop()
        self._anim.setStartValue(self._value)
        self._anim.setEndValue(float(score))
        self._anim.start()

    def color(self) -> QColor:
        p = self.palette_
        return QColor({"good": p.good, "warning": p.warn, "danger": p.danger}[self.level])

    def paintEvent(self, _):
        p = self.palette_
        qp = QPainter(self)
        qp.setRenderHint(QPainter.Antialiasing)
        w = self.width()
        thick = w * 0.075
        rect = QRectF(thick, thick, w - 2 * thick, w - 2 * thick)
        pen = QPen(QColor(p.stroke), thick, Qt.SolidLine, Qt.RoundCap)
        qp.setPen(pen)
        qp.drawArc(rect, 225 * 16, -270 * 16)
        col = self.color()
        pen.setColor(col)
        qp.setPen(pen)
        qp.drawArc(rect, 225 * 16, int(-270 * 16 * self._value / 100))
        # иконка щита
        f = QFont(theme.icon_font_family())
        f.setPixelSize(int(w * 0.24))
        qp.setFont(f)
        qp.setPen(col)
        qp.drawText(QRectF(0, w * 0.18, w, w * 0.36), Qt.AlignCenter, self.glyph)
        # число
        f2 = QFont(theme.base_font())
        f2.setPixelSize(int(w * 0.2))
        f2.setWeight(QFont.DemiBold)
        qp.setFont(f2)
        qp.setPen(QColor(p.text))
        qp.drawText(QRectF(0, w * 0.5, w, w * 0.24), Qt.AlignCenter, f"{int(round(self._value))}")
        f3 = QFont(theme.base_font())
        f3.setPixelSize(int(w * 0.065))
        qp.setFont(f3)
        qp.setPen(QColor(p.text2))
        from timav.i18n import tr
        qp.drawText(QRectF(0, w * 0.73, w, w * 0.1), Qt.AlignCenter, tr("индекс защиты"))


class ToggleSwitch(QAbstractButton):
    """Переключатель в стиле Windows 11."""

    def __init__(self, parent=None, checked: bool = False):
        super().__init__(parent)
        self.setCheckable(True)
        self.setChecked(checked)
        self.setCursor(Qt.PointingHandCursor)
        self._pos = 1.0 if checked else 0.0
        self.palette_ = theme.LIGHT
        self._anim = QPropertyAnimation(self, b"pos", self)
        self._anim.setDuration(140)
        self.toggled.connect(self._animate)

    def set_palette(self, p):
        self.palette_ = p
        self.update()

    def sizeHint(self):
        return QSize(44, 22)

    def getPos(self):
        return self._pos

    def setPos(self, v):
        self._pos = v
        self.update()

    pos = Property(float, getPos, setPos)

    def _animate(self, on: bool):
        self._anim.stop()
        self._anim.setStartValue(self._pos)
        self._anim.setEndValue(1.0 if on else 0.0)
        self._anim.start()

    def setChecked(self, c: bool):  # noqa: N802
        super().setChecked(c)
        self._pos = 1.0 if c else 0.0
        self.update()

    def paintEvent(self, _):
        p = self.palette_
        qp = QPainter(self)
        qp.setRenderHint(QPainter.Antialiasing)
        r = QRectF(1, 1, 42, 20)
        on = self.isChecked()
        if on:
            qp.setPen(Qt.NoPen)
            qp.setBrush(QColor(p.accent))
        else:
            qp.setPen(QPen(QColor(p.text2), 1))
            qp.setBrush(Qt.NoBrush)
        qp.drawRoundedRect(r, 10, 10)
        d = 12 if not self.underMouse() else 14
        x = 5 + self._pos * 22 + (12 - d) / 2 + 1
        qp.setPen(Qt.NoPen)
        qp.setBrush(QColor(p.accent_text if on else p.text2))
        qp.drawEllipse(QRectF(x, 11 - d / 2, d, d))

    def enterEvent(self, e):
        self.update()
        super().enterEvent(e)

    def leaveEvent(self, e):
        self.update()
        super().leaveEvent(e)


def icon_label(glyph: str, size: int = 16, color: str | None = None) -> QLabel:
    lab = QLabel(GLYPH.get(glyph, glyph))
    f = QFont(theme.icon_font_family())
    f.setPixelSize(int(size * 1.33))
    lab.setFont(f)
    lab.setFixedWidth(int(size * 1.33) + 8)
    lab.setAlignment(Qt.AlignCenter)
    if color:
        lab.setStyleSheet(f"color: {color};")
    return lab


class Card(QFrame):
    def __init__(self, parent=None, clickable: bool = False):
        super().__init__(parent)
        self.setObjectName("ClickCard" if clickable else "Card")
        self.lay = QVBoxLayout(self)
        self.lay.setContentsMargins(16, 14, 16, 14)
        self.lay.setSpacing(8)


class ClickCard(Card):
    clicked = Signal()

    def __init__(self, parent=None):
        super().__init__(parent, clickable=True)
        self.setCursor(Qt.PointingHandCursor)

    def mouseReleaseEvent(self, e):
        if e.button() == Qt.LeftButton and self.isEnabled():
            self.clicked.emit()
        super().mouseReleaseEvent(e)


class SettingRow(Card):
    """Строка настроек: иконка, заголовок, описание, элемент управления справа."""

    def __init__(self, glyph: str, title: str, desc: str, control: QWidget, parent=None):
        super().__init__(parent)
        row = QHBoxLayout()
        row.setSpacing(14)
        row.addWidget(icon_label(glyph, 16))
        col = QVBoxLayout()
        col.setSpacing(1)
        t = QLabel(title)
        d = QLabel(desc)
        d.setObjectName("Caption")
        d.setWordWrap(True)
        col.addWidget(t)
        col.addWidget(d)
        row.addLayout(col, 1)
        row.addWidget(control, 0, Qt.AlignRight | Qt.AlignVCenter)
        self.lay.addLayout(row)
        self.title_label, self.desc_label = t, d


class StatusTile(Card):
    """Плитка состояния на главной странице."""

    def __init__(self, glyph: str, title: str, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(96)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        top = QHBoxLayout()
        self.icon = icon_label(glyph, 15)
        top.addWidget(self.icon)
        t = QLabel(title)
        t.setObjectName("Caption")
        top.addWidget(t, 1)
        self.lay.addLayout(top)
        self.value = QLabel("—")
        self.value.setStyleSheet("font-size: 12pt; font-weight: 600;")
        self.value.setWordWrap(True)
        self.sub = QLabel("")
        self.sub.setObjectName("Caption")
        self.sub.setWordWrap(True)
        self.lay.addWidget(self.value)
        self.lay.addWidget(self.sub)
        self.lay.addStretch()

    def set(self, value: str, sub: str = "", color: str | None = None):
        self.value.setText(value)
        self.sub.setText(sub)
        self.icon.setStyleSheet(f"color: {color};" if color else "")


class InfoBar(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("InfoBar")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(12, 8, 12, 8)
        self.icon = icon_label("info", 14)
        self.text = QLabel()
        self.text.setWordWrap(True)
        lay.addWidget(self.icon)
        lay.addWidget(self.text, 1)
        self.hide()

    def show_message(self, text: str, kind: str, p: theme.Palette):
        col = {"info": p.accent, "good": p.good, "warning": p.warn, "danger": p.danger}[kind]
        g = {"info": "info", "good": "check", "warning": "warning", "danger": "error"}[kind]
        self.icon.setText(GLYPH[g])
        self.icon.setStyleSheet(f"color: {col};")
        bg = QColor(col)
        bg.setAlpha(28)
        self.setStyleSheet(f"QFrame#InfoBar {{ background: rgba({bg.red()},{bg.green()},{bg.blue()},28); }}")
        self.text.setText(text)
        self.show()


def page_header(title: str, subtitle: str = "") -> QWidget:
    w = QWidget()
    lay = QVBoxLayout(w)
    lay.setContentsMargins(0, 0, 0, 8)
    lay.setSpacing(2)
    t = QLabel(title)
    t.setObjectName("Title")
    lay.addWidget(t)
    if subtitle:
        s = QLabel(subtitle)
        s.setObjectName("Caption")
        s.setWordWrap(True)
        lay.addWidget(s)
    return w


def human_size(n: float) -> str:
    for unit in ("Б", "КБ", "МБ", "ГБ"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "Б" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} ТБ"


def human_duration(sec: float) -> str:
    sec = int(sec)
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"
