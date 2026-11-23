"""Тема в стиле Windows 11 (Fluent): палитры светлой/тёмной темы, QSS, тёмный заголовок окна."""
from __future__ import annotations

import ctypes
import sys
from dataclasses import dataclass

from PySide6.QtGui import QColor, QFont, QFontDatabase, QGuiApplication
from PySide6.QtCore import Qt


@dataclass(frozen=True)
class Palette:
    dark: bool
    bg: str            # фон окна (Mica-like)
    surface: str       # карточки
    surface2: str      # hover
    stroke: str
    text: str
    text2: str
    accent: str
    accent_hover: str
    accent_text: str
    nav_sel: str
    good: str = "#0f9d58"
    warn: str = "#c58a00"
    danger: str = "#d13438"


LIGHT = Palette(False, "#f3f3f3", "#fbfbfb", "#f0f0f0", "#e5e5e5", "#1b1b1b", "#5f5f5f",
                "#005fb8", "#1a6ec2", "#ffffff", "#eaeaea", good="#0f7b0f", warn="#9d5d00", danger="#c42b1c")
DARK = Palette(True, "#202020", "#2b2b2b", "#323232", "#3a3a3a", "#ffffff", "#c5c5c5",
               "#60cdff", "#4cc2ff", "#000000", "#2d2d2d", good="#6ccb5f", warn="#fce100", danger="#ff99a4")

CURRENT: Palette = LIGHT


def current() -> Palette:
    return CURRENT


def set_current(p: Palette) -> None:
    global CURRENT
    CURRENT = p


ICON_FONT = "Segoe Fluent Icons"
GLYPH = {
    "home": "", "scan": "", "shield": "", "journal": "", "quarantine": "",
    "ai": "", "update": "", "settings": "", "check": "", "warning": "",
    "error": "", "folder": "", "drive": "", "bolt": "", "file": "",
    "delete": "", "restore": "", "play": "", "pause": "", "stop": "",
    "export": "", "info": "", "bug": "", "cloud": "", "lock": "",
    "defender": "", "clock": "", "db": "",
}


def icon_font_family() -> str:
    fams = set(QFontDatabase.families())
    if ICON_FONT in fams:
        return ICON_FONT
    return "Segoe MDL2 Assets"


def system_is_dark() -> bool:
    hints = QGuiApplication.styleHints()
    try:
        return hints.colorScheme() == Qt.ColorScheme.Dark
    except AttributeError:
        return False


def resolve(theme: str) -> Palette:
    if theme == "dark":
        return DARK
    if theme == "light":
        return LIGHT
    return DARK if system_is_dark() else LIGHT


def base_font() -> QFont:
    fams = set(QFontDatabase.families())
    fam = "Segoe UI Variable Text" if "Segoe UI Variable Text" in fams else "Segoe UI"
    f = QFont(fam, 10)
    f.setHintingPreference(QFont.PreferNoHinting)
    return f


def stylesheet(p: Palette) -> str:
    icon = icon_font_family()
    return f"""
* {{ color: {p.text}; }}
QMainWindow, QWidget#Root {{ background: {p.bg}; }}
QWidget#Content {{ background: {p.bg}; }}
QScrollArea, QScrollArea > QWidget > QWidget {{ background: transparent; border: none; }}
QLabel {{ background: transparent; }}
QLabel#Title {{ font-size: 20pt; font-weight: 600; }}
QLabel#Subtitle {{ font-size: 13pt; font-weight: 600; }}
QLabel#Caption, QLabel.secondary {{ color: {p.text2}; font-size: 9pt; }}
QLabel#Icon {{ font-family: '{icon}'; font-size: 16pt; }}
QLabel#BigIcon {{ font-family: '{icon}'; font-size: 26pt; color: {p.accent}; }}

QFrame#Card {{ background: {p.surface}; border: 1px solid {p.stroke}; border-radius: 8px; }}
QFrame#Card:hover {{ border-color: {p.stroke}; }}
QFrame#ClickCard {{ background: {p.surface}; border: 1px solid {p.stroke}; border-radius: 8px; }}
QFrame#ClickCard:hover {{ background: {p.surface2}; }}
QFrame#InfoBar {{ border-radius: 6px; border: 1px solid {p.stroke}; }}

QPushButton {{
    background: {p.surface}; border: 1px solid {p.stroke}; border-bottom-color: {'#2a2a2a' if p.dark else '#cfcfcf'};
    border-radius: 5px; padding: 6px 16px; min-height: 20px;
}}
QPushButton:hover {{ background: {p.surface2}; }}
QPushButton:pressed {{ color: {p.text2}; }}
QPushButton:disabled {{ color: {p.text2}; background: {p.surface}; }}
QPushButton#Accent {{ background: {p.accent}; color: {p.accent_text}; border: 1px solid {p.accent}; }}
QPushButton#Accent:hover {{ background: {p.accent_hover}; }}
QPushButton#Accent:disabled {{ background: {p.stroke}; color: {p.text2}; border-color: {p.stroke}; }}
QPushButton#Danger {{ background: {p.danger}; color: {'#000' if p.dark else '#fff'}; border: 1px solid {p.danger}; }}

QPushButton#Nav {{
    text-align: left; border: none; background: transparent; padding: 8px 12px; border-radius: 5px;
    font-size: 10pt;
}}
QPushButton#Nav:hover {{ background: {p.nav_sel}; }}
QPushButton#Nav:checked {{ background: {p.nav_sel}; font-weight: 600; }}

QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox {{
    background: {p.surface}; border: 1px solid {p.stroke}; border-bottom: 2px solid {p.text2};
    border-radius: 5px; padding: 5px 8px; selection-background-color: {p.accent};
}}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus {{ border-bottom: 2px solid {p.accent}; }}
QComboBox::drop-down {{ border: none; width: 24px; }}
QComboBox QAbstractItemView {{ background: {p.surface}; border: 1px solid {p.stroke}; selection-background-color: {p.nav_sel}; selection-color: {p.text}; outline: none; }}

QProgressBar {{ background: {p.stroke}; border: none; border-radius: 2px; max-height: 4px; min-height: 4px; text-align: center; }}
QProgressBar::chunk {{ background: {p.accent}; border-radius: 2px; }}

QTableView, QTreeView, QListWidget {{
    background: {p.surface}; border: 1px solid {p.stroke}; border-radius: 8px;
    gridline-color: transparent; selection-background-color: {p.nav_sel}; selection-color: {p.text};
    alternate-background-color: {p.surface2}; outline: none;
}}
QTableView::item {{ padding: 4px; border: none; }}
QHeaderView::section {{
    background: {p.surface}; color: {p.text2}; border: none; border-bottom: 1px solid {p.stroke};
    padding: 6px 8px; font-weight: 600;
}}
QTableCornerButton::section {{ background: {p.surface}; border: none; }}

QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: {p.text2}; border-radius: 3px; min-height: 30px; margin: 0 2px; }}
QScrollBar::handle:vertical:hover {{ margin: 0; border-radius: 4px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: none; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
QScrollBar::handle:horizontal {{ background: {p.text2}; border-radius: 3px; min-width: 30px; }}

QPlainTextEdit, QTextEdit {{ background: {p.surface}; border: 1px solid {p.stroke}; border-radius: 8px; padding: 6px;
    font-family: 'Cascadia Mono', Consolas; font-size: 9pt; }}
QToolTip {{ background: {p.surface}; color: {p.text}; border: 1px solid {p.stroke}; padding: 4px; }}
QMenu {{ background: {p.surface}; border: 1px solid {p.stroke}; border-radius: 8px; padding: 4px; }}
QMenu::item {{ padding: 6px 24px 6px 12px; border-radius: 4px; }}
QMenu::item:selected {{ background: {p.nav_sel}; }}
QCheckBox {{ spacing: 8px; }}
"""


def apply_titlebar(win_id: int, p: Palette) -> None:
    """Тёмный/светлый заголовок окна, цвет заголовка и Mica (только Windows 11)."""
    if sys.platform != "win32":
        return
    try:
        dwm = ctypes.windll.dwmapi
        hwnd = ctypes.c_void_p(int(win_id))
        val = ctypes.c_int(1 if p.dark else 0)
        dwm.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(val), ctypes.sizeof(val))   # IMMERSIVE_DARK_MODE
        c = QColor(p.bg)
        colorref = ctypes.c_uint(c.red() | (c.green() << 8) | (c.blue() << 16))
        dwm.DwmSetWindowAttribute(hwnd, 35, ctypes.byref(colorref), ctypes.sizeof(colorref))  # CAPTION_COLOR
        corner = ctypes.c_int(2)  # DWMWCP_ROUND
        dwm.DwmSetWindowAttribute(hwnd, 33, ctypes.byref(corner), ctypes.sizeof(corner))
    except Exception:
        pass
