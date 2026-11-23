"""Локализация: строки в коде пишутся по-русски и оборачиваются в tr(); английские переводы — в i18n_en.py.
Язык выбирается при запуске (Параметры → Язык, нужен перезапуск)."""
from __future__ import annotations

LANG = "ru"


def set_language(lang: str) -> None:
    global LANG
    LANG = lang if lang in ("ru", "en") else "ru"


def tr(text: str, **kw) -> str:
    if LANG == "en":
        from timav.i18n_en import EN
        text = EN.get(text, text)
    if kw:
        try:
            return text.format(**kw)
        except (KeyError, IndexError, ValueError):
            return text
    return text
