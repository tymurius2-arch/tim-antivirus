"""Отчёты в HTML и PDF."""
from __future__ import annotations

import html
import platform
import time
from pathlib import Path

from timav import APP_NAME, __version__
from timav.core.threat_info import describe

CSS = """
body { font-family: 'Segoe UI', Arial, sans-serif; color: #1b1b1b; margin: 24px; }
h1 { color: #005fb8; font-size: 22pt; margin-bottom: 0; }
h2 { font-size: 14pt; margin-top: 24px; border-bottom: 1px solid #ddd; padding-bottom: 4px; }
.muted { color: #666; font-size: 9pt; }
table { border-collapse: collapse; width: 100%; font-size: 9pt; }
th { background: #f3f3f3; text-align: left; padding: 6px; border-bottom: 1px solid #ccc; }
td { padding: 6px; border-bottom: 1px solid #eee; vertical-align: top; }
.ok { color: #0f7b0f; font-weight: 600; } .bad { color: #c42b1c; font-weight: 600; } .warn { color: #9d5d00; font-weight: 600; }
.box { background: #f6f8fa; border: 1px solid #e1e4e8; border-radius: 6px; padding: 10px 14px; }
"""


def _e(s) -> str:
    return html.escape(str(s))


def _header(title: str, engine_version: str = "") -> str:
    return (f"<html><head><meta charset='utf-8'><style>{CSS}</style><title>{_e(title)}</title></head><body>"
            f"<h1>{_e(title)}</h1><p class='muted'>{APP_NAME} {__version__} · {_e(engine_version)} · "
            f"{_e(platform.node())} · {_e(platform.platform())} · {time.strftime('%d.%m.%Y %H:%M')}</p>")


def scan_report(stats, kind_ru: str, engine_version: str = "", db_text: str = "") -> str:
    threats = [d for d in stats.detections if d.kind == "threat"]
    susp = [d for d in stats.detections if d.kind != "threat"]
    state = "прервано" if stats.cancelled else "завершено"
    cls = "bad" if threats else "warn" if susp else "ok"
    verdict = (f"Найдено угроз: {len(threats)}" if threats else f"Подозрительных объектов: {len(susp)}" if susp
               else "Угроз не обнаружено")
    h = _header(f"Отчёт о сканировании", engine_version)
    h += (f"<div class='box'><p class='{cls}'>{_e(verdict)}</p>"
          f"<p>Тип: {_e(kind_ru)} сканирование ({state})<br>"
          f"Начало: {time.strftime('%d.%m.%Y %H:%M:%S', time.localtime(stats.started))}<br>"
          f"Длительность: {int(stats.elapsed)} с<br>Проверено файлов: {stats.scanned} · пропущено: {stats.skipped} · "
          f"ошибок доступа: {stats.errors}<br>{_e(db_text)}</p></div>")
    if stats.detections:
        h += "<h2>Обнаруженные объекты</h2><table><tr><th>Файл</th><th>Угроза</th><th>Описание</th><th>Опасность</th><th>Действие</th></tr>"
        for d in stats.detections:
            ti = describe(d.name)
            h += (f"<tr><td>{_e(d.path)}</td><td>{_e(d.name)}</td><td>{_e(ti.category)}: {_e(ti.description)}</td>"
                  f"<td>{_e(ti.danger_ru)}</td><td>{_e(d.action)}</td></tr>")
        h += "</table>"
    return h + "</body></html>"


def journal_report(events, title: str = "Журнал угроз", engine_version: str = "") -> str:
    h = _header(title, engine_version)
    kinds = {"threat": "Угроза", "suspicious": "Подозрительный", "scan": "Сканирование", "update": "Обновление",
             "info": "Информация"}
    th = sum(e.kind == "threat" for e in events)
    su = sum(e.kind == "suspicious" for e in events)
    h += f"<div class='box'>Событий: {len(events)} · угроз: {th} · подозрительных: {su}</div>"
    h += "<h2>События</h2><table><tr><th>Время</th><th>Тип</th><th>Объект / событие</th><th>Угроза</th><th>Действие</th></tr>"
    for e in events:
        h += (f"<tr><td>{time.strftime('%d.%m.%Y %H:%M', time.localtime(e.ts))}</td><td>{_e(kinds.get(e.kind, e.kind))}</td>"
              f"<td>{_e(e.path or e.details)}</td><td>{_e(e.threat)}</td><td>{_e(e.action)}</td></tr>")
    return h + "</table></body></html>"


def posture_report(checks) -> str:
    h = _header("Проверка безопасности системы")
    h += "<table><tr><th>Параметр</th><th>Состояние</th><th>Рекомендация</th></tr>"
    for c in checks:
        cls = {"ok": "ok", "warn": "warn", "bad": "bad"}.get(c.status, "muted")
        h += f"<tr><td>{_e(c.title)}</td><td class='{cls}'>{_e(c.detail)}</td><td>{_e(c.advice)}</td></tr>"
    return h + "</table></body></html>"


def save(html_text: str, target: str | Path) -> Path:
    """Сохраняет .html или .pdf (PDF через Qt, нужен QGuiApplication)."""
    target = Path(target)
    if target.suffix.lower() == ".pdf":
        from PySide6.QtCore import QMarginsF, QSizeF
        from PySide6.QtGui import QPageLayout, QPageSize, QPdfWriter, QTextDocument
        w = QPdfWriter(str(target))
        w.setPageSize(QPageSize(QPageSize.A4))
        w.setPageMargins(QMarginsF(12, 12, 12, 12), QPageLayout.Millimeter)
        w.setResolution(120)
        doc = QTextDocument()
        doc.setHtml(html_text)
        doc.setPageSize(QSizeF(w.width(), w.height()))
        doc.print_(w)
    else:
        target.write_text(html_text, encoding="utf-8")
    return target
