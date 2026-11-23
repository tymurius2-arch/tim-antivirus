"""Генерирует timav/resources/app.ico (многоразмерный) и installer/wizard-картинки."""
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from PySide6.QtCore import QBuffer, QByteArray, QIODevice  # noqa: E402
from PySide6.QtGui import QGuiApplication  # noqa: E402

app = QGuiApplication([])
from timav.app import render_icon  # noqa: E402

res = ROOT / "timav" / "resources"
res.mkdir(parents=True, exist_ok=True)
sizes = [16, 24, 32, 48, 64, 128, 256]
pngs = []
for s in sizes:
    ba = QByteArray()
    buf = QBuffer(ba)
    buf.open(QIODevice.WriteOnly)
    render_icon(s).save(buf, "PNG")
    pngs.append(bytes(ba))
# ICO-контейнер с PNG-кадрами
header = struct.pack("<HHH", 0, 1, len(sizes))
offset = 6 + 16 * len(sizes)
entries, data = b"", b""
for s, png in zip(sizes, pngs):
    entries += struct.pack("<BBBBHHII", s % 256, s % 256, 0, 0, 1, 32, len(png), offset + len(data))
    data += png
(res / "app.ico").write_bytes(header + entries + data)
render_icon(256).save(str(res / "app.png"))
print("ok", res / "app.ico")
