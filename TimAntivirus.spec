# -*- mode: python ; coding: utf-8 -*-
# Сборка: .venv\Scripts\pyinstaller TimAntivirus.spec --noconfirm
from pathlib import Path

ROOT = Path(SPECPATH)

EXCLUDE_QT = [
    "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets", "PySide6.QtWebEngineQuick", "PySide6.QtQuick",
    "PySide6.QtQml", "PySide6.QtQuick3D", "PySide6.Qt3DCore", "PySide6.Qt3DRender", "PySide6.QtMultimedia",
    "PySide6.QtCharts", "PySide6.QtDataVisualization", "PySide6.QtPdf", "PySide6.QtSql", "PySide6.QtTest",
    "PySide6.QtDesigner", "PySide6.QtBluetooth", "PySide6.QtPositioning", "PySide6.QtLocation",
    "PySide6.QtSerialPort", "PySide6.QtSensors", "PySide6.QtWebSockets", "PySide6.QtOpenGL",
    "PySide6.QtSpatialAudio", "PySide6.QtGraphs", "PySide6.QtHttpServer",
]

a = Analysis(
    [str(ROOT / "timav" / "__main__.py")],
    pathex=[str(ROOT)],
    datas=[(str(ROOT / "timav" / "resources"), "timav/resources")],
    hiddenimports=["watchdog.observers.read_directory_changes", "anthropic"],
    excludes=EXCLUDE_QT + ["tkinter", "pytest", "PyInstaller"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name="TimAntivirus",
    icon=str(ROOT / "timav" / "resources" / "app.ico"),
    console=False,
    version=str(ROOT / "installer" / "version_info.txt"),
    upx=False,
)
coll = COLLECT(exe, a.binaries, a.datas, name="TimAntivirus", upx=False)
