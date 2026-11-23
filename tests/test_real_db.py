"""Проверка официальных баз ClamAV на тестовой строке EICAR.

EICAR собирается в памяти и передаётся в clamd потоком (INSTREAM) — на диск ничего не пишется,
поэтому Microsoft Defender не реагирует. Запуск: pytest tests/test_real_db.py -m realdb
"""
import os
from pathlib import Path

import pytest

from timav.core import paths
from timav.core.clamav import ClamAVEngine

REAL_DB = Path(os.environ.get("LOCALAPPDATA", "")) / "TimAntivirus" / "db"
pytestmark = [pytest.mark.realdb,
              pytest.mark.skipif(paths.clamav_dir() is None or not (REAL_DB / "daily.cvd").exists()
                                 and not (REAL_DB / "daily.cld").exists(), reason="нет ClamAV или баз")]


def eicar() -> bytes:
    parts = ["X5O!P%@AP[4\\PZX54(P^)7CC)7}$", "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"]
    return "".join(parts).encode()


def test_eicar_detected_by_official_db():
    eng = ClamAVEngine(db=REAL_DB, port=33196)
    try:
        assert eng.start_daemon(wait=240), "clamd не загрузил базы"
        v = eng.scan_bytes(eicar(), "eicar")
        assert v.infected, v
        assert "Eicar" in v.signature
        assert eng.scan_bytes(b"just some harmless bytes" * 100).status == "clean"
    finally:
        eng.stop_daemon()
