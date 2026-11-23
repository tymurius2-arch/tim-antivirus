import hashlib
import os
import sys
from pathlib import Path

import pytest

# не подключаться к clamd запущенного у пользователя Tim Antivirus (порт 33110)
os.environ["TIMAV_CLAMD_PORT"] = "33190"

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True)
def data_dir(tmp_path, monkeypatch):
    d = tmp_path / "appdata"
    d.mkdir()
    monkeypatch.setenv("TIMAV_DATA_DIR", str(d))
    return d


@pytest.fixture
def sample(tmp_path):
    """Безопасный «вредонос»: случайные байты + собственная тестовая сигнатура в .hdb."""
    f = tmp_path / "victim" / "malware_sample.bin"
    f.parent.mkdir()
    payload = b"TIM-ANTIVIRUS-TEST-PAYLOAD-" + os.urandom(2048)
    f.write_bytes(payload)
    db = tmp_path / "db"
    db.mkdir()
    md5 = hashlib.md5(payload).hexdigest()
    (db / "tim_test.hdb").write_text(f"{md5}:{len(payload)}:Tim.Test.Signature\n")
    clean = f.parent / "clean.txt"
    clean.write_text("hello world " * 100)
    return {"file": f, "clean": clean, "db": db, "dir": f.parent}
