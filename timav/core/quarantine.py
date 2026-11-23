"""Карантин: файл перемещается в защищённое хранилище в обфусцированном виде (XOR),
чтобы его нельзя было случайно запустить. Поддерживается восстановление и удаление."""
from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path

from timav.core import paths

KEY = bytes(range(0x5A, 0x5A + 32))
CHUNK = 1 << 20


def _xor(data: bytes, offset: int) -> bytes:
    if not data:
        return data
    n = len(KEY)
    start = offset % n
    stream = (KEY * (len(data) // n + 2))[start:start + len(data)]
    x = int.from_bytes(data, "big") ^ int.from_bytes(stream, "big")
    return x.to_bytes(len(data), "big")


@dataclass
class QuarantineItem:
    id: str
    original_path: str
    threat: str
    sha256: str
    size: int
    ts: float


class Quarantine:
    def __init__(self, root: Path | None = None):
        self.root = root or paths.quarantine_dir()
        self.root.mkdir(parents=True, exist_ok=True)

    def _meta(self, qid: str) -> Path:
        return self.root / f"{qid}.json"

    def _blob(self, qid: str) -> Path:
        return self.root / f"{qid}.qbin"

    def add(self, path: str | Path, threat: str) -> QuarantineItem:
        src = Path(path)
        qid = uuid.uuid4().hex
        h = hashlib.sha256()
        size = 0
        blob = self._blob(qid)
        with open(src, "rb") as fi, open(blob, "wb") as fo:
            while True:
                buf = fi.read(CHUNK)
                if not buf:
                    break
                h.update(buf)
                fo.write(_xor(buf, size))
                size += len(buf)
        item = QuarantineItem(qid, str(src), threat, h.hexdigest(), size, time.time())
        self._meta(qid).write_text(json.dumps(asdict(item), ensure_ascii=False), encoding="utf-8")
        try:
            os.chmod(src, 0o666)
            src.unlink()
        except OSError:
            blob.unlink(missing_ok=True)
            self._meta(qid).unlink(missing_ok=True)
            raise
        return item

    def list(self) -> list[QuarantineItem]:
        items = []
        for m in self.root.glob("*.json"):
            try:
                items.append(QuarantineItem(**json.loads(m.read_text(encoding="utf-8"))))
            except (OSError, ValueError, TypeError):
                continue
        return sorted(items, key=lambda i: i.ts, reverse=True)

    def restore(self, qid: str, target: str | Path | None = None) -> Path:
        meta = json.loads(self._meta(qid).read_text(encoding="utf-8"))
        dst = Path(target or meta["original_path"])
        dst.parent.mkdir(parents=True, exist_ok=True)
        if dst.exists():
            dst = dst.with_name(dst.stem + "_restored" + dst.suffix)
        off = 0
        with open(self._blob(qid), "rb") as fi, open(dst, "wb") as fo:
            while True:
                buf = fi.read(CHUNK)
                if not buf:
                    break
                fo.write(_xor(buf, off))
                off += len(buf)
        self.delete(qid)
        return dst

    def delete(self, qid: str) -> None:
        self._blob(qid).unlink(missing_ok=True)
        self._meta(qid).unlink(missing_ok=True)

    def count(self) -> int:
        return len(list(self.root.glob("*.json")))
