"""ML-модель (Random Forest), обученная на открытом датасете ClaMP (5184 PE-файла: 2722 вредоносных,
2488 чистых; признаки заголовков PE). Обучение — tools/train_model.py, веса — resources/pe_model.json.
Инференс на чистом Python, без scikit-learn в сборке."""
from __future__ import annotations

import json
import time
from functools import lru_cache

from timav.core import paths

FEATURES = [
    "e_cblp", "e_cp", "e_crlc", "e_cparhdr", "e_minalloc", "e_maxalloc", "e_ss", "e_sp", "e_csum", "e_ip",
    "e_cs", "e_lfarlc", "e_ovno", "e_oemid", "e_oeminfo", "e_lfanew", "Machine", "NumberOfSections",
    "CreationYear", "PointerToSymbolTable", "NumberOfSymbols", "SizeOfOptionalHeader", "Characteristics",
    "Magic", "MajorLinkerVersion", "MinorLinkerVersion", "SizeOfCode", "SizeOfInitializedData",
    "SizeOfUninitializedData", "AddressOfEntryPoint", "BaseOfCode", "BaseOfData", "ImageBase",
    "SectionAlignment", "FileAlignment", "MajorOperatingSystemVersion", "MinorOperatingSystemVersion",
    "MajorImageVersion", "MinorImageVersion", "MajorSubsystemVersion", "MinorSubsystemVersion", "SizeOfImage",
    "SizeOfHeaders", "CheckSum", "Subsystem", "DllCharacteristics", "SizeOfStackReserve", "SizeOfStackCommit",
    "SizeOfHeapReserve", "SizeOfHeapCommit", "LoaderFlags", "NumberOfRvaAndSizes",
]


def extract(pe) -> list[float]:
    """Признаки в том же виде, что в ClaMP_Raw (pefile.PE)."""
    d, f, o = pe.DOS_HEADER, pe.FILE_HEADER, pe.OPTIONAL_HEADER
    year = time.gmtime(f.TimeDateStamp).tm_year if f.TimeDateStamp else 1970
    vals = {
        "e_cblp": d.e_cblp, "e_cp": d.e_cp, "e_crlc": d.e_crlc, "e_cparhdr": d.e_cparhdr,
        "e_minalloc": d.e_minalloc, "e_maxalloc": d.e_maxalloc, "e_ss": d.e_ss, "e_sp": d.e_sp,
        "e_csum": d.e_csum, "e_ip": d.e_ip, "e_cs": d.e_cs, "e_lfarlc": d.e_lfarlc, "e_ovno": d.e_ovno,
        "e_oemid": d.e_oemid, "e_oeminfo": d.e_oeminfo, "e_lfanew": d.e_lfanew, "Machine": f.Machine,
        "NumberOfSections": f.NumberOfSections, "CreationYear": year,
        "PointerToSymbolTable": f.PointerToSymbolTable, "NumberOfSymbols": f.NumberOfSymbols,
        "SizeOfOptionalHeader": f.SizeOfOptionalHeader, "Characteristics": f.Characteristics,
        "BaseOfData": getattr(o, "BaseOfData", 0),
    }
    for name in FEATURES:
        if name not in vals:
            vals[name] = getattr(o, name, 0)
    return [float(vals[n]) for n in FEATURES]


class ForestModel:
    def __init__(self, data: dict):
        self.features = data["features"]
        self.trees = data["trees"]
        self.meta = data.get("meta", {})

    def predict_proba(self, x: list[float]) -> float:
        total = 0.0
        for t in self.trees:
            node = 0
            feat, thr, left, right, val = t["f"], t["t"], t["l"], t["r"], t["v"]
            while left[node] != -1:
                node = left[node] if x[feat[node]] <= thr[node] else right[node]
            total += val[node]
        return total / len(self.trees)


@lru_cache(maxsize=1)
def load_model() -> ForestModel | None:
    p = paths.resource_dir() / "pe_model.json"
    try:
        return ForestModel(json.loads(p.read_text(encoding="utf-8")))
    except (OSError, ValueError, KeyError):
        return None


def predict(pe) -> float | None:
    m = load_model()
    if m is None:
        return None
    try:
        return m.predict_proba(extract(pe))
    except Exception:
        return None
