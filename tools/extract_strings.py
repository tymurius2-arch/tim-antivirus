"""Сбор строк для перевода (через ast, склеенные литералы учитываются).

1. Первый аргумент каждого вызова tr("…").
2. Фиксированные строки ядра, которые переводятся позже через tr(переменная): описания угроз,
   проверки системы, признаки AI-анализа, сообщения обновлений, VirusTotal, автозагрузки.
"""
import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CYR = re.compile("[А-Яа-яЁё]")
DATA_MODULES = {"posture.py", "threat_info.py", "ai_analyzer.py", "updater.py", "virustotal.py", "autoruns.py",
                "downloads.py"}
SKIP = {"Выполняемая задача", "Задача для выполнения", "Состояние назначенного задания", "ОБРАБОТЧИК COM",
        "отключено", "отказалась"}


def _docstrings(tree) -> set[int]:
    ids = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)):
            if node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant):
                ids.add(id(node.body[0].value))
    return ids


def collect() -> list[str]:
    out: list[str] = []
    for f in sorted((ROOT / "timav").rglob("*.py")):
        if f.name.startswith("i18n"):
            continue
        tree = ast.parse(f.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "tr" and node.args:
                a = node.args[0]
                if isinstance(a, ast.Constant) and isinstance(a.value, str) and CYR.search(a.value):
                    if a.value not in out:
                        out.append(a.value)
        if f.name in DATA_MODULES:
            docs = _docstrings(tree)
            skip_nodes = set()
            for node in ast.walk(tree):     # промпт для Claude не переводим
                if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "CLOUD_SYSTEM" for t in node.targets):
                    skip_nodes |= {id(n) for n in ast.walk(node)}
                if isinstance(node, ast.JoinedStr):
                    skip_nodes |= {id(n) for n in ast.walk(node)}
            for node in ast.walk(tree):
                if (isinstance(node, ast.Constant) and isinstance(node.value, str) and CYR.search(node.value)
                        and id(node) not in docs and id(node) not in skip_nodes and node.value not in SKIP
                        and "\n" not in node.value and node.value not in out):
                    out.append(node.value)
    return out


def missing() -> list[str]:
    sys.path.insert(0, str(ROOT))
    from timav.i18n_en import EN
    return [s for s in collect() if s not in EN]


if __name__ == "__main__":
    m = missing()
    for s in m:
        print(repr(s))
    print(len(m), file=sys.stderr)
