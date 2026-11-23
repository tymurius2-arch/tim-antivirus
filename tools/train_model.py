"""Обучение Random Forest на ClaMP_Raw-5184.csv и экспорт в timav/resources/pe_model.json.

Источник данных: https://github.com/urwithajit9/ClaMP (только числовые признаки PE-заголовков,
сами вредоносные файлы не скачиваются). Дополнительно проверяется доля ложных срабатываний
на заведомо чистых подписанных файлах этого компьютера.
"""
import csv
import glob
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import numpy as np  # noqa: E402
import pefile  # noqa: E402
from sklearn.ensemble import RandomForestClassifier  # noqa: E402
from sklearn.model_selection import cross_val_score, train_test_split  # noqa: E402
from sklearn.metrics import classification_report  # noqa: E402

from timav.core.ml_model import FEATURES, ForestModel, extract  # noqa: E402


def load():
    X, y = [], []
    with open(ROOT / "data" / "ClaMP_Raw-5184.csv", newline="") as f:
        for row in csv.DictReader(f):
            X.append([float(row[n] or 0) for n in FEATURES])
            y.append(int(row["class"]))
    return np.array(X), np.array(y)


def local_benign(limit=400):
    pats = [r"C:\Windows\System32\*.exe", r"C:\Windows\SysWOW64\*.exe", r"C:\Program Files\*\*.exe",
            r"C:\Program Files (x86)\*\*.exe", r"C:\Program Files\*\*\*.exe"]
    out = []
    for p in pats:
        for fn in glob.glob(p)[:limit]:
            try:
                pe = pefile.PE(fn, fast_load=True)
                out.append((fn, pe.OPTIONAL_HEADER.Magic, extract(pe)))
                pe.close()
            except Exception:
                pass
    return out


def export(clf) -> dict:
    trees = []
    for est in clf.estimators_:
        t = est.tree_
        v = t.value[:, 0, :]
        prob = (v[:, 1] / v.sum(axis=1)).round(4)
        trees.append({"f": t.feature.tolist(), "t": [round(float(x), 4) for x in t.threshold],
                      "l": t.children_left.tolist(), "r": t.children_right.tolist(), "v": prob.tolist()})
    return {"features": FEATURES, "trees": trees}


def main():
    X, y = load()
    print("датасет:", X.shape, "вредоносных:", int(y.sum()))
    clf = RandomForestClassifier(n_estimators=60, max_depth=12, min_samples_leaf=3, random_state=7, n_jobs=-1)
    cv = cross_val_score(clf, X, y, cv=5, scoring="accuracy")
    print(f"5-fold CV accuracy: {cv.mean():.4f} ± {cv.std():.4f}")
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=1, stratify=y)
    clf.fit(Xtr, ytr)
    print(classification_report(yte, clf.predict(Xte), target_names=["benign", "malware"], digits=3))
    clf.fit(X, y)
    data = export(clf)
    m = ForestModel(data)
    # согласованность экспорта со sklearn
    diff = max(abs(m.predict_proba(list(x)) - p) for x, p in zip(X[:300], clf.predict_proba(X[:300])[:, 1]))
    print("макс. расхождение экспорта:", round(diff, 6))
    ben = local_benign()
    stats = {}
    for fn, magic, x in ben:
        p = m.predict_proba(x)
        k = "PE32+" if magic == 0x20B else "PE32"
        s = stats.setdefault(k, [0, 0])
        s[0] += 1
        s[1] += p >= 0.5
    for k, (n, fp) in stats.items():
        print(f"локальные чистые {k}: {n} файлов, ложных срабатываний (p>=0.5): {fp} ({fp / max(n, 1):.1%})")
    data["meta"] = {"dataset": "ClaMP_Raw-5184", "cv_accuracy": round(float(cv.mean()), 4),
                    "local_fp": {k: round(fp / max(n, 1), 4) for k, (n, fp) in stats.items()}}
    out = ROOT / "timav" / "resources" / "pe_model.json"
    out.write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")
    print("сохранено", out, f"{out.stat().st_size / 1024:.0f} КБ")


if __name__ == "__main__":
    main()
