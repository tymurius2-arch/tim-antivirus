"""Проверка файла в VirusTotal по SHA-256 (сам файл не отправляется)."""
from __future__ import annotations

import json
import urllib.error
import urllib.request

API = "https://www.virustotal.com/api/v3/files/"


def lookup(sha256: str, api_key: str, timeout: float = 20) -> dict:
    req = urllib.request.Request(API + sha256, headers={"x-apikey": api_key.strip(), "User-Agent": "TimAntivirus/1.1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"found": False, "message": "Файл не встречался VirusTotal"}
        if e.code in (401, 403):
            return {"error": "Неверный API-ключ VirusTotal"}
        if e.code == 429:
            return {"error": "Превышен лимит VirusTotal (бесплатно — 4 запроса в минуту)"}
        return {"error": f"Ошибка VirusTotal: HTTP {e.code}"}
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {"error": f"Нет соединения с VirusTotal: {e}"}
    return parse(data, sha256)


def parse(data: dict, sha256: str) -> dict:
    a = data.get("data", {}).get("attributes", {})
    st = a.get("last_analysis_stats", {})
    results = a.get("last_analysis_results", {})
    names = sorted({v.get("result") for v in results.values()
                    if v.get("category") in ("malicious", "suspicious") and v.get("result")})
    engines = [(k, v.get("result")) for k, v in results.items() if v.get("category") == "malicious"]
    total = sum(st.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected"))
    return {
        "found": True, "malicious": st.get("malicious", 0), "suspicious": st.get("suspicious", 0),
        "harmless": st.get("harmless", 0), "undetected": st.get("undetected", 0), "total": total,
        "names": names[:12], "engines": engines[:15], "label": (a.get("popular_threat_classification") or {}).get(
            "suggested_threat_label", ""),
        "first_seen": a.get("first_submission_date"), "type": a.get("type_description", ""),
        "link": f"https://www.virustotal.com/gui/file/{sha256}",
    }
