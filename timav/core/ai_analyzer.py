"""AI-анализ подозрительных файлов.

1. Локальная модель: извлечение ~30 статических признаков (энтропия, структура PE, импорты,
   строки, расположение, двойные расширения, обфускация скриптов) и логистическая модель,
   дающая вероятность вредоносности. Работает офлайн, файл никуда не отправляется.
2. Облачный анализ (по желанию): признаки и выборка строк (не сам файл) отправляются в
   Claude API, который возвращает развёрнутое заключение на русском языке.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from timav.i18n import tr

try:
    import pefile  # type: ignore
except ImportError:  # pragma: no cover
    pefile = None

EXEC_EXT = {".exe", ".dll", ".scr", ".sys", ".com", ".cpl", ".ocx", ".msi", ".pif"}
SCRIPT_EXT = {".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".bat", ".cmd", ".hta", ".lnk"}
DOC_EXT = {".doc", ".docm", ".xls", ".xlsm", ".pptm", ".rtf", ".pdf"}
DECOY_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt", ".mp4", ".zip"}

SUSPICIOUS_IMPORTS = {
    "VirtualAllocEx": 1.0, "WriteProcessMemory": 1.2, "CreateRemoteThread": 1.4, "NtUnmapViewOfSection": 1.4,
    "SetWindowsHookExA": 0.8, "SetWindowsHookExW": 0.8, "GetAsyncKeyState": 0.7, "URLDownloadToFileA": 1.0,
    "URLDownloadToFileW": 1.0, "IsDebuggerPresent": 0.3, "CheckRemoteDebuggerPresent": 0.5,
    "AdjustTokenPrivileges": 0.5, "OpenProcess": 0.3, "QueueUserAPC": 0.9, "SetThreadContext": 1.0,
    "CryptEncrypt": 0.4, "InternetOpenUrlA": 0.4, "InternetOpenUrlW": 0.4, "WinExec": 0.6,
    "ShellExecuteA": 0.2, "RegSetValueExA": 0.2, "RegSetValueExW": 0.2, "MiniDumpWriteDump": 1.0,
}
PACKER_SECTIONS = {"upx0", "upx1", ".aspack", ".adata", ".nsp0", ".nsp1", "mpress1", ".petite", ".themida",
                   ".vmp0", ".vmp1", ".enigma1", "pec2", ".mpress"}

STRING_PATTERNS = {
    "powershell_enc": (re.compile(rb"powershell[^\n]{0,60}-(e|en|enc|encodedcommand)\b", re.I), 1.6),
    "invoke_expr": (re.compile(rb"\b(Invoke-Expression|IEX)\b\s*[\(\$]", re.I), 1.2),
    "from_base64": (re.compile(rb"FromBase64String", re.I), 0.8),
    "download_cradle": (re.compile(rb"(DownloadString|DownloadFile|Net\.WebClient|Invoke-WebRequest)", re.I), 1.0),
    "run_key": (re.compile(rb"Software\\Microsoft\\Windows\\CurrentVersion\\Run", re.I), 0.9),
    "shadow_delete": (re.compile(rb"vssadmin(\.exe)?\s+delete\s+shadows", re.I), 2.0),
    "bcdedit_recovery": (re.compile(rb"bcdedit[^\n]{0,40}recoveryenabled\s+no", re.I), 1.8),
    "defender_tamper": (re.compile(rb"(Set-MpPreference[^\n]{0,60}Disable|DisableAntiSpyware|DisableRealtimeMonitoring)", re.I), 1.8),
    "wscript_shell": (re.compile(rb"WScript\.Shell", re.I), 0.6),
    "eval_obf": (re.compile(rb"eval\s*\(\s*(unescape|atob|String\.fromCharCode)", re.I), 1.2),
    "ransom_note": (re.compile(rb"(all )?your (important |personal )?files (have been|are|were) encrypted", re.I), 1.4),
    "btc_wallet": (re.compile(rb"\b(bc1|[13])[a-km-zA-HJ-NP-Z1-9]{25,39}\b"), 0.5),
    "mimikatz": (re.compile(rb"(sekurlsa|mimikatz|lsadump::)", re.I), 2.2),
    "raw_ip_url": (re.compile(rb"https?://\d{1,3}(\.\d{1,3}){3}"), 0.7),
    "telegram_api": (re.compile(rb"api\.telegram\.org/bot", re.I), 0.9),
    "discord_webhook": (re.compile(rb"discord(app)?\.com/api/webhooks", re.I), 1.0),
    "browser_creds": (re.compile(rb"(Login Data|Local State|cookies\.sqlite|logins\.json)", re.I), 0.7),
    "long_b64": (re.compile(rb"[A-Za-z0-9+/]{400,}={0,2}"), 0.6),
}

TEXT_ONLY_PATTERNS = {"btc_wallet", "long_b64"}
# ключевые слова (в нижнем регистре), без которых шаблон заведомо не совпадёт
PREFILTER = {
    "powershell_enc": [b"powershell"], "invoke_expr": [b"iex", b"invoke-expression"],
    "from_base64": [b"frombase64string"],
    "download_cradle": [b"downloadstring", b"downloadfile", b"net.webclient", b"invoke-webrequest"],
    "run_key": [b"currentversion\\run"], "shadow_delete": [b"vssadmin"], "bcdedit_recovery": [b"bcdedit"],
    "defender_tamper": [b"set-mppreference", b"disableantispyware", b"disablerealtimemonitoring"],
    "wscript_shell": [b"wscript.shell"], "eval_obf": [b"eval"], "ransom_note": [b"encrypted"],
    "mimikatz": [b"sekurlsa", b"mimikatz", b"lsadump::"], "raw_ip_url": [b"http"],
    "telegram_api": [b"api.telegram.org"], "discord_webhook": [b"/api/webhooks"],
    "browser_creds": [b"login data", b"local state", b"cookies.sqlite", b"logins.json"],
}

# Веса логистической модели (подобраны экспертно; bias смещает модель к «чистому» классу).
BIAS = -4.2
WEIGHTS = {
    "trusted_signature": -4.0, "invalid_signature": 1.5, "installer": -0.8, "trusted_publisher": -6.0,
    "ml_model": 2.5,
    "high_entropy": 1.3, "very_high_entropy": 1.0, "packer_section": 1.6, "wx_section": 1.1,
    "few_imports": 0.9, "no_imports": 1.3, "susp_imports": 1.0, "no_signature": 0.6, "has_overlay": 0.4,
    "tls_callbacks": 0.4, "bad_timestamp": 0.5, "checksum_mismatch": 0.2, "strings": 1.0,
    "double_ext": 2.4, "temp_location": 0.7, "startup_location": 1.0, "script_type": 0.5,
    "hidden_attr": 0.6, "tiny_exe": 0.4, "entry_outside_code": 1.2, "macro_doc": 0.9,
}


@dataclass
class Indicator:
    name: str
    description: str
    weight: float


@dataclass
class AnalysisReport:
    path: str
    sha256: str
    size: int
    file_type: str
    entropy: float
    score: float                      # 0..1 вероятность вредоносности
    verdict: str                      # clean | low | suspicious | malicious
    indicators: list[Indicator] = field(default_factory=list)
    strings_sample: list[str] = field(default_factory=list)
    pe_info: dict = field(default_factory=dict)
    cloud: dict | None = None

    @property
    def verdict_ru(self) -> str:
        return tr({"clean": "Чистый", "low": "Низкий риск", "suspicious": "Подозрительный",
                   "malicious": "Вероятно вредоносный"}[self.verdict])

    def to_features(self) -> dict:
        return {
            "file_name": Path(self.path).name, "size": self.size, "sha256": self.sha256,
            "type": self.file_type, "entropy": round(self.entropy, 3), "local_score": round(self.score, 3),
            "indicators": [i.description for i in self.indicators], "pe": self.pe_info,
            "strings_sample": self.strings_sample[:60],
        }


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def _fast_entropy(data: bytes) -> float:
    # быстрый подсчёт через bytes.count; для больших буферов — по выборке до 2 МБ
    if len(data) < 4096:
        return shannon_entropy(data)
    if len(data) > 2 * 1024 * 1024:
        step = len(data) // 32
        data = b"".join(data[i:i + 65536] for i in range(0, len(data), step))
    n = len(data)
    ent = 0.0
    for b in range(256):
        c = data.count(bytes((b,)))
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def _printable_strings(data: bytes, min_len: int = 6, limit: int = 400) -> list[str]:
    out = []
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data):
        out.append(m.group().decode("ascii", "replace")[:200])
        if len(out) >= limit:
            break
    return out


class LocalAnalyzer:
    """Статический анализатор + логистическая модель."""

    READ_LIMIT = 8 * 1024 * 1024

    def __init__(self, trusted_publishers: list[str] | None = None):
        from timav.core.signer import DEFAULT_TRUSTED
        self.trusted = DEFAULT_TRUSTED if trusted_publishers is None else trusted_publishers

    def analyze(self, path: str | Path, quick: bool = False) -> AnalysisReport:
        """quick=True — для фоновых проверок: без SHA-256 всего файла и выборки строк."""
        path = Path(path)
        size = path.stat().st_size
        with open(path, "rb") as f:
            data = f.read(self.READ_LIMIT)
        sha = hashlib.sha256()
        if not quick:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    sha.update(chunk)
        ext = path.suffix.lower()
        is_pe = data[:2] == b"MZ"
        ftype = "PE (исполняемый)" if is_pe else ("скрипт" if ext in SCRIPT_EXT else
                                                  "документ" if ext in DOC_EXT else "данные")
        entropy = _fast_entropy(data)
        feats: dict[str, float] = {}
        inds: list[Indicator] = []
        pe_info: dict = {}

        def hit(name: str, desc: str, value: float = 1.0):
            feats[name] = feats.get(name, 0.0) + value
            inds.append(Indicator(name, desc, WEIGHTS.get(name, 1.0) * value))

        if is_pe:
            pe_info = self._pe_features(path, data, hit, size)
            if pe_info.get("installer"):
                # установщики и самораспаковывающиеся архивы сжаты — высокая энтропия для них норма
                hit("installer", tr("Похоже на установщик / самораспаковывающийся архив (сжатые данные в оверлее)"))
            else:
                if entropy > 7.2:
                    hit("high_entropy", tr("Высокая энтропия файла ({e}) — возможна упаковка/шифрование", e=f"{entropy:.2f}"))
                if entropy > 7.7:
                    hit("very_high_entropy", tr("Энтропия близка к максимальной"))
            if size < 20 * 1024:
                hit("tiny_exe", tr("Очень маленький исполняемый файл (часто загрузчик)"))
        elif ext in DOC_EXT and (b"vbaProject" in data or b"VBA" in data[:200000] and b"Auto" in data):
            hit("macro_doc", tr("Документ содержит макросы VBA"))

        if ext in SCRIPT_EXT:
            hit("script_type", tr("Исполняемый скрипт ({x})", x=ext))

        # строки
        str_score = 0.0
        data_l = data.lower()
        for key, (rx, w) in STRING_PATTERNS.items():
            if is_pe and key in TEXT_ONLY_PATTERNS:
                continue  # в больших бинарниках такие последовательности встречаются случайно
            tokens = PREFILTER.get(key)
            if tokens and not any(t in data_l for t in tokens):
                continue  # дешёвая проверка: без ключевого слова регулярное выражение не нужно
            if rx.search(data):
                str_score += w
                inds.append(Indicator(key, tr(_STRING_DESC.get(key, key)), w * WEIGHTS["strings"]))
        if str_score:
            feats["strings"] = str_score

        # имя и расположение
        name = path.name.lower()
        parts = name.split(".")
        if len(parts) >= 3 and "." + parts[-2] in DECOY_EXT and "." + parts[-1] in (EXEC_EXT | SCRIPT_EXT):
            hit("double_ext", tr("Двойное расширение «{x}» — маскировка под документ", x=f".{parts[-2]}.{parts[-1]}"))
        low = str(path).lower()
        if "\\temp\\" in low or "\\appdata\\local\\temp" in low:
            if is_pe or ext in SCRIPT_EXT:
                hit("temp_location", tr("Исполняемый файл во временной папке"))
        if "\\start menu\\programs\\startup" in low:
            hit("startup_location", tr("Файл в папке автозагрузки"))
        try:
            import ctypes
            attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))
            if attrs != -1 and attrs & 0x2 and (is_pe or ext in SCRIPT_EXT):
                hit("hidden_attr", tr("Скрытый исполняемый файл"))
        except Exception:
            pass

        z = BIAS + sum(WEIGHTS.get(k, 1.0) * v for k, v in feats.items())
        score = 1 / (1 + math.exp(-z))
        verdict = "clean" if score < 0.2 else "low" if score < 0.5 else "suspicious" if score < 0.8 else "malicious"
        strings = [] if quick else [s for s in _printable_strings(data) if len(s) > 7][:120]
        return AnalysisReport(str(path), sha.hexdigest(), size, ftype, entropy, score, verdict,
                              sorted(inds, key=lambda i: -i.weight), strings, pe_info)

    def _pe_features(self, path: Path, data: bytes, hit, size: int | None = None) -> dict:
        info: dict = {}
        if pefile is None:
            return info
        try:
            pe = pefile.PE(data=data, fast_load=True)
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
            ])
        except Exception as e:
            info["error"] = f"некорректный PE: {e}"
            return info
        secs = []
        for s in pe.sections:
            nm = s.Name.rstrip(b"\0").decode("latin-1", "replace")
            ent = s.get_entropy()
            secs.append({"name": nm, "entropy": round(ent, 2), "size": s.SizeOfRawData})
            if nm.lower() in PACKER_SECTIONS:
                hit("packer_section", tr("Секция упаковщика «{n}»", n=nm))
            ch = s.Characteristics
            if ch & 0x20000000 and ch & 0x80000000:
                hit("wx_section", tr("Секция «{n}» одновременно исполняемая и записываемая", n=nm))
        info["sections"] = secs
        imports = []
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            for imp in entry.imports:
                if imp.name:
                    imports.append(imp.name.decode("latin-1", "replace"))
        info["imports_count"] = len(imports)
        if not imports:
            hit("no_imports", tr("Нет таблицы импорта (характерно для упакованных файлов)"))
        elif len(imports) < 10:
            hit("few_imports", tr("Мало импортируемых функций ({n})", n=len(imports)))
        susp = [i for i in imports if i in SUSPICIOUS_IMPORTS]
        if susp:
            val = min(3.0, sum(SUSPICIOUS_IMPORTS[i] for i in susp))
            hit("susp_imports", tr("Подозрительные API: ") + ", ".join(sorted(set(susp))[:8]), val)
        info["suspicious_imports"] = sorted(set(susp))
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        has_sig = bool(sec_dir.VirtualAddress and sec_dir.Size)
        from timav.core.signer import is_trusted, signature
        valid, signer = signature(str(path)) if has_sig else (False, "")
        info["signed"] = has_sig
        info["signature_valid"] = valid
        info["signer"] = signer
        if valid and is_trusted(signer, self.trusted):
            info["trusted"] = True
            hit("trusted_publisher", tr("Доверенный издатель: ") + signer)
        elif valid:
            hit("trusted_signature", tr("Действительная цифровая подпись Authenticode") + (f": {signer}" if signer else ""))
        elif has_sig:
            hit("invalid_signature", tr("Цифровая подпись есть, но недействительна или повреждена"))
        else:
            hit("no_signature", tr("Нет цифровой подписи Authenticode"))
        if hasattr(pe, "DIRECTORY_ENTRY_TLS") and pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks:
            hit("tls_callbacks", tr("TLS-callbacks (код до точки входа)"))
        overlay = pe.get_overlay_data_start_offset()
        full = size or len(data)
        if overlay and full:
            sig_len = sec_dir.Size if has_sig else 0
            ratio = max(0, full - overlay - sig_len) / full
            info["overlay_ratio"] = round(ratio, 3)
            info["installer"] = ratio > 0.5 and full > 512 * 1024
            if not has_sig and not info["installer"] and overlay < len(data) - 1024:
                hit("has_overlay", tr("Данные в оверлее после конца образа"))
        ts = pe.FILE_HEADER.TimeDateStamp
        info["timestamp"] = ts
        if ts and (ts < 631152000 or ts > 2000000000):
            hit("bad_timestamp", tr("Аномальная метка времени компиляции"))
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        ep_sec = next((s for s in pe.sections if s.contains_rva(ep)), None)
        if ep_sec is not None and not (ep_sec.Characteristics & 0x20):
            hit("entry_outside_code", tr("Точка входа вне секции кода"))
        elif ep_sec is not None and ep_sec.Name.rstrip(b"\0").lower() not in (b".text", b"code", b".code", b"text"):
            info["entry_section"] = ep_sec.Name.rstrip(b"\0").decode("latin-1", "replace")
        from timav.core.ml_model import predict
        p = predict(pe)
        if p is not None:
            info["ml_probability"] = round(p, 3)
            val = (p - 0.5) * 2
            feats_desc = tr("ML-модель (Random Forest, ClaMP): вероятность вредоносности {p}", p=f"{p:.0%}")
            hit("ml_model", feats_desc, val)
        info["is_dll"] = bool(pe.FILE_HEADER.Characteristics & 0x2000)
        info["machine"] = hex(pe.FILE_HEADER.Machine)
        pe.close()
        return info


from timav.core.signer import verify_signature  # noqa: E402,F401  (совместимость)


_STRING_DESC = {
    "powershell_enc": "Запуск PowerShell с закодированной командой",
    "invoke_expr": "Динамическое выполнение кода (Invoke-Expression)",
    "from_base64": "Декодирование Base64 во время выполнения",
    "download_cradle": "Загрузка данных из интернета",
    "run_key": "Обращение к ключу автозапуска реестра",
    "shadow_delete": "Удаление теневых копий (типично для шифровальщиков)",
    "bcdedit_recovery": "Отключение восстановления Windows",
    "defender_tamper": "Попытка отключить Microsoft Defender",
    "wscript_shell": "Использование WScript.Shell",
    "eval_obf": "Обфусцированный eval()",
    "ransom_note": "Текст, похожий на записку вымогателя",
    "btc_wallet": "Похоже на адрес Bitcoin-кошелька",
    "mimikatz": "Строки инструмента кражи паролей (Mimikatz)",
    "raw_ip_url": "URL с IP-адресом вместо домена",
    "telegram_api": "Отправка данных через Telegram Bot API",
    "discord_webhook": "Отправка данных через Discord webhook",
    "browser_creds": "Обращение к хранилищу паролей браузера",
    "long_b64": "Длинный блок Base64 (встроенная нагрузка)",
}


CLOUD_MODEL = "claude-opus-5-5"
CLOUD_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["clean", "low", "suspicious", "malicious"]},
        "risk_score": {"type": "integer"},
        "family_guess": {"type": "string"},
        "explanation": {"type": "string"},
        "recommendations": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["verdict", "risk_score", "family_guess", "explanation", "recommendations"],
    "additionalProperties": False,
}
CLOUD_SYSTEM = (
    "Ты — аналитик вредоносного ПО в антивирусе Tim Antivirus. Тебе передают результаты статического "
    "анализа файла (признаки, импорты, выборку строк) — не сам файл. Оцени риск, предположи семейство "
    "(или «неизвестно»), объясни выводы простым русским языком для обычного пользователя (3–6 предложений) "
    "и дай 2–4 практические рекомендации. Учитывай, что легитимные установщики и упакованные программы "
    "тоже бывают с высокой энтропией. risk_score — целое от 0 до 100."
)


def _lang() -> str:
    from timav import i18n
    return i18n.LANG


class CloudAnalyzer:
    """Глубокий анализ признаков через Claude API (официальный SDK anthropic)."""

    def __init__(self, api_key: str):
        self.api_key = api_key.strip()

    def analyze(self, report: AnalysisReport) -> dict:
        import anthropic

        client = anthropic.Anthropic(api_key=self.api_key or None, timeout=120.0)
        payload = json.dumps(report.to_features(), ensure_ascii=False)
        try:
            resp = client.beta.messages.create(
                model=CLOUD_MODEL,
                max_tokens=4000,
                betas=["server-side-fallback-2026-07-01"],
                fallbacks="default",
                system=CLOUD_SYSTEM + (" Answer in English." if _lang() == "en" else ""),
                output_config={"effort": "low",
                               "format": {"type": "json_schema", "schema": CLOUD_SCHEMA}},
                messages=[{"role": "user", "content": "Результаты статического анализа:\n" + payload}],
            )
        except anthropic.AuthenticationError:
            return {"error": "Неверный API-ключ Claude"}
        except anthropic.RateLimitError:
            return {"error": "Превышен лимит запросов, попробуйте позже"}
        except anthropic.APIStatusError as e:
            return {"error": f"Ошибка API ({e.status_code})"}
        except anthropic.APIConnectionError:
            return {"error": "Нет соединения с Claude API"}
        if resp.stop_reason == "refusal":
            return {"error": "Модель отказалась анализировать этот запрос"}
        text = "".join(getattr(b, "text", "") for b in resp.content if getattr(b, "type", "") == "text")
        try:
            return json.loads(text)
        except ValueError:
            m = re.search(r"\{.*\}", text, re.S)
            if m:
                try:
                    return json.loads(m.group())
                except ValueError:
                    pass
            return {"error": "Не удалось разобрать ответ модели", "raw": text[:500]}


def is_analyzable(path: str) -> bool:
    ext = os.path.splitext(path)[1].lower()
    return ext in EXEC_EXT or ext in SCRIPT_EXT or ext in DOC_EXT
