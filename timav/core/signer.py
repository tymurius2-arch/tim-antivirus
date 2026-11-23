"""Цифровые подписи Authenticode: проверка (WinVerifyTrust), издатель (crypt32), доверенные издатели."""
from __future__ import annotations

import os
import sys
import threading

DEFAULT_TRUSTED = [
    "Microsoft Corporation", "Microsoft Windows", "Valve", "Google LLC", "Mozilla Corporation", "Apple Inc.",
    "Adobe Inc.", "Adobe Systems", "NVIDIA Corporation", "Intel Corporation", "Advanced Micro Devices",
    "Oracle America", "JetBrains", "Python Software Foundation", "Epic Games", "Discord Inc.", "Spotify AB",
    "Zoom Video Communications", "Opera Norway", "Brave Software", "Telegram FZ-LLC", "Yandex LLC",
    "Logitech", "Realtek Semiconductor", "Dropbox, Inc", "Electronic Arts", "Riot Games", "Ubisoft",
    "Cisco Systems", "Docker Inc", "GitHub, Inc.", "Notepad++", "Igor Pavlov", "VideoLAN", "Kaspersky",
]

_cache: dict[tuple, tuple[bool, str]] = {}
_lock = threading.Lock()


def verify_signature(path: str) -> bool:
    """WinVerifyTrust без сетевой проверки отзыва сертификата."""
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        from ctypes import wintypes

        class GUID(ctypes.Structure):
            _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD),
                        ("Data4", ctypes.c_ubyte * 8)]

        class WINTRUST_FILE_INFO(ctypes.Structure):
            _fields_ = [("cbStruct", wintypes.DWORD), ("pcwszFilePath", wintypes.LPCWSTR),
                        ("hFile", wintypes.HANDLE), ("pgKnownSubject", ctypes.c_void_p)]

        class WINTRUST_DATA(ctypes.Structure):
            _fields_ = [("cbStruct", wintypes.DWORD), ("pPolicyCallbackData", ctypes.c_void_p),
                        ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", wintypes.DWORD),
                        ("fdwRevocationChecks", wintypes.DWORD), ("dwUnionChoice", wintypes.DWORD),
                        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)), ("dwStateAction", wintypes.DWORD),
                        ("hWVTStateData", wintypes.HANDLE), ("pwszURLReference", wintypes.LPCWSTR),
                        ("dwProvFlags", wintypes.DWORD), ("dwUIContext", wintypes.DWORD),
                        ("pSignatureSettings", ctypes.c_void_p)]

        action = GUID(0x00AAC56B, 0xCD44, 0x11D0, (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))
        fi = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), path, None, None)
        wd = WINTRUST_DATA()
        wd.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        wd.dwUIChoice = 2            # WTD_UI_NONE
        wd.fdwRevocationChecks = 0   # WTD_REVOKE_NONE
        wd.dwUnionChoice = 1         # WTD_CHOICE_FILE
        wd.pFile = ctypes.pointer(fi)
        wd.dwStateAction = 1         # WTD_STATEACTION_VERIFY
        wd.dwProvFlags = 0x1000      # WTD_CACHE_ONLY_URL_RETRIEVAL
        wvt = ctypes.windll.wintrust.WinVerifyTrust
        wvt.argtypes = [wintypes.HWND, ctypes.POINTER(GUID), ctypes.c_void_p]
        wvt.restype = ctypes.c_long
        res = wvt(None, ctypes.byref(action), ctypes.byref(wd))
        wd.dwStateAction = 2         # WTD_STATEACTION_CLOSE
        wvt(None, ctypes.byref(action), ctypes.byref(wd))
        return res == 0
    except Exception:
        return False


def get_signer(path: str) -> str:
    """Имя издателя (CN сертификата подписи) встроенной подписи Authenticode, '' если нет."""
    if sys.platform != "win32":
        return ""
    import ctypes
    from ctypes import wintypes

    class BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.c_void_p)]

    class ALGID(ctypes.Structure):
        _fields_ = [("pszObjId", ctypes.c_char_p), ("Parameters", BLOB)]

    class FILETIME(ctypes.Structure):
        _fields_ = [("lo", wintypes.DWORD), ("hi", wintypes.DWORD)]

    class BITBLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.c_void_p), ("cUnusedBits", wintypes.DWORD)]

    class PUBKEY(ctypes.Structure):
        _fields_ = [("Algorithm", ALGID), ("PublicKey", BITBLOB)]

    class CERT_INFO(ctypes.Structure):
        _fields_ = [("dwVersion", wintypes.DWORD), ("SerialNumber", BLOB), ("SignatureAlgorithm", ALGID),
                    ("Issuer", BLOB), ("NotBefore", FILETIME), ("NotAfter", FILETIME), ("Subject", BLOB),
                    ("SubjectPublicKeyInfo", PUBKEY), ("IssuerUniqueId", BITBLOB),
                    ("SubjectUniqueId", BITBLOB), ("cExtension", wintypes.DWORD), ("rgExtension", ctypes.c_void_p)]

    class SIGNER_INFO(ctypes.Structure):  # начало CMSG_SIGNER_INFO
        _fields_ = [("dwVersion", wintypes.DWORD), ("Issuer", BLOB), ("SerialNumber", BLOB)]

    crypt32 = ctypes.windll.crypt32
    enc, ctype, ftype = wintypes.DWORD(), wintypes.DWORD(), wintypes.DWORD()
    store, msg = ctypes.c_void_p(), ctypes.c_void_p()
    ok = crypt32.CryptQueryObject(1, ctypes.c_wchar_p(path), 1 << 10, 2, 0, ctypes.byref(enc), ctypes.byref(ctype),
                                  ctypes.byref(ftype), ctypes.byref(store), ctypes.byref(msg), None)
    if not ok:
        return ""
    name = ""
    ctx = None
    try:
        size = wintypes.DWORD()
        crypt32.CryptMsgGetParam.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                             ctypes.POINTER(wintypes.DWORD)]
        if not crypt32.CryptMsgGetParam(msg, 6, 0, None, ctypes.byref(size)):
            return ""
        buf = ctypes.create_string_buffer(size.value)
        if not crypt32.CryptMsgGetParam(msg, 6, 0, buf, ctypes.byref(size)):
            return ""
        si = SIGNER_INFO.from_buffer(buf)
        ci = CERT_INFO()
        ci.Issuer = si.Issuer
        ci.SerialNumber = si.SerialNumber
        crypt32.CertFindCertificateInStore.restype = ctypes.c_void_p
        crypt32.CertFindCertificateInStore.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                                       wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p]
        ctx = crypt32.CertFindCertificateInStore(store, 0x10001, 0, 0xB0000, ctypes.byref(ci), None)
        if ctx:
            out = ctypes.create_unicode_buffer(512)
            crypt32.CertGetNameStringW.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                                   ctypes.c_wchar_p, wintypes.DWORD]
            crypt32.CertGetNameStringW(ctx, 4, 0, None, out, 512)
            name = out.value
    finally:
        if ctx:
            crypt32.CertFreeCertificateContext(ctypes.c_void_p(ctx))
        crypt32.CertCloseStore(store, 0)
        crypt32.CryptMsgClose(msg)
    return name


def signature(path: str) -> tuple[bool, str]:
    """(подпись действительна, издатель) с кэшем по размеру и времени изменения."""
    try:
        st = os.stat(path)
        key = (os.path.normcase(path), st.st_size, st.st_mtime_ns)
    except OSError:
        return False, ""
    with _lock:
        if key in _cache:
            return _cache[key]
    valid = verify_signature(path)
    try:
        signer = get_signer(path) if valid else ""
    except Exception:
        signer = ""
    with _lock:
        if len(_cache) > 20000:
            _cache.clear()
        _cache[key] = (valid, signer)
    return valid, signer


def is_trusted(signer: str, publishers: list[str]) -> bool:
    s = signer.lower()
    return bool(s) and any(p.strip() and p.strip().lower() in s for p in publishers)
