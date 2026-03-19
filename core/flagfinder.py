
import re
import base64
import binascii
from pathlib import Path
from typing import List, Tuple, Dict

DEFAULT_PATTERNS: Dict[str, re.Pattern] = {

    "Generic flag{}":   re.compile(rb"flag\{[\x20-\x7e]{1,128}\}", re.IGNORECASE),
    "CTF{}":            re.compile(rb"ctf\{[\x20-\x7e]{1,128}\}", re.IGNORECASE),
    "picoCTF{}":        re.compile(rb"picoctf\{[\x20-\x7e]{1,128}\}", re.IGNORECASE),
    "HTB{}":            re.compile(rb"htb\{[\x20-\x7e]{1,128}\}", re.IGNORECASE),
    "THM{}":            re.compile(rb"thm\{[\x20-\x7e]{1,128}\}", re.IGNORECASE),
    "DUCTF{}":          re.compile(rb"ductf\{[\x20-\x7e]{1,128}\}", re.IGNORECASE),
    "PCTF{}":           re.compile(rb"pctf\{[\x20-\x7e]{1,128}\}", re.IGNORECASE),
    "WH{}":             re.compile(rb"wh\{[\x20-\x7e]{1,128}\}", re.IGNORECASE),
    "FLAG=":            re.compile(rb"FLAG=[A-Za-z0-9+/=_\-]{4,64}", re.IGNORECASE),
}

HASH_PATTERNS: Dict[str, re.Pattern] = {
    "MD5 hash":    re.compile(rb"\b[0-9a-f]{32}\b", re.IGNORECASE),
    "SHA1 hash":   re.compile(rb"\b[0-9a-f]{40}\b", re.IGNORECASE),
    "SHA256 hash": re.compile(rb"\b[0-9a-f]{64}\b", re.IGNORECASE),
}

def expand_pattern(pattern: str) -> str:
    import re as _re

    shorthand = _re.match(r'^([A-Za-z0-9_\-]+)\{\}$', pattern)
    if shorthand:
        prefix = _re.escape(shorthand.group(1))
        return rf"{prefix}\{{[\x20-\x7e]{{1,128}}\}}"
    return pattern

def search_raw(data: bytes, extra_pattern: str = None) -> List[Tuple[str, int, str]]:
    findings: List[Tuple[str, int, str]] = []

    patterns = dict(DEFAULT_PATTERNS)

    if extra_pattern:
        try:
            expanded = expand_pattern(extra_pattern)
            patterns["Custom"] = re.compile(expanded.encode(), re.IGNORECASE)
        except re.error:
            pass

    for name, pattern in patterns.items():
        for match in pattern.finditer(data):
            text = match.group().decode("utf-8", errors="replace")
            findings.append((name, match.start(), text))

    return findings

def search_base64_decoded(data: bytes) -> List[Tuple[str, int, str]]:
    findings = []

    b64_pattern = re.compile(rb"[A-Za-z0-9+/]{20,}={0,2}")

    for match in b64_pattern.finditer(data):
        blob = match.group()

        pad = (4 - len(blob) % 4) % 4
        try:
            decoded = base64.b64decode(blob + b"=" * pad)

            for name, pat in DEFAULT_PATTERNS.items():
                for m in pat.finditer(decoded):
                    text = m.group().decode("utf-8", errors="replace")
                    findings.append((
                        f"Base64-decoded {name}",
                        match.start(),
                        text,
                    ))
        except Exception:
            continue

    return findings

def search_hex_decoded(data: bytes) -> List[Tuple[str, int, str]]:
    findings = []
    hex_pattern = re.compile(rb"(?:[0-9a-f]{2}){8,}", re.IGNORECASE)

    for match in hex_pattern.finditer(data):
        blob = match.group()
        try:
            decoded = binascii.unhexlify(blob)
            for name, pat in DEFAULT_PATTERNS.items():
                for m in pat.finditer(decoded):
                    text = m.group().decode("utf-8", errors="replace")
                    findings.append((
                        f"Hex-decoded {name}",
                        match.start(),
                        text,
                    ))
        except Exception:
            continue

    return findings

def search_all(
    filepath: Path,
    extra_pattern: str = None,
    check_encodings: bool = True,
) -> List[Tuple[str, int, str]]:
    with open(filepath, "rb") as fh:
        data = fh.read()

    results = search_raw(data, extra_pattern)

    if check_encodings:
        results.extend(search_base64_decoded(data))
        results.extend(search_hex_decoded(data))

    seen = set()
    unique = []
    for item in results:
        key = item[2]
        if key not in seen:
            seen.add(key)
            unique.append(item)

    unique.sort(key=lambda x: x[1])
    return unique
