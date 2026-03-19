
import re
from pathlib import Path
from typing import List, Tuple

INTERESTING_KEYWORDS = {
    "credentials":  re.compile(r"(?i)(password|passwd|pass|secret|token|apikey|api_key|auth|credentials?)"),
    "network":      re.compile(r"(?i)(https?://|ftp://|ssh://|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|localhost)"),
    "files":        re.compile(r"(?i)\.(txt|py|php|sh|bash|conf|cfg|ini|key|pem|log|zip|tar|gz)"),
    "encoding":     re.compile(r"(?i)(base64|hex|rot13|caesar|xor|md5|sha[0-9]|aes|rsa)"),
    "hints":        re.compile(r"(?i)(hint|clue|hidden|flag|ctf|steg|secret|decode|encrypt)"),
}

def extract_strings(
    filepath: Path,
    min_len: int = 4,
    include_unicode: bool = False,
) -> List[Tuple[int, str]]:
    results: List[Tuple[int, str]] = []

    with open(filepath, "rb") as fh:
        data = fh.read()

    ascii_pattern = re.compile(
        rb"[ -~]{" + str(min_len).encode() + rb",}",
    )
    for match in ascii_pattern.finditer(data):
        results.append((match.start(), match.group().decode("ascii", errors="replace")))

    if include_unicode:

        utf16_pattern = re.compile(
            rb"(?:[ -~]\x00){" + str(min_len).encode() + rb",}",
        )
        for match in utf16_pattern.finditer(data):
            decoded = match.group().decode("utf-16-le", errors="replace")
            results.append((match.start(), decoded))

    results.sort(key=lambda x: x[0])
    return results

def classify_string(s: str) -> List[str]:
    tags = []
    for category, pattern in INTERESTING_KEYWORDS.items():
        if pattern.search(s):
            tags.append(category)
    return tags

def filter_interesting(
    strings: List[Tuple[int, str]],
) -> List[Tuple[int, str, List[str]]]:
    out = []
    for offset, s in strings:
        tags = classify_string(s)
        if tags:
            out.append((offset, s, tags))
    return out

def deduplicate(
    strings: List[Tuple[int, str]],
) -> List[Tuple[int, str]]:
    seen = set()
    out = []
    for offset, s in strings:
        if s not in seen:
            seen.add(s)
            out.append((offset, s))
    return out
