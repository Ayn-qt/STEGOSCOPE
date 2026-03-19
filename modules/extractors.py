
import io
from pathlib import Path
from typing import List, Dict, Any, Optional

from core.hexview import find_in_hex

EMBEDDED_SIGNATURES: List[Dict] = [
    {"magic": b"\x89PNG\r\n\x1a\n", "name": "PNG Image",        "ext": ".png"},
    {"magic": b"\xff\xd8\xff",       "name": "JPEG Image",       "ext": ".jpg"},
    {"magic": b"GIF89a",             "name": "GIF Image",        "ext": ".gif"},
    {"magic": b"GIF87a",             "name": "GIF87a Image",     "ext": ".gif"},
    {"magic": b"PK\x03\x04",         "name": "ZIP Archive",      "ext": ".zip"},
    {"magic": b"\x1f\x8b",           "name": "Gzip Archive",     "ext": ".gz"},
    {"magic": b"BZh",                "name": "Bzip2 Archive",    "ext": ".bz2"},
    {"magic": b"7z\xbc\xaf'\x1c",    "name": "7-Zip Archive",    "ext": ".7z"},
    {"magic": b"Rar!\x1a\x07",       "name": "RAR Archive",      "ext": ".rar"},
    {"magic": b"%PDF",               "name": "PDF Document",     "ext": ".pdf"},
    {"magic": b"\x7fELF",            "name": "ELF Executable",   "ext": ".elf"},
    {"magic": b"MZ",                 "name": "PE Executable",    "ext": ".exe"},
    {"magic": b"RIFF",               "name": "RIFF Container",   "ext": ".wav"},
    {"magic": b"ID3",                "name": "MP3 Audio",        "ext": ".mp3"},
    {"magic": b"OggS",               "name": "Ogg Container",    "ext": ".ogg"},
    {"magic": b"SQLite format 3",    "name": "SQLite Database",  "ext": ".db"},
    {"magic": b"fLaC",               "name": "FLAC Audio",       "ext": ".flac"},
    {"magic": b"\xca\xfe\xba\xbe",   "name": "Mach-O Fat Binary","ext": ".macho"},
]

JPEG_EOI = b"\xff\xd9"
PNG_IEND = b"IEND\xaeB`\x82"

def scan_for_embedded(filepath: Path) -> List[Dict[str, Any]]:
    with open(filepath, "rb") as fh:
        data = fh.read()

    file_size = len(data)
    findings = []

    for sig in EMBEDDED_SIGNATURES:
        magic = sig["magic"]
        offsets = find_in_hex(data, magic)

        for offset in offsets:

            if offset == 0:
                continue

            findings.append({
                "name":       sig["name"],
                "ext":        sig["ext"],
                "offset":     offset,
                "hex_offset": hex(offset),
                "remaining":  file_size - offset,
            })

    findings.sort(key=lambda x: x["offset"])
    return findings

def carve_embedded(
    filepath: Path,
    out_dir: Path,
    max_files: int = 20,
) -> List[Dict[str, Any]]:
    out_dir.mkdir(parents=True, exist_ok=True)
    found = scan_for_embedded(filepath)

    if not found:
        return []

    with open(filepath, "rb") as fh:
        data = fh.read()

    carved = []
    for i, item in enumerate(found[:max_files]):
        offset = item["offset"]
        ext = item["ext"]
        name = item["name"]

        end = _find_trailer(data, offset, ext)
        chunk = data[offset:end]

        out_path = out_dir / f"carved_{i:04d}_{offset:08x}{ext}"
        try:
            out_path.write_bytes(chunk)
            carved.append({
                "source":     str(filepath),
                "name":       name,
                "offset":     offset,
                "size":       len(chunk),
                "output":     str(out_path),
            })
        except OSError as exc:
            carved.append({
                "name":  name,
                "offset": offset,
                "error": str(exc),
            })

    return carved

def _find_trailer(data: bytes, start: int, ext: str) -> int:
    if ext == ".jpg":
        idx = data.find(JPEG_EOI, start)
        return idx + len(JPEG_EOI) if idx != -1 else len(data)

    if ext == ".png":
        idx = data.find(PNG_IEND, start)
        return idx + len(PNG_IEND) if idx != -1 else len(data)

    if ext == ".zip":

        trailer = b"PK\x05\x06"
        idx = data.rfind(trailer, start)
        if idx != -1:

            return idx + 22
        return len(data)

    return len(data)
