
import os
import struct
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

try:
    from PIL import Image
    from PIL.ExifTags import TAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import exifread
    EXIFREAD_AVAILABLE = True
except ImportError:
    EXIFREAD_AVAILABLE = False

MAGIC_SIGNATURES: Dict[bytes, str] = {
    b"\x89PNG\r\n\x1a\n": "PNG Image",
    b"\xff\xd8\xff":       "JPEG Image",
    b"GIF87a":             "GIF87a Image",
    b"GIF89a":             "GIF89a Image",
    b"BM":                 "BMP Image",
    b"\x49\x49\x2a\x00":  "TIFF Image (little-endian)",
    b"\x4d\x4d\x00\x2a":  "TIFF Image (big-endian)",
    b"RIFF":               "RIFF Container (WAV/AVI)",
    b"ID3":                "MP3 Audio (ID3 tag)",
    b"\xff\xfb":           "MP3 Audio",
    b"OggS":               "Ogg Container",
    b"fLaC":               "FLAC Audio",
    b"PK\x03\x04":         "ZIP Archive",
    b"PK\x05\x06":         "ZIP Archive (empty)",
    b"\x1f\x8b":           "Gzip Compressed",
    b"BZh":                "Bzip2 Compressed",
    b"\xfd7zXZ\x00":       "XZ Compressed",
    b"7z\xbc\xaf'\x1c":    "7-Zip Archive",
    b"Rar!\x1a\x07":       "RAR Archive",
    b"\x7fELF":            "ELF Executable",
    b"MZ":                 "PE/DOS Executable",
    b"\xca\xfe\xba\xbe":   "Mach-O Fat Binary",
    b"\xfe\xed\xfa\xce":   "Mach-O 32-bit",
    b"\xfe\xed\xfa\xcf":   "Mach-O 64-bit",
    b"%PDF":               "PDF Document",
    b"\xd0\xcf\x11\xe0":   "Microsoft Office (OLE)",
    b"<!DOCTYPE":          "HTML Document",
    b"<html":              "HTML Document",
    b"SQLite":             "SQLite Database",
    b"\x00\x00\x00\x0cftyp": "MP4/ISO Base Media",
    b"\x00\x00\x01\xba":   "MPEG Video Stream",
    b"\x00\x00\x01\xb3":   "MPEG-1/2 Video",
}

def detect_file_type(data: bytes) -> str:
    for magic, name in MAGIC_SIGNATURES.items():
        if data.startswith(magic):
            return name

    return "Unknown / Binary"

def get_file_info(filepath: Path) -> Dict[str, Any]:
    stat = filepath.stat()
    mtime = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
    ctime = datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S")

    with open(filepath, "rb") as fh:
        header = fh.read(16)

    file_type = detect_file_type(header)

    return {
        "name":      filepath.name,
        "path":      str(filepath.resolve()),
        "size":      stat.st_size,
        "size_human": _human_size(stat.st_size),
        "modified":  mtime,
        "created":   ctime,
        "file_type": file_type,
        "extension": filepath.suffix.lower(),
        "permissions": oct(stat.st_mode)[-4:],
    }

def extract_exif(filepath: Path) -> Dict[str, Any]:
    exif_data: Dict[str, Any] = {}

    if PIL_AVAILABLE:
        try:
            img = Image.open(filepath)
            raw = img._getexif()
            if raw:
                for tag_id, value in raw.items():
                    tag_name = TAGS.get(tag_id, str(tag_id))

                    if isinstance(value, bytes) and len(value) > 64:
                        value = f"<binary {len(value)} bytes>"
                    exif_data[tag_name] = str(value)
        except Exception:
            pass

    if not exif_data and EXIFREAD_AVAILABLE:
        try:
            with open(filepath, "rb") as fh:
                tags = exifread.process_file(fh, stop_tag="UNDEF", details=False)
            for key, val in tags.items():

                short_key = key.split(" ", 1)[-1] if " " in key else key
                exif_data[short_key] = str(val)
        except Exception:
            pass

    return exif_data

def extract_png_chunks(data: bytes) -> list:
    chunks = []
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return chunks

    offset = 8
    while offset + 8 <= len(data):
        try:
            length = struct.unpack(">I", data[offset:offset + 4])[0]
            chunk_type = data[offset + 4:offset + 8].decode("ascii", errors="replace")
            chunks.append({"type": chunk_type, "length": length, "offset": offset})
            offset += 12 + length
        except Exception:
            break

    return chunks

def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"
