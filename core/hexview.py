
from pathlib import Path
from typing import List

def hexdump(data: bytes, start_offset: int = 0, width: int = 16) -> List[str]:
    lines = []
    for row_start in range(0, len(data), width):
        chunk = data[row_start: row_start + width]
        offset = start_offset + row_start

        hex_col = " ".join(f"{b:02x}" for b in chunk)

        hex_col = hex_col.ljust(width * 3 - 1)

        ascii_col = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)

        lines.append(f"  {offset:08x}  {hex_col}  |{ascii_col}|")

    return lines

def hexdump_from_file(filepath: Path, num_bytes: int = 256, offset: int = 0) -> List[str]:
    with open(filepath, "rb") as fh:
        fh.seek(offset)
        data = fh.read(num_bytes)

    return hexdump(data, start_offset=offset)

def highlight_magic(data: bytes) -> str:
    return " ".join(f"{b:02x}" for b in data[:8])

def find_in_hex(data: bytes, pattern: bytes) -> List[int]:
    offsets = []
    start = 0
    while True:
        idx = data.find(pattern, start)
        if idx == -1:
            break
        offsets.append(idx)
        start = idx + 1
    return offsets
