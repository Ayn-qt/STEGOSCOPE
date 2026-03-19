
import math
from collections import Counter
from pathlib import Path
from typing import List, Tuple, Dict

ENTROPY_BANDS = [
    (0.0,  1.0,  "Very Low",       "red",     "Near-zero entropy — likely padding, null bytes, or highly repetitive data."),
    (1.0,  3.5,  "Low",            "yellow",  "Low entropy — plain text, simple binaries, or structured data (e.g. BMP pixel rows)."),
    (3.5,  6.0,  "Moderate",       "green",   "Moderate entropy — typical for executable code or mixed content."),
    (6.0,  7.2,  "High",           "cyan",    "High entropy — compressed data (zip, gzip) or dense binary content."),
    (7.2,  7.8,  "Very High",      "magenta", "Very high entropy — likely encrypted or compressed payload. Investigate further."),
    (7.8,  8.01, "Extremely High", "bold red","Extremely high entropy — almost certainly encrypted/compressed. Strong steganography indicator."),
]

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    freq = Counter(data)
    total = len(data)
    entropy = 0.0

    for count in freq.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)

    return round(entropy, 4)

def interpret_entropy(h: float) -> Dict[str, str]:
    for lo, hi, label, color, desc in ENTROPY_BANDS:
        if lo <= h < hi:
            return {"label": label, "color": color, "description": desc}

    return {"label": "Unknown", "color": "white", "description": "Could not classify entropy."}

def sliding_window_entropy(
    data: bytes,
    window_size: int = 256,
    step: int = 64,
) -> List[Tuple[int, float]]:
    results = []
    for offset in range(0, len(data) - window_size, step):
        window = data[offset: offset + window_size]
        h = shannon_entropy(window)
        results.append((offset, h))
    return results

def find_high_entropy_regions(
    data: bytes,
    threshold: float = 7.2,
    window_size: int = 512,
    step: int = 128,
) -> List[Tuple[int, int, float]]:
    windows = sliding_window_entropy(data, window_size, step)
    regions = []
    in_region = False
    region_start = 0
    peak = 0.0

    for offset, h in windows:
        if h >= threshold:
            if not in_region:
                in_region = True
                region_start = offset
                peak = h
            else:
                peak = max(peak, h)
        else:
            if in_region:
                regions.append((region_start, offset, round(peak, 4)))
                in_region = False
                peak = 0.0

    if in_region:
        regions.append((region_start, len(data), round(peak, 4)))

    return regions

def byte_frequency(data: bytes) -> Dict[int, int]:
    freq = Counter(data)
    return {b: freq.get(b, 0) for b in range(256)}
