
import math
import struct
from pathlib import Path
from typing import List, Dict, Any, Optional
from collections import Counter

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

def extract_lsb_bytes(img) -> bytes:
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        pixels = list(img.getdata())
    bits = []
    for pixel in pixels:
        if isinstance(pixel, (tuple, list)):

            for channel in pixel[:3]:
                bits.append(channel & 1)
        else:

            bits.append(pixel & 1)

    byte_list = []
    for i in range(0, len(bits) - 7, 8):
        byte_val = 0
        for j in range(8):
            byte_val = (byte_val << 1) | bits[i + j]
        byte_list.append(byte_val)

    return bytes(byte_list)

def chi_square_lsb(lsb_data: bytes) -> float:
    n = len(lsb_data)
    if n == 0:
        return 0.0

    total_bits = n * 8
    ones  = sum(bin(b).count("1") for b in lsb_data)
    zeros = total_bits - ones
    expected = total_bits / 2

    chi2 = ((zeros - expected) ** 2 + (ones - expected) ** 2) / expected

    return round(chi2 / total_bits, 6)

def bit_ratio(lsb_data: bytes) -> float:
    if not lsb_data:
        return 0.0
    total = len(lsb_data) * 8
    ones  = sum(bin(b).count("1") for b in lsb_data)
    return round(ones / total, 4)

def lsb_entropy(lsb_data: bytes) -> float:
    if not lsb_data:
        return 0.0
    freq = Counter(lsb_data)
    total = len(lsb_data)
    h = 0.0
    for count in freq.values():
        p = count / total
        if p > 0:
            h -= p * math.log2(p)
    return round(h, 4)

def filesize_vs_dimensions(filepath: Path, img) -> Optional[Dict[str, Any]]:
    try:
        mode_bytes = {"1": 0.125, "L": 1, "P": 1, "RGB": 3, "RGBA": 4,
                      "CMYK": 4, "YCbCr": 3, "I": 4, "F": 4}
        bpp = mode_bytes.get(img.mode, 3)
        w, h = img.size
        expected_raw = w * h * bpp
        actual = filepath.stat().st_size

        ratio = actual / max(expected_raw, 1)
        return {
            "width": w,
            "height": h,
            "mode": img.mode,
            "expected_raw_bytes": expected_raw,
            "actual_file_bytes": actual,
            "ratio": round(ratio, 3),
            "suspicious": ratio > 1.5,
        }
    except Exception:
        return None

def check_palette_anomaly(img) -> Optional[Dict[str, Any]]:
    if img.mode != "P":
        return None

    palette = img.getpalette()
    if not palette:
        return None

    used_indices = set(img.getdata())
    total_entries = len(palette) // 3
    used_count = len(used_indices)
    unused_count = total_entries - used_count

    return {
        "total_palette_entries": total_entries,
        "used_entries": used_count,
        "unused_entries": unused_count,
        "suspicious": unused_count > 0,
    }

def analyze_wav_channels(filepath: Path) -> Optional[Dict[str, Any]]:
    try:
        import wave
        with wave.open(str(filepath), "rb") as wf:
            n_channels = wf.getnchannels()
            sampwidth = wf.getsampwidth()
            n_frames = wf.getnframes()
            raw = wf.readframes(n_frames)

        if n_channels < 2 or sampwidth < 2:
            return None

        left  = bytes(raw[i] for i in range(0, len(raw), sampwidth * 2))
        right = bytes(raw[i] for i in range(sampwidth, len(raw), sampwidth * 2))

        from core.entropy import shannon_entropy
        h_left  = shannon_entropy(left)
        h_right = shannon_entropy(right)
        diff = abs(h_left - h_right)

        return {
            "channels": n_channels,
            "sample_width_bytes": sampwidth,
            "left_entropy": h_left,
            "right_entropy": h_right,
            "entropy_diff": round(diff, 4),
            "suspicious": diff > 0.5,
        }
    except Exception:
        return None

def run_stego_detection(filepath: Path) -> Dict[str, Any]:
    results: Dict[str, Any] = {"hints": []}

    if PIL_AVAILABLE:
        try:
            img = Image.open(filepath)
            img_mode = img.mode

            analysis_img = img.convert("RGB") if img_mode not in ("RGB", "RGBA", "L") else img

            lsb_data = extract_lsb_bytes(analysis_img)
            chi2     = chi_square_lsb(lsb_data)
            lsb_ent  = lsb_entropy(lsb_data)
            b_ratio  = bit_ratio(lsb_data)

            results["lsb"] = {
                "lsb_sample_bytes": len(lsb_data),
                "chi_square_norm":  chi2,
                "bit_ratio":        b_ratio,
                "lsb_entropy":      lsb_ent,
            }

            if chi2 < 0.001 and 0.48 < b_ratio < 0.52:
                results["hints"].append(
                    f"LSB bit ratio is suspiciously perfect ({b_ratio}) with chi2={chi2} "
                    "— consistent with LSB steganography."
                )

            elif b_ratio < 0.05 or b_ratio > 0.95:
                results["hints"].append(
                    f"LSB bit ratio is extreme ({b_ratio}) — constant-value pixels or "
                    "zeroed channel may hide data."
                )

            fsd = filesize_vs_dimensions(filepath, img)
            if fsd:
                results["filesize_check"] = fsd
                if fsd["suspicious"]:
                    results["hints"].append(
                        f"File size ({fsd['actual_file_bytes']}B) is {fsd['ratio']}× larger "
                        f"than expected raw data — appended payload possible."
                    )

            pal = check_palette_anomaly(img)
            if pal:
                results["palette"] = pal
                if pal["suspicious"]:
                    results["hints"].append(
                        f"Palette has {pal['unused_entries']} unused entries — "
                        "data may be hidden in colour table."
                    )

        except Exception:
            results["image_error"] = "Could not open file as image (Pillow failed)."

    wav_result = analyze_wav_channels(filepath)
    if wav_result:
        results["wav_channels"] = wav_result
        if wav_result["suspicious"]:
            results["hints"].append(
                f"Left/right channel entropy differs by {wav_result['entropy_diff']} bits — "
                "possible audio steganography."
            )

    return results
