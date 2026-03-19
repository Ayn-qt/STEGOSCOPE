
import math
import warnings
from pathlib import Path
from typing import Optional, Tuple

def decode(filepath: Path, debug: bool = False) -> Optional[str]:
    try:
        from PIL import Image
    except ImportError:
        raise RuntimeError("Pillow is required: pip install Pillow")

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        img = Image.open(filepath).convert("RGB")
        w, h = img.size

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        pixels = list(img.getdata())

    lsbs_rgb = []
    lsbs_r   = []
    lsbs_g   = []
    lsbs_b   = []

    for pixel in pixels:
        lsbs_rgb.append(pixel[0] & 1)
        lsbs_rgb.append(pixel[1] & 1)
        lsbs_rgb.append(pixel[2] & 1)
        lsbs_r.append(pixel[0] & 1)
        lsbs_g.append(pixel[1] & 1)
        lsbs_b.append(pixel[2] & 1)

    max_bits     = w * h * 3
    header_width = math.ceil(math.log2(max_bits)) if max_bits > 0 else 24

    hw_candidates = sorted(set([
        header_width,
        header_width - 1,
        header_width - 2,
        math.ceil(math.log2(w * h * 4)) if w * h > 0 else 24,
        math.ceil(math.log2(w * h * 4)) - 1 if w * h > 0 else 23,
        round(math.log2(w * h * 4))     if w * h > 0 else 24,
        round(math.log2(w * h * 4)) - 1 if w * h > 0 else 23,
        round(math.log2(w * h * 3))     if w * h > 0 else 24,
        round(math.log2(w * h))         if w * h > 0 else 22,
        22, 23, 24, 25,
    ]))

    attempts = []
    for hw in [header_width - 1] + [x for x in hw_candidates if x != header_width - 1]:
        for bits, name in [(lsbs_rgb, "rgb"), (lsbs_r, "r"), (lsbs_g, "g"), (lsbs_b, "b")]:
            for lsb_first in [False, True]:
                attempts.append((bits, hw, lsb_first))

    best = None
    best_score = 0

    for bits, hdr_size, lsb_first in attempts:
        result = _try_decode(bits, hdr_size, lsb_first, max_bits)
        if result:
            score = _printable_score(result)
            if debug:
                ch = "rgb" if bits is lsbs_rgb else ("r" if bits is lsbs_r else ("g" if bits is lsbs_g else "b"))
                print(f"  hw={hdr_size} ch={ch} lsb={lsb_first} score={score:.2f}: '{result[:60]}'")
            if score > best_score:
                best_score = score
                best = result
            if score > 0.9:
                return result

    return best if best_score > 0.5 else None

def _try_decode(bits: list, header_size: int, lsb_first: bool, max_bits: int) -> Optional[str]:
    if len(bits) < header_size + 8:
        return None

    header_bits = bits[:header_size]
    if lsb_first:
        msg_length_bits = _bits_to_int_lsb(header_bits)
    else:
        msg_length_bits = _bits_to_int(header_bits)

    if msg_length_bits <= 0 or msg_length_bits > max_bits - header_size:
        return None

    start    = header_size
    end      = start + msg_length_bits
    if end > len(bits):
        return None

    msg_bits = bits[start:end]

    if lsb_first:
        return _bits_to_string_lsb(msg_bits)
    else:
        return _bits_to_string(msg_bits)

def _printable_score(s: str) -> float:
    if not s:
        return 0.0
    printable = sum(1 for c in s if 32 <= ord(c) <= 126)
    return printable / len(s)

def encode(filepath: Path, message: str, output_path: Path) -> bool:
    try:
        from PIL import Image
    except ImportError:
        raise RuntimeError("Pillow is required: pip install Pillow")

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        img = Image.open(filepath).convert("RGB")
        w, h = img.size

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        pixels = list(img.getdata())

    max_bits     = w * h * 3
    header_width = math.ceil(math.log2(max_bits)) if max_bits > 0 else 24

    msg_bits = []
    for char in message:
        bits = format(ord(char), '08b')
        msg_bits.extend(int(b) for b in bits)

    total_bits = len(msg_bits)

    if total_bits > max_bits - header_width:
        raise ValueError(
            f"Message too long: {total_bits} bits needed, "
            f"{max_bits - header_width} bits available"
        )

    header_bits = [int(b) for b in format(total_bits, f'0{header_width}b')]
    all_bits    = header_bits + msg_bits

    new_pixels  = list(pixels)
    bit_index   = 0
    pixel_index = 0

    while bit_index < len(all_bits) and pixel_index < len(new_pixels):
        r, g, b = new_pixels[pixel_index]
        if bit_index < len(all_bits):
            r = (r & 0xFE) | all_bits[bit_index]; bit_index += 1
        if bit_index < len(all_bits):
            g = (g & 0xFE) | all_bits[bit_index]; bit_index += 1
        if bit_index < len(all_bits):
            b = (b & 0xFE) | all_bits[bit_index]; bit_index += 1
        new_pixels[pixel_index] = (r, g, b)
        pixel_index += 1

    out_img = Image.new("RGB", (w, h))
    out_img.putdata(new_pixels)
    output_path = Path(output_path)
    if output_path.suffix.lower() not in ('.png', '.bmp'):
        output_path = output_path.with_suffix('.png')
    out_img.save(str(output_path), format='PNG')
    return True

def capacity(filepath: Path) -> Tuple[int, int]:
    try:
        from PIL import Image
    except ImportError:
        return 0, 0
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        img = Image.open(filepath)
        w, h = img.size
    max_bits    = w * h * 3
    header_w    = math.ceil(math.log2(max_bits)) if max_bits > 0 else 24
    usable_bits = max_bits - header_w
    return usable_bits // 8, usable_bits

def _bits_to_int(bits: list) -> int:
    result = 0
    for b in bits:
        result = (result << 1) | b
    return result

def _bits_to_int_lsb(bits: list) -> int:
    result = 0
    for i, b in enumerate(bits):
        result |= (b << i)
    return result

def _bits_to_string(bits: list) -> str:
    chars = []
    for i in range(0, len(bits) - 7, 8):
        byte_val = _bits_to_int(bits[i:i+8])
        if byte_val == 0:
            break
        chars.append(chr(byte_val))
    return ''.join(chars)

def _bits_to_string_lsb(bits: list) -> str:
    chars = []
    for i in range(0, len(bits) - 7, 8):
        byte_val = _bits_to_int_lsb(bits[i:i+8])
        if byte_val == 0:
            break
        chars.append(chr(byte_val))
    return ''.join(chars)

import math
import warnings
from pathlib import Path
from typing import Optional, Tuple

def decode(filepath: Path) -> Optional[str]:
    try:
        from PIL import Image
    except ImportError:
        raise RuntimeError("Pillow is required: pip install Pillow")

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        img = Image.open(filepath).convert("RGB")
        w, h = img.size

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        pixels = list(img.getdata())

    lsbs = []
    for pixel in pixels:
        lsbs.append(pixel[0] & 1)
        lsbs.append(pixel[1] & 1)
        lsbs.append(pixel[2] & 1)

    max_bits   = w * h * 3
    header_width = math.ceil(math.log2(max_bits)) if max_bits > 0 else 24

    if len(lsbs) < header_width:
        return None

    msg_length_bits = _bits_to_int(lsbs[:header_width])

    if msg_length_bits <= 0 or msg_length_bits > max_bits - header_width:
        return None

    start = header_width
    end   = start + msg_length_bits

    if end > len(lsbs):
        return None

    msg_bits = lsbs[start:end]

    message = _bits_to_string(msg_bits)
    return message if message else None

def encode(filepath: Path, message: str, output_path: Path) -> bool:
    try:
        from PIL import Image
    except ImportError:
        raise RuntimeError("Pillow is required: pip install Pillow")

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        img = Image.open(filepath).convert("RGB")
        w, h = img.size

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        pixels = list(img.getdata())

    max_bits     = w * h * 3
    header_width = math.ceil(math.log2(max_bits)) if max_bits > 0 else 24

    msg_bits = []
    for char in message:
        bits = format(ord(char), '08b')
        msg_bits.extend(int(b) for b in bits)

    total_bits = len(msg_bits)

    if total_bits > max_bits - header_width:
        raise ValueError(
            f"Message too long: {total_bits} bits needed, "
            f"{max_bits - header_width} bits available"
        )

    header_bits = [int(b) for b in format(total_bits, f'0{header_width}b')]

    all_bits = header_bits + msg_bits

    new_pixels = list(pixels)
    bit_index  = 0
    pixel_index = 0

    while bit_index < len(all_bits) and pixel_index < len(new_pixels):
        r, g, b = new_pixels[pixel_index]

        if bit_index < len(all_bits):
            r = (r & 0xFE) | all_bits[bit_index]
            bit_index += 1
        if bit_index < len(all_bits):
            g = (g & 0xFE) | all_bits[bit_index]
            bit_index += 1
        if bit_index < len(all_bits):
            b = (b & 0xFE) | all_bits[bit_index]
            bit_index += 1

        new_pixels[pixel_index] = (r, g, b)
        pixel_index += 1

    out_img = Image.new("RGB", (w, h))
    out_img.putdata(new_pixels)
    output_path = Path(output_path)
    if output_path.suffix.lower() not in ('.png', '.bmp'):
        output_path = output_path.with_suffix('.png')
    out_img.save(str(output_path), format='PNG')
    return True

def _bits_to_int(bits: list) -> int:
    result = 0
    for b in bits:
        result = (result << 1) | b
    return result

def _bits_to_string(bits: list) -> str:
    chars = []
    for i in range(0, len(bits) - 7, 8):
        byte_val = _bits_to_int(bits[i:i+8])
        if byte_val == 0:
            break
        chars.append(chr(byte_val))
    return ''.join(chars)

def capacity(filepath: Path) -> Tuple[int, int]:
    try:
        from PIL import Image
    except ImportError:
        return 0, 0

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        img = Image.open(filepath)
        w, h = img.size

    max_bits   = w * h * 3
    header_w   = math.ceil(math.log2(max_bits)) if max_bits > 0 else 24
    usable_bits = max_bits - header_w
    return usable_bits // 8, usable_bits
