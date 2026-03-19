
from pathlib import Path
from typing import Any, Dict

from rich.console import Console
from rich.table import Table
from rich import box

from modules.stego_detect import run_stego_detection
from core.utils import section, success, info, warn, error, finding

def cmd_detect(target: Path, args, console: Console) -> Dict[str, Any]:
    section("STEGO DETECTION", console)
    info("Running steganography heuristics...", console)

    results = run_stego_detection(target)
    hints = results.get("hints", [])

    lsb = results.get("lsb")
    if lsb:
        console.print()
        console.print("  [bold cyan]LSB Analysis:[/bold cyan]")
        finding("Sample bytes",      f"{lsb['lsb_sample_bytes']:,}", console)
        finding("Chi-square (norm)", str(lsb["chi_square_norm"]), console)
        finding("Bit ratio (0→1)",   str(lsb["bit_ratio"]), console)
        finding("LSB entropy",       str(lsb["lsb_entropy"]), console)

        if lsb["chi_square_norm"] < 0.001 and 0.48 < lsb["bit_ratio"] < 0.52:
            warn("Chi-square near zero with perfect 50/50 bit ratio — LSB steganography is likely.", console)
        elif lsb["bit_ratio"] < 0.05 or lsb["bit_ratio"] > 0.95:
            warn("Extreme bit ratio — constant pixel channel may conceal data.", console)
        else:
            info("LSB distribution within normal photographic range.", console)

    fsd = results.get("filesize_check")
    if fsd:
        console.print()
        console.print("  [bold cyan]File Size vs Dimensions:[/bold cyan]")
        finding("Dimensions",    f"{fsd['width']} × {fsd['height']} px ({fsd['mode']})", console)
        finding("Expected raw",  f"{fsd['expected_raw_bytes']:,} bytes", console)
        finding("Actual size",   f"{fsd['actual_file_bytes']:,} bytes", console)
        finding("Size ratio",    str(fsd["ratio"]), console)

        if fsd["suspicious"]:
            warn(f"File is {fsd['ratio']}× larger than expected — trailer data possible.", console)
        else:
            info("File size within expected range.", console)

    pal = results.get("palette")
    if pal:
        console.print()
        console.print("  [bold cyan]Palette Analysis (indexed PNG):[/bold cyan]")
        finding("Total entries",  str(pal["total_palette_entries"]), console)
        finding("Used entries",   str(pal["used_entries"]), console)
        finding("Unused entries", str(pal["unused_entries"]), console)

        if pal["suspicious"]:
            warn("Unused palette entries detected — may hide data.", console)
        else:
            info("No unused palette entries.", console)

    wav = results.get("wav_channels")
    if wav:
        console.print()
        console.print("  [bold cyan]WAV Channel Analysis:[/bold cyan]")
        finding("Channels",        str(wav["channels"]), console)
        finding("Sample width",    f"{wav['sample_width_bytes']} bytes", console)
        finding("Left entropy",    str(wav["left_entropy"]), console)
        finding("Right entropy",   str(wav["right_entropy"]), console)
        finding("Entropy diff",    str(wav["entropy_diff"]), console)

        if wav["suspicious"]:
            warn("Significant channel entropy asymmetry — check for audio steganography.", console)
        else:
            info("Channels appear balanced.", console)

    if "image_error" in results and not lsb:
        info(results["image_error"], console)
        info("Non-image file — only generic tests were applicable.", console)

    console.print()
    if hints:
        warn(f"[bold]{len(hints)} suspicious indicator(s) found:[/bold]", console)
        for h in hints:
            console.print(f"  [bold red]▶[/bold red] {h}")
    else:
        success("No steganographic anomalies detected.", console)

    return {"stego_hints": hints}
