
from pathlib import Path
from typing import Any, Dict, Optional

from rich.console import Console
from rich.table import Table
from rich import box

from core import metadata, strings, hexview, entropy, flagfinder
from core.utils import section, success, info, warn, error, finding

def cmd_metadata(target: Path, args, console: Console) -> Dict[str, Any]:

    file_info = metadata.get_file_info(target)

    section("FILE INFO", console)
    success(f"File: [bold white]{file_info['name']}[/bold white]", console)
    finding("Path",        file_info["path"], console)
    finding("Size",        f"{file_info['size_human']} ({file_info['size']:,} bytes)", console)
    finding("Type",        file_info["file_type"], console)
    finding("Extension",   file_info["extension"] or "(none)", console)
    finding("Modified",    file_info["modified"], console)
    finding("Permissions", file_info["permissions"], console)

    if "png" in file_info["file_type"].lower():
        with open(target, "rb") as fh:
            raw = fh.read()
        chunks = metadata.extract_png_chunks(raw)
        if chunks:
            section("PNG CHUNKS", console)
            tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
            tbl.add_column("Offset", style="dim")
            tbl.add_column("Type",   style="bold white")
            tbl.add_column("Size",   justify="right")
            for chunk in chunks:
                tbl.add_row(
                    hex(chunk["offset"]),
                    chunk["type"],
                    f"{chunk['length']:,} bytes",
                )
            console.print(tbl)

            non_standard = [c for c in chunks if c["type"] not in
                            ("IHDR", "IDAT", "IEND", "tEXt", "zTXt",
                             "iTXt", "cHRM", "gAMA", "sRGB", "bKGD",
                             "pHYs", "sBIT", "tIME", "hIST", "sPLT",
                             "PLTE", "tRNS")]
            if non_standard:
                for c in non_standard:
                    warn(f"Non-standard chunk: [bold red]{c['type']}[/bold red] "
                         f"at offset {hex(c['offset'])} — may contain hidden data!", console)

    section("EXIF METADATA", console)
    exif = metadata.extract_exif(target)
    if exif:
        tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
        tbl.add_column("Tag",   style="bold white", no_wrap=True)
        tbl.add_column("Value", style="cyan")
        for tag, value in sorted(exif.items()):

            display = value if len(value) <= 80 else value[:77] + "..."
            tbl.add_row(tag, display)
        console.print(tbl)
        success(f"Found [bold]{len(exif)}[/bold] EXIF fields.", console)
    else:
        info("No EXIF metadata found.", console)

    return {"file_type": file_info["file_type"], "exif": exif}

def cmd_strings(target: Path, args, console: Console) -> Dict[str, Any]:
    min_len = getattr(args, "min_len", 4)

    section("STRINGS EXTRACTION", console)
    info(f"Minimum string length: {min_len}", console)

    raw_strings = strings.extract_strings(target, min_len=min_len)
    deduped = strings.deduplicate(raw_strings)
    interesting = strings.filter_interesting(raw_strings)

    if not raw_strings:
        warn("No strings found.", console)
        return {"strings": []}

    if interesting:
        console.print(f"\n  [bold yellow]⚑ Interesting strings ({len(interesting)} found):[/bold yellow]")
        tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
        tbl.add_column("Offset",     style="dim", width=12)
        tbl.add_column("String",     style="bold white")
        tbl.add_column("Categories", style="yellow")
        for offset, s, tags in interesting:
            tbl.add_row(hex(offset), s[:120], ", ".join(tags))
        console.print(tbl)

    verbose = getattr(args, "verbose", False)
    if verbose:
        console.print(f"\n  [dim]All strings ({len(deduped)} unique):[/dim]")
        for offset, s in deduped[:200]:
            console.print(f"  [dim]{hex(offset):>12}[/dim]  {s}")
        if len(deduped) > 200:
            warn(f"...and {len(deduped) - 200} more. Use -v and pipe to a pager.", console)
    else:
        info(f"Total strings: {len(raw_strings)}, unique: {len(deduped)}, "
             f"interesting: {len(interesting)}  (use -v for full list)", console)

    return {"strings": [s for _, s in deduped]}

def cmd_hex(target: Path, args, console: Console) -> Dict[str, Any]:
    num_bytes = getattr(args, "bytes", 256)

    section(f"HEX PREVIEW (first {num_bytes} bytes)", console)

    lines = hexview.hexdump_from_file(target, num_bytes=num_bytes)

    console.print(f"  [dim]{'OFFSET':10}  {'HEX':47}  ASCII[/dim]")
    console.print(f"  [dim]{'─'*10}  {'─'*47}  {'─'*16}[/dim]")

    for line in lines:

        parts = line.split("|", 1)
        if len(parts) == 2:
            console.print(f"[cyan]{parts[0]}[/cyan][dim]|{parts[1]}[/dim]")
        else:
            console.print(f"[cyan]{line}[/cyan]")

    with open(target, "rb") as fh:
        first8 = fh.read(8)
    magic_hex = hexview.highlight_magic(first8)
    info(f"Magic bytes: [bold yellow]{magic_hex}[/bold yellow]", console)

    return {}

def cmd_entropy(target: Path, args, console: Console) -> Dict[str, Any]:
    section("ENTROPY ANALYSIS", console)

    with open(target, "rb") as fh:
        data = fh.read()

    h = entropy.shannon_entropy(data)
    interp = entropy.interpret_entropy(h)

    bar = _entropy_bar(h)
    console.print(f"\n  Entropy:  [bold {interp['color']}]{h:.4f} / 8.0000[/bold {interp['color']}]  {bar}")
    console.print(f"  Rating:   [bold {interp['color']}]{interp['label']}[/bold {interp['color']}]")
    console.print(f"  Meaning:  [dim]{interp['description']}[/dim]\n")

    if len(data) > 512:
        hot_regions = entropy.find_high_entropy_regions(data, threshold=7.2)
        if hot_regions:
            warn(f"Found {len(hot_regions)} high-entropy region(s):", console)
            for start, end, peak in hot_regions[:10]:
                console.print(
                    f"    [yellow]{hex(start)}[/yellow] → [yellow]{hex(end)}[/yellow]  "
                    f"peak entropy [bold red]{peak}[/bold red]"
                )
        else:
            info("No isolated high-entropy regions found.", console)

    return {"entropy": h}

def _entropy_bar(h: float, width: int = 30) -> str:
    filled = int((h / 8.0) * width)
    bar = "█" * filled + "░" * (width - filled)
    return f"[dim][[/dim]{bar}[dim]][/dim]"

def cmd_flags(target: Path, args, console: Console) -> Dict[str, Any]:
    extra_pattern = getattr(args, "pattern", None)

    section("FLAG SEARCH", console)
    info("Searching raw bytes, Base64-decoded content, and hex-decoded content...", console)

    findings = flagfinder.search_all(target, extra_pattern=extra_pattern)

    if not findings:
        info("No flag patterns detected.", console)
        return {"flags_found": []}

    tbl = Table(box=box.ROUNDED, show_header=True, header_style="bold green")
    tbl.add_column("Pattern",  style="cyan",       no_wrap=True)
    tbl.add_column("Offset",   style="dim",         width=12)
    tbl.add_column("Match",    style="bold yellow")

    for name, offset, match_str in findings:
        tbl.add_row(name, hex(offset), match_str)

    console.print(tbl)
    success(f"[bold green]{len(findings)} flag candidate(s) found![/bold green]", console)

    return {"flags_found": [m for _, _, m in findings]}

def run_all(target: Path, args, console: Console) -> Dict[str, Any]:
    results: Dict[str, Any] = {}

    r = cmd_metadata(target, args, console)
    results.update(r)

    r = cmd_strings(target, args, console)
    results.update(r)

    r = cmd_hex(target, args, console)
    results.update(r)

    r = cmd_entropy(target, args, console)
    results.update(r)

    r = cmd_flags(target, args, console)
    results.update(r)

    from commands.detect import cmd_detect
    r = cmd_detect(target, args, console)
    results.update(r)

    from commands.extract import cmd_extract_scan_only
    r = cmd_extract_scan_only(target, args, console)
    results.update(r)

    return results
