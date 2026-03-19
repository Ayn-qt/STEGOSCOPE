
from pathlib import Path
from typing import Any, Dict

from rich.console import Console
from rich.table import Table
from rich import box

from modules.stego_tools import (
    steghide_extract, steghide_auto,
    outguess_extract, stegcracker_crack,
    zsteg_scan, exiftool_scan,
    available_tools, COMMON_PASSWORDS,
)
from modules.stylesuxx import decode as stylesuxx_decode, encode as stylesuxx_encode, capacity
from core.utils import section, success, info, warn, error, finding

def cmd_toolkit(args, console: Console) -> None:
    section("EXTERNAL TOOL STATUS", console)

    tools = available_tools()

    tbl = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
    tbl.add_column("Tool",        style="bold white", width=14)
    tbl.add_column("Status",      width=16)
    tbl.add_column("Purpose",     style="dim")
    tbl.add_column("Install",     style="dim cyan")

    tool_info = {
        "steghide":    ("JPEG/BMP extraction with password",    "https://steghide.sourceforge.net"),
        "outguess":    ("JPEG DCT steganography extraction",    "sudo apt install outguess"),
        "stegcracker": ("Brute-force steghide passwords",       "pip install stegcracker"),
        "zsteg":       ("PNG/BMP deep LSB analysis",            "gem install zsteg"),
        "foremost":    ("File carving alternative to binwalk",  "sudo apt install foremost"),
        "exiftool":    ("Deep metadata extraction",             "https://exiftool.org"),
    }

    for tool, available in tools.items():
        purpose, install = tool_info.get(tool, ("", ""))
        status = "[bold green]✔  Installed[/bold green]" if available else "[bold red]✘  Missing[/bold red]"
        tbl.add_row(tool, status, purpose, install)

    console.print(tbl)
    console.print()
    installed = sum(1 for v in tools.values() if v)
    if installed == len(tools):
        success(f"All {len(tools)} tools installed — full capability available!", console)
    else:
        warn(f"{installed}/{len(tools)} tools installed. Install missing tools for full coverage.", console)

def cmd_stylesuxx(target: Path, args, console: Console) -> dict:

    from commands.analyze import cmd_metadata, cmd_strings, cmd_hex, cmd_entropy, cmd_flags
    from commands.detect import cmd_detect

    cmd_metadata(target, args, console)
    cmd_entropy(target, args, console)
    cmd_strings(target, args, console)
    cmd_hex(target, args, console)
    cmd_flags(target, args, console)
    cmd_detect(target, args, console)

    section("STYLESUXX DECODE", console)

    with open(target, "rb") as f:
        header = f.read(4)

    is_png  = header[:4] == b"\x89PNG"
    is_jpeg = header[:2] == b"\xff\xd8"

    if is_jpeg:
        warn("This file is a JPEG — stylesuxx encoding requires a lossless PNG.", console)
        warn("JPEG compression destroys hidden LSB data. Attempting anyway...", console)
    elif not is_png:
        warn(f"Unexpected file format (header: {header.hex()}) — results may be unreliable.", console)
    else:
        info("PNG file confirmed — lossless format, LSB data should be intact.", console)

    max_chars, max_bits = capacity(target)
    info(f"Image capacity: up to [cyan]{max_chars:,}[/cyan] characters", console)

    info("Decoding stylesuxx LSB message...", console)
    debug = getattr(args, "debug", False)
    if debug:
        console.print("  [dim]Debug mode — showing all attempts:[/dim]")
    try:
        message = stylesuxx_decode(target, debug=debug)
    except Exception as exc:
        error(f"Decode failed: {exc}", console)
        return {"stylesuxx": None}

    if message:
        success(f"[bold green]Message found![/bold green]", console)
        console.print()
        console.print(f"  [bold yellow]Hidden message:[/bold yellow]")
        console.print(f"  [green]{message[:1000]}[/green]")

        import re
        flag_re = re.compile(r'[A-Za-z]{2,15}\{[\x20-\x7e]{1,80}\}')
        flags = flag_re.findall(message)
        if flags:
            console.print()
            success(f"[bold green]FLAG(S) FOUND:[/bold green]", console)
            for f in flags:
                console.print(f"  [bold yellow]🚩 {f}[/bold yellow]")
    else:
        warn("No stylesuxx message found.", console)
        if is_jpeg:
            console.print()
            console.print("  [dim]This is likely because the JPEG compression destroyed the hidden data.[/dim]")
            console.print("  [dim]Get the original PNG file and try again.[/dim]")

    return {"stylesuxx": message}

    tools = available_tools()

    tbl = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
    tbl.add_column("Tool",        style="bold white", width=14)
    tbl.add_column("Status",      width=12)
    tbl.add_column("Purpose",     style="dim")
    tbl.add_column("Install",     style="dim cyan")

    tool_info = {
        "steghide":    ("JPEG/BMP extraction with password",    "https://steghide.sourceforge.net"),
        "outguess":    ("JPEG DCT steganography extraction",    "sudo apt install outguess"),
        "stegcracker": ("Brute-force steghide passwords",       "pip install stegcracker"),
        "zsteg":       ("PNG/BMP deep LSB analysis",            "gem install zsteg"),
        "foremost":    ("File carving alternative to binwalk",  "sudo apt install foremost"),
        "exiftool":    ("Deep metadata extraction",             "https://exiftool.org"),
    }

    for tool, available in tools.items():
        purpose, install = tool_info.get(tool, ("", ""))
        status = "[bold green]✔  Installed[/bold green]" if available else "[bold red]✘  Missing[/bold red]"
        tbl.add_row(tool, status, purpose, install)

    console.print(tbl)

    installed = sum(1 for v in tools.values() if v)
    console.print()
    if installed == len(tools):
        success(f"All {len(tools)} tools installed — full capability available!", console)
    else:
        warn(f"{installed}/{len(tools)} tools installed. Install missing tools for full coverage.", console)

def cmd_steghide(target: Path, args, console: Console) -> Dict[str, Any]:
    password = getattr(args, "password", "") or ""
    out_dir = Path(getattr(args, "out_dir", "./stegoscope_extracted"))

    section("STEGHIDE EXTRACTION", console)

    if password:
        info(f"Trying password: [bold yellow]{password}[/bold yellow]", console)
    else:
        info("Trying empty password (most common in CTFs)...", console)

    result = steghide_extract(target, password=password, out_dir=out_dir)
    _print_tool_result(result, console)

    if not result["success"] and not password:
        warn("Empty password failed.", console)
        info("Tip: Run [bold cyan]stegoscope crack " + str(target) + "[/bold cyan] to auto-try common passwords.", console)

    return {"steghide": result}

def cmd_crack(target: Path, args, console: Console) -> Dict[str, Any]:
    wordlist  = getattr(args, "wordlist", None)
    out_dir   = Path(getattr(args, "out_dir", "./stegoscope_extracted"))
    extra_pwd = getattr(args, "password", None)

    section("PASSWORD CRACKING", console)

    info(f"Phase 1: Trying {len(COMMON_PASSWORDS)} common CTF passwords with steghide...", console)

    extra = [extra_pwd] if extra_pwd else None
    result = steghide_auto(target, out_dir=out_dir, extra_passwords=extra)

    tried = result.get("tried_passwords", len(COMMON_PASSWORDS))

    if result["success"]:
        success(f"Password found after {tried} attempt(s)!", console)
        _print_tool_result(result, console)
        return {"crack": result}
    else:
        warn(f"No match in {tried} common passwords.", console)

    if wordlist:
        info(f"Phase 2: Running stegcracker with wordlist: [cyan]{wordlist}[/cyan]", console)
        warn("This may take a while depending on wordlist size...", console)

        sc_result = stegcracker_crack(target, wordlist=wordlist, out_dir=out_dir)
        _print_tool_result(sc_result, console)

        if sc_result["success"]:
            return {"crack": sc_result}
        else:
            error("Password not found in wordlist.", console)
            return {"crack": sc_result}
    else:
        info("Tip: Run with [bold cyan]--wordlist rockyou.txt[/bold cyan] for a full dictionary attack.", console)
        info("Download rockyou.txt: https://github.com/brannondorsey/naive-hashcat/releases", console)

    console.print()
    info("Trying outguess (no password required)...", console)
    og_result = outguess_extract(target, out_dir=out_dir)
    _print_tool_result(og_result, console)

    return {"crack": result, "outguess": og_result}

def cmd_zsteg(target: Path, args, console: Console) -> Dict[str, Any]:
    section("ZSTEG DEEP LSB SCAN", console)

    info("Running zsteg -a (all bit planes, all channels)...", console)
    result = zsteg_scan(target, all_checks=True)

    if not result["success"]:
        _print_tool_result(result, console)
        return {"zsteg": result}

    findings = result.get("findings", [])
    if findings:
        success(f"zsteg found {len(findings)} interesting result(s):", console)
        for f in findings:
            console.print(f"  [bold green]▶[/bold green] {f}")
    else:
        info("zsteg found no obvious hidden data.", console)

    if getattr(args, "verbose", False):
        console.print()
        console.print("[dim]Full zsteg output:[/dim]")
        console.print(f"[dim]{result['output']}[/dim]")

    return {"zsteg": result}

def cmd_outguess(target: Path, args, console: Console) -> Dict[str, Any]:
    password = getattr(args, "password", None)
    out_dir  = Path(getattr(args, "out_dir", "./stegoscope_extracted"))

    section("OUTGUESS EXTRACTION", console)
    info("Running outguess extraction...", console)

    result = outguess_extract(target, out_dir=out_dir, password=password)
    _print_tool_result(result, console)
    return {"outguess": result}

def cmd_exiftool(target: Path, args, console: Console) -> Dict[str, Any]:
    section("EXIFTOOL METADATA", console)

    result = exiftool_scan(target)

    if not result["success"]:
        _print_tool_result(result, console)
        return {"exiftool": result}

    fields = result.get("fields", {})
    if not fields:
        info("No metadata found.", console)
        return {"exiftool": result}

    tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
    tbl.add_column("Tag",   style="bold white", no_wrap=True, width=30)
    tbl.add_column("Value", style="cyan")

    suspicious_keys = {"comment", "description", "usercomment", "xpcomment",
                       "software", "artist", "copyright", "imagedescription",
                       "documentname", "pagename"}

    for key, value in fields.items():
        display_val = value if len(value) <= 100 else value[:97] + "..."
        if key.lower().replace(" ", "") in suspicious_keys:
            tbl.add_row(f"[yellow]{key}[/yellow]", f"[yellow]{display_val}[/yellow]")
        else:
            tbl.add_row(key, display_val)

    console.print(tbl)
    success(f"Found {len(fields)} metadata fields.", console)
    return {"exiftool": result}

def _print_tool_result(result: Dict[str, Any], console: Console) -> None:
    tool = result.get("tool", "tool")

    if result.get("success"):
        success(f"[bold green]{tool} succeeded![/bold green]", console)
        if result.get("password") is not None:
            finding("Password",   repr(result["password"]), console)
        if result.get("extracted"):
            finding("Saved to",   result["extracted"], console)

            try:
                content = Path(result["extracted"]).read_bytes()
                printable = bytes(b for b in content if 0x20 <= b <= 0x7e)
                if printable:
                    console.print(f"\n  [bold yellow]Extracted content:[/bold yellow]")
                    console.print(f"  [green]{printable[:500].decode('ascii', errors='replace')}[/green]")
            except Exception:
                pass
        if result.get("output"):
            console.print(f"  [dim]{result['output'][:300]}[/dim]")
    else:
        err = result.get("error", "Unknown error")
        if "not installed" in err:
            warn(f"{tool} is not installed.", console)

            for line in err.splitlines():
                console.print(f"  [dim]{line}[/dim]")
        else:
            error(f"{tool} failed: {err[:200]}", console)
