
from pathlib import Path
from typing import Optional, Dict, Any

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.rule import Rule
from rich import box

BANNER = r"""
  ____  _                  ____                       
/ ___|| |_ ___  __ _  ___/ ___|  ___ ___  _ __   ___ 
\___ \| __/ _ \/ _` |/ _ \___ \ / __/ _ \| '_ \ / _ \
 ___) | ||  __/ (_| | (_) |__) | (_| (_) | |_) |  __/
|____/ \__\___|\__, |\___/____/ \___\___/| .__/ \___|
               |___/                     |_|         
"""

def banner(console: Console) -> None:
    styled = Text(BANNER, style="bold cyan")
    subtitle = Text("  CTF Steganography & Digital Forensics Automation Tool  v1.0.0",
                    style="dim white")
    console.print(styled)
    console.print(subtitle)
    console.print(Rule(style="cyan dim"))
    console.print()

def validate_file(filepath: str, console: Console) -> Optional[Path]:
    p = Path(filepath)
    if not p.exists():
        console.print(f"[bold red][-] Error:[/bold red] File not found: [yellow]{filepath}[/yellow]")
        return None
    if not p.is_file():
        console.print(f"[bold red][-] Error:[/bold red] Not a file: [yellow]{filepath}[/yellow]")
        return None
    if not p.stat().st_size:
        console.print(f"[bold red][-] Error:[/bold red] File is empty: [yellow]{filepath}[/yellow]")
        return None
    return p

def section(title: str, console: Console) -> None:
    console.print()
    console.print(Rule(f"[bold green] {title} [/bold green]", style="green dim"))

def success(msg: str, console: Console) -> None:
    console.print(f"[bold green][+][/bold green] {msg}")

def info(msg: str, console: Console) -> None:
    console.print(f"[bold cyan][*][/bold cyan] {msg}")

def warn(msg: str, console: Console) -> None:
    console.print(f"[bold yellow][!][/bold yellow] {msg}")

def error(msg: str, console: Console) -> None:
    console.print(f"[bold red][-][/bold red] {msg}")

def finding(label: str, value: str, console: Console) -> None:
    console.print(f"  [bold white]{label}:[/bold white] [cyan]{value}[/cyan]")

def print_suggestions(results: Dict[str, Any], console: Console) -> None:
    section("SUGGESTIONS", console)
    suggestions = []

    entropy = results.get("entropy", 0.0)
    flags_found = results.get("flags_found", [])
    strings = results.get("strings", [])
    file_type = results.get("file_type", "").lower()
    stego_hints = results.get("stego_hints", [])
    embedded = results.get("embedded_files", [])

    if entropy > 7.5:
        suggestions.append("High entropy detected — file may contain encrypted/compressed data. Try [bold]binwalk -e[/bold] or [bold]foremost[/bold].")
    if entropy < 1.0:
        suggestions.append("Very low entropy — file may be padded or contain hidden null bytes. Inspect raw hex carefully.")

    if flags_found:
        suggestions.append(f"[bold green]FLAG CANDIDATE(S) FOUND![/bold green] Review the [FLAGFINDER] section above.")

    for s in strings:
        lw = s.lower()
        if any(kw in lw for kw in ["password", "pass", "secret", "key", "token", "hidden"]):
            suggestions.append(f"Interesting string found: [yellow]{s}[/yellow] — potential credential or hint.")
            break

    if "png" in file_type or "bmp" in file_type:
        suggestions.append("Image file detected — consider running [bold]zsteg[/bold] (PNG/BMP LSB analysis).")
        suggestions.append("Try [bold]stegsolve[/bold] for bit-plane analysis and colour channel inspection.")

    if "jpeg" in file_type or "jpg" in file_type:
        suggestions.append("JPEG detected — run [bold]steghide extract -sf file.jpg[/bold] with empty passphrase.")
        suggestions.append("Check for JFIF/EXIF trailer data with [bold]exiftool[/bold].")

    if "wav" in file_type or "mp3" in file_type or "audio" in file_type:
        suggestions.append("Audio file — open in [bold]Audacity[/bold] and inspect spectrogram for hidden text.")
        suggestions.append("Try [bold]mp3stego[/bold] or [bold]DeepSound[/bold] for audio steganography.")

    if stego_hints:
        suggestions.append("LSB anomalies detected — try [bold]zsteg -a file.png[/bold] or [bold]stegsolve[/bold].")

    if embedded:
        suggestions.append("Embedded files found — run [bold]binwalk -e --run-as=root file[/bold] to extract.")

    if not suggestions:
        suggestions.append("No immediate indicators found. Try manual inspection or specialised tools like [bold]stegdetect[/bold].")

    for i, s in enumerate(suggestions, 1):
        console.print(f"  [bold magenta][{i:02d}][/bold magenta] {s}")

    console.print()
