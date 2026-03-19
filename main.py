
import sys
import argparse
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from commands.analyze import cmd_metadata, cmd_strings, cmd_hex, cmd_entropy, cmd_flags
from commands.detect import cmd_detect
from commands.extract import cmd_extract
from commands.crack import (
    cmd_steghide, cmd_crack, cmd_zsteg, cmd_outguess,
    cmd_exiftool, cmd_toolkit, cmd_stylesuxx
)
from core.utils import banner, validate_file

console = Console()

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stegoscope",
        description="StegoScope — CTF Steganography & Digital Forensics Automation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  stegoscope analyze  file.png         Run full analysis suite
  stegoscope auto     file.png         Auto-mode: all checks + summary report
  stegoscope metadata file.png         Extract EXIF/file metadata
  stegoscope strings  file.png         Extract readable ASCII strings
  stegoscope hex      file.png         Hex preview of first 256 bytes
  stegoscope entropy  file.png         Calculate byte entropy
  stegoscope flags    file.png         Search for CTF flag patterns
  stegoscope detect   file.png         Detect stego anomalies (LSB, etc.)
  stegoscope extract  file.png         Run binwalk / embedded file extraction

  stegoscope steghide file.jpg         Extract with steghide (empty password)
  stegoscope steghide file.jpg -p abc  Extract with known password
  stegoscope crack    file.jpg         Auto brute-force common passwords
  stegoscope crack    file.jpg --wordlist rockyou.txt   Full wordlist attack
  stegoscope zsteg    file.png         Deep LSB scan via zsteg
  stegoscope outguess file.jpg         Extract via outguess
  stegoscope exiftool file.jpg         Deep metadata via exiftool
  stegoscope toolkit                   Show all external tool status
        """,
    )

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    def add_file_arg(p):
        p.add_argument("file", type=str, help="Target file to analyse")
        p.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
        p.add_argument("-o", "--output", type=str, help="Write report to file")

    p_analyze = subparsers.add_parser("analyze", help="Run full analysis suite on a file")
    add_file_arg(p_analyze)

    p_auto = subparsers.add_parser("auto", help="Auto mode: all checks + summary report")
    add_file_arg(p_auto)

    p_meta = subparsers.add_parser("metadata", help="Extract EXIF and file metadata")
    add_file_arg(p_meta)

    p_strings = subparsers.add_parser("strings", help="Extract ASCII strings from binary")
    add_file_arg(p_strings)
    p_strings.add_argument("--min-len", type=int, default=4, help="Minimum string length (default: 4)")

    p_hex = subparsers.add_parser("hex", help="Hex dump preview of file")
    add_file_arg(p_hex)
    p_hex.add_argument("--bytes", type=int, default=256, help="Number of bytes to preview (default: 256)")

    p_entropy = subparsers.add_parser("entropy", help="Calculate byte entropy")
    add_file_arg(p_entropy)

    p_flags = subparsers.add_parser("flags", help="Search for CTF flag patterns")
    add_file_arg(p_flags)
    p_flags.add_argument("--pattern", type=str, help="Additional custom regex pattern to search")

    p_detect = subparsers.add_parser("detect", help="Detect steganographic anomalies")
    add_file_arg(p_detect)

    p_extract = subparsers.add_parser("extract", help="Extract embedded files via binwalk")
    add_file_arg(p_extract)
    p_extract.add_argument("--out-dir", type=str, default="./stegoscope_extracted",
                           help="Output directory for extracted files")

    p_steghide = subparsers.add_parser("steghide", help="Extract with steghide (known/empty password)")
    add_file_arg(p_steghide)
    p_steghide.add_argument("-p", "--password", type=str, default="",
                            help="Password to try (default: empty)")
    p_steghide.add_argument("--out-dir", type=str, default="./stegoscope_extracted")

    p_crack = subparsers.add_parser("crack", help="Brute-force stego password (steghide + stegcracker)")
    add_file_arg(p_crack)
    p_crack.add_argument("-p", "--password", type=str, help="Extra password to try first")
    p_crack.add_argument("--wordlist", type=str, help="Path to wordlist file for stegcracker")
    p_crack.add_argument("--out-dir", type=str, default="./stegoscope_extracted")

    p_zsteg = subparsers.add_parser("zsteg", help="Deep LSB scan via zsteg (PNG/BMP)")
    add_file_arg(p_zsteg)

    p_outguess = subparsers.add_parser("outguess", help="Extract hidden data via outguess (JPEG)")
    add_file_arg(p_outguess)
    p_outguess.add_argument("-p", "--password", type=str, help="Optional password")
    p_outguess.add_argument("--out-dir", type=str, default="./stegoscope_extracted")

    p_exiftool = subparsers.add_parser("exiftool", help="Deep metadata extraction via exiftool")
    add_file_arg(p_exiftool)

    p_stylesuxx = subparsers.add_parser("stylesuxx", help="Decode stylesuxx web steganography (stylesuxx.github.io)")
    add_file_arg(p_stylesuxx)
    p_stylesuxx.add_argument("--debug", action="store_true", help="Show all decode attempts with scores")

    p_toolkit = subparsers.add_parser("toolkit", help="Show status of all external tools")

    return parser

def main():
    banner(console)

    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "toolkit":
        cmd_toolkit(args, console)
        sys.exit(0)

    target = validate_file(args.file, console)
    if target is None:
        sys.exit(1)

    dispatch = {
        "analyze":  lambda: _run_analyze(args, target),
        "auto":     lambda: _run_auto(args, target),
        "metadata": lambda: cmd_metadata(target, args, console),
        "strings":  lambda: cmd_strings(target, args, console),
        "hex":      lambda: cmd_hex(target, args, console),
        "entropy":  lambda: cmd_entropy(target, args, console),
        "flags":    lambda: cmd_flags(target, args, console),
        "detect":   lambda: cmd_detect(target, args, console),
        "extract":  lambda: cmd_extract(target, args, console),
        "steghide":   lambda: cmd_steghide(target, args, console),
        "crack":      lambda: cmd_crack(target, args, console),
        "zsteg":      lambda: cmd_zsteg(target, args, console),
        "outguess":   lambda: cmd_outguess(target, args, console),
        "exiftool":   lambda: cmd_exiftool(target, args, console),
        "stylesuxx":  lambda: cmd_stylesuxx(target, args, console),
    }

    handler = dispatch.get(args.command)
    if handler:
        handler()
    else:
        console.print(f"[red]Unknown command: {args.command}[/red]")
        sys.exit(1)

def _run_analyze(args, target: Path):
    from commands.analyze import run_all
    run_all(target, args, console)

def _run_auto(args, target: Path):
    from commands.analyze import run_all
    from core.utils import print_suggestions
    results = run_all(target, args, console)
    print_suggestions(results, console)

if __name__ == "__main__":
    main()
