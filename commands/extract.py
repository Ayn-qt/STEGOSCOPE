
from pathlib import Path
from typing import Any, Dict

from rich.console import Console
from rich.table import Table
from rich import box

from modules.binwalk_scan import (
    is_binwalk_available,
    run_binwalk_scan,
    run_binwalk_extract,
)
from modules.extractors import scan_for_embedded, carve_embedded
from core.utils import section, success, info, warn, error, finding

def cmd_extract(target: Path, args, console: Console) -> Dict[str, Any]:
    out_dir = Path(getattr(args, "out_dir", "./stegoscope_extracted"))

    section("EMBEDDED FILE EXTRACTION", console)

    if is_binwalk_available():
        success("binwalk is available — using it for extraction.", console)
        info(f"Output directory: {out_dir}", console)

        scan_results = run_binwalk_scan(target)
        if scan_results:
            _print_binwalk_table(scan_results, console)
        else:
            info("No embedded signatures found by binwalk.", console)
            return {"embedded_files": []}

        info("Running binwalk extraction...", console)
        bw_output = run_binwalk_extract(target, str(out_dir))
        if bw_output:
            console.print(f"\n[dim]{bw_output}[/dim]")

        success(f"Extraction complete. Check: [bold]{out_dir}[/bold]", console)
        return {"embedded_files": [r["description"] for r in scan_results]}

    warn("binwalk not found — using built-in signature scanner.", console)
    info("Install binwalk for deeper analysis: pip install binwalk", console)

    embedded = scan_for_embedded(target)

    if not embedded:
        info("No embedded file signatures detected.", console)
        return {"embedded_files": []}

    tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
    tbl.add_column("Offset",     style="dim",        width=12)
    tbl.add_column("Hex Offset", style="dim",        width=12)
    tbl.add_column("Type",       style="bold white")
    tbl.add_column("Remaining",  justify="right",    style="cyan")

    for item in embedded:
        tbl.add_row(
            str(item["offset"]),
            item["hex_offset"],
            item["name"],
            f"{item['remaining']:,} bytes",
        )
    console.print(tbl)

    info(f"Carving {len(embedded)} embedded file(s) to: {out_dir}", console)
    carved = carve_embedded(target, out_dir)

    if carved:
        success(f"Carved {len(carved)} file(s):", console)
        for c in carved:
            if "error" not in c:
                console.print(
                    f"  [bold green]✔[/bold green] [white]{c['name']}[/white] "
                    f"@ {hex(c['offset'])} → [cyan]{c['output']}[/cyan] "
                    f"({c['size']:,} bytes)"
                )
            else:
                console.print(
                    f"  [bold red]✘[/bold red] [white]{c['name']}[/white] "
                    f"@ {hex(c['offset'])} — {c['error']}"
                )
    else:
        warn("Carving produced no output files.", console)

    return {"embedded_files": [i["name"] for i in embedded]}

def cmd_extract_scan_only(target: Path, args, console: Console) -> Dict[str, Any]:
    section("EMBEDDED FILE SCAN", console)

    if is_binwalk_available():
        scan_results = run_binwalk_scan(target)
        if scan_results:
            _print_binwalk_table(scan_results, console)
            warn(f"{len(scan_results)} embedded structure(s) detected. "
                 "Run [bold]stegoscope extract[/bold] to carve them out.", console)
            return {"embedded_files": [r["description"] for r in scan_results]}
        else:
            info("No embedded structures found by binwalk.", console)
            return {"embedded_files": []}

    embedded = scan_for_embedded(target)
    if embedded:
        for item in embedded:
            warn(f"Embedded [bold]{item['name']}[/bold] at offset {item['hex_offset']}", console)
        return {"embedded_files": [i["name"] for i in embedded]}
    else:
        info("No embedded file signatures found.", console)
        return {"embedded_files": []}

def _print_binwalk_table(scan_results, console: Console) -> None:
    tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
    tbl.add_column("Offset",      style="dim",        width=12)
    tbl.add_column("Hex Offset",  style="dim",        width=12)
    tbl.add_column("Description", style="bold white")

    for item in scan_results:
        tbl.add_row(str(item["offset"]), item["hex_offset"], item["description"])

    console.print(tbl)
