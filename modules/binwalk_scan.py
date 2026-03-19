
import subprocess
import shutil
from pathlib import Path
from typing import List, Dict, Optional

def is_binwalk_available() -> bool:
    return shutil.which("binwalk") is not None

def run_binwalk_scan(filepath: Path) -> Optional[List[Dict]]:
    if not is_binwalk_available():
        return None

    try:
        result = subprocess.run(
            ["binwalk", "--signature", str(filepath)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        return _parse_binwalk_output(result.stdout)
    except subprocess.TimeoutExpired:
        return []
    except Exception:
        return None

def run_binwalk_extract(filepath: Path, out_dir: str) -> Optional[str]:
    if not is_binwalk_available():
        return None

    try:
        result = subprocess.run(
            ["binwalk", "--extract", "--directory", out_dir, str(filepath)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "Binwalk extraction timed out (>120s)."
    except Exception as exc:
        return f"Binwalk error: {exc}"

def _parse_binwalk_output(output: str) -> List[Dict]:
    findings = []
    lines = output.strip().splitlines()

    for line in lines:

        if not line or line.startswith("DECIMAL") or line.startswith("---"):
            continue

        parts = line.split(None, 2)
        if len(parts) >= 3:
            try:
                offset = int(parts[0])
                hex_offset = parts[1]
                description = parts[2].strip()
                findings.append({
                    "offset":      offset,
                    "hex_offset":  hex_offset,
                    "description": description,
                })
            except (ValueError, IndexError):
                continue

    return findings
