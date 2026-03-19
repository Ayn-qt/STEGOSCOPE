
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, Any, Optional, List

def is_available(tool: str) -> bool:
    return shutil.which(tool) is not None

def available_tools() -> Dict[str, bool]:
    return {
        "steghide":    is_available("steghide"),
        "outguess":    is_available("outguess"),
        "stegcracker": is_available("stegcracker"),
        "zsteg":       is_available("zsteg"),
        "foremost":    is_available("foremost"),
        "exiftool":    is_available("exiftool"),
    }

COMMON_PASSWORDS = [
    "",
    "password",
    "secret",
    "hidden",
    "stego",
    "steghide",
    "flag",
    "ctf",
    "admin",
    "123456",
    "letmein",
    "passw0rd",
    "root",
    "toor",
    "hack",
    "1234",
    "qwerty",
    "abc123",
    "test",
    "guest",
]

def steghide_extract(
    filepath: Path,
    password: str = "",
    out_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    if not is_available("steghide"):
        return {
            "tool": "steghide",
            "success": False,
            "error": "steghide is not installed. Install from: https://steghide.sourceforge.net",
        }

    out_dir = out_dir or filepath.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"steghide_extracted_{filepath.stem}.bin"

    try:
        result = subprocess.run(
            [
                "steghide", "extract",
                "-sf", str(filepath),
                "-p", password,
                "-xf", str(out_file),
                "-f",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        combined = result.stdout + result.stderr
        success = result.returncode == 0 and out_file.exists()

        return {
            "tool":      "steghide",
            "success":   success,
            "output":    combined.strip(),
            "extracted": str(out_file) if success else None,
            "password":  password if success else None,
            "error":     None if success else combined.strip(),
        }

    except subprocess.TimeoutExpired:
        return {"tool": "steghide", "success": False, "error": "Timed out (>30s)"}
    except Exception as exc:
        return {"tool": "steghide", "success": False, "error": str(exc)}

def steghide_auto(
    filepath: Path,
    out_dir: Optional[Path] = None,
    extra_passwords: Optional[List[str]] = None,
) -> Dict[str, Any]:
    passwords = list(COMMON_PASSWORDS)
    if extra_passwords:
        passwords = list(extra_passwords) + passwords

    last_result = None
    for pwd in passwords:
        result = steghide_extract(filepath, password=pwd, out_dir=out_dir)
        last_result = result
        if result["success"]:
            result["tried_passwords"] = passwords.index(pwd) + 1
            return result

    if last_result:
        last_result["tried_passwords"] = len(passwords)
    return last_result or {"tool": "steghide", "success": False, "error": "No passwords worked"}

def outguess_extract(
    filepath: Path,
    out_dir: Optional[Path] = None,
    password: Optional[str] = None,
) -> Dict[str, Any]:
    if not is_available("outguess"):
        return {
            "tool": "outguess",
            "success": False,
            "error": "outguess is not installed. Install: sudo apt install outguess",
        }

    out_dir = out_dir or filepath.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"outguess_extracted_{filepath.stem}.txt"

    cmd = ["outguess", "-r", str(filepath), str(out_file)]
    if password:
        cmd += ["-k", password]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )

        combined = result.stdout + result.stderr
        success = result.returncode == 0 and out_file.exists() and out_file.stat().st_size > 0

        return {
            "tool":      "outguess",
            "success":   success,
            "output":    combined.strip(),
            "extracted": str(out_file) if success else None,
            "password":  password,
            "error":     None if success else combined.strip(),
        }

    except subprocess.TimeoutExpired:
        return {"tool": "outguess", "success": False, "error": "Timed out (>30s)"}
    except Exception as exc:
        return {"tool": "outguess", "success": False, "error": str(exc)}

def stegcracker_crack(
    filepath: Path,
    wordlist: Optional[str] = None,
    out_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    if not is_available("stegcracker"):
        return {
            "tool": "stegcracker",
            "success": False,
            "error": (
                "stegcracker is not installed.\n"
                "Install: pip install stegcracker\n"
                "Requires: steghide to also be installed"
            ),
        }

    if not wordlist:
        candidates = [
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/wordlists/rockyou.txt.gz",
            "rockyou.txt",
        ]
        wordlist = next((w for w in candidates if Path(w).exists()), None)
        if not wordlist:
            return {
                "tool": "stegcracker",
                "success": False,
                "error": (
                    "No wordlist found. Download rockyou.txt or specify one with --wordlist.\n"
                    "Download: https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
                ),
            }

    out_dir = out_dir or filepath.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        result = subprocess.run(
            ["stegcracker", str(filepath), wordlist],
            capture_output=True,
            text=True,
            timeout=300,
        )

        combined = result.stdout + result.stderr

        password = None
        extracted = None
        for line in combined.splitlines():
            if "password:" in line.lower():
                password = line.split(":")[-1].strip()
            if "saved to" in line.lower() or "decoded" in line.lower():
                parts = line.split()
                for p in parts:
                    if Path(p).exists():
                        extracted = p

        success = result.returncode == 0 and password is not None

        return {
            "tool":      "stegcracker",
            "success":   success,
            "output":    combined.strip(),
            "extracted": extracted,
            "password":  password,
            "error":     None if success else "Password not found in wordlist",
        }

    except subprocess.TimeoutExpired:
        return {"tool": "stegcracker", "success": False,
                "error": "Timed out after 5 minutes — try a smaller wordlist"}
    except Exception as exc:
        return {"tool": "stegcracker", "success": False, "error": str(exc)}

def zsteg_scan(filepath: Path, all_checks: bool = True) -> Dict[str, Any]:
    if not is_available("zsteg"):
        return {
            "tool": "zsteg",
            "success": False,
            "error": (
                "zsteg is not installed.\n"
                "Install: gem install zsteg  (requires Ruby)\n"
                "Windows: install Ruby from https://rubyinstaller.org then run: gem install zsteg"
            ),
        }

    cmd = ["zsteg", "-a" if all_checks else "", str(filepath)]
    cmd = [c for c in cmd if c]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )

        combined = result.stdout + result.stderr

        findings = []
        for line in combined.splitlines():
            if "text:" in line or "file:" in line or "flag" in line.lower():
                findings.append(line.strip())

        return {
            "tool":     "zsteg",
            "success":  True,
            "output":   combined.strip(),
            "findings": findings,
            "error":    None,
        }

    except subprocess.TimeoutExpired:
        return {"tool": "zsteg", "success": False, "error": "Timed out (>120s)"}
    except Exception as exc:
        return {"tool": "zsteg", "success": False, "error": str(exc)}

def exiftool_scan(filepath: Path) -> Dict[str, Any]:
    if not is_available("exiftool"):
        return {
            "tool": "exiftool",
            "success": False,
            "error": (
                "exiftool is not installed.\n"
                "Install: https://exiftool.org  or  choco install exiftool  (Windows)"
            ),
        }

    try:
        result = subprocess.run(
            ["exiftool", str(filepath)],
            capture_output=True,
            text=True,
            timeout=30,
        )

        lines = result.stdout.strip().splitlines()
        fields = {}
        for line in lines:
            if ":" in line:
                key, _, value = line.partition(":")
                fields[key.strip()] = value.strip()

        return {
            "tool":    "exiftool",
            "success": True,
            "output":  result.stdout.strip(),
            "fields":  fields,
            "error":   None,
        }

    except subprocess.TimeoutExpired:
        return {"tool": "exiftool", "success": False, "error": "Timed out"}
    except Exception as exc:
        return {"tool": "exiftool", "success": False, "error": str(exc)}
