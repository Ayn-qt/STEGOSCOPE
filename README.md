# 🔬 StegoScope

**CTF Steganography & Digital Forensics Automation Tool**

StegoScope is a modular Python CLI for rapid forensic triage of images,
audio files, and arbitrary binaries in CTF competitions and red-team
engagements.

---

## Features

| Module          | What it does                                                   |
|-----------------|----------------------------------------------------------------|
| **metadata**    | EXIF extraction (Pillow + exifread), PNG chunk analysis        |
| **strings**     | ASCII/UTF-16 string extraction with keyword classification     |
| **hex**         | Classic hex-dump preview with ASCII sidebar                    |
| **entropy**     | Shannon entropy + sliding-window hotspot detection             |
| **flags**       | Regex search for flag{}, picoCTF{}, HTB{}, base64/hex variants |
| **detect**      | LSB chi-square, palette anomalies, WAV channel asymmetry       |
| **extract**     | binwalk integration + built-in magic-byte file carver          |
| **auto**        | All checks + prioritised suggestions report                    |

---

## Installation

```bash
# 1. Clone / download the project
git clone https://github.com/yourname/stegoscope.git
cd stegoscope

# 2. Create a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. (Optional) Install binwalk for deeper extraction
#    macOS:  brew install binwalk
#    Debian: sudo apt install binwalk
#    pip:    pip install binwalk

# 5. Make the CLI executable (Linux/macOS)
chmod +x main.py

# 6. Optionally add to PATH
ln -s $(pwd)/main.py /usr/local/bin/stegoscope
```

---

## Usage

```
stegoscope <command> <file> [options]
```

### Commands

```bash
# Full analysis suite (metadata + strings + hex + entropy + flags + detect + scan)
stegoscope analyze mystery.png

# Auto mode — same as analyze but adds a ranked suggestion block at the end
stegoscope auto mystery.png

# Individual modules
stegoscope metadata  mystery.png          # EXIF + file info + PNG chunks
stegoscope strings   mystery.png          # Extract ASCII strings
stegoscope strings   mystery.png --min-len 8   # Longer minimum length
stegoscope hex       mystery.png          # First 256 bytes hex dump
stegoscope hex       mystery.png --bytes 512   # More bytes
stegoscope entropy   mystery.png          # Shannon entropy + hotspots
stegoscope flags     mystery.png          # Flag pattern search
stegoscope flags     mystery.png --pattern "ACME\{[^}]+\}"  # Custom regex
stegoscope detect    mystery.png          # LSB / stego heuristics
stegoscope extract   mystery.png          # Extract embedded files
stegoscope extract   mystery.png --out-dir ./carved   # Custom output dir

# Verbose mode (more output)
stegoscope strings   mystery.png -v
stegoscope analyze   mystery.png -v
```

---

## Example Output

```
 ____  _                  ____                       
/ ___|| |_ ___  __ _  ___/ ___|  ___ ___  _ __   ___ 
\___ \| __/ _ \/ _` |/ _ \___ \ / __/ _ \| '_ \ / _ \
 ___) | ||  __/ (_| | (_) |__) | (_| (_) | |_) |  __/
|____/ \__\___|\__, |\___/____/ \___\___/| .__/ \___|
               |___/                     |_|         
  CTF Steganography & Digital Forensics Automation Tool  v1.0.0
────────────────────────────────────────────────────────────────

─────────────────────── FILE INFO ────────────────────────────
[+] File: mystery.png
  Path:         /home/ctf/challenges/mystery.png
  Size:         142.3 KB (145,720 bytes)
  Type:         PNG Image
  Extension:    .png
  Modified:     2025-03-01 14:22:08
  Permissions:  0644

─────────────────────── ENTROPY ANALYSIS ──────────────────────
  Entropy:  7.9201 / 8.0000  [████████████████████████████░░]
  Rating:   Extremely High
  Meaning:  Almost certainly encrypted/compressed. Strong stego indicator.

[!] Found 1 high-entropy region(s):
    0x8400 → 0x22000  peak entropy 7.98

─────────────────────── FLAG SEARCH ───────────────────────────
[*] Searching raw bytes, Base64-decoded, and hex-decoded content...
╭─────────────────┬────────────┬───────────────────────────╮
│ Pattern         │ Offset     │ Match                     │
├─────────────────┼────────────┼───────────────────────────┤
│ picoCTF{}       │ 0x2200     │ picoCTF{st3g0_master_2024}│
╰─────────────────┴────────────┴───────────────────────────╯
[+] 1 flag candidate(s) found!

─────────────────────── SUGGESTIONS ───────────────────────────
  [01] FLAG CANDIDATE(S) FOUND! Review the [FLAGFINDER] section above.
  [02] High entropy — try binwalk -e or foremost.
  [03] Image file — consider running zsteg (PNG/BMP LSB analysis).
```

---

## Project Structure

```
stegoscope/
│
├── main.py                  # CLI entry point, argument parser, dispatcher
├── requirements.txt
├── README.md
│
├── core/                    # Pure-logic modules (no CLI I/O)
│   ├── metadata.py          # EXIF, magic bytes, PNG chunks
│   ├── strings.py           # String extraction & classification
│   ├── hexview.py           # Hex dump generation
│   ├── entropy.py           # Shannon entropy, sliding window
│   ├── flagfinder.py        # CTF flag regex + encoding search
│   └── utils.py             # Banner, validators, Rich helpers
│
├── modules/                 # Higher-level analysis modules
│   ├── binwalk_scan.py      # binwalk subprocess wrapper
│   ├── stego_detect.py      # LSB, chi-square, WAV, palette checks
│   └── extractors.py        # Built-in magic-byte carver
│
└── commands/                # CLI command handlers (output + routing)
    ├── analyze.py            # metadata, strings, hex, entropy, flags, run_all
    ├── detect.py             # stego detection display
    └── extract.py            # extraction display
```

---

## Adding a New Module

1. Create `core/my_module.py` with pure analysis logic (returns dicts/lists).
2. Create (or extend) a handler in `commands/` that calls the core module and
   prints results using `rich`.
3. Register a new sub-command in `main.py`'s `build_parser()`.
4. Optionally call your module from `run_all()` in `commands/analyze.py`.

---

## External Tool Recommendations

After running StegoScope, these external tools complement it well:

| Tool         | Use case                              | Install                  |
|--------------|---------------------------------------|--------------------------|
| `zsteg`      | PNG/BMP LSB deep scan                 | `gem install zsteg`      |
| `steghide`   | JPEG/BMP passphrase extraction        | `apt install steghide`   |
| `stegsolve`  | Bit-plane image analysis (GUI)        | Java JAR download        |
| `exiftool`   | Deep EXIF/metadata extraction         | `apt install exiftool`   |
| `foremost`   | File carving alternative to binwalk   | `apt install foremost`   |
| `audacity`   | Audio spectrogram / LSB analysis      | `apt install audacity`   |
| `volatility` | Memory image forensics                | pip install volatility3  |

---

## License

MIT — free for CTF, educational, and security research use.
