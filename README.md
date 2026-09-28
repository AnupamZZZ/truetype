# truetype

![CI](https://github.com/YOUR-USERNAME/truetype/actions/workflows/ci.yml/badge.svg)

Find out what a file **really** is, no matter what its name says.
Attackers often disguise an executable as `holiday.png` or `movie.mp4`. `truetype` reads the
file's actual bytes and warns you when the name and content don't match.

## What it detects

- Executables (Windows PE, Linux ELF, macOS Mach-O, `.lnk`) renamed to images, video, audio or documents
- Double extensions (`invoice.pdf.exe`) and Unicode right-to-left override tricks
- Data appended after a valid PNG/JPEG/GIF end marker
- Executable headers hidden inside otherwise normal files
- Script-like text inside media files, and executables inside ZIP-based files

## Install

```bash
pip install git+https://github.com/YOUR-USERNAME/truetype.git
```

## Usage

```bash
truetype suspicious.png
truetype ~/Downloads -r -q        # scan a folder recursively, show only problems
truetype ~/Downloads -r --json    # machine-readable output
python -m truetype file.mp4       # without installing the command
```

Exit codes: `0` clean, `1` suspicious, `2` dangerous (handy for scripts and CI).

## Desktop app (no terminal needed)

```bash
pip install tkinterdnd2      # optional, enables drag-and-drop
python -m truetype.gui       # or double-click TrueType.pyw on Windows
```

Drop files or folders on the window (or use the buttons) and get a green / amber / red verdict.
Build a standalone app with no Python required:

```bash
pip install pyinstaller tkinterdnd2
pyinstaller --onefile --windowed --name TrueType --collect-all tkinterdnd2 --paths src TrueType.pyw
```

The result is in `dist/`.

## As a library

```python
from truetype import analyze, verdict
result = analyze("photo.png")
print(verdict(result["findings"]), result["detected"])
```

## Limitations

This is a signature-based heuristic checker, not antivirus. Encrypted or compressed payloads
can evade it, and it does not inspect Office macros or PDF JavaScript. Use it alongside, not
instead of, proper endpoint protection.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT
