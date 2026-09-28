"""
truetype - detect what a file REALLY is, regardless of its name.

Catches:
  * extension/content mismatch (e.g. an .exe renamed to photo.png)
  * executables disguised as media/documents
  * double extensions (invoice.pdf.exe) and Unicode right-to-left tricks
  * data appended after a valid image (PNG/JPEG/GIF) end marker
  * executables embedded inside otherwise normal-looking files

Usage:
  python truetype.py file1.png movie.mp4
  python truetype.py ~/Downloads -r          # scan a folder recursively
  python truetype.py ~/Downloads -r --json   # machine-readable output

Exit codes: 0 = all clean, 1 = suspicious found, 2 = dangerous found.
"""
import argparse, json, mmap, os, sys

# ---------------------------------------------------------------- signatures
# (name, category, matcher(head_bytes) -> bool)
def _riff(sub):
    return lambda h: h[:4] == b"RIFF" and h[8:12] == sub

def _ftyp(h):
    return h[4:8] == b"ftyp"

SIGNATURES = [
    ("PNG image",        "image",      lambda h: h.startswith(b"\x89PNG\r\n\x1a\n")),
    ("JPEG image",       "image",      lambda h: h.startswith(b"\xff\xd8\xff")),
    ("GIF image",        "image",      lambda h: h[:6] in (b"GIF87a", b"GIF89a")),
    ("BMP image",        "image",      lambda h: h.startswith(b"BM") and len(h) > 14 and h[6:10] == b"\0\0\0\0"),
    ("WebP image",       "image",      _riff(b"WEBP")),
    ("ICO icon",         "image",      lambda h: h.startswith(b"\x00\x00\x01\x00")),
    ("TIFF image",       "image",      lambda h: h[:4] in (b"II*\x00", b"MM\x00*")),
    ("MP4/MOV video",    "video",      _ftyp),
    ("AVI video",        "video",      _riff(b"AVI ")),
    ("Matroska/WebM",    "video",      lambda h: h.startswith(b"\x1aE\xdf\xa3")),
    ("WAV audio",        "audio",      _riff(b"WAVE")),
    ("MP3 audio",        "audio",      lambda h: h.startswith(b"ID3") or h[:2] in (b"\xff\xfb", b"\xff\xf3", b"\xff\xf2")),
    ("OGG",              "audio",      lambda h: h.startswith(b"OggS")),
    ("FLAC audio",       "audio",      lambda h: h.startswith(b"fLaC")),
    ("PDF document",     "document",   lambda h: h.startswith(b"%PDF")),
    ("OLE2 (old Office/MSI)", "document", lambda h: h.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")),
    ("RTF document",     "document",   lambda h: h.startswith(b"{\\rtf")),
    ("ZIP-based (zip/docx/xlsx/apk/jar)", "archive", lambda h: h[:4] in (b"PK\x03\x04", b"PK\x05\x06")),
    ("RAR archive",      "archive",    lambda h: h.startswith(b"Rar!\x1a\x07")),
    ("7-Zip archive",    "archive",    lambda h: h.startswith(b"7z\xbc\xaf\x27\x1c")),
    ("GZIP archive",     "archive",    lambda h: h.startswith(b"\x1f\x8b")),
    # ---- executable formats: the dangerous ones
    ("Windows PE executable (exe/dll/scr)", "executable", lambda h: h.startswith(b"MZ")),
    ("Linux ELF executable", "executable", lambda h: h.startswith(b"\x7fELF")),
    ("macOS Mach-O executable", "executable",
        lambda h: h[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe",
                            b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe") and not h[4:8] == b"\x00\x00\x00\x34"),
    ("Windows shortcut (.lnk)", "executable", lambda h: h.startswith(b"L\x00\x00\x00\x01\x14\x02\x00")),
    ("Script with shebang", "script",  lambda h: h.startswith(b"#!")),
]

# extension -> allowed categories
EXT_CATEGORY = {
    **dict.fromkeys([".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".ico", ".tif", ".tiff"], {"image"}),
    **dict.fromkeys([".mp4", ".mov", ".m4v", ".avi", ".mkv", ".webm"], {"video"}),
    **dict.fromkeys([".mp3", ".wav", ".ogg", ".flac", ".m4a"], {"audio", "video"}),
    ".pdf": {"document"},
    **dict.fromkeys([".doc", ".xls", ".ppt"], {"document"}),
    **dict.fromkeys([".docx", ".xlsx", ".pptx", ".zip", ".jar", ".apk"], {"archive"}),
    **dict.fromkeys([".rar", ".7z", ".gz", ".tgz"], {"archive"}),
    **dict.fromkeys([".exe", ".dll", ".scr", ".sys", ".com"], {"executable"}),
    ".lnk": {"executable"},
}
# text-ish files have no magic bytes; treat as "unknown" but scan for scripts
TEXT_EXTS = {".txt", ".csv", ".json", ".xml", ".md", ".html", ".htm", ".log", ".ini"}
EXEC_EXTS = {".exe", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf",
             ".msi", ".lnk", ".jar", ".hta", ".pif", ".cpl", ".sh", ".app", ".dll"}
BIDI_CHARS = {"\u202e", "\u202d", "\u202b", "\u202a", "\u2066", "\u2067", "\u2068"}

# executables hiding INSIDE another file
EMBEDDED = [
    (b"This program cannot be run in DOS mode", "Windows PE executable"),
    (b"\x7fELF\x02\x01\x01", "Linux ELF executable"),
]
SCRIPT_HINTS = [b"powershell", b"cmd.exe /c", b"WScript.Shell", b"<script", b"#!/bin/"]


def identify(head):
    for name, cat, fn in SIGNATURES:
        try:
            if fn(head):
                return name, cat
        except Exception:
            pass
    return None, None


def is_valid_pe(head):
    """Confirm MZ files really have a PE header (fewer false positives)."""
    if len(head) < 0x40:
        return False
    off = int.from_bytes(head[0x3C:0x40], "little")
    return off + 4 <= len(head) and head[off:off + 4] == b"PE\0\0"


def trailing_bytes(mm, kind, size):
    """Bytes stored after the format's official end marker."""
    if kind == "PNG image":
        i = mm.rfind(b"IEND\xaeB`\x82")
        return size - (i + 8) if i != -1 else 0
    if kind == "JPEG image":
        i = mm.rfind(b"\xff\xd9")
        return size - (i + 2) if i != -1 else 0
    if kind == "GIF image":
        i = mm.rfind(b"\x3b")
        return size - (i + 1) if i != -1 else 0
    return 0


def analyze(path):
    findings = []  # (severity, message); severity: "warn" | "danger"
    name = os.path.basename(path)
    lower = name.lower().rstrip(". ")
    root, ext = os.path.splitext(lower)

    # ---- filename tricks
    if any(c in name for c in BIDI_CHARS):
        findings.append(("danger", "Filename contains a Unicode direction-override character "
                                   "(used to make 'exe' look like 'png')."))
    if name != name.rstrip(". "):
        findings.append(("warn", "Filename ends with spaces/dots (hides the real extension on Windows)."))
    inner_ext = os.path.splitext(root)[1]
    if ext in EXEC_EXTS and inner_ext in EXT_CATEGORY and inner_ext not in EXEC_EXTS:
        findings.append(("danger", f"Double extension: looks like '{inner_ext}' but is actually '{ext}'."))
    if len(name) > 60 and "  " in name:
        findings.append(("warn", "Long name with runs of spaces (pushes real extension out of view)."))

    result = {"path": path, "detected": None, "category": None, "findings": findings}
    try:
        size = os.path.getsize(path)
        if size == 0:
            findings.append(("warn", "File is empty."))
            return result
        with open(path, "rb") as f:
            head = f.read(4096)
            detected, cat = identify(head)
            # MZ without PE header is probably not an exe
            if detected and cat == "executable" and head.startswith(b"MZ") and not is_valid_pe(head):
                pass
            result["detected"], result["category"] = detected or "Unknown/plain data", cat

            # ---- extension vs content
            expected = EXT_CATEGORY.get(ext)
            if cat == "executable" and (ext not in EXEC_EXTS):
                findings.append(("danger", f"EXECUTABLE disguised as '{ext or 'no extension'}': "
                                           f"content is {detected}."))
            elif cat == "script" and ext not in EXEC_EXTS:
                findings.append(("danger", f"Script disguised as '{ext or 'no extension'}'."))
            elif expected and cat and cat not in expected:
                findings.append(("warn", f"Extension '{ext}' expects {'/'.join(sorted(expected))}, "
                                         f"but content is {detected}."))
            elif expected and cat is None and ext not in EXEC_EXTS:
                findings.append(("warn", f"Extension '{ext}' but no valid {'/'.join(sorted(expected))} "
                                         f"signature found (file may be corrupt or fake)."))
            if ext in TEXT_EXTS and cat is None and b"\x00" in head:
                findings.append(("warn", f"'{ext}' is supposed to be text but contains binary data."))

            # ---- deep scans (media/documents only)
            if size < 500 * 1024 * 1024 and cat not in ("executable", "script"):
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    for sig, label in EMBEDDED:
                        pos = mm.find(sig, 1)
                        if pos != -1 and cat != "archive":
                            findings.append(("danger", f"Embedded {label} signature found at "
                                                       f"byte {pos} (hidden payload / polyglot)."))
                    if cat != "archive":
                        # 'MZ' + valid PE header somewhere inside
                        pos = mm.find(b"MZ", 1)
                        checked = 0
                        while pos != -1 and checked < 50:
                            chunk = mm[pos:pos + 4096]
                            if is_valid_pe(chunk):
                                findings.append(("danger", f"Hidden Windows executable header at byte {pos}."))
                                break
                            pos = mm.find(b"MZ", pos + 2)
                            checked += 1
                    extra = trailing_bytes(mm, detected, size)
                    if extra > 0:
                        sev = "danger" if extra > 1024 else "warn"
                        findings.append((sev, f"{extra:,} bytes hidden after the {detected} end marker "
                                              f"(classic way to smuggle data inside an image)."))
                    if cat in ("image", "video", "audio"):
                        low = mm[:min(size, 8 * 1024 * 1024)].lower()
                        for hint in SCRIPT_HINTS:
                            if hint.lower() in low:
                                findings.append(("warn", f"Script-like text {hint!r} found inside a "
                                                         f"{cat} file."))
                                break
            # ZIP-family: peek inside for executables
            if cat == "archive" and detected.startswith("ZIP"):
                import zipfile
                try:
                    with zipfile.ZipFile(path) as z:
                        bad = [n for n in z.namelist() if os.path.splitext(n.lower())[1] in EXEC_EXTS]
                        if bad and ext not in (".jar", ".apk", ".zip"):
                            findings.append(("warn", f"Contains executable-type entries: {', '.join(bad[:5])}"))
                        elif bad:
                            findings.append(("warn", f"Archive contains executables: {', '.join(bad[:5])}"))
                except zipfile.BadZipFile:
                    findings.append(("warn", "Corrupt ZIP structure."))
    except (PermissionError, OSError) as e:
        findings.append(("warn", f"Could not read file: {e}"))
    return result


def verdict(findings):
    if any(s == "danger" for s, _ in findings):
        return "DANGEROUS"
    if findings:
        return "SUSPICIOUS"
    return "CLEAN"


def collect(paths, recursive):
    for p in paths:
        if os.path.isdir(p):
            if recursive:
                for r, _, files in os.walk(p):
                    for fn in files:
                        yield os.path.join(r, fn)
            else:
                for fn in os.listdir(p):
                    fp = os.path.join(p, fn)
                    if os.path.isfile(fp):
                        yield fp
        elif os.path.isfile(p):
            yield p
        else:
            print(f"[skip] not found: {p}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description="Detect what a file really is under its extension.")
    ap.add_argument("paths", nargs="+")
    ap.add_argument("-r", "--recursive", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("-q", "--quiet", action="store_true", help="only show non-clean files")
    args = ap.parse_args()

    worst, out = 0, []
    for path in collect(args.paths, args.recursive):
        res = analyze(path)
        v = verdict(res["findings"])
        res["verdict"] = v
        worst = max(worst, {"CLEAN": 0, "SUSPICIOUS": 1, "DANGEROUS": 2}[v])
        out.append(res)
        if args.json:
            continue
        if args.quiet and v == "CLEAN":
            continue
        icon = {"CLEAN": "[ OK ]", "SUSPICIOUS": "[WARN]", "DANGEROUS": "[DANGER]"}[v]
        print(f"{icon} {path}\n       real type: {res['detected']}")
        for sev, msg in res["findings"]:
            print(f"       {'!!' if sev == 'danger' else ' !'} {msg}")
    if args.json:
        print(json.dumps([{**r, "findings": [{"severity": s, "message": m} for s, m in r["findings"]]}
                          for r in out], indent=2))
    sys.exit(worst)


if __name__ == "__main__":
    main()
