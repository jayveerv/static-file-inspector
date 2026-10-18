#!/usr/bin/env python3
"""
Static File Inspector  -  CLI edition
=====================================
Inspects a file WITHOUT executing it. It reads the bytes and reports:
  - cryptographic hashes (MD5, SHA-1, SHA-256, SHA-512)
  - the real file type from magic bytes (not the extension)
  - Shannon entropy (flags packed / encrypted content)
  - readable ASCII strings, with analyst-relevant ones tagged
  - a static risk score and observations

This is a defensive / educational static-analysis tool. It never runs the
file, so it is safe to point at any sample inside a controlled environment.

Usage:
    python inspect.py <file>
    python inspect.py <file> --json
    python inspect.py <file> --strings 6        # min string length
    python inspect.py <file> --no-strings

Author: Jayveer Vasava
License: MIT
"""
from __future__ import annotations
import argparse
import hashlib
import json
import math
import re
import sys
from collections import Counter
from pathlib import Path

# ----------------------------------------------------------------------------
# magic-byte signatures: (name, typical_ext, risk 0-2, signature bytes)
# ----------------------------------------------------------------------------
SIGNATURES = [
    ("Windows PE executable (EXE/DLL)", ".exe/.dll", 2, b"\x4D\x5A"),
    ("ELF executable (Linux)",          "ELF",       2, b"\x7FELF"),
    ("Mach-O executable (macOS)",       "Mach-O",    2, b"\xFE\xED\xFA\xCE"),
    ("Java class",                      ".class",    1, b"\xCA\xFE\xBA\xBE"),
    ("MSI installer / OLE compound",    ".msi/.doc", 2, b"\xD0\xCF\x11\xE0\xA1\xB1"),
    ("MS Office legacy (doc/xls/ppt)",  ".doc",      1, b"\xD0\xCF\x11\xE0"),
    ("ZIP archive (also jar/apk/docx)", ".zip",      1, b"PK\x03\x04"),
    ("RAR archive",                     ".rar",      1, b"Rar!"),
    ("7-Zip archive",                   ".7z",       1, b"7z\xBC\xAF"),
    ("GZIP archive",                    ".gz",       1, b"\x1F\x8B"),
    ("PDF document",                    ".pdf",      1, b"%PDF"),
    ("RTF document",                    ".rtf",      1, b"{\\rtf"),
    ("Windows shortcut (LNK)",          ".lnk",      2, b"\x4C\x00\x00\x00"),
    ("PNG image",                       ".png",      0, b"\x89PNG"),
    ("JPEG image",                      ".jpg",      0, b"\xFF\xD8\xFF"),
    ("GIF image",                       ".gif",      0, b"GIF8"),
]

# interesting-string patterns: (compiled regex, tag, risk 0-2)
PATTERNS = [
    (re.compile(rb"https?://[^\s\"'<>]{4,}", re.I),                        "URL",             1),
    (re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b"),                          "IP",              1),
    (re.compile(rb"\b[a-z0-9-]+\.(?:ru|cn|tk|top|xyz|gq|cf|ml|su|pw)\b", re.I), "suspicious TLD", 2),
    (re.compile(rb"CreateProcess|VirtualAlloc|WriteProcessMemory|LoadLibrary|"
                rb"GetProcAddress|RegSetValue|ShellExecute|WinExec|"
                rb"URLDownloadToFile|CreateRemoteThread|SetWindowsHookEx"),  "Windows API",     2),
    (re.compile(rb"powershell|cmd\.exe|-enc |-nop |bypass |Invoke-Expression|"
                rb"IEX|DownloadString|FromBase64String", re.I),             "script/command",  2),
    (re.compile(rb"[A-Za-z0-9+/]{40,}={0,2}"),                              "base64 blob",     1),
    (re.compile(rb"[A-Za-z]:\\|C:\\Windows|C:\\Users|AppData|Temp\\|System32", re.I), "fs path", 1),
    (re.compile(rb"HKEY_|HKLM|HKCU|CurrentVersion\\Run|Software\\Microsoft"), "registry key",   2),
    (re.compile(rb"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", re.I),           "email",           0),
    (re.compile(rb"bitcoin|wallet|0x[a-f0-9]{40}", re.I),                   "crypto wallet",   2),
]


def detect_type(data: bytes):
    """Return (name, ext, risk) from magic bytes, with a text fallback."""
    for name, ext, risk, sig in SIGNATURES:
        if data.startswith(sig):
            return name, ext, risk
    sample = data[:512]
    if sample:
        printable = sum(1 for b in sample if b in (9, 10, 13) or 32 <= b < 127)
        if printable / len(sample) > 0.90:
            return "Text / script (ASCII)", ".txt", 1
    return "Unknown / raw binary", "-", 1


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0 = uniform, 8 = max randomness)."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def extract_strings(data: bytes, minlen: int = 4, cap: int = 100_000):
    """Yield printable ASCII runs of length >= minlen."""
    out, cur = [], bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= minlen:
                out.append(bytes(cur))
                if len(out) >= cap:
                    return out
            cur = bytearray()
    if len(cur) >= minlen:
        out.append(bytes(cur))
    return out


def tag_strings(strings):
    """Return {tag: [examples]} for strings matching analyst patterns."""
    tagged = {}
    for s in strings:
        for regex, tag, _risk in PATTERNS:
            if regex.search(s):
                tagged.setdefault(tag, []).append(s.decode("latin-1", "replace"))
                break
    return tagged


def hashes(data: bytes) -> dict:
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
    }


def fmt_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 ** 2:
        return f"{n/1024:.1f} KB"
    return f"{n/1024**2:.2f} MB"


def analyze(path: Path, minlen: int, want_strings: bool) -> dict:
    data = path.read_bytes()
    name = path.name
    tname, text, trisk = detect_type(data)
    ent = shannon_entropy(data)
    strings = extract_strings(data, minlen) if want_strings else []
    tagged = tag_strings(strings) if want_strings else {}

    # extension-vs-type mismatch
    dot_ext = path.suffix.lower()
    mismatch = bool(
        dot_ext and text.startswith(".") and text != "-"
        and dot_ext not in text.lower()
    )

    # scoring + observations
    score = 0
    observations = []
    if trisk >= 2:
        observations.append(("WARN", "Executable or active-content file type - handle with care."))
        score += 30
    if ent > 7.2:
        observations.append(("WARN", f"High entropy ({ent:.2f}) - likely packed, compressed or encrypted."))
        score += 25
    elif 0 < ent < 1:
        observations.append(("INFO", "Very low entropy - mostly repeated or empty bytes."))
    if mismatch:
        observations.append(("BAD", f"Extension {dot_ext} does not match detected type ({tname}) - possible disguise."))
        score += 35
    for tag, examples in tagged.items():
        risk = next(r for _, t, r in PATTERNS if t == tag)
        score += (4 if risk >= 2 else 1) * min(len(examples), 10)
        lvl = "WARN" if risk >= 2 else "INFO"
        observations.append((lvl, f"{len(examples)} {tag} string(s) found."))
    if not observations:
        observations.append(("OK", "No notable static indicators in this file."))
    score = min(100, score)
    verdict = "HIGH INDICATORS" if score >= 55 else "REVIEW ADVISED" if score >= 25 else "LOW INDICATORS"

    return {
        "file": name,
        "size_bytes": len(data),
        "size_human": fmt_size(len(data)),
        "detected_type": tname,
        "typical_ext": text,
        "name_ext": dot_ext or "-",
        "header_hex": data[:16].hex(" ").upper(),
        "entropy": round(ent, 3),
        "hashes": hashes(data),
        "string_count": len(strings),
        "tagged_strings": {k: v[:15] for k, v in tagged.items()},
        "static_score": score,
        "verdict": verdict,
        "observations": [{"level": l, "text": t} for l, t in observations],
    }


def print_report(r: dict):
    line = "=" * 60
    print(line)
    print("  STATIC FILE INSPECTION REPORT")
    print(line)
    print(f"  File          : {r['file']}")
    print(f"  Size          : {r['size_human']} ({r['size_bytes']:,} bytes)")
    print(f"  Detected type : {r['detected_type']}")
    print(f"  Typical ext   : {r['typical_ext']}   Name ext: {r['name_ext']}")
    print(f"  Header (hex)  : {r['header_hex']}")
    print(f"  Entropy       : {r['entropy']} bits/byte")
    print(f"  Strings       : {r['string_count']:,}")
    print(f"  Static score  : {r['static_score']}/100  ->  {r['verdict']}")
    print()
    print("  Hashes")
    for k, v in r["hashes"].items():
        print(f"    {k.upper():<7}: {v}")
    print()
    print("  Observations")
    for o in r["observations"]:
        print(f"    [{o['level']:<4}] {o['text']}")
    if r["tagged_strings"]:
        print()
        print("  Notable strings (first few per category)")
        for tag, examples in r["tagged_strings"].items():
            print(f"    {tag}:")
            for ex in examples[:5]:
                ex = ex if len(ex) <= 90 else ex[:87] + "..."
                print(f"      - {ex}")
    print(line)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Inspect a file statically, without running it.")
    ap.add_argument("file", help="path to the file to inspect")
    ap.add_argument("--json", action="store_true", help="print the report as JSON")
    ap.add_argument("--strings", type=int, default=4, metavar="N", help="minimum string length (default 4)")
    ap.add_argument("--no-strings", action="store_true", help="skip string extraction")
    args = ap.parse_args(argv)

    path = Path(args.file)
    if not path.is_file():
        print(f"error: not a file: {path}", file=sys.stderr)
        return 2

    report = analyze(path, args.strings, not args.no_strings)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
