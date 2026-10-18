# Static File Inspector

A static file analysis tool that inspects a file **without executing it**. Point it
at any file and get a report: cryptographic hashes, the real file type from magic
bytes, Shannon entropy, readable strings with analyst-relevant ones tagged, and a
static risk score with observations.

It ships in two forms:

- **Web** (`web/index.html`) — a single self-contained page with a tabbed analyst
  dashboard. Drag in a file and the report renders in the browser. Nothing is
  uploaded; all analysis runs client-side using the Web Crypto API.
- **CLI** (`cli/inspect.py`) — a Python command-line tool, standard library only,
  with human-readable and JSON output.

### Features (web)

- **Hashes** — SHA-1 / SHA-256 / SHA-512, with copy for IOC-feed lookups
- **True type** — detected from magic bytes, with extension-mismatch detection
- **Entropy** — overall and, for PE files, **per-section** entropy to spot packing
- **PE structure** — architecture, format, compile timestamp, imported DLLs, sections
- **Archive view** — lists ZIP/JAR/APK/Office entries from the central directory
  (no decompression) and flags executable/script files hidden inside
- **PDF objects** — counts active-content objects (`/JavaScript`, `/OpenAction`,
  `/Launch`, `/EmbeddedFile`, …)
- **Strings** — filterable, with analyst-relevant runs tagged
- **IOC extraction** — URLs, domains, IPs, emails, wallets, deduplicated and
  exportable as JSON
- **MITRE ATT&CK** — maps found API/command strings to techniques (leads to verify)
- **Session history** — inspect several files and compare their scores

> This is a **defensive / educational** tool. It reads bytes; it never runs the file.
> Always handle real malware samples inside an isolated, controlled environment.

## Why static analysis

Running a suspicious file is risky and slow. A lot can be learned first, safely, from
the bytes alone:

| Signal | What it tells an analyst |
|---|---|
| **Hashes** (MD5/SHA-1/SHA-256/SHA-512) | Unique fingerprint to look up in threat-intel feeds |
| **Magic bytes** | The *real* type, regardless of the extension |
| **Entropy** | Values near 8.0 suggest packing/encryption (hidden payload) |
| **Strings** | URLs, IPs, Windows APIs, PowerShell, registry keys, wallets |
| **Extension mismatch** | A `.pdf` that is really a `.exe` is a classic disguise |

## CLI usage

No dependencies — Python 3.8+ only.

```bash
# human-readable report
python cli/inspect.py samples/invoice.pdf

# JSON (for piping into other tools / a SIEM)
python cli/inspect.py samples/invoice.pdf --json

# tune string extraction
python cli/inspect.py file.bin --strings 6
python cli/inspect.py file.bin --no-strings
```

### Example

```
$ python cli/inspect.py samples/invoice.pdf
============================================================
  STATIC FILE INSPECTION REPORT
============================================================
  File          : invoice.pdf
  Detected type : Windows PE executable (EXE/DLL)
  Typical ext   : .exe/.dll   Name ext: .pdf
  Entropy       : 4.997 bits/byte
  Static score  : 66/100  ->  HIGH INDICATORS

  Observations
    [WARN] Executable or active-content file type - handle with care.
    [BAD ] Extension .pdf does not match detected type - possible disguise.
    [INFO] 1 URL string(s) found.
============================================================
```

## Web usage

Open `web/index.html` in any browser, or host it (GitHub Pages, Netlify, etc.).
Drop a file onto the page — hashes, type, entropy, strings and observations render
locally. Nothing leaves the browser.

## Included samples

`samples/` holds harmless test files so you can see each code path:

- `invoice.pdf` — a tiny file with an `MZ` (PE) header but a `.pdf` name → triggers the
  type-mismatch and executable flags
- `readme.txt` — a plain text file → low score
- `blob.bin` — random bytes → entropy ~8.0, high-entropy flag

## How it works

1. Read the whole file into memory (bytes).
2. Compare the first bytes against a table of known magic-byte signatures.
3. Compute Shannon entropy over the byte-frequency distribution.
4. Walk the bytes to collect printable ASCII runs (default min length 4), then tag
   runs matching analyst patterns (URLs, IPs, Windows APIs, etc.).
5. Combine the signals into a 0–100 static score and a list of observations.

## Roadmap

- [ ] List files inside ZIP / archive containers
- [ ] PE section + import-table parsing
- [ ] Optional hash lookup against a local IOC list
- [ ] YARA rule matching

## License

MIT — see `LICENSE`.

Built by **Jayveer Vasava** · [github.com/jayveerv](https://github.com/jayveerv)
