# snaffler-argus

Parse [Snaffler](https://github.com/SnaffCon/Snaffler) logs into an interactive, self-contained HTML report.

Snaffler's raw output is dense and hard to triage — thousands of lines of TSV-ish text across a domain sweep. `snaffler-argus` turns that into something you can actually work with: filterable tables, auto-extracted credentials, duplicate detection, and credential-reuse analysis.

Named after **Argus Panoptes**, the hundred-eyed watchman of Greek myth.

## Features

- **Single-file Python script** — no dependencies beyond the standard library
- **Self-contained HTML output** — open in any browser, no server, no internet, easy to share
- **Robust parser** — handles pipes inside regex patterns, missing fields, and the usual Snaffler edge cases
- **Auto-extracted credentials** — pulls passwords, usernames, connection strings, API keys, and GPP cPasswords out of match contexts
- **Quick Wins panel** — ranks findings by actionability (cred extraction + rule severity + file type)
- **Credential reuse detection** — flags passwords/secrets that appear across multiple files or hosts
- **Deduplication** — collapses identical findings with an `×N` badge instead of repeating rows
- **Auto-tagging** — `CREDS`, `KEY`, `KDBX`, `GPP`, `CONFIG`, `DEPLOY`, `RDP`, `ADMIN$`, `GIT`...
- **Group-by views** — flat / by host / by share / by rule, with collapsible groups
- **Sticky filter toolbar** — severity chips, type filters, "has credentials", tag filters
- **Click-to-expand details** — full path, rule, access, size, modified date, and highlighted match context
- **CSV export** of filtered findings

## Quick start

```bash
# Run Snaffler with file output
Snaffler.exe -s -o snaffler.log

# Generate the report
python snaffler-argus.py snaffler.log

# Open the report
start snaffler_report.html   # Windows
open snaffler_report.html    # macOS
xdg-open snaffler_report.html  # Linux
```

## Usage

```
python snaffler-argus.py [-h] [-o OUTPUT] [-t TITLE] files [files ...]

positional arguments:
  files                 Snaffler log file(s)

optional arguments:
  -h, --help            Show help
  -o, --output OUTPUT   Output HTML path (default: snaffler_report.html)
  -t, --title TITLE     Report title (default: "Snaffler Report")
```

**Examples:**

```bash
# Basic
python snaffler-argus.py snaffler.log

# Custom title and output path
python snaffler-argus.py snaffler.log -o acme-audit.html -t "ACME Corp Internal Audit"

# Merge multiple Snaffler runs
python snaffler-argus.py dc1.log dc2.log fileservers.log --title "Full Domain Sweep"
```

Sample output for the included `sample.log`:

```
[*] sample.log: 12 parsed, 0 skipped
[*] Enriching 12 findings...
[+] Report: snaffler_report.html
    12 total -> 10 unique (2 duplicates removed)
    2 Critical | 3 High | 1 Medium | 4 Low
    6 hosts | 6 quick wins | 4 with creds | 2 reused creds
```

## Input format

`snaffler-argus` parses the standard Snaffler text log format:

```
[id] timestamp [File] {Severity}<Rule|Access|Pattern|Size|Modified>(\\UNC\path) match context
[id] timestamp [Share] {Severity}<\\host\share>(Access)
```

It correctly handles pipes inside regex patterns, missing context, escape sequences (`\r\n`, `\t`), and non-standard size fields.

## Auto-tagging rules

| Tag | Detection |
|-----|-----------|
| `CREDS` | Extracted password / secret / connection string |
| `KEY` | `.pfx`, `.p12`, `.pem`, `.key`, `.ppk`, `id_rsa`, etc. |
| `KDBX` | `.kdbx`, `.kdb` |
| `GPP` | `Groups.xml`, `Drives.xml`, `ScheduledTasks.xml`, etc. |
| `CONFIG` | `web.config`, `appsettings.json`, `app.config` |
| `DEPLOY` | `unattend.xml`, `sysprep.xml`, `autounattend.xml` |
| `RDP` | `.rdp`, `.rdg` |
| `GIT` | `.git-credentials`, `.netrc` |
| `ADMIN$` | Path contains an administrative share (`C$`, `ADMIN$`, etc.) |

## Why "argus"?

Argus Panoptes — Ἄργος Πανόπτης, "Argus all-seeing" — was the hundred-eyed giant of Greek myth, set as a watchman by Hera. After his death, his eyes were transferred to the peacock's tail. Felt fitting for a tool whose whole job is to make sure no finding slips through unseen.

## License

MIT — see [LICENSE](LICENSE).

## Contributing

PRs welcome. If you have a Snaffler output that doesn't parse, open an issue with a sanitised sample.
