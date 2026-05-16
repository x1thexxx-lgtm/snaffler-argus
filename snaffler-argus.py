#!/usr/bin/env python3
"""
snaffler-argus - Parse Snaffler logs into an interactive HTML report.

Usage:
    python snaffler-argus.py snaffler.log
    python snaffler-argus.py snaffler.log -o report.html -t "Client Audit"
    python snaffler-argus.py run1.log run2.log --title "Full Domain Sweep"
"""

import re
import sys
import html
import json
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

# ─── Constants ───────────────────────────────────────────────────────────────

SEVERITY_ORDER = {"Black": 0, "Red": 1, "Yellow": 2, "Green": 3}
SEVERITY_LABELS = {"Black": "Critical", "Red": "High", "Yellow": "Medium", "Green": "Low"}

LINE_RE = re.compile(
    r"\[([^\]]+)\]\s+"
    r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}Z)\s+"
    r"\[(\w+)\]\s+"
    r"\{(\w+)\}"
    r"<([^>]*)>"
    r"\(([^)]*)\)"
    r"(.*)",
    re.DOTALL,
)

DATE_TAIL_RE = re.compile(r"\|(\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}Z?)$")

CRED_PATTERNS = [
    (re.compile(r"(?:password|passwd|pwd|pass)\s*[=:]\s*[\"']?([^\s\"';,}\]\r\n]{3,})", re.I), "password"),
    (re.compile(r"(?:Password|Pwd)\s*=\s*([^;\"\s]{3,})", re.I), "password"),
    (re.compile(r"\$(?:cred|pass|password|secret|pwd)\s*=\s*[\"']([^\"']{3,})[\"']", re.I), "password"),
    (re.compile(r"-(?:Password|Pass|Credential|SecureString)\s+[\"']?([^\s\"';,}\]]{3,})", re.I), "password"),
    (re.compile(r"(?:user(?:\s*name)?|login|uid|User\s*Id)\s*[=:]\s*[\"']?([^\s\"';,}\]\r\n]{2,})", re.I), "username"),
    (re.compile(r"\$(?:user|username|login)\s*=\s*[\"']([^\"']{2,})[\"']", re.I), "username"),
    (re.compile(r"(?:api[_\-]?key|token|secret|auth[_\-]?key)\s*[=:]\s*[\"']?([^\s\"';,}\]\r\n]{4,})", re.I), "secret"),
    (re.compile(r"connectionString\s*=\s*\"([^\"]+)\"", re.I), "connstr"),
    (re.compile(r"cpassword\s*=\s*\"([^\"]+)\"", re.I), "gpp_password"),
]

INTERESTING_EXTENSIONS = {
    ".kdbx": "KDBX", ".kdb": "KDBX",
    ".pfx": "KEY", ".p12": "KEY", ".pem": "KEY", ".key": "KEY", ".ppk": "KEY",
    ".rdp": "RDP", ".rdg": "RDP",
    ".vmx": "VM", ".vmdk": "VM",
}

INTERESTING_FILENAMES = {
    "web.config": "CONFIG", "appsettings.json": "CONFIG", "app.config": "CONFIG",
    "unattend.xml": "DEPLOY", "sysprep.xml": "DEPLOY", "autounattend.xml": "DEPLOY",
    "id_rsa": "KEY", "id_ed25519": "KEY", "id_ecdsa": "KEY",
    ".git-credentials": "GIT", ".netrc": "GIT",
    "groups.xml": "GPP", "drives.xml": "GPP", "datasources.xml": "GPP",
    "scheduledtasks.xml": "GPP", "services.xml": "GPP",
    "shadow": "SHADOW", "passwd": "SHADOW",
}


# ─── Parser ──────────────────────────────────────────────────────────────────

def parse_rule_info(raw):
    """Parse angle-bracket content for File/Dir entries. Handles pipes in regex patterns."""
    result = {"rule": raw, "access": "", "pattern": "", "size": "", "modified": ""}

    date_m = DATE_TAIL_RE.search(raw)
    if not date_m:
        parts = raw.split("|", 2)
        result["rule"] = parts[0]
        if len(parts) > 1:
            result["access"] = parts[1]
        if len(parts) > 2:
            result["pattern"] = parts[2]
        return result

    result["modified"] = date_m.group(1)
    rest = raw[: date_m.start()]

    last_pipe = rest.rfind("|")
    if last_pipe >= 0:
        result["size"] = rest[last_pipe + 1 :]
        rest = rest[:last_pipe]

    parts = rest.split("|", 2)
    result["rule"] = parts[0]
    if len(parts) > 1:
        result["access"] = parts[1]
    if len(parts) > 2:
        result["pattern"] = parts[2]

    return result


def parse_line(line):
    """Parse a single Snaffler log line."""
    line = line.strip()
    if not line:
        return None
    m = LINE_RE.match(line)
    if not m:
        return None

    identity, timestamp, ftype, severity, angle, paren, context = m.groups()
    r = {"identity": identity, "timestamp": timestamp, "type": ftype, "severity": severity}

    if ftype == "Share":
        r["share"] = angle
        r["access"] = paren
        r["host"] = _host(angle)
        r["path"] = ""
        r["rule"] = ""
        r["context"] = ""
        r["size"] = ""
        r["modified"] = ""
        r["pattern"] = ""
    else:
        info = parse_rule_info(angle)
        r["rule"] = info["rule"]
        r["access"] = info["access"]
        r["pattern"] = info["pattern"]
        r["size"] = info["size"]
        r["modified"] = info["modified"]
        r["path"] = paren
        r["share"] = _share(paren)
        r["host"] = _host(paren)
        r["context"] = _unescape(context) if context else ""

    return r


def parse_file(filepath):
    findings = []
    skipped = 0
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            r = parse_line(line)
            if r:
                findings.append(r)
            elif line.strip():
                skipped += 1
    return findings, skipped


# ─── Enrichment ──────────────────────────────────────────────────────────────

def enrich(findings):
    """Add tags, extract credentials, compute filename/extension for each finding."""
    for f in findings:
        path = f.get("path", "") or f.get("share", "")
        fname = path.rsplit("\\", 1)[-1] if "\\" in path else path
        ext = ""
        if "." in fname:
            ext = "." + fname.rsplit(".", 1)[-1].lower()

        f["filename"] = fname
        f["ext"] = ext

        tags = set()
        creds = []

        # Tag by extension
        if ext in INTERESTING_EXTENSIONS:
            tags.add(INTERESTING_EXTENSIONS[ext])

        # Tag by filename
        for name, tag in INTERESTING_FILENAMES.items():
            if name.lower() in fname.lower():
                tags.add(tag)
                break

        # Tag admin share access
        share = f.get("share", "")
        if share and any(s in share for s in ("$", "ADMIN$", "C$", "D$")):
            tags.add("ADMIN$")

        # Extract credentials from context
        ctx = f.get("context", "")
        if ctx:
            for pat, ctype in CRED_PATTERNS:
                for m in pat.finditer(ctx):
                    val = m.group(1).strip("\"'")
                    if len(val) >= 3 and val not in ("null", "None", "empty", "xxx", "***"):
                        creds.append({"type": ctype, "value": val})
                        if ctype in ("password", "secret", "connstr"):
                            tags.add("CREDS")

        # Tag by rule name patterns
        rule = f.get("rule", "")
        if any(k in rule for k in ("Pass", "Cred", "Secret", "Token")):
            if ctx and not tags & {"CREDS"}:
                tags.add("CREDS?")
        if any(k in rule for k in ("Key", "Cert", "Private")):
            tags.add("KEY")

        f["tags"] = sorted(tags)
        f["creds"] = creds

    return findings


def deduplicate(findings):
    """Collapse exact duplicates (same path + rule). Keeps first occurrence, tracks count."""
    seen = {}
    deduped = []
    for f in findings:
        key = (f.get("path", "") or f.get("share", ""), f.get("rule", ""), f.get("severity", ""))
        if key in seen:
            seen[key]["dupe_count"] = seen[key].get("dupe_count", 1) + 1
            # merge creds from duplicate if richer context
            existing_creds = {c["value"] for c in seen[key].get("creds", [])}
            for c in f.get("creds", []):
                if c["value"] not in existing_creds:
                    seen[key]["creds"].append(c)
                    existing_creds.add(c["value"])
        else:
            f["dupe_count"] = 1
            seen[key] = f
            deduped.append(f)
    return deduped


def find_cred_reuse(findings):
    """Find credentials that appear across multiple distinct files."""
    cred_locations = defaultdict(list)
    for f in findings:
        for c in f.get("creds", []):
            if c["type"] in ("password", "secret", "connstr", "gpp_password"):
                path = f.get("path", "") or f.get("share", "")
                cred_locations[c["value"]].append({
                    "path": path,
                    "host": f.get("host", ""),
                    "filename": f.get("filename", ""),
                    "rule": f.get("rule", ""),
                })

    reuse = []
    for val, locations in cred_locations.items():
        unique_paths = list({loc["path"] for loc in locations})
        unique_hosts = list({loc["host"] for loc in locations if loc["host"]})
        if len(unique_paths) >= 2:
            reuse.append({
                "value": val,
                "count": len(unique_paths),
                "hosts": unique_hosts[:8],
                "files": [loc["filename"] for loc in locations[:6]],
                "paths": unique_paths[:6],
            })
        elif len(unique_paths) == 1 and len(unique_hosts) == 1:
            # same cred, one path — not reuse, skip
            pass

    reuse.sort(key=lambda x: -x["count"])
    return reuse[:20]


def make_quick_wins(findings):
    """Select high-value findings that represent immediate actionable wins."""
    scored = []
    for i, f in enumerate(findings):
        if f["type"] == "Share":
            continue
        score = 0
        tags = set(f.get("tags", []))

        if f["severity"] == "Black":
            score += 100
        elif f["severity"] == "Red":
            score += 50

        if "CREDS" in tags:
            score += 80
        if "KEY" in tags:
            score += 70
        if "KDBX" in tags:
            score += 65
        if "GPP" in tags:
            score += 90
        if "ADMIN$" in tags:
            score += 20
        if f.get("creds"):
            score += 30

        if score >= 50:
            title = _qw_title(f)
            detail = _qw_detail(f)
            scored.append({"i": i, "title": title, "detail": detail, "score": score})

    scored.sort(key=lambda x: -x["score"])
    return scored[:25]


def _qw_title(f):
    fname = f.get("filename", "")
    ext = f.get("ext", "")
    rule = f.get("rule", "")
    tags = f.get("tags", [])

    if ext in (".kdbx", ".kdb"):
        return f"KeePass database — {fname}"
    if ext in (".pfx", ".p12", ".pem", ".key", ".ppk"):
        return f"Private key — {fname}"
    if "id_rsa" in fname or "id_ed25519" in fname or "id_ecdsa" in fname:
        return f"SSH private key — {fname}"
    if ext in (".rdp", ".rdg"):
        return f"RDP connection — {fname}"
    if "GPP" in tags:
        return f"GPP cPassword — {fname}"
    if "CONFIG" in tags:
        return f"App config credentials — {fname}"
    if "DEPLOY" in tags:
        return f"Deployment creds — {fname}"
    if "CREDS" in tags:
        return f"Hardcoded credentials — {fname}"
    return f"{rule} — {fname}"


def _qw_detail(f):
    creds = f.get("creds", [])
    if not creds:
        return ""
    parts = []
    seen = set()
    for c in creds:
        key = f"{c['type']}:{c['value']}"
        if key in seen:
            continue
        seen.add(key)
        label = c["type"].capitalize()
        parts.append(f"{label}: {c['value']}")
    return " | ".join(parts[:4])


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _host(path):
    m = re.match(r"\\\\([^\\]+)", path)
    return m.group(1) if m else ""


def _share(path):
    m = re.match(r"(\\\\[^\\]+\\[^\\]+)", path)
    return m.group(1) if m else ""


def _unescape(ctx):
    ctx = ctx.replace("\\r\\n", "\n").replace("\\n", "\n").replace("\\t", "\t")
    ctx = re.sub(r"\\\\ ", " ", ctx)
    ctx = re.sub(r"\\(.)", r"\1", ctx)
    return ctx.strip()


# ─── Report Generation ───────────────────────────────────────────────────────

def generate_report(findings, output_path, title, input_files):
    total_raw = len(findings)
    if total_raw == 0:
        print("[!] No findings parsed.")
        return

    # Deduplicate
    findings = deduplicate(findings)
    total = len(findings)
    dupes_removed = total_raw - total

    # Credential reuse analysis
    cred_reuse = find_cred_reuse(findings)

    sev_counts = Counter(f["severity"] for f in findings)
    type_counts = Counter(f["type"] for f in findings)
    rule_counts = Counter(f["rule"] for f in findings if f["rule"])
    host_counts = Counter(f["host"] for f in findings if f["host"])
    ext_counts = Counter(f["ext"] for f in findings if f["ext"] and f["type"] != "Share")
    tag_counts = Counter(t for f in findings for t in f.get("tags", []))

    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
    quick_wins = make_quick_wins(sorted_findings)

    data = json.dumps([{
        "i": i, "ts": f["timestamp"], "ty": f["type"], "sv": f["severity"],
        "ru": f.get("rule", ""), "ho": f.get("host", ""),
        "sh": f.get("share", ""), "pa": f.get("path", ""),
        "fn": f.get("filename", ""), "ext": f.get("ext", ""),
        "ac": f.get("access", ""), "sz": f.get("size", ""),
        "mo": f.get("modified", ""),
        "cx": html.escape(f.get("context", "")[:2000]),
        "pt": f.get("pattern", ""),
        "tg": f.get("tags", []),
        "cr": f.get("creds", []),
        "dc": f.get("dupe_count", 1),
    } for i, f in enumerate(sorted_findings)])

    qw_json = json.dumps(quick_wins)
    reuse_json = json.dumps(cred_reuse)

    stats = json.dumps({
        "total": total,
        "total_raw": total_raw,
        "dupes_removed": dupes_removed,
        "sev": {k: sev_counts.get(k, 0) for k in ("Black", "Red", "Yellow", "Green")},
        "types": dict(type_counts),
        "rules": rule_counts.most_common(15),
        "hosts": host_counts.most_common(15),
        "exts": ext_counts.most_common(12),
        "tags": dict(tag_counts),
        "hosts_total": len(host_counts),
        "creds_total": sum(1 for f in findings if f.get("creds")),
        "cred_reuse_count": len(cred_reuse),
        "write_access": sum(1 for f in findings if "W" in f.get("access", "")),
    })

    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    files_str = ", ".join(str(f) for f in input_files)

    report = HTML_TEMPLATE
    report = report.replace("__TITLE__", html.escape(title))
    report = report.replace("__GENERATED__", now)
    report = report.replace("__FILES__", html.escape(files_str))
    report = report.replace("/*__DATA__*/[]", data)
    report = report.replace("/*__QW__*/[]", qw_json)
    report = report.replace("/*__REUSE__*/[]", reuse_json)
    report = report.replace("/*__STATS__*/{}", stats)

    Path(output_path).write_text(report, encoding="utf-8")

    print(f"[+] Report: {output_path}")
    print(f"    {total_raw} total -> {total} unique ({dupes_removed} duplicates removed)")
    print(f"    {sev_counts.get('Black',0)} Critical | {sev_counts.get('Red',0)} High | {sev_counts.get('Yellow',0)} Medium | {sev_counts.get('Green',0)} Low")
    print(f"    {len(host_counts)} hosts | {len(quick_wins)} quick wins | {sum(1 for f in findings if f.get('creds'))} with creds | {len(cred_reuse)} reused creds")


# ─── HTML Template ───────────────────────────────────────────────────────────

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>__TITLE__</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Crect width='100' height='100' rx='15' fill='%231e293b'/%3E%3Ctext x='50' y='68' text-anchor='middle' font-family='monospace' font-size='60' font-weight='bold' fill='%23f97316'%3ES%3C/text%3E%3C/svg%3E">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f5f6f8;color:#212529;font-size:13px;line-height:1.5}
a{color:#2563eb;text-decoration:none}
.hidden{display:none!important}

/* Header */
.hdr{background:#1e293b;color:#fff;padding:18px 30px}
.hdr h1{font-size:1.3em;font-weight:600;margin-bottom:2px}
.hdr-meta{font-size:.8em;color:#94a3b8}
.hdr-counts{display:flex;gap:14px;margin-top:10px}
.hdr-counts .hc{display:flex;align-items:center;gap:5px;font-size:.82em;font-weight:600}
.hdr-counts .dot{width:10px;height:10px;border-radius:2px}

/* Layout */
.wrap{max-width:1500px;margin:0 auto;padding:20px 24px 60px}

/* Block layout */
.block{margin-bottom:30px}
.block-title{font-size:1em;font-weight:600;color:#1e293b;margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid #e2e8f0;display:flex;align-items:center;gap:8px}
.block-count{color:#94a3b8;font-weight:400;font-size:.82em}
.card{background:#fff;border:1px solid #e2e8f0;border-radius:6px;overflow:hidden}

/* View bar */
.view-bar{display:flex;align-items:center;gap:4px;margin:8px 0 6px;padding:0 2px;font-size:.78em}
.view-label{color:#64748b;font-weight:500;margin-right:4px}
.view-btn{padding:3px 11px;border:1px solid transparent;border-radius:4px;background:transparent;color:#64748b;font-size:.78em;cursor:pointer;font-weight:500}
.view-btn:hover{background:#f1f5f9;color:#1e293b}
.view-btn.on{background:#1e293b;color:#fff}
.view-spacer{flex:1}
.view-hint{color:#94a3b8;font-size:.78em}

/* Group rows */
.group-row{background:#f8fafc;cursor:pointer;border-top:1px solid #e2e8f0}
.group-row:hover{background:#f1f5f9}
.group-row td{padding:7px 10px!important;font-weight:600;font-size:.84em}
.group-toggle{display:inline-block;width:12px;color:#64748b;font-size:.7em;transition:transform .12s}
.group-row.collapsed .group-toggle{transform:rotate(-90deg)}
.group-name{color:#1e293b;font-family:Consolas,monospace}
.group-meta{color:#64748b;font-weight:400;font-size:.85em;margin-left:6px}
.group-dots{display:inline-flex;gap:2px;margin:0 8px;vertical-align:middle}
.group-dot{width:6px;height:6px;border-radius:50%;display:inline-block}
.sticky-toolbar{position:sticky;top:0;z-index:50;box-shadow:0 1px 3px rgba(0,0,0,.04)}

/* Summary cards */
.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1px;background:#e2e8f0;border-radius:6px;overflow:hidden;margin-bottom:16px}
.scard{background:#fff;padding:14px 16px;text-align:center}
.scard .val{font-size:1.7em;font-weight:700;line-height:1.2}
.scard .lbl{font-size:.72em;color:#64748b;text-transform:uppercase;letter-spacing:.5px;margin-top:2px}
.scard.crit .val{color:#991b1b}.scard.high .val{color:#9a3412}
.scard.med .val{color:#854d0e}.scard.low .val{color:#166534}

/* Quick wins */
.qw-list{padding:0}
.qw-item{display:flex;gap:12px;padding:10px 16px;border-bottom:1px solid #f1f5f9;align-items:flex-start}
.qw-item:last-child{border-bottom:none}
.qw-item:hover{background:#fafbfc}
.qw-sev{flex-shrink:0;width:3px;border-radius:2px;align-self:stretch;min-height:32px}
.qw-body{flex:1;min-width:0}
.qw-title{font-weight:600;font-size:.86em;margin-bottom:2px;color:#1e293b}
.qw-path{font-family:Consolas,'Courier New',monospace;font-size:.76em;color:#64748b;word-break:break-all}
.qw-creds{font-family:Consolas,'Courier New',monospace;font-size:.78em;color:#7f1d1d;background:#fbf3f3;border:1px solid #f0d6d6;padding:3px 7px;border-radius:2px;margin-top:4px;display:inline-block;word-break:break-all}
.qw-tags{margin-top:3px}

/* Credential reuse */
.reuse-table{width:100%;border-collapse:collapse}
.reuse-table th{text-align:left;padding:8px 14px;font-size:.72em;text-transform:uppercase;letter-spacing:.5px;color:#64748b;background:#f8fafc;border-bottom:1px solid #e2e8f0}
.reuse-table td{padding:8px 14px;border-bottom:1px solid #f1f5f9;font-size:.84em;vertical-align:top}
.reuse-table tr:hover td{background:#f8fafc}
.reuse-val{font-family:Consolas,monospace;font-weight:600;color:#dc2626}
.reuse-where{font-family:Consolas,monospace;font-size:.88em;color:#64748b}

/* Stats row */
.stats-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:16px;margin-bottom:16px}
.stat-panel{background:#fff;border:1px solid #e2e8f0;border-radius:6px;padding:14px 16px}
.stat-panel h4{font-size:.72em;text-transform:uppercase;letter-spacing:.8px;color:#64748b;margin-bottom:10px;font-weight:600}
.bar-row{display:flex;align-items:center;gap:8px;margin-bottom:5px}
.bar-label{width:50px;font-size:.78em;text-align:right;font-weight:600}
.bar-track{flex:1;height:6px;background:#f1f5f9;border-radius:3px;overflow:hidden}
.bar-fill{height:100%;border-radius:3px}
.bar-num{width:30px;font-size:.78em;color:#64748b;text-align:right}
.stat-list{list-style:none}
.stat-list li{display:flex;justify-content:space-between;padding:3px 4px;font-size:.8em;border-bottom:1px solid #f1f5f9;cursor:pointer;border-radius:2px;transition:background .1s}
.stat-list li:hover{background:#f1f5f9}
.stat-list li:last-child{border-bottom:none}
.stat-list .n{color:#64748b;font-variant-numeric:tabular-nums;font-weight:500}

/* Toolbar */
.toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;padding:12px 18px;background:#fff;border:1px solid #e2e8f0;border-radius:6px;margin-bottom:12px}
.search-box{flex:1;min-width:180px;padding:7px 12px;border:1px solid #d1d5db;border-radius:5px;font-size:.84em;background:#fff;color:#1e293b}
.search-box:focus{outline:none;border-color:#2563eb;box-shadow:0 0 0 2px rgba(37,99,235,.1)}
.btn{padding:5px 13px;border:1px solid #d1d5db;border-radius:5px;background:#fff;color:#475569;font-size:.78em;cursor:pointer;transition:all .1s;font-weight:500}
.btn:hover{background:#f8fafc;border-color:#94a3b8}
.btn.on{background:#1e293b;color:#fff;border-color:#1e293b}
.btn.sev-Black.on{background:#742a2a;border-color:#742a2a;color:#fff}
.btn.sev-Red.on{background:#c2410c;border-color:#c2410c;color:#fff}
.btn.sev-Yellow.on{background:#a16207;border-color:#a16207;color:#fff}
.btn.sev-Green.on{background:#15803d;border-color:#15803d;color:#fff}
.sep{width:1px;height:20px;background:#e2e8f0}
.export-btn{margin-left:auto}

/* Findings table */
.findings-tbl{width:100%;border-collapse:collapse}
.findings-tbl th{position:sticky;top:0;z-index:2;padding:5px 7px;text-align:left;font-size:.68em;text-transform:uppercase;letter-spacing:.5px;color:#64748b;font-weight:600;background:#f8fafc;border-bottom:2px solid #e2e8f0;cursor:pointer;user-select:none;white-space:nowrap}
.findings-tbl th:hover{color:#1e293b}
.findings-tbl th .arr{margin-left:3px;font-size:.75em;color:#94a3b8}
.findings-tbl td{padding:4px 7px;border-bottom:1px solid #f1f5f9;vertical-align:middle;font-size:.82em;line-height:1.35}
.findings-tbl tbody tr{transition:background .08s}
.findings-tbl tbody tr.clickable{cursor:pointer}
.findings-tbl tbody tr.clickable:hover td{background:#f0f7ff}
.findings-tbl tbody tr.active td{background:#eff6ff;border-bottom-color:#dbeafe}

/* Severity */
.sev-badge{display:inline-block;padding:1px 6px;border-radius:2px;font-size:.72em;font-weight:600;text-align:center;letter-spacing:.2px}
.sev-Black{background:#742a2a;color:#fff}
.sev-Red{background:#c2410c;color:#fff}
.sev-Yellow{background:#a16207;color:#fff}
.sev-Green{background:#15803d;color:#fff}
.dupe-badge{display:inline-block;font-size:.66em;background:#e0e7ff;color:#3730a3;padding:1px 4px;border-radius:2px;font-weight:600;margin-left:3px}

/* Tags */
.tag{display:inline-block;padding:0 5px;border-radius:2px;font-size:.65em;font-weight:600;margin-right:2px;text-transform:uppercase;letter-spacing:.3px;line-height:1.6}
.tag-CREDS,.tag-GPP{background:#f1e1e1;color:#7f1d1d}
.tag-KEY{background:#fde8d8;color:#7c2d12}
.tag-KDBX{background:#fef3c7;color:#713f12}
.tag-CONFIG,.tag-DEPLOY{background:#dbeafe;color:#1e3a5f}
.tag-ADMIN\${background:#ede9fe;color:#4c1d95}
.tag-GIT,.tag-RDP,.tag-VM,.tag-SHADOW{background:#dcfce7;color:#14532d}
.tag-CREDS\?{background:#f1f5f9;color:#475569}

/* Path */
.fp{font-family:Consolas,'Courier New',monospace;font-size:.85em;word-break:break-all;line-height:1.3}
.fp-dir{color:#94a3b8}.fp-name{color:#1e293b;font-weight:600}
.ctx-preview{display:block;font-size:.78em;color:#64748b;margin-top:2px;font-family:Consolas,monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%}
.ctx-preview mark{background:#fff3cd;color:#664d03;padding:0 1px;border-radius:1px}

/* Detail row */
.detail-row{display:none}
.detail-row.open{display:table-row}
.detail-row td{padding:0!important;background:#fafbfc}
.detail-box{padding:12px 16px;border-bottom:2px solid #e2e8f0}
.detail-grid{display:grid;grid-template-columns:auto 1fr;gap:3px 14px;font-size:.78em;margin-bottom:8px}
.detail-grid dt{color:#64748b;font-weight:500}
.detail-grid dd{color:#1e293b;font-family:Consolas,monospace;word-break:break-all}
.detail-ctx{background:#f6f8fa;color:#24292f;padding:10px 14px;border:1px solid #e2e8f0;border-radius:3px;font-family:Consolas,'Courier New',monospace;font-size:.78em;line-height:1.6;white-space:pre-wrap;word-break:break-all;max-height:280px;overflow-y:auto}
.detail-ctx mark{background:#fff3cd;color:#664d03;border-radius:1px;padding:0 1px}
.detail-ctx mark.v{background:#f8d7da;color:#58151c;font-weight:600;padding:0 2px}

/* Pager */
.pager{display:flex;justify-content:space-between;align-items:center;padding:10px 14px;border-top:1px solid #e2e8f0;font-size:.8em;color:#64748b}
.pager button{padding:5px 14px;border:1px solid #d1d5db;border-radius:5px;background:#fff;color:#475569;cursor:pointer;font-size:.84em}
.pager button:hover:not(:disabled){background:#f8fafc;border-color:#94a3b8}
.pager button:disabled{opacity:.35;cursor:default}

/* Print */
@media print{
  .hdr{background:#1e293b;-webkit-print-color-adjust:exact;print-color-adjust:exact}
  .tabs,.toolbar,.pager{display:none}
  .panel{display:block!important}
  .detail-row.open{display:table-row}
  body{background:#fff}
}
@media(max-width:800px){.summary{grid-template-columns:repeat(3,1fr)}.stats-row{grid-template-columns:1fr}}
</style>
</head>
<body>

<div class="hdr">
  <h1>__TITLE__</h1>
  <div class="hdr-meta">Generated __GENERATED__ | Source: __FILES__</div>
  <div class="hdr-counts" id="hdrCounts"></div>
</div>

<div class="wrap">

<!-- OVERVIEW / STATS -->
<section class="block">
  <h2 class="block-title">Overview</h2>
  <div class="summary" id="summaryCards"></div>
  <div class="stats-row">
    <div class="stat-panel"><h4>Severity Distribution</h4><div id="sevBars"></div></div>
    <div class="stat-panel"><h4>Top Triggered Rules</h4><ul class="stat-list" id="topRules"></ul></div>
    <div class="stat-panel"><h4>Hosts with Most Findings</h4><ul class="stat-list" id="topHosts"></ul></div>
    <div class="stat-panel"><h4>File Extensions</h4><ul class="stat-list" id="topExts"></ul></div>
  </div>
</section>

<!-- QUICK WINS -->
<section class="block" id="qwBlock">
  <h2 class="block-title">Quick Wins <span class="block-count" id="qwCount"></span></h2>
  <div class="card"><div class="qw-list" id="qwList"></div></div>
</section>

<!-- CREDENTIAL REUSE (hidden if none) -->
<section class="block hidden" id="reuseBlock">
  <h2 class="block-title">Credential Reuse <span class="block-count" id="reuseCount"></span></h2>
  <div class="card">
    <table class="reuse-table">
      <thead><tr><th>Credential</th><th>Locations</th><th>Hosts</th><th>Files</th></tr></thead>
      <tbody id="reuseBody"></tbody>
    </table>
  </div>
</section>

<!-- FINDINGS -->
<section class="block">
  <h2 class="block-title">Findings <span class="block-count" id="findCount"></span></h2>

  <div class="toolbar sticky-toolbar">
    <input type="text" class="search-box" id="searchBox" placeholder="Filter by path, host, rule, keyword...">
    <span class="sep"></span>
    <button class="btn sev-Black" data-sv="Black" onclick="togF(this,'sv')">Critical</button>
    <button class="btn sev-Red" data-sv="Red" onclick="togF(this,'sv')">High</button>
    <button class="btn sev-Yellow" data-sv="Yellow" onclick="togF(this,'sv')">Medium</button>
    <button class="btn sev-Green" data-sv="Green" onclick="togF(this,'sv')">Low</button>
    <span class="sep"></span>
    <button class="btn" data-ty="File" onclick="togF(this,'ty')">Files</button>
    <button class="btn" data-ty="Share" onclick="togF(this,'ty')">Shares</button>
    <span class="sep"></span>
    <button class="btn" id="credsBtn" onclick="togCreds(this)">Has Creds</button>
    <span class="sep" id="tagSep"></span>
    <span id="tagBtns"></span>
    <button class="btn export-btn" onclick="exportCSV()">Export CSV</button>
  </div>

  <div class="view-bar">
    <span class="view-label">Group by:</span>
    <button class="view-btn on" data-view="flat" onclick="setView(this)">None</button>
    <button class="view-btn" data-view="ho" onclick="setView(this)">Host</button>
    <button class="view-btn" data-view="sh" onclick="setView(this)">Share</button>
    <button class="view-btn" data-view="ru" onclick="setView(this)">Rule</button>
    <span class="view-spacer"></span>
    <span class="view-hint" id="viewHint"></span>
  </div>

  <div class="card">
    <table class="findings-tbl">
      <thead><tr>
        <th style="width:62px" onclick="doSort('sv')">Severity<span class="arr" id="a_sv"></span></th>
        <th style="width:130px" onclick="doSort('ru')">Rule<span class="arr" id="a_ru"></span></th>
        <th style="width:130px" onclick="doSort('ho')">Host<span class="arr" id="a_ho"></span></th>
        <th onclick="doSort('pa')">Path / Share<span class="arr" id="a_pa"></span></th>
        <th style="width:50px" onclick="doSort('sz')">Size<span class="arr" id="a_sz"></span></th>
        <th style="width:48px" onclick="doSort('mo')">Age<span class="arr" id="a_mo"></span></th>
        <th style="width:90px">Tags</th>
      </tr></thead>
      <tbody id="tbody"></tbody>
    </table>
    <div class="pager">
      <span id="pagerInfo"></span>
      <div style="display:flex;gap:6px">
        <button onclick="goPrev()">Prev</button>
        <button onclick="goNext()">Next</button>
      </div>
    </div>
  </div>
</section>

</div>

<script>
const D=/*__DATA__*/[];
const QW=/*__QW__*/[];
const REUSE=/*__REUSE__*/[];
const S=/*__STATS__*/{};
const SEV_ORD={Black:0,Red:1,Yellow:2,Green:3};
const PAGE=50;
let filtered=D.slice(),sortCol='sv',sortAsc=true,page=0;
let fSev=new Set(),fTy=new Set(),fTag=new Set(),fRule='',fHost='',fCreds=false;
let viewMode='flat';

function init(){
  renderHeader();
  renderOverview();
  renderReuse();
  buildFilters();
  applyFilters();
  initKB();
}

function setView(btn){
  document.querySelectorAll('.view-btn').forEach(b=>b.classList.remove('on'));
  btn.classList.add('on');
  viewMode=btn.dataset.view;
  page=0;render();
}

function renderHeader(){
  const h=document.getElementById('hdrCounts');
  const items=[
    {c:'#ef4444',l:'Critical',n:S.sev.Black},
    {c:'#f97316',l:'High',n:S.sev.Red},
    {c:'#eab308',l:'Medium',n:S.sev.Yellow},
    {c:'#22c55e',l:'Low',n:S.sev.Green}
  ];
  h.innerHTML=items.map(x=>'<span class="hc"><span class="dot" style="background:'+x.c+'"></span>'+x.n+' '+x.l+'</span>').join('');
}

function renderOverview(){
  // Summary cards — 6 most useful, with hierarchy
  const dupeNote=S.dupes_removed?' <span style="font-size:.7em;color:#94a3b8">('+S.dupes_removed+' duplicates merged)</span>':'';
  const reuseClick=S.cred_reuse_count?'onclick="document.getElementById(\'reuseBlock\').scrollIntoView({behavior:\'smooth\'})" style="cursor:pointer"':'';
  document.getElementById('summaryCards').innerHTML=
    '<div class="scard"><div class="val">'+S.total+'</div><div class="lbl">Findings'+dupeNote+'</div></div>'+
    '<div class="scard crit"><div class="val">'+S.sev.Black+'</div><div class="lbl">Critical</div></div>'+
    '<div class="scard high"><div class="val">'+S.sev.Red+'</div><div class="lbl">High</div></div>'+
    '<div class="scard"><div class="val">'+S.hosts_total+'</div><div class="lbl">Hosts</div></div>'+
    '<div class="scard"><div class="val">'+S.creds_total+'</div><div class="lbl">With Credentials</div></div>'+
    '<div class="scard" '+reuseClick+'><div class="val">'+(S.cred_reuse_count||0)+'</div><div class="lbl">Reused Creds</div></div>';

  // Quick wins
  document.getElementById('qwCount').textContent='('+QW.length+')';
  const qw=document.getElementById('qwList');
  if(!QW.length){qw.innerHTML='<div style="padding:14px 18px;color:#64748b;font-size:.85em">No quick wins identified — review findings below.</div>';} else {
    qw.innerHTML=QW.map(q=>{
      const f=D[q.i];
      const sc={'Black':'#991b1b','Red':'#c2410c','Yellow':'#a16207','Green':'#15803d'}[f.sv]||'#64748b';
      const tags=(f.tg||[]).map(t=>'<span class="tag tag-'+t+'">'+t+'</span>').join('');
      return '<div class="qw-item"><div class="qw-sev" style="background:'+sc+'"></div><div class="qw-body">'+
        '<div class="qw-title">'+esc(q.title)+'</div>'+
        '<div class="qw-path">'+esc(f.pa||f.sh)+'</div>'+
        (q.detail?'<div class="qw-creds">'+esc(q.detail)+'</div>':'')+
        '<div class="qw-tags" style="margin-top:4px">'+tags+'</div>'+
      '</div></div>';
    }).join('');
  }

  // Severity bars
  const total=S.total;
  const sevs=[{k:'Black',c:'#991b1b',l:'Critical'},{k:'Red',c:'#9a3412',l:'High'},{k:'Yellow',c:'#854d0e',l:'Medium'},{k:'Green',c:'#166534',l:'Low'}];
  document.getElementById('sevBars').innerHTML=sevs.map(s=>{
    const n=S.sev[s.k]||0;const pct=total?(n/total*100).toFixed(1):0;
    return '<div class="bar-row"><span class="bar-label" style="color:'+s.c+'">'+s.l+'</span><div class="bar-track"><div class="bar-fill" style="width:'+pct+'%;background:'+s.c+'"></div></div><span class="bar-num">'+n+'</span></div>';
  }).join('');

  // Lists - clickable to filter findings
  document.getElementById('topRules').innerHTML=S.rules.map(x=>'<li onclick="filterByRule(\''+ea(x[0])+'\')" title="Click to filter findings"><span>'+esc(x[0])+'</span><span class="n">'+x[1]+'</span></li>').join('');
  document.getElementById('topHosts').innerHTML=S.hosts.map(x=>'<li onclick="filterByHost(\''+ea(x[0])+'\')" title="Click to filter findings"><span>'+esc(x[0])+'</span><span class="n">'+x[1]+'</span></li>').join('');
  document.getElementById('topExts').innerHTML=S.exts.map(x=>'<li onclick="filterByText(\''+ea(x[0])+'\')" title="Click to filter findings"><span>'+esc(x[0]||'(none)')+'</span><span class="n">'+x[1]+'</span></li>').join('');
}

function renderReuse(){
  if(!REUSE.length)return;
  document.getElementById('reuseBlock').classList.remove('hidden');
  document.getElementById('reuseCount').textContent='('+REUSE.length+')';
  document.getElementById('reuseBody').innerHTML=REUSE.map(r=>
    '<tr><td><span class="reuse-val">'+esc(r.value)+'</span></td>'+
    '<td><strong>'+r.count+'</strong></td>'+
    '<td>'+r.hosts.map(h=>esc(h)).join(', ')+'</td>'+
    '<td><span class="reuse-where">'+r.files.map(f=>esc(f)).join(', ')+'</span></td></tr>'
  ).join('');
}

function buildFilters(){
  const all=new Set();
  D.forEach(f=>(f.tg||[]).forEach(t=>all.add(t)));
  if(!all.size){document.getElementById('tagSep').classList.add('hidden');return;}
  const el=document.getElementById('tagBtns');
  el.innerHTML=Array.from(all).map(t=>'<button class="btn" data-tg="'+t+'" onclick="togF(this,\'tg\')">'+t+'</button>').join(' ');
}

function togF(b,kind){
  b.classList.toggle('on');
  if(kind==='sv'){fSev.clear();document.querySelectorAll('[data-sv].on').forEach(x=>fSev.add(x.dataset.sv));}
  else if(kind==='ty'){fTy.clear();document.querySelectorAll('[data-ty].on').forEach(x=>fTy.add(x.dataset.ty));}
  else{fTag.clear();document.querySelectorAll('[data-tg].on').forEach(x=>fTag.add(x.dataset.tg));}
  applyFilters();
}

function applyFilters(){
  const q=document.getElementById('searchBox').value.toLowerCase();
  filtered=D.filter(r=>{
    if(fSev.size&&!fSev.has(r.sv))return false;
    if(fTy.size&&!fTy.has(r.ty))return false;
    if(fTag.size&&!(r.tg||[]).some(t=>fTag.has(t)))return false;
    if(fCreds&&!(r.cr&&r.cr.length))return false;
    if(q){if(![r.pa,r.ho,r.ru,r.sh,r.cx,r.fn,(r.tg||[]).join(' ')].join(' ').toLowerCase().includes(q))return false;}
    return true;
  });
  sortData();page=0;render();
}

function sortData(){
  filtered.sort((a,b)=>{
    let va=a[sortCol]||'',vb=b[sortCol]||'';
    if(sortCol==='sv'){va=SEV_ORD[va]??9;vb=SEV_ORD[vb]??9;}
    else if(sortCol==='mo'){va=a.mo||'9999';vb=b.mo||'9999';}
    else{va=String(va).toLowerCase();vb=String(vb).toLowerCase();}
    return sortAsc?(va<vb?-1:va>vb?1:0):(va>vb?-1:va<vb?1:0);
  });
}

function doSort(col){
  if(sortCol===col)sortAsc=!sortAsc;else{sortCol=col;sortAsc=true;}
  document.querySelectorAll('.arr').forEach(a=>a.textContent='');
  const el=document.getElementById('a_'+col);
  if(el)el.textContent=sortAsc?'▲':'▼';
  sortData();render();
}

const LABELS={Black:'Critical',Red:'High',Yellow:'Medium',Green:'Low'};
const SEV_DOTS={Black:'#991b1b',Red:'#9a3412',Yellow:'#854d0e',Green:'#166534'};

function rowHTML(r){
  const hasCtx=!!(r.cx&&r.cx.length>0);
  const pp=splitPath(r.pa||r.sh);
  const tags=(r.tg||[]).map(t=>'<span class="tag tag-'+t+'">'+t+'</span>').join('');
  const age=r.mo?fileAge(r.mo):'';
  const dupe=r.dc>1?'<span class="dupe-badge">x'+r.dc+'</span>':'';
  const cls=hasCtx?'clickable':'';
  const click=hasCtx?' onclick="togDetail(this)"':'';
  let h='<tr class="'+cls+'"'+click+'>'+
    '<td><span class="sev-badge sev-'+r.sv+'">'+LABELS[r.sv]+'</span>'+dupe+'</td>'+
    '<td>'+esc(r.ru)+'</td>'+
    '<td style="font-family:Consolas,monospace;font-size:.88em">'+esc(r.ho)+'</td>'+
    '<td><span class="fp"><span class="fp-dir">'+esc(pp[0])+'</span><span class="fp-name">'+esc(pp[1])+'</span></span>'+(hasCtx?'<span class="ctx-preview">'+hlPreview(r.cx)+'</span>':'')+'</td>'+
    '<td style="color:#64748b;white-space:nowrap">'+esc(r.sz)+'</td>'+
    '<td style="color:#64748b;white-space:nowrap">'+age+'</td>'+
    '<td>'+tags+'</td>'+
  '</tr>';
  if(hasCtx){
    h+='<tr class="detail-row"><td colspan="7"><div class="detail-box">'+
      '<dl class="detail-grid">'+
      '<dt>Full Path</dt><dd>'+esc(r.pa||r.sh)+'</dd>'+
      (r.ru?'<dt>Rule</dt><dd>'+esc(r.ru)+'</dd>':'')+
      (r.ac?'<dt>Access</dt><dd>'+esc(r.ac)+'</dd>':'')+
      (r.sz?'<dt>Size</dt><dd>'+esc(r.sz)+'</dd>':'')+
      (r.mo?'<dt>Modified</dt><dd>'+esc(r.mo)+'</dd>':'')+
      '</dl>'+
      '<div class="detail-ctx">'+hlCtx(r.cx)+'</div>'+
    '</div></td></tr>';
  }
  return h;
}

function groupRowHTML(name,items,collapsed){
  const counts={Black:0,Red:0,Yellow:0,Green:0};
  items.forEach(r=>{counts[r.sv]=(counts[r.sv]||0)+1;});
  let dots='';
  ['Black','Red','Yellow','Green'].forEach(s=>{if(counts[s])dots+='<span class="group-dot" style="background:'+SEV_DOTS[s]+'" title="'+counts[s]+' '+LABELS[s]+'"></span>';});
  const cls='group-row'+(collapsed?' collapsed':'');
  return '<tr class="'+cls+'" onclick="togGroup(this)">'+
    '<td colspan="7">'+
      '<span class="group-toggle">&#9660;</span> '+
      '<span class="group-name">'+esc(name||'(none)')+'</span>'+
      '<span class="group-dots">'+dots+'</span>'+
      '<span class="group-meta">'+items.length+' '+(items.length===1?'finding':'findings')+'</span>'+
    '</td></tr>';
}

function render(){
  const tb=document.getElementById('tbody');
  const total=filtered.length;
  document.getElementById('findCount').textContent='('+total+')';

  if(viewMode==='flat'){
    document.querySelector('.pager').style.display='';
    document.getElementById('viewHint').textContent='';
    const start=page*PAGE,slice=filtered.slice(start,start+PAGE);
    tb.innerHTML=slice.map(rowHTML).join('');
    const pages=Math.ceil(total/PAGE)||1;
    document.getElementById('pagerInfo').textContent=total+' findings | Page '+(page+1)+' of '+pages;
    return;
  }

  // Grouped view
  document.querySelector('.pager').style.display='none';
  const key={ho:r=>r.ho,sh:r=>r.sh||r.pa,ru:r=>r.ru}[viewMode];
  const groups=new Map();
  for(const r of filtered){
    const k=key(r)||'(none)';
    if(!groups.has(k))groups.set(k,[]);
    groups.get(k).push(r);
  }
  const sorted=[...groups.entries()].sort((a,b)=>{
    const sa=Math.min(...a[1].map(r=>SEV_ORD[r.sv]??9));
    const sb=Math.min(...b[1].map(r=>SEV_ORD[r.sv]??9));
    if(sa!==sb)return sa-sb;
    return b[1].length-a[1].length;
  });

  document.getElementById('viewHint').textContent=sorted.length+' groups · click to expand';
  let h='';
  // expand top groups by default if total findings small, otherwise collapse all
  let expanded=0;
  for(let i=0;i<sorted.length;i++){
    const [name,items]=sorted[i];
    const collapse=total>200||expanded>=3;
    h+=groupRowHTML(name,items,collapse);
    if(!collapse){
      h+=items.map(rowHTML).join('');
      expanded++;
    }
  }
  tb.innerHTML=h;
}

function togGroup(headerTr){
  const wasCollapsed=headerTr.classList.contains('collapsed');
  headerTr.classList.toggle('collapsed');
  if(wasCollapsed){
    // Need to render the rows - find which group this is and insert
    const allHeaders=Array.from(document.querySelectorAll('.group-row'));
    const idx=allHeaders.indexOf(headerTr);
    const name=headerTr.querySelector('.group-name').textContent;
    // Re-derive items from filtered
    const key={ho:r=>r.ho,sh:r=>r.sh||r.pa,ru:r=>r.ru}[viewMode];
    const items=filtered.filter(r=>(key(r)||'(none)')===name);
    const html=items.map(rowHTML).join('');
    headerTr.insertAdjacentHTML('afterend',html);
  } else {
    // Collapse - remove all rows until next group-row
    let next=headerTr.nextElementSibling;
    while(next&&!next.classList.contains('group-row')){
      const toRemove=next;next=next.nextElementSibling;toRemove.remove();
    }
  }
}

function togDetail(tr){
  const dr=tr.nextElementSibling;
  if(!dr||!dr.classList.contains('detail-row'))return;
  const wasOpen=dr.classList.contains('open');
  // close all others
  document.querySelectorAll('.detail-row.open').forEach(r=>{r.classList.remove('open');r.previousElementSibling.classList.remove('active');});
  if(!wasOpen){dr.classList.add('open');tr.classList.add('active');}
}

function splitPath(p){if(!p)return['',''];const i=p.lastIndexOf('\\');return i>=0?[p.slice(0,i+1),p.slice(i+1)]:['',p];}

function fileAge(d){
  try{const ms=Date.now()-new Date(d.replace(' ','T')).getTime();const days=Math.floor(ms/864e5);
    if(days<0)return'';if(days<30)return days+'d';if(days<365)return Math.floor(days/30)+'mo';
    return Math.floor(days/365)+'y';
  }catch(e){return'';}
}

function hlPreview(text){
  // Find an interesting snippet around a keyword, else take the start
  let t=text.replace(/\n+/g,' ').replace(/\s+/g,' ');
  const m=t.match(/.{0,30}(?:password|passwd|pwd|secret|key|token|connectionstring|user\s*id|credential)[^\n]{0,50}/i);
  let snip=m?'…'+m[0]+'…':t.slice(0,90);
  if(t.length>90&&!m)snip+='…';
  return snip.replace(/(password|passwd|pwd|secret|key|token|user(?:name)?|credential|connectionString)/gi,'<mark>$1</mark>');
}

function hlCtx(text){
  return text
    .replace(/((?:password|passwd|pwd|secret|token|api[_\-]?key|credential)\s*[=:]\s*)(["']?)([^\s"';,}\]\r\n]{2,})/gi,'$1$2<mark class="v">$3</mark>')
    .replace(/((?:user(?:name)?|login|uid|User\s*Id)\s*[=:]\s*)(["']?)([^\s"';,}\]\r\n]{2,})/gi,'$1$2<mark>$3</mark>')
    .replace(/(connectionString|Data\s*Source|Initial\s*Catalog)/gi,'<mark>$1</mark>');
}

function esc(s){return s?s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'):'';}
function ea(s){return (s||'').replace(/\\/g,'\\\\').replace(/'/g,"\\'");}
function goPrev(){if(page>0){page--;render();}}
function goNext(){if((page+1)*PAGE<filtered.length){page++;render();}}

function filterByRule(name){
  document.getElementById('searchBox').value=name;applyFilters();
  document.querySelector('.sticky-toolbar').scrollIntoView({behavior:'smooth',block:'start'});
}
function filterByHost(name){
  document.getElementById('searchBox').value=name;applyFilters();
  document.querySelector('.sticky-toolbar').scrollIntoView({behavior:'smooth',block:'start'});
}
function filterByText(t){
  document.getElementById('searchBox').value=t;applyFilters();
  document.querySelector('.sticky-toolbar').scrollIntoView({behavior:'smooth',block:'start'});
}
function togCreds(b){
  b.classList.toggle('on');
  fCreds=b.classList.contains('on');
  applyFilters();
}

function exportCSV(){
  let csv='Severity,Type,Rule,Host,Share,Path,Filename,Size,Modified,Access,Tags,Duplicates,Context\n';
  for(const r of filtered){csv+=[r.sv,r.ty,r.ru,r.ho,r.sh,r.pa,r.fn,r.sz,r.mo,r.ac,(r.tg||[]).join(';'),r.dc,'"'+(r.cx||'').replace(/"/g,'""')+'"'].join(',')+'\n';}
  const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv'}));a.download='snaffler_export.csv';a.click();
}

function initKB(){
  document.addEventListener('keydown',e=>{
    if(e.target.tagName==='INPUT'){if(e.key==='Escape'){e.target.blur();e.target.value='';applyFilters();}return;}
    if(e.key==='/'){e.preventDefault();document.getElementById('searchBox').focus();}
  });
  document.getElementById('searchBox').addEventListener('input',debounce(applyFilters,200));
}
function debounce(fn,ms){let t;return function(){clearTimeout(t);t=setTimeout(fn,ms);};}

document.addEventListener('DOMContentLoaded',init);
</script>
</body>
</html>"""


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description="snaffler-argus — parse Snaffler logs and generate an interactive HTML report")
    p.add_argument("files", nargs="+", help="Snaffler log file(s)")
    p.add_argument("-o", "--output", default=None, help="Output HTML path (default: snaffler_report.html)")
    p.add_argument("-t", "--title", default="Snaffler Report", help="Report title")
    args = p.parse_args()

    all_findings = []
    for fpath in args.files:
        fp = Path(fpath)
        if not fp.exists():
            print(f"[!] Not found: {fpath}")
            sys.exit(1)
        findings, skipped = parse_file(fp)
        print(f"[*] {fp.name}: {len(findings)} parsed, {skipped} skipped")
        all_findings.extend(findings)

    if not all_findings:
        print("[!] No findings parsed from any file. Check format.")
        sys.exit(1)

    print(f"[*] Enriching {len(all_findings)} findings...")
    enrich(all_findings)

    output = args.output or "snaffler_report.html"
    generate_report(all_findings, output, args.title, args.files)


if __name__ == "__main__":
    main()
