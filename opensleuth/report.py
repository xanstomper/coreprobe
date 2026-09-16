"""Report generation: HTML (AXIOM-style), CSV, JSON, timeline."""

import csv
import html
import json
from datetime import datetime, timezone
from pathlib import Path

from .util import fmt_size, iso_now

_CSV_COLUMNS = {
    "messages": ["date", "chat", "sender", "from_me", "service", "text", "attachments", "id"],
    "contacts": ["name", "organization", "department", "phones", "emails", "other", "birthday", "created", "modified"],
    "calls": ["date", "phone", "direction", "type", "duration_seconds", "answered", "country"],
    "history": ["date", "url", "title", "visit_count", "origin", "load_successful"],
    "bookmarks": ["title", "url", "folder", "modified"],
    "keychain": ["kind", "service", "account", "group", "data_size", "data_hex", "plaintext_attempt", "created", "modified"],
    "voicemail": ["date", "sender", "callback_token", "duration_seconds", "expiration", "trashed", "flags", "audio_present", "audio_size"],
    "notes": ["title", "created", "modified", "body_size", "body_saved", "body_hex"],
    "app_databases": ["domain", "path", "size"],
}

_PAGE_CSS = """
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { margin: 0; font: 14px/1.45 ui-monospace, 'SF Mono', Menlo, monospace; background: #0b0e14; color: #d7dae0; }
header { padding: 18px 28px; background: #11151d; border-bottom: 1px solid #232a37; position: sticky; top: 0; z-index: 5; }
header h1 { margin: 0; font-size: 18px; color: #7ee8a2; }
header .sub { color: #8b93a7; font-size: 12px; margin-top: 4px; }
nav { padding: 10px 28px; background: #0f131b; border-bottom: 1px solid #1d2430; display: flex; gap: 8px; flex-wrap: wrap; }
nav a { color: #9db2d0; text-decoration: none; padding: 4px 10px; border: 1px solid #232a37; border-radius: 6px; font-size: 12px; }
nav a:hover { border-color: #7ee8a2; color: #7ee8a2; }
main { padding: 22px 28px; max-width: 1400px; }
section { margin-bottom: 34px; }
h2 { font-size: 15px; color: #7ee8a2; border-bottom: 1px solid #1d2430; padding-bottom: 8px; }
h2 .count { color: #8b93a7; font-weight: normal; }
table { border-collapse: collapse; width: 100%; margin-top: 10px; font-size: 12.5px; }
th { text-align: left; color: #aeb6c8; border-bottom: 1px solid #2a3242; padding: 6px 8px; position: sticky; top: 90px; background: #0b0e14; }
td { border-bottom: 1px solid #171d28; padding: 5px 8px; vertical-align: top; }
tr:hover td { background: #121823; }
.mono { color: #e6a3f2; word-break: break-all; }
meta, .js-hidden { display: none; }
#filter { width: 260px; padding: 7px 10px; background: #0f131b; border: 1px solid #2a3242; color: #d7dae0; border-radius: 6px; }
.badge { display: inline-block; padding: 1px 7px; border-radius: 10px; font-size: 11px; }
.badge.in { background: #1d2b45; color: #7fb3ff; } .badge.out { background: #123224; color: #7ee8a2; }
.kv { display: grid; grid-template-columns: 220px 1fr; gap: 3px 14px; margin-top: 8px; }
.kv .k { color: #8b93a7; } .kv .v { word-break: break-all; }
pre { background: #0f131b; border: 1px solid #1d2430; padding: 12px; overflow: auto; max-height: 320px; font-size: 11.5px; }
footer { color: #545d6e; padding: 18px 28px; font-size: 11px; }
"""


def _esc(v):
    if v is None:
        return ""
    return html.escape(str(v), quote=True)


def _table(headers, rows, row_render=None):
    """rows: list of dicts; row_render maps dict -> list of cell strings."""
    out = ["<table><thead><tr>"]
    for h in headers:
        out.append(f"<th>{_esc(h)}</th>")
    out.append("</tr></thead><tbody>")
    for r in rows:
        cells = row_render(r) if row_render else [_esc(r.get(h, "")) for h in headers]
        out.append("<tr>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>")
    out.append("</tbody></table>")
    return "".join(out)


def _timeline(artifacts):
    events = []
    for m in artifacts.get("messages", []):
        if m.get("date"):
            events.append((m["date"], "Message", ("Sent to " if m["from_me"] else "From ") + (_esc(m["chat"]) or "?") + ": " + _esc((m["text"] or "")[:120])))
    for c in artifacts.get("calls", []):
        if c.get("date"):
            events.append((c["date"], "Call", _esc(f"{c['type']} {c['direction']} {c.get('phone') or ''} ({c.get('duration_seconds') or 0}s)")))
    for h in artifacts.get("history", []):
        if h.get("date"):
            events.append((h["date"], "Web", _esc(f"{h.get('title') or ''} - {h['url']}")))
    events.sort(reverse=True)
    return events


def build_report(artifacts, outdir: Path, html_path=None):
    """Write report.html + artifacts.json + per-artifact CSVs + timeline.csv."""
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    # JSON
    (outdir / "artifacts.json").write_text(
        json.dumps(artifacts, indent=2, default=str), encoding="utf-8"
    )

    # CSVs
    timeline = _timeline(artifacts)
    for name in ("messages", "contacts", "calls", "history", "bookmarks",
                 "keychain", "voicemail", "notes", "app_databases"):
        cols = _CSV_COLUMNS[name]
        rows = artifacts.get(name, [])
        with open(outdir / f"{name}.csv", "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            w.writerows(rows)
    with open(outdir / "timeline.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["timestamp", "artifact", "summary"])
        w.writerows(timeline)

    # HTML
    dev = artifacts.get("device", {}) or {}
    apps = artifacts.get("apps", []) or []
    files = artifacts.get("files", {}) or {}
    prefs = artifacts.get("prefs", {}) or {}

    sec = []
    sec.append(
        "<section id=summary><h2>Device <span class=count>"
        + _esc(f"{dev.get('product') or '?'} - {dev.get('serial') or '?'}")
        + "</span></h2><div class=kv>"
        + "".join(f'<div class=k>{_esc(k)}</div><div class=v>{_esc(str(v))}</div>' for k, v in dev.items())
        + "</div></section>"
    )
    sec.append(
        "<section id=apps><h2>Applications <span class=count>"
        + str(len(apps))
        + "</span></h2>"
        + _table(
            ["Bundle ID", "Version", "Name"],
            apps,
            lambda r: [_esc(r.get("bundle_id")), _esc(r.get("version")), _esc(r.get("name"))],
        )
        + "</section>"
    )
    sec.append(
        "<section id=messages><h2>Messages <span class=count>"
        + str(len(artifacts.get("messages", [])))
        + "</span></h2>"
        + _table(
            ["Date", "Chat", "Sender", "Dir", "Service", "Text", "Attachments"],
            artifacts.get("messages", []),
            lambda r: [
                _esc(r.get("date")),
                _esc(r.get("chat")),
                _esc(r.get("sender")),
                '<span class="badge {}">{}</span>'.format("out" if r.get("from_me") else "in", "Sent" if r.get("from_me") else "Recv"),
                _esc(r.get("service")),
                _esc(r.get("text")),
                _esc("; ".join(r.get("attachments") or [])),
            ],
        )
        + "</section>"
    )
    sec.append(
        "<section id=contacts><h2>Contacts <span class=count>"
        + str(len(artifacts.get("contacts", [])))
        + "</span></h2>"
        + _table(
            ["Name", "Organization", "Phones", "Emails", "Other", "Birthday"],
            artifacts.get("contacts", []),
            lambda r: [
                _esc(r.get("name")),
                _esc(r.get("organization")),
                _esc("; ".join(r.get("phones") or [])),
                _esc("; ".join(r.get("emails") or [])),
                _esc("; ".join(r.get("other") or [])),
                _esc(r.get("birthday")),
            ],
        )
        + "</section>"
    )
    sec.append(
        "<section id=calls><h2>Call History <span class=count>"
        + str(len(artifacts.get("calls", [])))
        + "</span></h2>"
        + _table(
            ["Date", "Phone", "Direction", "Type", "Duration", "Answered"],
            artifacts.get("calls", []),
            lambda r: [
                _esc(r.get("date")),
                _esc(r.get("phone")),
                _esc(r.get("direction")),
                _esc(r.get("type")),
                f"{int(r.get('duration_seconds') or 0)}s",
                _esc(r.get("answered")),
            ],
        )
        + "</section>"
    )
    sec.append(
        "<section id=history><h2>Safari History <span class=count>"
        + str(len(artifacts.get("history", [])))
        + "</span></h2>"
        + _table(
            ["Date", "URL", "Title", "Visits"],
            artifacts.get("history", []),
            lambda r: [
                _esc(r.get("date")),
                f'<span class=mono>{_esc(r.get("url"))}</span>',
                _esc(r.get("title")),
                _esc(r.get("visit_count")),
            ],
        )
        + "</section>"
    )
    sec.append(
        "<section id=bookmarks><h2>Safari Bookmarks <span class=count>"
        + str(len(artifacts.get("bookmarks", [])))
        + "</span></h2>"
        + _table(["Title", "URL"], artifacts.get("bookmarks", []), lambda r: [_esc(r.get("title")), f'<span class=mono>{_esc(r.get("url"))}</span>'])
        + "</section>"
    )
    if prefs:
        rows = [{"plist": k, "content": json.dumps(v, default=str)[:400]} for k, v in list(prefs.items())[:200]]
        sec.append(
            "<section id=prefs><h2>Preferences <span class=count>"
            + str(len(prefs))
            + "</span></h2>"
            + _table(["Plist", "Content"], rows, lambda r: [_esc(r["plist"]), '<span class=mono>' + _esc(r["content"]) + "</span>"])
            + "</section>"
        )
    sec.append(
        "<section id=files><h2>Backup Content <span class=count>"
        + _esc(fmt_size(files.get("bytes")))
        + "</span></h2><div class=kv><div class=k>Files</div><div class=v>"
        + str(files.get("files"))
        + "</div><div class=k>Total size</div><div class=v>"
        + fmt_size(files.get("bytes"))
        + "</div><div class=k>App domains</div><div class=v>"
        + str(len(files.get("app_domains", [])))
        + "</div></div><pre>"
        + _esc(json.dumps(files.get("app_domains", [])[:60], indent=1, default=str))
        + "</pre></section>"
    )
    sec.append(
        "<section id=keychain><h2>Keychain <span class=count>"
        + str(len(artifacts.get("keychain", [])))
        + "</span></h2>"
        + _table(
            ["Kind", "Service", "Account", "Group", "Data", "Plaintext attempt"],
            artifacts.get("keychain", []),
            lambda r: [
                _esc(r.get("kind")),
                _esc(r.get("service")),
                _esc(r.get("account")),
                _esc(r.get("group")),
                f"{r.get('data_size') or 0}B <span class=mono>{_esc(r.get('data_hex'))}</span>",
                _esc(r.get("plaintext_attempt")),
            ],
        )
        + "</section>"
    )
    sec.append(
        "<section id=voicemail><h2>Voicemail <span class=count>"
        + str(len(artifacts.get("voicemail", [])))
        + "</span></h2>"
        + _table(
            ["Date", "Sender", "Callback token", "Duration", "Trashed", "Audio"],
            artifacts.get("voicemail", []),
            lambda r: [
                _esc(r.get("date")),
                _esc(r.get("sender")),
                _esc(r.get("callback_token")),
                f"{int(r.get('duration_seconds') or 0)}s",
                _esc(r.get("trashed")),
                f"{'yes' if r.get('audio_present') else 'no'} ({r.get('audio_size') or 0}B)",
            ],
        )
        + "</section>"
    )
    sec.append(
        "<section id=notes><h2>Notes <span class=count>"
        + str(len(artifacts.get("notes", [])))
        + "</span></h2>"
        + _table(
            ["Title", "Created", "Modified", "Body"],
            artifacts.get("notes", []),
            lambda r: [
                _esc(r.get("title")),
                _esc(r.get("created")),
                _esc(r.get("modified")),
                f"{r.get('body_size') or 0}B <span class=mono>{_esc(r.get('body_hex'))}</span>",
            ],
        )
        + "</section>"
    )
    sec.append(
        "<section id=databases><h2>App Databases <span class=count>"
        + str(len(artifacts.get("app_databases", [])))
        + "</span></h2>"
        + _table(
            ["Domain", "Path", "Size"],
            artifacts.get("app_databases", [])[:300],
            lambda r: [_esc(r.get("domain")), '<span class=mono>' + _esc(r.get("path")) + "</span>", _esc(r.get("size"))],
        )
        + "</section>"
    )
    sec.append(
        "<section id=timeline><h2>Timeline <span class=count>"
        + str(len(timeline))
        + "</span></h2>"
        + _table(["Timestamp", "Artifact", "Summary"], timeline, lambda r: [_esc(r[0]), _esc(r[1]), r[2]])
        + "</section>"
    )

    nav_links = "".join(
        f'<a href="#{name}">{name.title().replace("_", " ")}</a>'
        for name in ["summary", "apps", "messages", "contacts", "calls", "history", "bookmarks",
                 "keychain", "voicemail", "notes", "prefs", "databases", "files", "timeline"]
    )
    html_doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>opensleuth report - {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</title>
<style>{_PAGE_CSS}</style></head>
<body>
<header><h1>opensleuth forensics report</h1>
<div class=sub>{iso_now()} &middot; generated locally by opensleuth &middot; open-source AXIOM/Cellebrite-style triage</div></header>
<nav>{nav_links} <input id=filter placeholder="filter tables..."></nav>
<main>{''.join(sec)}</main>
<footer>opensleuth - all evidence is read-only. Secure Enclave keys and filesystem-level data are not extractable on stock iOS.</footer>
<script>
const f=document.getElementById('filter');
f.addEventListener('input',()=>{{
 const q=f.value.toLowerCase();
 document.querySelectorAll('tbody tr').forEach(tr=>{{
   tr.style.display=tr.textContent.toLowerCase().includes(q)?'':'none';
 }});
}});
</script>
</body></html>"""
    (outdir / "report.html").write_text(html_doc, encoding="utf-8")
    return outdir