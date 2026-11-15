"""Downloadable outputs: text report, HTML report, SVG badge."""
from html import escape

from checks import CHECKS, describe, fix_for

STATUS_LABEL = {"pass": "PASS", "warn": "PARTIAL", "fail": "FIX NEEDED"}
GRADE_COLOR = {"A+": "#2e9e5b", "A": "#4caf50", "B": "#c8a400", "C": "#e07b00", "F": "#d64545"}


def build_text_report(r, mode: str, platform: str) -> str:
    lines = [
        "# SiteHouse Security Checkup Report",
        f"Website: {r.url}",
        f"Grade: {r.grade} ({r.score}/100) | SSL Days Remaining: {r.days_left if r.days_left >= 0 else 'N/A'}",
        f"View Mode: {mode} | Platform: {platform}",
        "-" * 50,
    ]
    for c in CHECKS:
        res = r.results[c["id"]]
        title, msg = describe(c, res.status, res.detail, mode)
        lines.append(f"\n[{STATUS_LABEL[res.status]}] {title} ({res.points:g}/{c['pts']} pts)")
        lines.append(f"  {msg}")
        if res.status != "pass":
            text, code = fix_for(c, platform)
            lines.append(f"  How to fix ({platform}): {text}")
            if code:
                lines += ["    " + ln for ln in code.splitlines()]
    return "\n".join(lines)


def build_html_report(r, mode: str, platform: str) -> str:
    color = {"pass": "#2e9e5b", "warn": "#e0a100", "fail": "#d64545"}
    cards = []
    for c in CHECKS:
        res = r.results[c["id"]]
        title, msg = describe(c, res.status, res.detail, mode)
        fix_html = ""
        if res.status != "pass":
            text, code = fix_for(c, platform)
            fix_html = f"<p><b>Fix ({escape(platform)}):</b> {escape(text)}</p>"
            if code:
                fix_html += f"<pre>{escape(code)}</pre>"
        cards.append(
            f'<div class="card" style="border-left:6px solid {color[res.status]}">'
            f"<h3>{escape(title)} <small>{res.points:g}/{c['pts']} pts</small></h3>"
            f"<p>{escape(msg)}</p>{fix_html}</div>"
        )
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>SiteHouse Report</title>
<style>body{{font-family:system-ui,sans-serif;max-width:760px;margin:2rem auto;padding:0 1rem;color:#222}}
.card{{background:#f7f7f7;padding:.6rem 1rem;margin:.8rem 0;border-radius:6px}}
pre{{background:#272822;color:#eee;padding:.6rem;overflow-x:auto;border-radius:4px}}
small{{color:#777;font-weight:normal}}.grade{{font-size:3rem;font-weight:700;color:{GRADE_COLOR[r.grade]}}}</style></head><body>
<h1>🏠 SiteHouse Security Checkup</h1><p>{escape(r.url)}</p>
<div class="grade">{escape(r.grade)} <small>{r.score}/100</small></div>
<p>Reading mode: {escape(mode)} · Platform: {escape(platform)}</p>{''.join(cards)}</body></html>"""


def build_badge_svg(r) -> str:
    color = GRADE_COLOR[r.grade]
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="150" height="22" role="img" aria-label="SiteHouse: {escape(r.grade)}">
<rect width="95" height="22" fill="#555" rx="3"/><rect x="95" width="55" height="22" fill="{color}" rx="3"/>
<g fill="#fff" font-family="Verdana,sans-serif" font-size="11" text-anchor="middle">
<text x="47" y="15">🏠 SiteHouse</text><text x="122" y="15">{escape(r.grade)} · {r.score}</text></g></svg>"""
