import time

import streamlit as st
import streamlit.components.v1 as components

from checks import CHECKS, CHECK_BY_ID, DEEP_CHECKS, MODES, PLATFORMS, describe, fix_for
from reports import build_badge_svg, build_html_report, build_text_report
from scanner import ScanError, scan

MIN_SECONDS_BETWEEN_SCANS = 10
ICON = {"pass": "🟢", "warn": "🟡", "fail": "🔴"}
COLOR = {"pass": "#2e9e5b", "warn": "#e0a100", "fail": "#d64545"}

st.set_page_config(page_title="SiteHouse Security Checkup", page_icon="🏠")


def house_svg(r) -> str:
    c = lambda cid: COLOR[r.results[cid].status]
    return f"""<svg viewBox="0 0 300 260" xmlns="http://www.w3.org/2000/svg" style="width:100%;max-height:260px">
<rect x="205" y="38" width="22" height="50" fill="{c('hsts')}" stroke="#888"/>
<polygon points="35,112 150,25 265,112" fill="{c('csp')}" stroke="#888" stroke-width="2"/>
<rect x="60" y="112" width="180" height="108" fill="#e8e2d4" stroke="#888" stroke-width="2"/>
<rect x="128" y="150" width="44" height="70" rx="3" fill="{c('https')}" stroke="#555"/>
<circle cx="162" cy="188" r="3" fill="#fff"/>
<rect x="75" y="135" width="38" height="38" fill="{c('frame')}" stroke="#555"/>
<rect x="187" y="135" width="38" height="38" fill="{c('frame')}" stroke="#555"/>
<rect x="45" y="220" width="210" height="12" fill="{c('ssl_valid')}" stroke="#888"/>
<rect x="115" y="236" width="70" height="12" rx="2" fill="{c('files')}" stroke="#888"/>
</svg>"""


def render_card(c, res, mode, platform):
    title, msg = describe(c, res.status, res.detail, mode)
    with st.container(border=True):
        st.markdown(f"#### {ICON[res.status]} {title} *({res.points:g}/{c['pts']} pts)*")
        st.write(msg)
        if res.status != "pass":
            with st.expander(f"🛠️ Fix for {platform}"):
                text, code = fix_for(c, platform)
                st.info(text)
                if code:
                    st.code(code)


# --- UI ---
st.title("🏠 SiteHouse Security Checkup")
st.caption("Check any website's safety in seconds—explained so anyone can understand. "
           "Only scan sites you own or have permission to test.")

with st.form("scan_form"):
    url_input = st.text_input("Website Address", placeholder="Type a website (e.g., example.com)")
    deep = st.checkbox("🔬 Include deep checks (software versions, JavaScript libraries, exposed paths — about 25 extra requests)")
    confirm = st.checkbox("I own this website or have permission to test it (required for deep checks)")
    submitted = st.form_submit_button("🔍 Scan")

if submitted and url_input.strip():
    wait = MIN_SECONDS_BETWEEN_SCANS - (time.time() - st.session_state.get("last_scan", 0))
    if deep and not confirm:
        st.warning("Please tick the permission box to run deep checks, or untick deep checks for a basic scan.")
    elif wait > 0:
        st.warning(f"Please wait {int(wait) + 1}s before scanning again.")
    else:
        st.session_state["last_scan"] = time.time()
        bar = st.progress(0.0, text="Knocking on the front door...")

        def on_progress(done, total, part):
            bar.progress(min(done / total, 1.0), text=f"Checked: {part}")

        try:
            result = scan(url_input, on_progress, deep=deep)
            history = st.session_state.setdefault("history", [])
            prev = next((h for h in reversed(history) if h["host"] == result.host), None)
            st.session_state["prev_score"] = prev["score"] if prev else None
            history.append({"time": result.scanned_at, "host": result.host,
                            "grade": result.grade, "score": result.score,
                            "deep": f"{result.deep_grade} ({result.deep_score})" if result.deep_results else "-"})
            st.session_state["result"], st.session_state["error"] = result, None
            st.session_state["celebrate"] = result.score == 100
        except ScanError as e:
            st.session_state["result"], st.session_state["error"] = None, str(e)
        finally:
            bar.empty()

if st.session_state.get("error"):
    st.error(st.session_state["error"])

r = st.session_state.get("result")
if r:
    if st.session_state.pop("celebrate", False):
        st.balloons()

    for note in r.notes:
        st.info(note)

    c1, c2 = st.columns(2)
    mode = c1.radio("Who is reading?", MODES, horizontal=True)
    platform = c2.selectbox("Platform", PLATFORMS)

    prev = st.session_state.get("prev_score")
    g_col, h_col = st.columns([1, 2])
    with g_col:
        delta = f"{r.score - prev:+d} vs last scan" if prev is not None else None
        st.metric("Security Grade", r.grade, delta, delta_color="off" if prev == r.score else "normal")
        st.caption(f"{r.score} / 100 points")
        if r.deep_results:
            st.metric("Deep Checks Grade", r.deep_grade)
            st.caption(f"{r.deep_score} / 100 points (scored separately)")
        if r.days_left >= 0:
            st.caption(f"🔒 Lock valid for **{r.days_left} days**")
    with h_col:
        components.html(house_svg(r), height=260)

    st.caption("ℹ️ This is a configuration and hygiene check, not a penetration test. "
               "A good grade does not prove a site is secure.")

    with st.expander("🏡 House X-Ray details"):
        for c in CHECKS + (DEEP_CHECKS if r.deep_results else []):
            res = r.results.get(c["id"]) or r.deep_results.get(c["id"])
            label = c["house"][0] if res.status == "pass" else (
                "Partly secured" if res.status == "warn" else c["house"][1])
            st.markdown(f"{ICON[res.status]} **{c['part']}:** {label}")

    todo = sorted((x for x in r.results.values() if x.status != "pass"),
                  key=lambda x: CHECK_BY_ID[x.id]["pts"] - x.points, reverse=True)[:3]
    if todo:
        st.subheader("🎯 Fix these first")
        for x in todo:
            c = CHECK_BY_ID[x.id]
            title, _ = describe(c, x.status, x.detail, mode)
            st.markdown(f"- **{title}** — up to **+{c['pts'] - x.points:g} pts**")

    d1, d2, d3 = st.columns(3)
    host = r.host
    d1.download_button("📥 Text report", build_text_report(r, mode, platform),
                       file_name=f"sitehouse-report-{host}.txt", mime="text/plain")
    d2.download_button("🌐 HTML report", build_html_report(r, mode, platform),
                       file_name=f"sitehouse-report-{host}.html", mime="text/html")
    d3.download_button("🏅 SVG badge", build_badge_svg(r),
                       file_name=f"sitehouse-badge-{host}.svg", mime="image/svg+xml")

    for c in CHECKS:
        render_card(c, r.results[c["id"]], mode, platform)

    if r.deep_results:
        st.subheader("🔬 Deep checks")
        st.caption("Passive checks only: we read public pages and compare exposed versions with public "
                   "databases. Nothing is logged into, guessed or exploited. Versions are inferred from "
                   "page source and can be imprecise.")
        for c in DEEP_CHECKS:
            render_card(c, r.deep_results[c["id"]], mode, platform)

        with st.expander("🔎 What we detected"):
            d = r.detected
            st.write(f"**CMS / platform:** {d.get('cms', 'nothing identifiable')}")
            if d.get("plugins"):
                st.write("**WordPress plugins:** " + ", ".join(f"{k} ({v})" for k, v in d["plugins"].items()))
            if d.get("themes"):
                st.write("**WordPress themes:** " + ", ".join(f"{k} ({v})" for k, v in d["themes"].items()))
            libs = d.get("js_libs") or {}
            st.write("**JavaScript libraries:** " + (", ".join(f"{k} {'/'.join(v)}" for k, v in libs.items()) or "none of the tracked libraries found"))
            st.write(f"**security.txt:** {d.get('security_txt', 'not checked')}")

if st.session_state.get("history"):
    with st.expander("📈 Scan history (this session)"):
        st.dataframe(st.session_state["history"][::-1], use_container_width=True, hide_index=True)
