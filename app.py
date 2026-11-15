import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse
import requests
import streamlit as st

st.set_page_config(page_title="SiteHouse Security Checkup", page_icon="🏠")

# --- 1. RULEBOOK & EXPLANATIONS ---
CHECKS = [
{
"id": "https", "pts": 20, "part": "Front Door Lock",
"house": ("🔒 Locked Gold Padlock", "🚪 Unlocked Door"),
"Kid": ("Front Door Lock (HTTPS)", "Visitors use a secret code so spies cannot listen in!", "Uh oh! Your front door is unlocked on public Wi-Fi."),
"Business": ("Encrypted Connection", "Customer forms are encrypted, boosting trust and SEO.", "Browsers warn visitors your site is 'Not Secure'."),
"Developer": ("HTTPS Enforcement", "Site resolved securely over HTTPS.", "Site served over plain HTTP without TLS redirect."),
"fixes": {
"WordPress": "Install 'Really Simple SSL' or enable SSL in your hosting panel.",
"Shopify / Wix": "Go to Settings -> Domains and toggle SSL ON.",
"Vercel / Netlify": "Verify custom domain DNS; HTTPS is automatic.",
"Nginx / Custom": "Run Certbot (Let's Encrypt) and redirect port 80 to 443."
}
},
{
"id": "ssl_valid", "pts": 15, "part": "Lock Warranty",
"house": ("📅 Valid Lock Warranty", "⚠️ Expiring/Broken Lock"),
"Kid": ("Lock Warranty (SSL Expiry)", "Your front door lock is fresh and up to date!", "Your lock warranty is expired or running out very soon!"),
"Business": ("SSL Certificate Health", "Your security certificate is active with plenty of days left.", "An expired SSL certificate will block customers with a scary browser warning."),
"Developer": ("TLS Certificate Validity", "Certificate is valid with >14 days remaining.", "Certificate is expired, unreachable, or expires in <14 days."),
"fixes": {
"WordPress": "Check auto-renewal in cPanel/hosting dashboard or Cloudflare SSL.",
"Shopify / Wix": "Contact platform support if auto-renewing SSL is stuck.",
"Vercel / Netlify": "Check domain settings and renew/re-verify DNS records.",
"Nginx / Custom": "Run `sudo certbot renew` and ensure a cron job/systemd timer is active."
}
},
{
"id": "hsts", "pts": 15, "part": "Automatic Deadbolt",
"house": ("🛡️ Auto-Lock Active", "🔓 Manual Lock Only"),
"Kid": ("Automatic Deadbolt (HSTS)", "Your door automatically locks behind every visitor!", "Visitors have to remember to lock the door themselves."),
"Business": ("Strict Connection Security", "Blocks Wi-Fi interception attacks automatically.", "Attackers on public Wi-Fi could downgrade visitor connections."),
"Developer": ("HSTS Header", "Strict-Transport-Security header is active.", "Missing 'Strict-Transport-Security' response header."),
"fixes": {
"WordPress": "Activate the 'Headers Security Advanced & HSTS WP' plugin.",
"Shopify / Wix": "Handled automatically when primary domain redirect is active.",
"Vercel / Netlify": "Add `Strict-Transport-Security: max-age=31536000` in config.",
"Nginx / Custom": "Add `add_header Strict-Transport-Security \"max-age=31536000\";`."
}
},
{
"id": "frame", "pts": 15, "part": "Window Blinds",
"house": ("🪟 Blinds Closed", "👀 Open Windows"),
"Kid": ("Window Blinds (Anti-Clickjacking)", "Copycat sites cannot put your house inside a fake window!", "Windows are open! Sneaky sites could trap your page in a frame."),
"Business": ("Brand Impersonation Guard", "Stops scammers from embedding your site to steal clicks.", "Scammers could overlay invisible buttons over your pages."),
"Developer": ("Frame Protection", "X-Frame-Options or CSP frame-ancestors is set.", "Missing 'X-Frame-Options' or CSP 'frame-ancestors'."),
"fixes": {
"WordPress": "Add `Header always set X-Frame-Options \"SAMEORIGIN\"` to `.htaccess`.",
"Shopify / Wix": "Protected on checkout by default; audit custom app embeds.",
"Vercel / Netlify": "Add `X-Frame-Options: SAMEORIGIN` to your headers file.",
"Nginx / Custom": "Add `add_header X-Frame-Options \"SAMEORIGIN\";` in Nginx."
}
},
{
"id": "csp", "pts": 20, "part": "Guest List",
"house": ("📋 Guest List Active", "🎉 Anyone Can Walk In"),
"Kid": ("Party Guest List (CSP)", "Only approved scripts are allowed inside your website.", "No guest list! Outside scripts might sneak into your pages."),
"Business": ("Malicious Script Blocker", "Blocks unauthorized code from stealing form data.", "Higher risk of script injection if a plugin has a bug."),
"Developer": ("Content-Security-Policy", "CSP header is configured.", "Missing 'Content-Security-Policy' header."),
"fixes": {
"WordPress": "Use the 'HTTP Headers' plugin to set `default-src 'self'`.",
"Shopify / Wix": "Remove unused third-party apps; add CSP via Cloudflare.",
"Vercel / Netlify": "Define `Content-Security-Policy` in `vercel.json` or `_headers`.",
"Nginx / Custom": "Add `add_header Content-Security-Policy \"default-src 'self';\";`."
}
},
{
"id": "env", "pts": 15, "part": "Welcome Mat",
"house": ("🧹 Clean Mat (No Keys)", "🔑 Keys Under Mat!"),
"Kid": ("Keys Under the Mat (.env)", "No secret house keys left hiding under the welcome mat!", "DANGER! Your secret password file (.env) is sitting out in the open!"),
"Business": ("Secret File Protection", "Database passwords and API keys are safely hidden.", "CRITICAL: Server passwords are publicly readable right now."),
"Developer": ("Exposed /.env Check", "GET /.env did not expose environment secrets.", "GET /.env returned HTTP 200 with secret key patterns!"),
"fixes": {
"WordPress": "Add `RedirectMatch 403 /\\..*$` to your `.htaccess` file.",
"Shopify / Wix": "Managed by platform; never put API secrets in theme JS files.",
"Vercel / Netlify": "Keep `.env` out of Git; use dashboard Environment Variables.",
"Nginx / Custom": "Add `location ~ /\\. { deny all; }` to block hidden files."
}
}
]

# --- 2. SCANNER ENGINE ---
def check_ssl_days(hostname: str) -> int:
try:
ctx = ssl.create_default_context()
with socket.create_connection((hostname, 443), timeout=5) as sock:
with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
cert = ssock.getpeercert()
exp_str = cert["notAfter"]
exp_date = datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
return (exp_date - datetime.now(timezone.utc)).days
except Exception:
return -1

def scan_site(raw_url: str):
url = raw_url.strip() if raw_url.startswith(("http://", "https://")) else f"https://{raw_url.strip()}"
req_headers = {"User-Agent": "SiteHouseSecurityCheckup/1.0 (Educational Scanner)"}
try:
res = requests.get(url, headers=req_headers, timeout=8)
except requests.RequestException as e:
return None, 0, f"Could not reach site: {e}", -1

hdrs = {k.lower(): v for k, v in res.headers.items()}
parsed = urlparse(res.url)
base = f"{parsed.scheme}://{parsed.netloc}"
days_left = check_ssl_days(parsed.hostname) if parsed.hostname else -1

env_safe = True
try:
env = requests.get(f"{base}/.env", headers=req_headers, timeout=4, allow_redirects=False)
if env.status_code == 200 and any(w in env.text for w in ("DB_", "SECRET", "KEY")):
env_safe = False
except requests.RequestException:
pass

passed_map = {
"https": res.url.startswith("https://"),
"ssl_valid": days_left > 14,
"hsts": "strict-transport-security" in hdrs,
"frame": "x-frame-options" in hdrs or "frame-ancestors" in hdrs.get("content-security-policy", ""),
"csp": "content-security-policy" in hdrs,
"env": env_safe,
}

score = sum(c["pts"] for c in CHECKS if passed_map[c["id"]])
return passed_map, score, res.url, days_left

def build_report_text(url: str, grade: str, score: int, days_left: int, passed_map: dict, mode: str, platform: str) -> str:
lines = [
"# SiteHouse Security Checkup Report",
f"Website: {url}",
f"Grade: {grade} ({score}/100) | SSL Days Remaining: {days_left if days_left >= 0 else 'N/A'}",
f"View Mode: {mode} | Platform: {platform}",
"-" * 50,
]
for c in CHECKS:
ok = passed_map[c["id"]]
title, pass_msg, fail_msg = c[mode]
status = "[PASS]" if ok else "[FIX NEEDED]"
lines.append(f"\n{status} {title} (+{c['pts']} pts)")
lines.append(f" {pass_msg if ok else fail_msg}")
if not ok:
lines.append(f" How to fix ({platform}): {c['fixes'][platform]}")
return "\n".join(lines)

# --- 3. USER INTERFACE ---
st.title("🏠 SiteHouse Security Checkup")
st.caption("Check any website's safety in 3 seconds—explained so anyone can understand.")

url_input = st.text_input("Website Address", placeholder="Type a website (e.g., example.com)")

if url_input:
with st.spinner("Knocking on the front door and checking the lock warranty..."):
passed_map, score, info, days_left = scan_site(url_input)

if not passed_map:
st.error(info)
else:
if score == 100:
st.balloons()

# Controls
c1, c2 = st.columns(2)
mode = c1.radio("Who is reading?", ["Kid", "Business", "Developer"], horizontal=True)
platform = c2.selectbox("Platform", ["WordPress", "Shopify / Wix", "Vercel / Netlify", "Nginx / Custom"])

# Grade & House Visual
grade = next(g for min_s, g in [(95, "A+"), (80, "A"), (60, "B"), (40, "C"), (0, "F")] if score >= min_s)
g_col, h_col = st.columns([1, 2])

with g_col:
st.metric("Security Grade", grade, f"{score} / 100 pts")
if days_left >= 0:
st.caption(f"🔒 Lock valid for **{days_left} days**")

with h_col:
house_lines = [f"**{c['part']}:** {c['house'][0 if passed_map[c['id']] else 1]}" for c in CHECKS]
st.info("🏡 **Visual House X-Ray**\n\n" + "\n\n".join(house_lines))

# Download Report Button
report_txt = build_report_text(info, grade, score, days_left, passed_map, mode, platform)
st.download_button(
label="📥 Download Checkup Report",
data=report_txt,
file_name=f"sitehouse-report-{urlparse(info).netloc}.txt",
mime="text/plain"
)

# Detailed Cards
for c in CHECKS:
ok = passed_map[c["id"]]
title, pass_msg, fail_msg = c[mode]
with st.container(border=True):
st.markdown(f"#### {'🟢' if ok else '🔴'} {title} *(+{c['pts']} pts)*")
st.write(pass_msg if ok else fail_msg)
if not ok:
with st.expander(f"🛠️ Fix for {platform}"):
st.info(c["fixes"][platform])
