"""Scanner engine: no Streamlit imports, so it can be tested on its own."""
import ipaddress
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests

try:
    import dns.resolver as dns_resolver
except ImportError:  # email check degrades gracefully
    dns_resolver = None

from checks import CHECKS, CHECK_BY_ID, DEEP_BY_ID, DEEP_CHECKS, FACTOR
from deep import check_js_libs, check_paths, check_software

TOOL_UA = "SiteHouseSecurityCheckup/2.0 (Educational Scanner)"
BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
BLOCKED_CODES = (403, 429, 503)
ALLOWED_PORTS = {None, 80, 443}
ENV_LINE = re.compile(r"^\s*[A-Z][A-Z0-9_]*\s*=", re.MULTILINE)


class ScanError(Exception):
    pass


@dataclass
class CheckResult:
    id: str
    status: str            # "pass" | "warn" | "fail"
    detail: str = ""
    points: float = 0.0


@dataclass
class ScanResult:
    url: str
    host: str
    results: dict = field(default_factory=dict)
    score: int = 0
    grade: str = "F"
    days_left: int = -1
    notes: list = field(default_factory=list)
    scanned_at: str = ""
    deep_results: dict = field(default_factory=dict)
    deep_score: int = 0
    deep_grade: str = "F"
    detected: dict = field(default_factory=dict)


def grade_for(score: int) -> str:
    return next(g for min_s, g in [(95, "A+"), (80, "A"), (60, "B"), (40, "C"), (0, "F")] if score >= min_s)


# ---------- networking helpers ----------
def is_public_host(host: str) -> bool:
    """SSRF guard: refuse localhost / private / link-local / reserved addresses."""
    try:
        infos = socket.getaddrinfo(host, None)
        return all(ipaddress.ip_address(i[4][0].split("%")[0]).is_global for i in infos)
    except (socket.gaierror, UnicodeError, ValueError):
        return False


def make_headers(ua: str) -> dict:
    h = {"User-Agent": ua}
    if ua == BROWSER_UA:  # look like a real browser
        h.update({
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        })
    return h


def safe_get(url: str, ua: str = TOOL_UA, timeout: int = 8, max_hops: int = 10):
    """GET that follows redirects manually, validating every hop against the SSRF guard.
    Keeps cookies between hops (many sites redirect until a cookie is set)."""
    session = requests.Session()
    chain = []
    for _ in range(max_hops + 1):
        try:
            p = urlparse(url)
            port = p.port
        except ValueError:
            raise ScanError("That doesn't look like a valid web address.")
        if p.scheme not in ("http", "https") or not p.hostname or port not in ALLOWED_PORTS:
            raise ScanError("Please enter a normal website address (http/https on standard ports).")
        if not is_public_host(p.hostname):
            raise ScanError("That address isn't a publicly reachable website, so it can't be scanned.")
        chain.append(url)
        try:
            r = session.get(url, headers=make_headers(ua), timeout=timeout,
                            allow_redirects=False, stream=True)
                except requests.exceptions.ConnectTimeout:
            raise ScanError("The site didn't answer in time. It may be down, or it may block "
                            "scanners running from overseas cloud servers. Try again, or run "
                            "the app on your own computer.")
        except requests.RequestException as e:
            raise ScanError(f"Could not reach site: {str(e)[:150]}")
        if r.is_redirect and r.headers.get("location"):
            url = urljoin(url, r.headers["location"])
            r.close()
            continue
        return r
    tail = " → ".join(c[:70] for c in chain[-4:])
    raise ScanError(f"Too many redirects. Last hops: {tail}")


# ---------- pure evaluators (easy to unit test) ----------
def eval_hsts(h: dict):
    v = h.get("strict-transport-security")
    if not v:
        return "fail", "Header missing."
    m = re.search(r"max-age=(\d+)", v, re.I)
    age = int(m.group(1)) if m else 0
    if age < 15552000:
        return "warn", f"max-age is {age}s; use at least 15552000 (6 months)."
    if "includesubdomains" not in v.lower():
        return "warn", "add includeSubDomains to cover all subdomains."
    return "pass", ""


def eval_csp(h: dict):
    csp = h.get("content-security-policy")
    if not csp:
        return "fail", "Header missing."
    low = csp.lower()
    weak = [w for w in ("'unsafe-inline'", "'unsafe-eval'") if w in low]
    if re.search(r"(^|[\s;])\*([\s;]|$)", csp):
        weak.append("wildcard (*) source")
    if weak:
        return "warn", "policy allows " + ", ".join(weak) + "."
    return "pass", ""


def eval_frame(h: dict):
    ok = "x-frame-options" in h or "frame-ancestors" in h.get("content-security-policy", "").lower()
    return ("pass", "") if ok else ("fail", "Header missing.")


def eval_nosniff(h: dict):
    return ("pass", "") if h.get("x-content-type-options", "").lower().strip() == "nosniff" else ("fail", "Header missing.")


def eval_referrer(h: dict):
    v = h.get("referrer-policy", "").lower()
    if not v:
        return "fail", "Header missing."
    if "unsafe-url" in v or "no-referrer-when-downgrade" in v:
        return "warn", f"'{v}' still leaks full URLs; prefer strict-origin-when-cross-origin."
    return "pass", ""


def eval_permissions(h: dict):
    ok = "permissions-policy" in h or "feature-policy" in h
    return ("pass", "") if ok else ("fail", "Header missing.")


def eval_cookies(cookies: list, is_https: bool):
    if not cookies:
        return "pass", ""
    no_secure, weak = [], []
    for c in cookies:
        parts = [p.strip().lower() for p in c.split(";")]
        name = parts[0].split("=")[0]
        attrs = {p.split("=")[0] for p in parts[1:]}
        if "secure" not in attrs:
            no_secure.append(name)
        elif "httponly" not in attrs or "samesite" not in attrs:
            weak.append(name)
    if no_secure:
        return "fail", "no Secure flag on: " + ", ".join(no_secure[:5])
    if weak:
        return "warn", "missing HttpOnly/SameSite on: " + ", ".join(weak[:5])
    return "pass", ""


def eval_leak(h: dict):
    server = h.get("server", "")
    if re.search(r"\d+\.\d+", server):
        return "fail", f"Server: {server}"
    if "x-powered-by" in h:
        return "warn", f"X-Powered-By: {h['x-powered-by']} — remove it."
    return "pass", ""


# ---------- network checks (run in parallel) ----------
def check_ssl(host: str):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        exp = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
        days = (exp - datetime.now(timezone.utc)).days
    except Exception as e:
        return "fail", f"Could not validate certificate: {type(e).__name__}", -1
    if days > 14:
        return "pass", "", days
    if days >= 0:
        return "warn", f"certificate expires in {days} day(s).", days
    return "fail", "certificate has expired.", days


def check_redirect(host: str):
    try:
        r = requests.get(f"http://{host}/", headers={"User-Agent": TOOL_UA}, timeout=5, allow_redirects=False)
        r.close()
    except requests.RequestException:
        return "pass", "Plain HTTP isn't served at all."
    if r.is_redirect:
        loc = urljoin(f"http://{host}/", r.headers.get("location", ""))
        if loc.lower().startswith("https://"):
            return "pass", ""
        return "fail", f"redirects to {loc[:80]}"
    return "fail", f"http:// answered {r.status_code} instead of redirecting."


def _probe(base: str, path: str):
    try:
        r = requests.get(base + path, headers={"User-Agent": TOOL_UA}, timeout=4,
                         allow_redirects=False, stream=True)
        try:
            ctype = r.headers.get("content-type", "").lower()
            body = next(r.iter_content(4096), b"") if r.status_code == 200 else b""
        finally:
            r.close()
        return path, r.status_code, ctype, body.decode("utf-8", "ignore")
    except requests.RequestException:
        return path, None, "", ""


EXPOSURE_RULES = {
    "/.env": lambda c, b: bool(ENV_LINE.search(b)),
    "/.git/config": lambda c, b: "[core]" in b,
    "/wp-config.php.bak": lambda c, b: "DB_NAME" in b or "<?php" in b,
    "/backup.zip": lambda c, b: b.startswith("PK") or "zip" in c,
}


def check_files(base: str):
    with ThreadPoolExecutor(max_workers=4) as pool:
        probes = list(pool.map(lambda p: _probe(base, p), EXPOSURE_RULES))
    exposed = [path for path, code, ctype, body in probes
               if code == 200 and "text/html" not in ctype and EXPOSURE_RULES[path](ctype, body)]
    return ("fail", ", ".join(exposed)) if exposed else ("pass", "")


def check_email(host: str):
    if dns_resolver is None:
        return "warn", "install `dnspython` to check SPF/DMARC."
    domain = host[4:] if host.startswith("www.") else host

    def txt(name):
        try:
            return [b"".join(r.strings).decode("utf-8", "ignore") for r in dns_resolver.resolve(name, "TXT", lifetime=4)]
        except Exception:
            return []

    spf = any(t.lower().startswith("v=spf1") for t in txt(domain))
    dmarc_recs = [t for t in txt("_dmarc." + domain) if t.lower().startswith("v=dmarc1")]
    if spf and dmarc_recs:
        if re.search(r"p\s*=\s*none", dmarc_recs[0], re.I):
            return "warn", "DMARC policy is p=none (monitor only); move to quarantine or reject."
        return "pass", ""
    missing = [n for n, ok in (("SPF", spf), ("DMARC", bool(dmarc_recs))) if not ok]
    return ("warn" if len(missing) == 1 else "fail"), "missing " + " and ".join(missing) + " record."


# ---------- main entry ----------
def scan(raw_url: str, on_progress=None, deep: bool = False) -> ScanResult:
    """Scan a site. on_progress(done, total, part_name) is always called from the calling thread."""
    raw = raw_url.strip()
    if not raw:
        raise ScanError("Please type a website address.")
    url = raw if raw.lower().startswith(("http://", "https://")) else f"https://{raw}"

    notes = []
    try:
        res = safe_get(url, TOOL_UA)
    except ScanError as e:
        if "redirect" not in str(e).lower():
            raise
        res = safe_get(url, BROWSER_UA)  # retry like a normal browser
        notes.append("The site redirected our scanner in a loop, so we retried like a normal browser.")
    if res.status_code in BLOCKED_CODES:
        res.close()
        res = safe_get(url, BROWSER_UA)
        if res.status_code in BLOCKED_CODES:
            notes.append(f"The site answered HTTP {res.status_code} (it may block scanners or be rate-limiting), "
                         "so some results may be incomplete.")
        else:
            notes.append("The site blocked our scanner's user-agent, so we retried like a normal browser.")
    elif res.status_code >= 400:
        notes.append(f"The site answered HTTP {res.status_code} at this address; headers were still checked.")
    body = ""
    if deep:  # read (a capped amount of) the page so deep checks can inspect it
        try:
            raw = b""
            for chunk in res.iter_content(65536):
                raw += chunk
                if len(raw) >= 500_000:
                    break
            body = raw.decode(res.encoding or "utf-8", "ignore")
        except Exception:
            body = ""
    res.close()

    parsed = urlparse(res.url)
    host = parsed.hostname
    base = f"{parsed.scheme}://{parsed.netloc}"
    is_https = parsed.scheme == "https"
    h = {k.lower(): v for k, v in res.headers.items()}
    try:
        cookies = res.raw.headers.getlist("set-cookie")
    except Exception:
        cookies = [res.headers["set-cookie"]] if "set-cookie" in res.headers else []

    out = ScanResult(url=res.url, host=host, notes=notes, scanned_at=datetime.now().strftime("%H:%M:%S"))
    total = len(CHECKS) + (len(DEEP_CHECKS) if deep else 0)

    def add(cid, status, detail=""):
        out.results[cid] = CheckResult(cid, status, detail, CHECK_BY_ID[cid]["pts"] * FACTOR[status])
        if on_progress:
            on_progress(len(out.results) + len(out.deep_results), total, CHECK_BY_ID[cid]["part"])

    # Instant, header-based checks
    add("https", *(("pass", "") if is_https else ("fail", "Final URL is plain HTTP.")))
    add("hsts", *(eval_hsts(h) if is_https else ("fail", "Site isn't on HTTPS.")))
    add("frame", *eval_frame(h))
    add("csp", *eval_csp(h))
    add("nosniff", *eval_nosniff(h))
    add("referrer", *eval_referrer(h))
    add("permissions", *eval_permissions(h))
    add("cookies", *(eval_cookies(cookies, True) if is_https else (("fail", "Cookies sent over plain HTTP.") if cookies else ("pass", ""))))
    add("leak", *eval_leak(h))

    # Slow, network-based checks in parallel
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {pool.submit(check_files, base): "files",
                   pool.submit(check_email, host): "email",
                   pool.submit(check_redirect, host): "redirect"}
        if is_https:
            futures[pool.submit(check_ssl, host)] = "ssl_valid"
        else:
            add("ssl_valid", "fail", "Site isn't on HTTPS.")
        for fut in as_completed(futures):
            cid = futures[fut]
            try:
                r = fut.result()
            except Exception:
                add(cid, "warn", "this check could not run.")
                continue
            if cid == "ssl_valid":
                out.days_left = r[2]
                add(cid, r[0], r[1])
            else:
                add(cid, r[0], r[1])

    if deep:
        with ThreadPoolExecutor(max_workers=3) as pool:
            dfut = {pool.submit(check_software, body, h): "software",
                    pool.submit(check_js_libs, body): "js_libs",
                    pool.submit(check_paths, base): "paths"}
            for fut in as_completed(dfut):
                cid = dfut[fut]
                try:
                    status, detail, found = fut.result()
                except Exception:
                    status, detail, found = "warn", "this check could not run.", {}
                out.deep_results[cid] = CheckResult(cid, status, detail, DEEP_BY_ID[cid]["pts"] * FACTOR[status])
                out.detected.update(found)
                if on_progress:
                    on_progress(len(out.results) + len(out.deep_results), total, DEEP_BY_ID[cid]["part"])
        out.deep_score = round(sum(r.points for r in out.deep_results.values()))
        out.deep_grade = grade_for(out.deep_score)

    out.score = round(sum(r.points for r in out.results.values()))
    out.grade = grade_for(out.score)
    return out
