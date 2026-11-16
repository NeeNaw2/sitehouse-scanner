"""Deep checks: passive, read-only inspection of what a site already shows the public.
Nothing here logs in, guesses passwords, injects input or tries to exploit anything."""
import re
from concurrent.futures import ThreadPoolExecutor

import requests

UA = "SiteHouseSecurityCheckup/2.0 (Educational Scanner)"


# ---------- version helpers ----------
def version_tuple(v: str) -> tuple:
    nums = [int(x) for x in re.findall(r"\d+", v)[:4]]
    return tuple(nums + [0] * (4 - len(nums)))


def _get_json(url, params=None, timeout=5):
    try:
        r = requests.get(url, params=params, headers={"User-Agent": UA}, timeout=timeout)
        return r.json() if r.status_code == 200 else None
    except (requests.RequestException, ValueError):
        return None


# ---------- 1. CMS / plugin detection ----------
GEN_RES = [
    re.compile(r'<meta[^>]+name=["\']generator["\'][^>]*content=["\']([^"\']+)', re.I),
    re.compile(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]*name=["\']generator["\']', re.I),
]


def detect_cms(html: str):
    """Returns (name, version) - either may be None."""
    gen = ""
    for rx in GEN_RES:
        m = rx.search(html)
        if m:
            gen = m.group(1).strip()
            break
    if "wordpress" in gen.lower() or "/wp-content/" in html or "/wp-includes/" in html:
        m = re.search(r"WordPress\s+(\d+(?:\.\d+){1,3})", gen, re.I) or \
            re.search(r"/wp-includes/[^\"'\s]*\?ver=(\d+\.\d+(?:\.\d+)?)", html)
        return "WordPress", (m.group(1) if m else None)
    if gen:
        m = re.search(r"(\d+(?:\.\d+)+)", gen)
        name = re.split(r"\s+\d", gen)[0].strip()
        return name[:40], (m.group(1) if m else None)
    return None, None


def detect_wp_components(html: str, kind: str) -> dict:
    """kind = 'plugins' or 'themes'. Returns {slug: version-or-None} from asset URLs."""
    found = {}
    for m in re.finditer(rf"/wp-content/{kind}/([a-z0-9_\-]+)/([^\"'\s<>]*)", html, re.I):
        slug, rest = m.group(1).lower(), m.group(2)
        v = re.search(r"[?&]ver=(\d+(?:\.\d+){1,3})", rest)
        if slug not in found or (v and not found[slug]):
            found[slug] = v.group(1) if v else None
    return found


def latest_wp_core():
    data = _get_json("https://api.wordpress.org/core/version-check/1.7/")
    try:
        return data["offers"][0]["current"]
    except (TypeError, KeyError, IndexError):
        return None


def latest_component(kind: str, slug: str):
    if kind == "plugins":
        data = _get_json("https://api.wordpress.org/plugins/info/1.2/",
                         {"action": "plugin_information", "request[slug]": slug})
    else:
        data = _get_json("https://api.wordpress.org/themes/info/1.2/",
                         {"action": "theme_information", "request[slug]": slug})
    return data.get("version") if isinstance(data, dict) else None


def classify_core(installed: str, latest: str) -> str:
    a, b = version_tuple(installed), version_tuple(latest)
    if a >= b:
        return "ok"
    return "patch" if a[:2] == b[:2] else "behind"


def check_software(html: str, headers: dict = None):
    """(status, detail, found). Compares exposed versions with the latest releases."""
    name, ver = detect_cms(html)
    found = {}
    if not name:
        return "pass", "", found
    found["cms"] = f"{name} {ver}".strip() if ver else name
    if name != "WordPress":
        return "pass", "", found

    plugins = detect_wp_components(html, "plugins")
    themes = detect_wp_components(html, "themes")
    found["plugins"] = {k: v or "version hidden" for k, v in plugins.items()}
    found["themes"] = {k: v or "version hidden" for k, v in themes.items()}

    fails, warns = [], []
    latest = latest_wp_core()
    if ver and latest:
        state = classify_core(ver, latest)
        if state == "behind":
            fails.append(f"WordPress {ver} is behind the latest {latest}")
        elif state == "patch":
            warns.append(f"WordPress {ver} can be updated to {latest}")

    # A plugin's ?ver= sometimes just repeats the WordPress version; ignore those.
    todo = [(k, s, v) for k, d in (("plugins", plugins), ("themes", themes))
            for s, v in d.items() if v and v != ver][:20]
    if todo:
        with ThreadPoolExecutor(max_workers=6) as pool:
            latests = list(pool.map(lambda t: latest_component(t[0], t[1]), todo))
        outdated = [f"{s} {v}→{l}" for (k, s, v), l in zip(todo, latests)
                    if l and version_tuple(v) < version_tuple(l)]
        if len(outdated) >= 3:
            fails.append("outdated plugins/themes: " + ", ".join(outdated[:5]))
        elif outdated:
            warns.append("outdated plugins/themes: " + ", ".join(outdated))

    status = "fail" if fails else "warn" if warns else "pass"
    return status, "; ".join(fails + warns), found


# ---------- 2. Vulnerable JavaScript libraries ----------
ALIASES = {"angular.js": "angular", "angularjs": "angular", "jquery-ui-dist": "jquery-ui",
           "jqueryui": "jquery-ui", "moment.js": "moment", "lodash.js": "lodash",
           "vue.js": "vue", "underscore.js": "underscore", "handlebars.js": "handlebars",
           "twitter-bootstrap": "bootstrap"}
KNOWN_LIBS = {"jquery", "jquery-ui", "bootstrap", "lodash", "moment", "angular",
              "handlebars", "underscore", "vue"}
LIB_PATTERNS = [
    re.compile(r"/ajax/libs/([a-z0-9.\-]+)/(\d+(?:\.\d+){1,3})/", re.I),
    re.compile(r"/npm/([a-z0-9.\-]+)@(\d+(?:\.\d+){1,3})", re.I),
    re.compile(r"unpkg\.com/([a-z0-9.\-]+)@(\d+(?:\.\d+){1,3})", re.I),
    re.compile(r"/([a-z][a-z0-9.\-]*?)[.\-]v?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js", re.I),
]
SCRIPT_SRC = re.compile(r"<script[^>]+src=[\"']([^\"']+)", re.I)


def detect_js_libs(html: str) -> dict:
    libs = {}
    for src in SCRIPT_SRC.findall(html):
        for rx in LIB_PATTERNS:
            m = rx.search(src)
            if not m:
                continue
            name = ALIASES.get(m.group(1).lower(), m.group(1).lower())
            if name in KNOWN_LIBS:
                libs.setdefault(name, set()).add(m.group(2))
            break
    return {k: sorted(v, key=version_tuple) for k, v in libs.items()}


def assess_lib(name: str, v: str):
    """Built-in rules (no network). Returns (status, note)."""
    t = version_tuple(v)
    if name == "jquery" and t < (3, 5, 0, 0):
        return "fail", "known XSS issues, fixed in 3.5.0"
    if name == "jquery-ui" and t < (1, 13, 2, 0):
        return "fail", "known XSS issues, fixed in 1.13.2"
    if name == "bootstrap":
        if t < (3, 4, 1, 0) or (t[0] == 4 and t < (4, 3, 1, 0)):
            return "fail", "known XSS issues, fixed in 3.4.1 / 4.3.1"
        if t[0] <= 3:
            return "warn", "Bootstrap 3 is end-of-life"
    if name == "lodash" and t < (4, 17, 21, 0):
        return "fail", "known prototype-pollution/injection issues, fixed in 4.17.21"
    if name == "moment" and t < (2, 29, 4, 0):
        return "fail", "known ReDoS/path-traversal issues, fixed in 2.29.4"
    if name == "handlebars" and t < (4, 7, 7, 0):
        return "fail", "known code-execution issues, fixed in 4.7.7"
    if name == "underscore" and t < (1, 12, 1, 0):
        return "fail", "known code-injection issue, fixed in 1.12.1"
    if name == "angular" and t[0] == 1:
        return "warn", "AngularJS is end-of-life (no security fixes)"
    if name == "vue" and t[0] == 2:
        return "warn", "Vue 2 is end-of-life"
    return "pass", ""


def osv_ids(name: str, version: str) -> list:
    """Best-effort lookup in the public OSV.dev database; silently returns [] on any problem."""
    try:
        r = requests.post("https://api.osv.dev/v1/query", timeout=5, headers={"User-Agent": UA},
                          json={"package": {"name": name, "ecosystem": "npm"}, "version": version})
        if r.status_code != 200:
            return []
        return [v["id"] for v in r.json().get("vulns", [])][:3]
    except (requests.RequestException, ValueError, KeyError):
        return []


def check_js_libs(html: str):
    libs = detect_js_libs(html)
    found = {"js_libs": {k: v for k, v in libs.items()}}
    pairs = [(n, v) for n, vs in libs.items() for v in vs][:8]
    if not pairs:
        return "pass", "", found
    with ThreadPoolExecutor(max_workers=6) as pool:
        osv = list(pool.map(lambda p: osv_ids(*p), pairs))
    fails, warns = [], []
    for (n, v), ids in zip(pairs, osv):
        status, note = assess_lib(n, v)
        if ids:
            status, note = "fail", f"public advisories: {', '.join(ids)}"
        if status == "fail":
            fails.append(f"{n} {v} ({note})")
        elif status == "warn":
            warns.append(f"{n} {v} ({note})")
    status = "fail" if fails else "warn" if warns else "pass"
    return status, "; ".join(fails + warns), found


# ---------- 3. Exposed paths ----------
def _sql_dump(c, b):
    return "text/html" not in c and bool(re.search(r"-- MySQL dump|-- PostgreSQL database dump|CREATE TABLE|INSERT INTO", b))


def _php_log(c, b):
    return bool(re.match(r"\[\d{1,2}-\w{3}-\d{4}", b))


def _listing(c, b):
    return bool(re.search(r"<title>\s*Index of /", b, re.I))


# (path, severity, label, predicate(content_type, body))
PATH_RULES = [
    ("/phpinfo.php", "fail", "phpinfo() page", lambda c, b: "PHP Version" in b),
    ("/server-status", "fail", "Apache server-status", lambda c, b: "Apache Server Status" in b),
    ("/.git/HEAD", "fail", "Git repository", lambda c, b: b.startswith("ref:")),
    ("/wp-content/debug.log", "fail", "WordPress debug.log", lambda c, b: _php_log(c, b)),
    ("/error_log", "fail", "error_log file", lambda c, b: _php_log(c, b)),
    ("/dump.sql", "fail", "SQL dump", _sql_dump),
    ("/backup.sql", "fail", "SQL dump", _sql_dump),
    ("/db.sql", "fail", "SQL dump", _sql_dump),
    ("/database.sql", "fail", "SQL dump", _sql_dump),
    ("/.DS_Store", "warn", ".DS_Store file", lambda c, b: "Bud1" in b[:16]),
    ("/phpmyadmin/", "warn", "phpMyAdmin reachable", lambda c, b: "phpMyAdmin" in b),
    ("/adminer.php", "warn", "Adminer reachable", lambda c, b: "Adminer" in b),
    ("/wp-json/wp/v2/users", "warn", "WordPress user list public",
     lambda c, b: "json" in c and b.lstrip().startswith("[") and '"slug"' in b),
    ("/xmlrpc.php", "warn", "XML-RPC enabled",
     lambda c, b: "XML-RPC server accepts POST requests only" in b),
    ("/wp-content/uploads/", "warn", "Directory listing", lambda c, b: _listing(c, b)),
    ("/uploads/", "warn", "Directory listing", lambda c, b: _listing(c, b)),
    ("/backup/", "warn", "Directory listing", lambda c, b: _listing(c, b)),
    ("/backups/", "warn", "Directory listing", lambda c, b: _listing(c, b)),
    ("/files/", "warn", "Directory listing", lambda c, b: _listing(c, b)),
]


def _probe(base: str, path: str):
    try:
        r = requests.get(base + path, headers={"User-Agent": UA}, timeout=4,
                         allow_redirects=False, stream=True)
        try:
            ctype = r.headers.get("content-type", "").lower()
            body = next(r.iter_content(4096), b"") if r.status_code == 200 else b""
        finally:
            r.close()
        return r.status_code, ctype, body.decode("utf-8", "ignore")
    except requests.RequestException:
        return None, "", ""


def evaluate_paths(results) -> tuple:
    """results: list of (code, ctype, body) aligned with PATH_RULES. Returns (crit, warn) label lists."""
    crit, warn = [], []
    for (path, sev, label, pred), (code, ctype, body) in zip(PATH_RULES, results):
        if code == 200 and pred(ctype, body):
            (crit if sev == "fail" else warn).append(f"{label} ({path})")
    return crit, warn


def check_paths(base: str):
    paths = [r[0] for r in PATH_RULES] + ["/.well-known/security.txt"]
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda p: _probe(base, p), paths))
    crit, warn = evaluate_paths(results[:-1])
    code, _, body = results[-1]
    found = {"security_txt": "present" if code == 200 and "Contact:" in body else "missing",
             "paths_found": crit + warn}
    status = "fail" if crit else "warn" if warn else "pass"
    return status, "; ".join((crit + warn)[:6]), found
