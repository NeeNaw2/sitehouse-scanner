from checks import CHECKS
from scanner import (eval_cookies, eval_csp, eval_hsts, eval_leak, eval_referrer,
                     grade_for, is_public_host)


def test_points_total_100():
    assert sum(c["pts"] for c in CHECKS) == 100


def test_every_check_has_all_text():
    for c in CHECKS:
        for m in ("Kid", "Business", "Developer"):
            assert len(c[m]) == 3
        for p in ("WordPress", "Shopify / Wix", "Vercel / Netlify", "Nginx / Custom"):
            assert p in c["fixes"]


def test_grades():
    assert grade_for(100) == "A+" and grade_for(80) == "A" and grade_for(60) == "B"
    assert grade_for(40) == "C" and grade_for(10) == "F"


def test_hsts():
    assert eval_hsts({})[0] == "fail"
    assert eval_hsts({"strict-transport-security": "max-age=60"})[0] == "warn"
    assert eval_hsts({"strict-transport-security": "max-age=31536000"})[0] == "warn"
    assert eval_hsts({"strict-transport-security": "max-age=31536000; includeSubDomains"})[0] == "pass"


def test_csp():
    assert eval_csp({})[0] == "fail"
    assert eval_csp({"content-security-policy": "default-src 'self' 'unsafe-inline'"})[0] == "warn"
    assert eval_csp({"content-security-policy": "default-src *"})[0] == "warn"
    assert eval_csp({"content-security-policy": "default-src 'self'"})[0] == "pass"


def test_cookies():
    assert eval_cookies([], True)[0] == "pass"
    assert eval_cookies(["a=1; Path=/"], True)[0] == "fail"
    assert eval_cookies(["a=1; Secure"], True)[0] == "warn"
    assert eval_cookies(["a=1; Secure; HttpOnly; SameSite=Lax"], True)[0] == "pass"


def test_leak_and_referrer():
    assert eval_leak({"server": "nginx/1.18.0"})[0] == "fail"
    assert eval_leak({"x-powered-by": "PHP"})[0] == "warn"
    assert eval_leak({"server": "cloudflare"})[0] == "pass"
    assert eval_referrer({"referrer-policy": "unsafe-url"})[0] == "warn"


def test_ssrf_guard():
    assert not is_public_host("127.0.0.1")
    assert not is_public_host("localhost")
    assert not is_public_host("169.254.169.254")
    assert not is_public_host("10.0.0.5")


# ---------------- deep checks ----------------
from checks import DEEP_CHECKS
from deep import (PATH_RULES, assess_lib, classify_core, detect_cms, detect_js_libs,
                  detect_wp_components, evaluate_paths, version_tuple)


def test_deep_points_total_100_and_text_complete():
    assert sum(c["pts"] for c in DEEP_CHECKS) == 100
    for c in DEEP_CHECKS:
        for m in ("Kid", "Business", "Developer"):
            assert len(c[m]) == 3
        for p in ("WordPress", "Shopify / Wix", "Vercel / Netlify", "Nginx / Custom"):
            assert p in c["fixes"]


def test_version_tuple_and_core_classification():
    assert version_tuple("6.2") < version_tuple("6.2.1") < version_tuple("6.10")
    assert classify_core("6.8.1", "6.8.1") == "ok"
    assert classify_core("6.8.0", "6.8.1") == "patch"
    assert classify_core("6.2.0", "6.8.1") == "behind"


def test_detect_cms():
    html = '<meta name="generator" content="WordPress 6.4.2" />'
    assert detect_cms(html) == ("WordPress", "6.4.2")
    html2 = '<link href="/wp-includes/css/x.css?ver=6.1.1">'
    assert detect_cms(html2) == ("WordPress", "6.1.1")
    assert detect_cms("<html></html>") == (None, None)


def test_detect_wp_plugins():
    html = '<script src="/wp-content/plugins/elementor/a.js?ver=3.5.0"></script><link href="/wp-content/themes/astra/s.css">'
    assert detect_wp_components(html, "plugins") == {"elementor": "3.5.0"}
    assert detect_wp_components(html, "themes") == {"astra": None}


def test_detect_js_libs():
    html = ('<script src="https://code.jquery.com/jquery-3.3.1.min.js"></script>'
            '<script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/3.3.7/js/bootstrap.min.js"></script>'
            '<script src="https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"></script>'
            '<script src="/static/app.js"></script>')
    libs = detect_js_libs(html)
    assert libs == {"jquery": ["3.3.1"], "bootstrap": ["3.3.7"], "lodash": ["4.17.21"]}


def test_assess_lib():
    assert assess_lib("jquery", "3.3.1")[0] == "fail"
    assert assess_lib("jquery", "3.7.1")[0] == "pass"
    assert assess_lib("bootstrap", "4.6.0")[0] == "pass"
    assert assess_lib("bootstrap", "3.3.7")[0] == "fail"
    assert assess_lib("angular", "1.8.2")[0] == "warn"
    assert assess_lib("lodash", "4.17.21")[0] == "pass"


def test_path_rules_avoid_false_positives():
    soft404 = [(200, "text/html", "<html><title>Home</title>welcome</html>")] * len(PATH_RULES)
    assert evaluate_paths(soft404) == ([], [])
    hits = []
    for path, sev, label, pred in PATH_RULES:
        hits.append((200, "text/plain", "ref: refs/heads/main") if path == "/.git/HEAD" else (404, "", ""))
    crit, warn = evaluate_paths(hits)
    assert crit == ["Git repository (/.git/HEAD)"] and warn == []
    listing = [(200, "text/html", "<title>Index of /uploads</title>") if p[0] == "/uploads/" else (404, "", "") for p in PATH_RULES]
    assert evaluate_paths(listing)[1] == ["Directory listing (/uploads/)"]
