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
