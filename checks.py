"""Rulebook: what we check, how many points it is worth, and the plain-language text."""

PLATFORMS = ["WordPress", "Shopify / Wix", "Vercel / Netlify", "Nginx / Custom"]
MODES = ["Kid", "Business", "Developer"]
FACTOR = {"pass": 1.0, "warn": 0.5, "fail": 0.0}


def header_fix(name: str, value: str) -> dict:
    """Fix snippets for any 'add this response header' check."""
    return {
        "WordPress": ("Add to `.htaccess` (Apache), or use a headers plugin such as 'HTTP Headers'.",
                      f'Header always set {name} "{value}"'),
        "Shopify / Wix": ("These platforms don't let you edit response headers. Put Cloudflare (free) in front "
                          "and add a Response Header Transform Rule.", None),
        "Vercel / Netlify": ("Add to the `headers` section of `vercel.json`, or to a Netlify `_headers` file.",
                             f"/*\n  {name}: {value}"),
        "Nginx / Custom": ("Add inside your `server` block, then reload Nginx:",
                           f'add_header {name} "{value}" always;'),
    }


CHECKS = [
    {
        "id": "https", "pts": 15, "part": "Front Door Lock",
        "house": ("🔒 Locked Gold Padlock", "🚪 Unlocked Door"),
        "Kid": ("Front Door Lock (HTTPS)", "Visitors use a secret code so spies cannot listen in!", "Uh oh! Your front door is unlocked on public Wi-Fi."),
        "Business": ("Encrypted Connection", "Customer forms are encrypted, boosting trust and SEO.", "Browsers warn visitors your site is 'Not Secure'."),
        "Developer": ("HTTPS Enforcement", "Site resolved securely over HTTPS.", "Site served over plain HTTP without TLS redirect."),
        "fixes": {
            "WordPress": "Install 'Really Simple SSL' or enable SSL in your hosting panel.",
            "Shopify / Wix": "Go to Settings -> Domains and toggle SSL ON.",
            "Vercel / Netlify": "Verify custom domain DNS; HTTPS is automatic.",
            "Nginx / Custom": ("Run Certbot (Let's Encrypt) and redirect port 80 to 443:", "sudo certbot --nginx -d example.com"),
        },
    },
    {
        "id": "redirect", "pts": 5, "part": "Old-Address Sign",
        "house": ("➡️ Old Address Redirects", "🚧 Old Door Still Open"),
        "Kid": ("Old-Address Sign (HTTP → HTTPS)", "Visitors using the old address get sent to the locked door!", "Visitors using the old address walk through an unlocked door."),
        "Business": ("HTTP → HTTPS Redirect", "Anyone typing the old http:// address lands on the secure site.", "Visitors on http:// stay on an unencrypted page."),
        "Developer": ("HTTP → HTTPS Redirect", "http:// answers with 301/302/307/308 to https:// (or isn't served).", "http:// serves content or redirects to another http:// URL."),
        "fixes": {
            "WordPress": "Enable 'Force HTTPS' in Really Simple SSL or your host's panel.",
            "Shopify / Wix": "Turn on 'Redirect all traffic to HTTPS' in domain settings.",
            "Vercel / Netlify": "Enable 'Force HTTPS' (Netlify) — Vercel does this automatically.",
            "Nginx / Custom": ("Add a port-80 server block that redirects:", "server {\n  listen 80;\n  server_name example.com;\n  return 301 https://$host$request_uri;\n}"),
        },
    },
    {
        "id": "ssl_valid", "pts": 10, "part": "Lock Warranty",
        "house": ("📅 Valid Lock Warranty", "⚠️ Expiring/Broken Lock"),
        "Kid": ("Lock Warranty (SSL Expiry)", "Your front door lock is fresh and up to date!", "Your lock warranty is expired or running out very soon!"),
        "Business": ("SSL Certificate Health", "Your security certificate is active with plenty of days left.", "An expired SSL certificate will block customers with a scary browser warning."),
        "Developer": ("TLS Certificate Validity", "Certificate is valid with >14 days remaining.", "Certificate is expired, unreachable, or expires in <14 days."),
        "fixes": {
            "WordPress": "Check auto-renewal in cPanel/hosting dashboard or Cloudflare SSL.",
            "Shopify / Wix": "Contact platform support if auto-renewing SSL is stuck.",
            "Vercel / Netlify": "Check domain settings and renew/re-verify DNS records.",
            "Nginx / Custom": ("Renew now and make sure a timer/cron job is active:", "sudo certbot renew\nsystemctl list-timers | grep certbot"),
        },
    },
    {
        "id": "hsts", "pts": 8, "part": "Automatic Deadbolt",
        "house": ("🛡️ Auto-Lock Active", "🔓 Manual Lock Only"),
        "Kid": ("Automatic Deadbolt (HSTS)", "Your door automatically locks behind every visitor!", "Visitors have to remember to lock the door themselves."),
        "Business": ("Strict Connection Security", "Blocks Wi-Fi interception attacks automatically.", "Attackers on public Wi-Fi could downgrade visitor connections."),
        "Developer": ("HSTS Header", "Strict-Transport-Security is set with a long max-age.", "Missing 'Strict-Transport-Security' response header."),
        "fixes": header_fix("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    },
    {
        "id": "frame", "pts": 7, "part": "Window Blinds",
        "house": ("🪟 Blinds Closed", "👀 Open Windows"),
        "Kid": ("Window Blinds (Anti-Clickjacking)", "Copycat sites cannot put your house inside a fake window!", "Windows are open! Sneaky sites could trap your page in a frame."),
        "Business": ("Brand Impersonation Guard", "Stops scammers from embedding your site to steal clicks.", "Scammers could overlay invisible buttons over your pages."),
        "Developer": ("Frame Protection", "X-Frame-Options or CSP frame-ancestors is set.", "Missing 'X-Frame-Options' or CSP 'frame-ancestors'."),
        "fixes": header_fix("X-Frame-Options", "SAMEORIGIN"),
    },
    {
        "id": "csp", "pts": 14, "part": "Guest List",
        "house": ("📋 Guest List Active", "🎉 Anyone Can Walk In"),
        "Kid": ("Party Guest List (CSP)", "Only approved scripts are allowed inside your website.", "No guest list! Outside scripts might sneak into your pages."),
        "Business": ("Malicious Script Blocker", "Blocks unauthorized code from stealing form data.", "Higher risk of script injection if a plugin has a bug."),
        "Developer": ("Content-Security-Policy", "CSP is set without 'unsafe-inline', 'unsafe-eval' or wildcards.", "Missing 'Content-Security-Policy' header."),
        "fixes": header_fix("Content-Security-Policy", "default-src 'self'"),
    },
    {
        "id": "nosniff", "pts": 5, "part": "Package Labels",
        "house": ("🏷️ Labels Respected", "🏷️ Labels Ignored"),
        "Kid": ("Package Labels (nosniff)", "Browsers trust the label on every package and don't guess what's inside!", "Browsers might open a package and guess wrong — sneaky files could sneak through."),
        "Business": ("File-Type Protection", "Browsers can't be tricked into running uploads as code.", "Uploaded files could be mis-read by browsers as scripts."),
        "Developer": ("X-Content-Type-Options", "X-Content-Type-Options: nosniff is set.", "Missing 'X-Content-Type-Options: nosniff'."),
        "fixes": header_fix("X-Content-Type-Options", "nosniff"),
    },
    {
        "id": "referrer", "pts": 3, "part": "Privacy Curtain",
        "house": ("🧵 Curtain Drawn", "🔦 Address Leaks Out"),
        "Kid": ("Privacy Curtain (Referrer-Policy)", "Your visitors' footsteps aren't shared with other websites!", "Other websites can see exactly which page your visitors came from."),
        "Business": ("Visitor Privacy", "Page addresses aren't leaked to third parties.", "Full page URLs (maybe with private info) leak to other sites."),
        "Developer": ("Referrer-Policy", "Referrer-Policy is set to a safe value.", "Missing or unsafe 'Referrer-Policy'."),
        "fixes": header_fix("Referrer-Policy", "strict-origin-when-cross-origin"),
    },
    {
        "id": "permissions", "pts": 2, "part": "Gadget Lock",
        "house": ("🎛️ Gadgets Restricted", "📷 Camera & Mic Open"),
        "Kid": ("Gadget Lock (Permissions-Policy)", "Cameras and microphones are locked unless you say so!", "Any embedded widget could ask to use the camera or mic."),
        "Business": ("Browser Feature Limits", "Risky browser features are restricted.", "Third-party embeds can request camera, mic or location."),
        "Developer": ("Permissions-Policy", "Permissions-Policy header is set.", "Missing 'Permissions-Policy' header."),
        "fixes": header_fix("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
    },
    {
        "id": "cookies", "pts": 6, "part": "Cookie Jar",
        "house": ("🍪 Jar Sealed", "🍪 Jar Left Open"),
        "Kid": ("Cookie Jar Lid (Cookie Flags)", "Your cookies are sealed so nobody can grab them!", "Your cookie jar lid is loose — cookies could be grabbed."),
        "Business": ("Session Cookie Safety", "Login/session cookies are protected from theft.", "Session cookies could be stolen or misused."),
        "Developer": ("Cookie Flags", "All cookies have Secure, HttpOnly and SameSite (or none are set).", "Cookies are missing Secure / HttpOnly / SameSite."),
        "fixes": {
            "WordPress": "Add `define('COOKIE_SECURE', true);`-style hardening via a security plugin, and force HTTPS.",
            "Shopify / Wix": "Managed by the platform; check third-party apps that set their own cookies.",
            "Vercel / Netlify": ("Set flags where your app sets cookies, e.g.:", "Set-Cookie: session=abc; Secure; HttpOnly; SameSite=Lax"),
            "Nginx / Custom": ("Set flags in your app or proxy, e.g.:", "proxy_cookie_flags ~ secure httponly samesite=lax;"),
        },
    },
    {
        "id": "leak", "pts": 3, "part": "Name Tag",
        "house": ("🙈 No Name Tag", "🏷️ Software Name Shown"),
        "Kid": ("Hidden Name Tag (Server Info)", "Your site doesn't announce what software it uses!", "Your site shouts out what software (and version) it runs."),
        "Business": ("Technology Disclosure", "Software versions aren't advertised to attackers.", "Attackers can look up known bugs for your exact software version."),
        "Developer": ("Server / X-Powered-By", "No versioned Server or X-Powered-By header.", "Server or X-Powered-By header reveals software/version."),
        "fixes": {
            "WordPress": "Remove `X-Powered-By` in PHP (`expose_php = Off`) or via your host.",
            "Shopify / Wix": "Managed by the platform; nothing to change.",
            "Vercel / Netlify": ("Frameworks like Next.js can drop the header:", "// next.config.js\nmodule.exports = { poweredByHeader: false };"),
            "Nginx / Custom": ("Hide versions:", "server_tokens off;\nproxy_hide_header X-Powered-By;"),
        },
    },
    {
        "id": "files", "pts": 12, "part": "Welcome Mat",
        "house": ("🧹 Clean Mat (No Keys)", "🔑 Keys Under Mat!"),
        "Kid": ("Keys Under the Mat (Secret Files)", "No secret house keys left hiding under the welcome mat!", "DANGER! A secret file (like passwords or a backup) is sitting out in the open!"),
        "Business": ("Secret File Protection", "Database passwords, source history and backups are safely hidden.", "CRITICAL: Sensitive files are publicly downloadable right now."),
        "Developer": ("Exposed Files (.env, .git, backups)", "/.env, /.git/config, /wp-config.php.bak, /backup.zip not exposed.", "Sensitive path(s) returned HTTP 200 with secret-looking content."),
        "fixes": {
            "WordPress": ("Block hidden files and backups in `.htaccess`, then rotate any exposed passwords:", 'RedirectMatch 403 /\\..*$\n<FilesMatch "\\.(bak|zip|sql)$">\n  Require all denied\n</FilesMatch>'),
            "Shopify / Wix": "Managed by platform; never put API secrets in theme JS files.",
            "Vercel / Netlify": "Keep `.env` out of Git and out of the publish directory; use dashboard Environment Variables.",
            "Nginx / Custom": ("Deny hidden files, then rotate any exposed secrets:", "location ~ /\\. { deny all; }\nlocation ~* \\.(bak|zip|sql)$ { deny all; }"),
        },
    },
    {
        "id": "email", "pts": 10, "part": "Mailbox Stamp",
        "house": ("✉️ Mail Is Stamped", "📪 Anyone Can Fake Your Mail"),
        "Kid": ("Mailbox Stamp (SPF + DMARC)", "Nobody can mail letters pretending to be you!", "Bad guys could send letters that look like they're from you."),
        "Business": ("Email Spoofing Protection", "Scammers can't easily send email as your domain.", "Scammers can send phishing emails that appear to come from you."),
        "Developer": ("SPF + DMARC DNS Records", "SPF and DMARC (policy quarantine/reject) found.", "SPF and/or DMARC TXT records missing or DMARC p=none."),
        "fixes": {
            "WordPress": ("Add these DNS TXT records at your domain registrar / DNS host:", 'example.com        TXT  "v=spf1 include:_spf.yourmailprovider.com ~all"\n_dmarc.example.com TXT  "v=DMARC1; p=quarantine; rua=mailto:you@example.com"'),
            "Shopify / Wix": ("Add these DNS TXT records in your domain settings:", 'example.com        TXT  "v=spf1 include:_spf.yourmailprovider.com ~all"\n_dmarc.example.com TXT  "v=DMARC1; p=quarantine; rua=mailto:you@example.com"'),
            "Vercel / Netlify": ("Add these DNS TXT records in your DNS provider:", 'example.com        TXT  "v=spf1 include:_spf.yourmailprovider.com ~all"\n_dmarc.example.com TXT  "v=DMARC1; p=quarantine; rua=mailto:you@example.com"'),
            "Nginx / Custom": ("Add these DNS TXT records at your DNS host:", 'example.com        TXT  "v=spf1 include:_spf.yourmailprovider.com ~all"\n_dmarc.example.com TXT  "v=DMARC1; p=quarantine; rua=mailto:you@example.com"'),
        },
    },
]

CHECK_BY_ID = {c["id"]: c for c in CHECKS}


def describe(check: dict, status: str, detail: str, mode: str):
    """Plain-language (title, message) for one result in the chosen reading mode."""
    title, ok_msg, bad_msg = check[mode]
    if status == "pass":
        return title, ok_msg
    if status == "warn":
        return title, f"Partly there — {detail}" if detail else "Partly there — can be improved."
    msg = bad_msg
    if detail and (mode == "Developer" or check["id"] == "files"):
        msg += f" ({detail})"
    return title, msg


def fix_for(check: dict, platform: str):
    """Returns (text, code_or_None) for the chosen platform."""
    fix = check["fixes"][platform]
    return fix if isinstance(fix, tuple) else (fix, None)
