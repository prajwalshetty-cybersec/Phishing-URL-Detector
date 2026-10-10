"""
phishing_detector.py  --  single-file, offline Phishing URL Detector (v2)

Usage (Windows):
    py phishing_detector.py                      (interactive: paste a URL)
    py phishing_detector.py "http://example.xyz/login"
    py phishing_detector.py -f urls.txt --html report.html

No dependencies. Pure Python 3 standard library.
After each scan a hacker-theme HTML report opens in your browser
(use --no-open to skip that, --no-report for console only). Console output is ASCII-only
so it works in any Windows terminal.

NOTE: This is a heuristic that only reads the URL text. It cannot prove a site
is safe. "NO OBVIOUS RED FLAGS" means the URL itself looks clean, nothing more.
"""

import argparse
import datetime
import html
import os
import re
import sys
import webbrowser
from pathlib import Path
from urllib.parse import urlparse, unquote

# --------------------------------------------------------------------------- #
# Reference data
# --------------------------------------------------------------------------- #

# brand token -> official registrable domains
BRANDS = {
    "paypal": ["paypal.com", "paypal.me"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.co.jp", "amazonaws.com"],
    "google": ["google.com", "google.co.in", "googleapis.com", "gstatic.com", "goo.gl"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "microsoftonline.com", "outlook.com", "office365.com", "windows.com"],
    "outlook": ["outlook.com", "live.com", "office.com", "microsoft.com"],
    "office365": ["office.com", "office365.com", "microsoft.com"],
    "apple": ["apple.com", "icloud.com"],
    "icloud": ["icloud.com", "apple.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com", "whatsapp.net"],
    "telegram": ["telegram.org", "t.me"],
    "twitter": ["twitter.com", "x.com"],
    "linkedin": ["linkedin.com"],
    "dropbox": ["dropbox.com"],
    "github": ["github.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "hsbc": ["hsbc.com", "hsbc.co.uk", "hsbc.co.in"],
    "coinbase": ["coinbase.com"],
    "binance": ["binance.com"],
    "metamask": ["metamask.io"],
    "sbi": ["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com"],
    "hdfc": ["hdfcbank.com", "hdfc.com"],
    "hdfcbank": ["hdfcbank.com"],
    "icici": ["icicibank.com", "icici.com"],
    "icicibank": ["icicibank.com"],
    "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"],
    "flipkart": ["flipkart.com"],
    "irctc": ["irctc.co.in"],
    "aadhaar": ["uidai.gov.in"],
    "incometax": ["incometax.gov.in"],
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "shorte.st", "cutt.ly", "rebrand.ly", "rb.gy", "tiny.cc",
    "s.id", "v.gd", "shorturl.at", "t.ly", "lnkd.in", "bl.ink",
}

# platforms where anyone can host a page for free (often abused for phishing)
FREE_HOSTING = {
    "web.app", "firebaseapp.com", "pages.dev", "workers.dev", "github.io",
    "netlify.app", "vercel.app", "herokuapp.com", "glitch.me", "weebly.com",
    "wixsite.com", "blogspot.com", "000webhostapp.com", "ngrok.io",
    "ngrok-free.app", "r2.dev", "notion.site", "canva.site", "framer.app",
    "godaddysites.com", "square.site", "myshopify.com", "sites.google.com",
    "forms.gle", "typeform.com", "surge.sh", "repl.co", "replit.app",
    "trycloudflare.com", "azurewebsites.net", "appspot.com",
}

CHEAP_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "link", "work",
    "zip", "mov", "country", "support", "buzz", "rest", "icu", "cyou",
    "cfd", "sbs", "monster", "live", "fit", "bid", "loan", "men", "date",
    "party", "review", "stream", "download", "racing", "win", "vip", "su",
    "ru", "cn", "pw", "cc", "ws", "info", "site", "online", "store", "tech",
}

KEYWORDS = [
    "login", "log-in", "signin", "sign-in", "verify", "verification",
    "account", "update", "secure", "security", "banking", "confirm",
    "webscr", "password", "passwd", "suspend", "suspended", "unlock",
    "billing", "invoice", "wallet", "reset", "authenticate", "support",
    "alert", "urgent", "recover", "recovery", "validate", "payment",
    "refund", "kyc", "otp", "reward", "prize", "claim", "free", "bonus",
]

TWO_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.in",
    "net.in", "org.in", "gov.in", "ac.in", "co.jp", "com.br", "co.nz",
    "co.za", "com.cn", "com.mx", "com.sg", "com.hk", "co.id",
}

LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
                      "7": "t", "8": "b", "@": "a", "$": "s", "!": "i"})

IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def split_host(host):
    """Return (registrable_domain, subdomain_labels)."""
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in TWO_LEVEL_SUFFIXES:
        return ".".join(labels[-3:]), labels[:-3]
    if len(labels) >= 2:
        return ".".join(labels[-2:]), labels[:-2]
    return host, []


def levenshtein(a, b):
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def tokens(text):
    return [t for t in re.split(r"[^a-z0-9]+", text.lower()) if t]


def brand_in(text, brand):
    """Brand appears as a token, or as a substring when the brand is long."""
    low = text.lower()
    if len(brand) >= 6:
        return brand in low
    return brand in tokens(low)


def is_official(reg, brand):
    return reg in BRANDS[brand]


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #


def analyze(url):
    raw = url.strip()
    parsed = urlparse(raw if "://" in raw else "http://" + raw)
    host = (parsed.hostname or "").lower().rstrip(".")
    path = unquote(parsed.path or "")
    query = unquote(parsed.query or "")
    reg, subs = split_host(host)
    tld = host.split(".")[-1] if "." in host else ""
    name_part = reg.split(".")[0]
    reasons = []  # (weight, message)

    def add(w, msg):
        reasons.append((w, msg))

    if not host:
        return {"url": raw, "score": 0, "label": "INVALID URL",
                "reasons": [(0, "Could not read a hostname from this input.")], "host": host}

    # --- host-level signals ---
    if IP_RE.match(host):
        add(25, "Uses a raw IP address instead of a domain name.")
    if "@" in raw.split("//", 1)[-1].split("/", 1)[0]:
        add(20, "Contains '@' in the address; everything before it is ignored by the browser (obfuscation trick).")
    if host.startswith("xn--") or ".xn--" in host:
        add(20, "Uses punycode (xn--), which can disguise look-alike Unicode characters.")
    if reg in SHORTENERS:
        add(20, "Link shortener hides the real destination; expand it before trusting it.")
    if reg in FREE_HOSTING:
        add(15, f"Hosted on a free/public platform ({reg}) that attackers commonly abuse.")
    if tld in CHEAP_TLDS and reg not in SHORTENERS:
        add(10, f"Uses the '.{tld}' TLD, which is cheap/free and overrepresented in phishing.")
    if parsed.port and parsed.port not in (80, 443):
        add(6, f"Uses a non-standard port ({parsed.port}).")
    if parsed.scheme != "https":
        add(10, "Not HTTPS; anything typed on this page is sent unencrypted.")

    # --- structure ---
    if len(subs) >= 3:
        add(12, f"{len(subs)} subdomain levels; often used to push the real domain out of view.")
    hy = name_part.count("-") + sum(s.count("-") for s in subs)
    if hy >= 3:
        add(10, f"{hy} hyphens in the domain, a common pattern in throwaway phishing domains.")
    elif hy == 2:
        add(5, "Multiple hyphens in the domain.")
    digits = sum(c.isdigit() for c in host)
    if host and not IP_RE.match(host) and digits / len(host) > 0.25:
        add(8, "Hostname is unusually digit-heavy.")
    if len(raw) > 100:
        add(12, "Very long URL (over 100 characters).")
    elif len(raw) > 75:
        add(6, "Long URL (over 75 characters).")
    if "%" in raw and re.search(r"%[0-9a-fA-F]{2}", raw):
        add(5, "Contains percent-encoded characters.")
    if re.search(r"https?://", path + "?" + query, re.I):
        add(12, "Another URL is embedded inside this one (possible redirect/obfuscation).")
    if re.search(r"\.(com|net|org|in|co)\.", host) and not host.endswith(tuple("." + s for s in TWO_LEVEL_SUFFIXES)):
        add(20, "A well-known TLD appears inside the hostname (e.g. paypal.com.evil.xyz) to look legitimate.")

    # --- brand impersonation ---
    hit_brand = None
    for brand in BRANDS:
        if is_official(reg, brand):
            continue
        in_host = brand_in(host, brand)
        in_path = brand_in(path + " " + query, brand)
        if in_host:
            add(30, f"Mentions the brand '{brand}' in the domain, but '{reg}' is not an official {brand} domain.")
            hit_brand = brand
            break
        if in_path and not hit_brand:
            add(15, f"Mentions '{brand}' in the path/query while hosted on '{reg}' (not official).")
            hit_brand = brand

    # --- typosquatting (paypa1, arnazon, g00gle, micros0ft ...) ---
    if not hit_brand or True:
        cand = set(tokens(name_part)) | {name_part.replace("-", "")}
        for sub in subs:
            cand |= set(tokens(sub))
        done = False
        for tok in cand:
            if done or len(tok) < 4:
                continue
            norm = tok.translate(LEET).replace("rn", "m").replace("vv", "w")
            for brand in BRANDS:
                if len(brand) < 5 or is_official(reg, brand) or tok == brand:
                    continue
                d = min(levenshtein(tok, brand), levenshtein(norm, brand))
                limit = 2 if len(brand) >= 8 else 1
                if 0 < d <= limit or (norm == brand and tok != brand):
                    add(35, f"'{tok}' looks like a misspelling/look-alike of '{brand}' (typosquatting).")
                    done = True
                    break

    # --- keywords ---
    scan_text = (host + " " + path + " " + query).lower()
    found = [k for k in KEYWORDS if k in scan_text]
    if found:
        add(min(20, 5 * len(found)), "Phishing-style keyword(s): " + ", ".join(found[:6]) + ".")

    # --- combination bonus: free hosting / cheap TLD + brand or credential words ---
    if (reg in FREE_HOSTING or tld in CHEAP_TLDS) and (hit_brand or found):
        add(10, "Combines a free/cheap host with brand or login-style wording, a very common phishing combination.")

    total = max(0, min(100, sum(w for w, _ in reasons)))
    if total >= 45:
        label = "LIKELY PHISHING"
    elif total >= 20:
        label = "SUSPICIOUS"
    else:
        label = "NO OBVIOUS RED FLAGS"
    reasons.sort(key=lambda r: -r[0])
    return {"url": raw, "score": total, "label": label, "reasons": reasons, "host": host}


# --------------------------------------------------------------------------- #
# Output: console
# --------------------------------------------------------------------------- #

BANNER = r"""
 ____  _   _ ___ ____  _   _ ___ _   _  ____
|  _ \| | | |_ _/ ___|| | | |_ _| \ | |/ ___|
| |_) | |_| || |\___ \| |_| || ||  \| | |  _
|  __/|  _  || | ___) |  _  || || |\  | |_| |
|_|   |_| |_|___|____/|_| |_|___|_| \_|\____|
      U R L   D E T E C T O R   //   v2
"""

USE_COLOR = sys.stdout.isatty()
LABEL_CODE = {"LIKELY PHISHING": "1;91", "SUSPICIOUS": "1;93",
              "NO OBVIOUS RED FLAGS": "1;92", "INVALID URL": "90"}


def enable_ansi():
    """Turn on ANSI colour processing in Windows 10+ consoles."""
    if os.name == "nt":
        os.system("")


def paint(text, code):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


def print_console(v):
    code = LABEL_CODE.get(v["label"], "0")
    filled = int(30 * v["score"] / 100)
    bar = "#" * filled + "-" * (30 - filled)
    print(paint("-" * 66, "31"))
    print(paint("[TARGET] ", "91") + v["url"])
    print(paint("[SCORE ] ", "91") + paint(f"[{bar}] {v['score']}/100", code))
    print(paint("[STATUS] ", "91") + paint(v["label"], code))
    for w, m in v["reasons"]:
        print(paint(f"  [+{w:<2}] ", "91") + m)
    if v["label"] == "NO OBVIOUS RED FLAGS":
        print(paint("  [i]    Only the URL text looks clean. This is not proof of safety.", "90"))


# --------------------------------------------------------------------------- #
# Output: hacker-theme HTML report
# --------------------------------------------------------------------------- #

COLORS = {"LIKELY PHISHING": "#ff1744", "SUSPICIOUS": "#ff9100",
          "NO OBVIOUS RED FLAGS": "#00e676", "INVALID URL": "#9e9e9e"}
CLASSES = {"LIKELY PHISHING": "bad", "SUSPICIOUS": "warn",
           "NO OBVIOUS RED FLAGS": "ok", "INVALID URL": "na"}

REPORT_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PHISHING URL DETECTOR // THREAT REPORT</title>
<script>document.documentElement.className='js';</script>
<style>
:root{--bg:#050000;--red:#ff1744;--redg:rgba(255,23,68,.55);--txt:#ffd9de;--mut:#a65b66;--panel:rgba(14,2,4,.88)}
*{box-sizing:border-box}
html,body{margin:0;background:var(--bg);color:var(--txt);font-family:"Cascadia Mono","Fira Code",Consolas,"Courier New",monospace}
body{min-height:100vh;overflow-x:hidden}
#rain{position:fixed;inset:0;width:100%;height:100%;z-index:0;opacity:.32}
body::before{content:"";position:fixed;inset:0;z-index:3;pointer-events:none;
  background:repeating-linear-gradient(0deg,rgba(0,0,0,.30) 0,rgba(0,0,0,.30) 1px,transparent 1px,transparent 3px)}
body::after{content:"";position:fixed;inset:0;z-index:3;pointer-events:none;
  background:radial-gradient(ellipse at center,transparent 55%,rgba(0,0,0,.8) 100%)}
.wrap{position:relative;z-index:1;max-width:920px;margin:0 auto;padding:26px 14px 60px;animation:flick 7s infinite}

.term{border:1px solid var(--red);background:var(--panel);box-shadow:0 0 34px -6px var(--redg);margin-bottom:18px}
.tbar{display:flex;align-items:center;gap:7px;padding:7px 12px;background:rgba(255,23,68,.14);border-bottom:1px solid var(--red);font-size:12px;color:var(--mut)}
.tbar i{width:10px;height:10px;border-radius:50%;background:var(--red);opacity:.85}
.tbar i:nth-child(2){opacity:.55}.tbar i:nth-child(3){opacity:.3}
.tbar span{margin-left:8px;letter-spacing:1px}
.tbody{padding:16px 18px 18px}
.ascii{margin:0 0 6px;color:#ff5470;font-weight:700;font-size:15px;line-height:1.15;text-shadow:0 0 5px var(--redg);overflow-x:auto}

.glitch{position:relative;display:inline-block;margin:8px 0 14px;font-size:clamp(24px,6vw,42px);font-weight:700;letter-spacing:5px;color:#fff;text-shadow:0 0 14px var(--redg)}
.glitch::before,.glitch::after{content:attr(data-text);position:absolute;top:0;width:100%;height:100%;overflow:hidden}
.glitch::before{left:2px;color:var(--red);animation:g1 2.6s infinite linear alternate-reverse}
.glitch::after{left:-2px;color:#ff8a98;animation:g2 3.1s infinite linear alternate-reverse}
@keyframes g1{0%{clip-path:inset(20% 0 70% 0)}20%{clip-path:inset(62% 0 10% 0)}40%{clip-path:inset(40% 0 40% 0)}60%{clip-path:inset(82% 0 4% 0)}80%{clip-path:inset(8% 0 82% 0)}100%{clip-path:inset(50% 0 30% 0)}}
@keyframes g2{0%{clip-path:inset(70% 0 12% 0)}25%{clip-path:inset(12% 0 72% 0)}50%{clip-path:inset(55% 0 25% 0)}75%{clip-path:inset(30% 0 52% 0)}100%{clip-path:inset(88% 0 2% 0)}}

.cmd{font-size:14px;margin:4px 0 12px;word-break:break-all}
.ps{color:var(--red);font-weight:700}
.caret{display:inline-block;width:9px;height:1em;background:var(--red);vertical-align:-2px;margin-left:2px;animation:blink 1s steps(2) infinite}
@keyframes blink{50%{opacity:0}}
.boot{font-size:12.5px;line-height:1.7;color:var(--mut)}
.boot .okk{color:var(--red);font-weight:700}
.meta{margin-top:10px;font-size:12px;color:var(--mut);display:flex;gap:18px;flex-wrap:wrap}
.meta b{color:var(--txt)}

.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:18px}
.stat{border:1px solid var(--c);background:var(--panel);padding:10px 14px;display:flex;align-items:baseline;justify-content:space-between;box-shadow:0 0 18px -8px var(--c)}
.stat b{font-size:28px;color:var(--c);text-shadow:0 0 10px var(--c)}
.stat span{font-size:11px;letter-spacing:2px;color:var(--mut)}

.card{border:1px solid var(--c);border-left-width:4px;background:var(--panel);padding:14px 16px 12px;margin-bottom:16px;box-shadow:0 0 26px -10px var(--c)}
.chead{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}
.tag{font-size:11px;letter-spacing:2px;color:var(--mut)}
.verdict{font-weight:700;letter-spacing:3px;font-size:13px;color:var(--c);border:1px solid var(--c);padding:3px 12px;text-shadow:0 0 8px var(--c)}
.bad .verdict{animation:blink 1.2s steps(2) infinite}
.url{margin:10px 0 2px;color:#fff;font-weight:700;word-break:break-all;font-size:14px}
.url::before{content:"TARGET> ";color:var(--c)}
.meter{position:relative;height:18px;margin:12px 0 4px;border:1px solid var(--c);background:rgba(255,255,255,.04)}
.fill{height:100%;width:var(--w);background:var(--c);box-shadow:0 0 14px var(--c);transition:width 1.3s cubic-bezier(.2,.8,.2,1);
  -webkit-mask:repeating-linear-gradient(90deg,#000 0 8px,transparent 8px 10px);mask:repeating-linear-gradient(90deg,#000 0 8px,transparent 8px 10px)}
.js .fill{width:0}
.mlabel{font-size:11px;letter-spacing:2px;color:var(--mut);margin-bottom:10px}
.mlabel b{color:var(--c)}
.log{list-style:none;margin:0;padding:8px 0 0;border-top:1px dashed rgba(255,23,68,.35);font-size:13px;line-height:1.55}
.log li{margin:3px 0;padding-left:2px;color:var(--txt)}
.log li::before{content:"> ";color:var(--mut)}
.sev{display:inline-block;min-width:38px;margin-right:8px;font-weight:700}
.hi{color:#fff}.hi .sev{color:#ff1744;text-shadow:0 0 8px #ff1744}
.mid .sev{color:#ff6e40}
.lo{color:#d9b3b8}.lo .sev{color:var(--mut)}
.note{margin-top:8px;font-size:12px;color:var(--mut)}

footer{margin-top:26px;text-align:center;font-size:11px;letter-spacing:1px;color:var(--mut)}
footer b{color:var(--red)}

.js .reveal{opacity:0;transform:translateY(4px);transition:opacity .35s ease,transform .35s ease}
.js .reveal.show{opacity:1;transform:none}

@keyframes flick{0%,90%,100%{opacity:1}91%{opacity:.88}92%{opacity:1}95%{opacity:.94}96%{opacity:1}}
@media (max-width:560px){.ascii{font-size:9px}.tbody{padding:12px}.sev{min-width:34px}}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}.js .reveal{opacity:1;transform:none}}
::selection{background:var(--red);color:#000}
</style>
</head>
<body>
<canvas id="rain" aria-hidden="true"></canvas>
<div class="wrap">
  <div class="term">
    <div class="tbar"><i></i><i></i><i></i><span>root@phishing-detector: ~/scan</span></div>
    <div class="tbody">
      <pre class="ascii">__BANNER__</pre>
      <h1 class="glitch" data-text="THREAT REPORT">THREAT REPORT</h1>
      <div class="cmd"><span class="ps">root@detector:~#</span> <span id="typed" data-text="__CMD__">__CMD__</span><span class="caret"></span></div>
      <div class="boot">
        <div class="reveal">[ <span class="okk">OK</span> ] heuristic engine loaded (typosquat / brand / host / keyword rules)</div>
        <div class="reveal">[ <span class="okk">OK</span> ] offline mode: no network requests were made</div>
        <div class="reveal">[ <span class="okk">OK</span> ] analysis complete, __COUNT__ target(s) scored</div>
      </div>
      <div class="meta"><span>SCAN TIME <b>__TIME__</b></span><span>TARGETS <b>__COUNT__</b></span></div>
    </div>
  </div>

  <div class="stats">__STATS__</div>

  __CARDS__

  <footer>
    <b>PHISHING URL DETECTOR</b> // heuristic analysis of URL text only // not proof of safety
  </footer>
</div>

<script>
(function(){
  var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* ---- red matrix rain ---- */
  var cv = document.getElementById('rain');
  if (cv && !reduce) {
    var ctx = cv.getContext('2d'), W, H, cols, drops, fs = 16;
    var chars = '01ABCDEF<>/{}[]$#%&*+=!?@'.split('');
    var size = function(){
      W = cv.width = window.innerWidth; H = cv.height = window.innerHeight;
      cols = Math.floor(W / fs); drops = [];
      for (var i = 0; i < cols; i++) drops[i] = Math.random() * -40;
    };
    size(); window.addEventListener('resize', size);
    setInterval(function(){
      ctx.fillStyle = 'rgba(5,0,0,.12)'; ctx.fillRect(0, 0, W, H);
      ctx.fillStyle = '#ff1744'; ctx.font = fs + 'px monospace';
      for (var i = 0; i < cols; i++) {
        ctx.fillText(chars[Math.floor(Math.random() * chars.length)], i * fs, drops[i] * fs);
        if (drops[i] * fs > H && Math.random() > 0.975) drops[i] = 0;
        drops[i]++;
      }
    }, 60);
  }

  /* ---- boot sequence ---- */
  var items = [].slice.call(document.querySelectorAll('.reveal'));
  var fillBar = function(el){
    var f = el.querySelector ? el.querySelector('.fill') : null;
    if (f) setTimeout(function(){ f.style.width = f.getAttribute('data-score') + '%'; }, 80);
  };
  if (reduce) {
    items.forEach(function(e){ e.classList.add('show'); fillBar(e); });
    return;
  }
  var typed = document.getElementById('typed');
  var text = typed ? (typed.getAttribute('data-text') || '') : '';
  if (typed) typed.textContent = '';
  var i = 0;
  var typeStep = function(){
    if (typed && i <= text.length) { typed.textContent = text.slice(0, i++); setTimeout(typeStep, 16); }
    else reveal(0);
  };
  var reveal = function(n){
    if (n >= items.length) return;
    var e = items[n];
    e.classList.add('show'); fillBar(e);
    setTimeout(function(){ reveal(n + 1); }, e.classList.contains('card') ? 320 : 120);
  };
  typeStep();
})();
</script>
</body>
</html>
"""


def _sev_class(w):
    return "hi" if w >= 25 else "mid" if w >= 10 else "lo"


def html_report(verdicts):
    esc = html.escape
    counts = {"LIKELY PHISHING": 0, "SUSPICIOUS": 0, "NO OBVIOUS RED FLAGS": 0}
    cards = []
    for n, v in enumerate(verdicts, 1):
        counts[v["label"]] = counts.get(v["label"], 0) + 1
        color = COLORS.get(v["label"], "#ffffff")
        cls = CLASSES.get(v["label"], "na")
        items = "".join(
            f'<li class="reveal {_sev_class(w)}"><span class="sev">+{w}</span>{esc(m)}</li>'
            for w, m in v["reasons"]
        ) or '<li class="reveal lo"><span class="sev">--</span>No indicators triggered.</li>'
        note = ""
        if v["label"] == "NO OBVIOUS RED FLAGS":
            note = '<div class="note reveal">[i] Only the URL text was analysed. This is not proof of safety.</div>'
        tag = f"TARGET_{n:02d}"
        url = esc(v["url"])
        label = esc(v["label"])
        score = v["score"]
        cards.append(
            f'<section class="card reveal {cls}" style="--c:{color};--w:{score}%">'
            f'<div class="chead"><span class="tag">[{tag}]</span><span class="verdict">{label}</span></div>'
            f'<div class="url">{url}</div>'
            f'<div class="meter"><div class="fill" data-score="{score}"></div></div>'
            f'<div class="mlabel">THREAT SCORE <b>{score}/100</b></div>'
            f'<ul class="log">{items}</ul>{note}</section>'
        )

    stats = "".join(
        f'<div class="stat reveal" style="--c:{COLORS[lbl]}"><b>{counts.get(lbl, 0)}</b><span>{name}</span></div>'
        for lbl, name in (("LIKELY PHISHING", "PHISHING"), ("SUSPICIOUS", "SUSPICIOUS"),
                          ("NO OBVIOUS RED FLAGS", "CLEAN"))
    )

    first = verdicts[0]["url"] if verdicts else ""
    if len(verdicts) == 1:
        short = first if len(first) <= 90 else first[:87] + "..."
        cmd = f'phishing_detector --scan "{short}"'
    else:
        cmd = f"phishing_detector --scan --batch {len(verdicts)} targets"

    page = REPORT_TEMPLATE
    page = page.replace("__BANNER__", esc(BANNER.strip("\n"), quote=False))
    page = page.replace("__CMD__", esc(cmd, quote=True))
    page = page.replace("__COUNT__", str(len(verdicts)))
    page = page.replace("__TIME__", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    page = page.replace("__STATS__", stats)
    page = page.replace("__CARDS__", "\n  ".join(cards))
    return page


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def main():
    enable_ansi()
    ap = argparse.ArgumentParser(description="Offline Phishing URL Detector (single file)")
    ap.add_argument("url", nargs="?", help="URL to check")
    ap.add_argument("-f", "--file", help="Text file with one URL per line")
    ap.add_argument("--html", default="report.html",
                    help="Where to save the HTML report (default: report.html)")
    ap.add_argument("--no-report", action="store_true", help="Console output only, skip the HTML report")
    ap.add_argument("--no-open", action="store_true", help="Do not open the report in the browser automatically")
    a = ap.parse_args()

    print(paint(BANNER, "91"))

    urls = []
    if a.url:
        urls.append(a.url)
    if a.file:
        with open(a.file, "r", encoding="utf-8") as fh:
            urls += [l.strip() for l in fh if l.strip()]
    if not urls:
        try:
            u = input(paint("root@detector:~# ", "1;91") + "paste a URL to scan > ").strip()
        except EOFError:
            u = ""
        if not u:
            ap.print_help()
            sys.exit(1)
        urls.append(u)

    verdicts = [analyze(u) for u in urls]
    for v in verdicts:
        print_console(v)
    print(paint("-" * 66, "31"))

    if not a.no_report:
        with open(a.html, "w", encoding="utf-8") as fh:
            fh.write(html_report(verdicts))
        full = Path(a.html).resolve()
        print(paint("[+] ", "91") + f"HTML report saved: {full}")
        if not a.no_open:
            try:
                webbrowser.open(full.as_uri())
                print(paint("[+] ", "91") + "Opening report in your browser...")
            except Exception:
                print(paint("[!] ", "91") + "Could not open the browser. Open the file above manually.")


if __name__ == "__main__":
    main()
