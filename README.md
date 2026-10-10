# Phishing URL Detector

An offline, rule-based tool that scores how likely a URL is to be a phishing link and explains **why**. It is a single Python file with no dependencies, and it makes no network requests.

> This tool only reads the URL text. It cannot prove a site is safe. "NO OBVIOUS RED FLAGS" means the URL itself looks clean, nothing more.

## What it detects

| Signal | Example |
|---|---|
| Typosquatting / look-alike brands | `paypa1.com`, `arnazon.com`, `g00gle.com` |
| Brand name on a non-official domain | `secure-hdfcbank-kyc.web.app` |
| Real domain faked inside a hostname | `paypal.com.verify-account.xyz` |
| Free hosting platforms often abused | `web.app`, `github.io`, `sites.google.com`, `netlify.app` |
| Link shorteners | `bit.ly`, `tinyurl.com` |
| Raw IP address instead of a domain | `http://192.168.1.1/login` |
| `@` trick, punycode (`xn--`), embedded URLs | `http://google.com@evil.xyz` |
| Cheap or high-abuse TLDs | `.xyz`, `.top`, `.tk` |
| Phishing keywords | `login`, `verify`, `kyc`, `otp`, `suspend` |
| No HTTPS, long URLs, many hyphens or subdomains | |

## Verdicts

| Score | Verdict |
|---|---|
| 0-19 | NO OBVIOUS RED FLAGS |
| 20-44 | SUSPICIOUS |
| 45-100 | LIKELY PHISHING |

## Requirements

Python 3.8 or newer. No `pip install` needed.

## Usage

**Windows** (use `py`):
```
py phishing_detector.py
py phishing_detector.py "http://paypa1-secure-login.com/verify"
py phishing_detector.py -f sample_urls.txt --html report.html
```

**Linux / macOS / Kali** (use `python3`):
```
python3 phishing_detector.py "http://paypa1-secure-login.com/verify"
python3 phishing_detector.py -f sample_urls.txt --html report.html
```

Run without arguments and it asks you to paste a URL.

### The hacker-theme report

Every scan writes `report.html` and **opens it in your browser automatically**. The report has:

- red matrix-rain background, CRT scanlines and a glitching title
- a terminal window that types out the scan command and prints a boot log
- a segmented threat meter and a log-style list of why each URL scored what it did
- a summary strip (phishing / suspicious / clean) and a layout that works on phones

Open `sample_report.html` to see an example without running anything. It is a plain HTML file with no internet needed. If your system has "reduce motion" turned on, the animations switch off automatically.

### Options

| Option | What it does |
|---|---|
| `-f FILE` | Scan every URL in a text file (one per line) |
| `--html PATH` | Where to save the report (default `report.html`) |
| `--no-open` | Save the report but do not open the browser |
| `--no-report` | Console output only, no HTML report |

## Run the tests

```
py test_detector.py
```

## Project structure

```
Phishing-URL-Detector/
├── phishing_detector.py   # the whole tool (detector + CLI + HTML report)
├── test_detector.py       # sanity tests
├── sample_urls.txt        # example URLs to try
├── sample_report.html     # example output
├── README.md
└── .gitignore
```

## Limitations

- It is a heuristic, so it will miss well-crafted attacks and some legitimate URLs may look suspicious.
- It cannot detect a hacked legitimate website or a brand-new plain-looking domain.
- It does not check domain age, WHOIS, SSL certificates, or live page content.

## Ideas to extend it

- Add domain-age and DNS checks (network required).
- Cross-check with Google Safe Browsing or PhishTank.
- Train a machine-learning model on a labeled phishing dataset using these features.
- Add more brands to the `BRANDS` dictionary for your region.

## Disclaimer

For educational and defensive use. Do not rely on it as your only protection against phishing.
