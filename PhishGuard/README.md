# PhishGuard - Phishing URL Detector

A Python tool with a command-line mode and a Flask web app. It scores a URL from 0 to 100, explains why it looks safe or dangerous, and stores every scan in SQLite.

## Checks it performs
- No HTTPS, IP address instead of a domain, `@` in the URL
- Very long URLs, too many subdomains, many hyphens
- Punycode / non-ASCII characters (homograph attacks)
- URL shorteners and risky TLDs (`.xyz`, `.top`, ...)
- Suspicious words like `login`, `verify`, `kyc`
- **Look-alike brands**: `paypa1.com`, `amaz0n.com` are caught using leetspeak
  normalization and Levenshtein edit distance

## Web app
```
pip install -r requirements.txt
python app.py        # open http://127.0.0.1:5000
python test_app.py
```
Pages: **Check URL** (single + bulk), **History** (filter by verdict), **Statistics**, and a JSON API at `/api/check?url=...`.

## Command line
```
python main.py http://paypa1-secure-login.example-bank.xyz/verify
python main.py --file sample/urls.txt     # also creates report.html
python test_phishguard.py
```

## Files
| File | Purpose |
|------|---------|
| `analyzer.py` | Scoring logic and look-alike detection |
| `rules.py` | Brand list, keywords, TLDs |
| `report.py` | HTML report generator |
| `main.py` | Command-line interface |
| `app.py` | Flask routes, input validation, JSON API |
| `database.py` | SQLite storage, history, statistics |
| `templates/`, `static/` | HTML pages and CSS |
| `test_app.py` | Tests for the web app and database |
| `test_phishguard.py` | Tests |

## Limitations
Rule-based only. It does not check live reputation databases, so it can give false positives and negatives. The URLs in `sample/` are fictional examples.

## Ideas for future work
- Add a machine-learning classifier
- Check domain age with WHOIS
- Build a browser extension or web UI
