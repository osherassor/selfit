<h1 align="center">🌐 Selfit — Web Discovery Scanner</h1>

<p align="center">
  <strong>Find every web service on a target, screenshot it, and tell you what's interesting.</strong><br>
  Web service discovery + SSL analysis + subdomain enumeration + path fuzzing + default-cred testing — all in one Python CLI with a live HTML report.
</p>

<p align="center">
  <img src="https://img.shields.io/github/stars/osherassor/selfit?style=for-the-badge&logo=github&color=ffd700" alt="Stars">
  <img src="https://img.shields.io/github/last-commit/osherassor/selfit?style=for-the-badge&logo=git&color=00d4aa" alt="Last commit">
  <img src="https://img.shields.io/badge/python-3.8%2B-3776ab?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-informational?style=for-the-badge" alt="License">
</p>

---

## What is this?

You hand it a target — IP, hostname, CIDR, or a list — and it gives you back: every web service it found, screenshots, SSL cert details, discovered subdomains, fuzzed paths, default-cred hits, and a clean HTML report you can share. It's the "what's actually running on this perimeter?" answer in one shot.

## 🚀 Quick start

```bash
git clone https://github.com/osherassor/selfit
cd selfit
pip install -r requirements.txt
playwright install chromium

python web_discovery_scan.py --input example.com --ports 80,443
```

## ✨ Features

- 🌐 **Service discovery** — finds and analyzes web services across your targets
- 🔐 **SSL/TLS** — validates certs, checks expiry, extracts SANs
- 📸 **Screenshots** — high-quality captures of every service (Playwright/Chromium)
- 🔗 **Subdomain enum** — active + passive (cert-based)
- 🔍 **Path fuzzing** — discovers hidden paths/files with custom wordlists
- 🔑 **Default-cred testing** — with smart false-positive detection
- 📊 **Live HTML report** — interactive, sortable, screenshots embedded
- 🎯 **Reverse DNS** — auto for IP targets
- ⚡ **Threaded** — configurable concurrency + timeouts
- 🎨 **Colored CLI** — progress bars and live status

## 📖 Usage examples

### Basics

```bash
# Single target
python web_discovery_scan.py --input example.com --ports 80,443

# Multiple
python web_discovery_scan.py --input 192.168.1.1,192.168.1.2 --ports 80,443,8080

# Whole subnet
python web_discovery_scan.py --input 192.168.1.0/24 --ports 80,443

# From a file
python web_discovery_scan.py --input-file targets.txt --ports 80,443
```

### Full feature scan

```bash
python web_discovery_scan.py \
  --input example.com \
  --ports 80,443,8080,8443 \
  --enable-fuzzing \
  --creds-check \
  --threads 10 \
  --timeout 10
```

### Custom fuzzing wordlist

```bash
python web_discovery_scan.py \
  --input example.com \
  --enable-fuzzing \
  --fuzz-wordlist custom_paths.txt
```

### Faster — skip screenshots

```bash
python web_discovery_scan.py --input example.com --no-screenshots
```

## 🔧 CLI reference

### Input
- `--input` — single IP / hostname / CIDR
- `--input-file` — file with one target per line

### Ports
- `--ports` — comma-separated. Default: `80,443,8080,8000,8443,8888,81,82,7000,9443`

### Performance
- `--threads` — concurrent threads (default 30)
- `--timeout` — connect timeout in seconds (default 5)

### Feature flags
- `--enable-fuzzing` — turn on path fuzzing
- `--fuzz-wordlist` — custom wordlist
- `--creds-check` — default-credential testing
- `--creds-file` — custom `username:password` file
- `--subdomain-enum` / `--no-subdomain-enum` — control active subdomain enum (on by default)
- `--no-recursive` — don't recurse discovered subdomains

### Output
- `--output` — output dir (default `outputs`)
- `--no-screenshots` — disable screenshot capture
- `--no-html` — disable HTML report

## 📁 Output structure

```
outputs/
├── report.html          # interactive report
├── found_web.csv        # CSV export
└── screenshots/
    ├── target1_443_https.png
    ├── target2_80_http.png
    └── ...
```

## 📊 What's in the HTML report

- 📈 **Summary stats** — total services, HTTPS count, service types
- 🎯 **Target info** — original targets + discovered subdomains
- 🔑 **Credential findings** — default creds that worked
- 📋 **Sortable, searchable tables**
- 🖼️ **Screenshot gallery** — click to enlarge
- 📄 **Per-service detail** — headers, cookies, certs, discovered paths
- 🔍 **Collapsible sections** — keep things tidy

## 🔍 Default fuzzing wordlist covers

- 🛂 **Admin** — `/admin`, `/login`, `/auth`, `/management`
- 🌐 **API** — `/api`, `/api/v1`, `/api/v2`, `/rest`
- 📜 **Common files** — `/robots.txt`, `/sitemap.xml`, `/.env`
- 💾 **Backups** — `/backup`, `/bak`, `/old`
- 🧪 **Dev** — `/dev`, `/test`, `/staging`, `/debug`

## 🔑 Default-cred testing

Tests common combos (`admin:admin`, `admin:password`, `root:root`, `user:user`, `guest:guest`, …) using diffing between with/without-creds responses to suppress false positives.

## 🤝 Pairs well with

- 📚 **[AwesomeWL](https://github.com/osherassor/AwesomeWL)** — feed `web-application/Common_list.txt` to `--fuzz-wordlist`, and `subdomains/subdomains.txt` to your subdomain enum step. They're built for this.
- 🧰 **[MyCyberTool](https://github.com/osherassor/MyCyberTool)** — once selfit gives you a service URL, take it to MyCyberTool for headers / CORS / TLS / 403-bypass checks.
- 🧪 **[passive-pentest-profiler](https://github.com/osherassor/passive-pentest-profiler)** — open the discovered service in Chrome with the profiler installed for the passive deep-dive (cookies, JWTs, secrets in JS).

```bash
# Common combo
curl -sO https://raw.githubusercontent.com/osherassor/AwesomeWL/main/web-application/Common_list.txt
python web_discovery_scan.py --input example.com --enable-fuzzing --fuzz-wordlist Common_list.txt
```

## 🛠️ Requirements

- Python 3.8+
- Windows / macOS / Linux
- Playwright Chromium

## 🚨 Notes

- ⚖️ **Authorized targets only**
- 🐢 **Be respectful** — tune `--threads` / `--timeout` to the target's tolerance
- 🔓 **SSL errors are ignored** for scanning coverage
- 🐏 **Screenshots are RAM-hungry** — use `--no-screenshots` on big sweeps

## 📄 License

MIT

---

<p align="center"><sub>Made for the security community.</sub></p>
