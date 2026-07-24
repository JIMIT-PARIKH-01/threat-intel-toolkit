# Threat Intel Toolkit

Defensive threat-intelligence tools — **dependency-free**, GUI + CLI.

1. **Phishing URL detector** — scores a URL for phishing indicators (raw IPs, `@` tricks,
   look-alike keywords, suspicious TLDs, homographs, shorteners). **Fully offline** — never
   contacts the URL.
2. **VirusTotal checker** — reputation lookup for a file hash / URL / IP / domain via the
   VirusTotal API v3 (summarises engine verdicts). Needs a free API key.

Standard library only (`urllib`, `json`, `base64`, `re`). Python 3.8+.

## VirusTotal key
```powershell
setx VT_API_KEY "your_free_key_from_virustotal.com"
```
(or pass `--key` on the CLI / paste it in the GUI).

## Run
```powershell
python threatintel/gui.py                 # GUI (tabs: Phishing / VirusTotal), or run.bat

python -m threatintel phish "http://paypal-verify.tk/login@evil"
python -m threatintel vt    44d88612fea8a8f36de82e1278abb02f
python -m threatintel vt    8.8.8.8 --key YOUR_KEY
```

## Layout
```
threat-intel-toolkit/
└── threatintel/
    ├── phishing.py   # offline heuristic URL scorer
    ├── vt_check.py   # VirusTotal API v3 lookups
    ├── cli.py  gui.py  run.bat
```

MIT — see [LICENSE](./LICENSE).
