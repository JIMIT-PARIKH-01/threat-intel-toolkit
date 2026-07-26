# Threat Intel Toolkit

[![CI](https://github.com/JIMIT-PARIKH-01/threat-intel-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/JIMIT-PARIKH-01/threat-intel-toolkit/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.8%2B-blue) ![License](https://img.shields.io/badge/license-MIT-green)

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

## ⬇️ Download & Install

**This is a public tool — download and use it on your device for free.**

```bash
# 1) Clone it
git clone https://github.com/JIMIT-PARIKH-01/threat-intel-toolkit.git
cd threat-intel-toolkit

# 2) ...or download a ZIP (no git needed)
#    https://github.com/JIMIT-PARIKH-01/threat-intel-toolkit/archive/refs/heads/main.zip

# 3) ...or install the command straight from GitHub
pip install git+https://github.com/JIMIT-PARIKH-01/threat-intel-toolkit.git
```

Then run it as shown in the usage section above (CLI `python -m ...`, or launch
the GUI via `run.bat`).

<details>
<summary><b>🔒 Requesting access to a private tool</b></summary>

Public tools install with the commands above. If a tool is **private**, access
is granted by the owner through GitHub — a static link cannot unlock private
code, only GitHub can:

1. **Request access** — open an [access request](https://github.com/JIMIT-PARIKH-01/JIMIT-PARIKH-01/issues/new?template=tool-access-request.md&title=Access+request:+threat-intel-toolkit) or message on
   [LinkedIn](https://www.linkedin.com/in/jimit-devangkumar-parikh/).
2. The owner reviews it and, if approved, **adds you as a collaborator** on the
   private repository.
3. GitHub then lets you clone / download it with your own account. Access is
   revoked the moment the owner removes you as a collaborator.

</details>

