"""
Phishing URL detector (heuristic; standard library only).

Scores a URL for common phishing indicators (raw IPs, credential tricks,
look-alike keywords, suspicious TLDs, homographs, shorteners) and returns a
risk level with reasons. Fully offline -- no request is sent to the URL.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field

# Action/credential words that are suspicious *in a hostname* (brand names are
# handled separately by KNOWN_BRANDS + the impersonation checks, so a legitimate
# brand domain isn't penalised just for containing its own name).
CREDENTIAL_WORDS = {"login", "signin", "verify", "secure", "account", "update",
                    "confirm", "password", "passwd", "banking", "webscr", "wallet",
                    "support", "recover", "unlock", "auth", "session", "billing"}
SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click",
                   "link", "zip", "country", "kim", "loan", "download"}
SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
              "buff.ly", "rebrand.ly", "cutt.ly", "rb.gy"}
KNOWN_BRANDS = {"paypal", "google", "apple", "microsoft", "amazon", "facebook",
                "instagram", "netflix", "whatsapp", "linkedin", "github", "dropbox",
                "chase", "wellsfargo", "coinbase", "binance", "outlook", "icloud",
                "gmail", "yahoo", "bankofamerica", "citibank", "americanexpress"}
# leet -> letter, so "g00gle"/"paypa1" normalise back to the real brand
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s"})


@dataclass
class PhishResult:
    url: str
    score: int = 0
    risk: str = "low"
    reasons: list = field(default_factory=list)

    def as_text(self) -> str:
        lines = [f"URL   : {self.url}",
                 f"Risk  : {self.risk.upper()} (score {self.score})"]
        if self.reasons:
            lines.append("Indicators:")
            for r in self.reasons:
                lines.append(f"  - {r}")
        else:
            lines.append("No phishing indicators found.")
        return "\n".join(lines)


def analyze(url: str) -> PhishResult:
    raw = url.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "http://" + raw
    parts = urllib.parse.urlsplit(raw)
    host = (parts.hostname or "").lower()
    labels = host.split(".") if host else []
    res = PhishResult(url=url)

    def add(points: int, reason: str) -> None:
        res.score += points
        res.reasons.append(reason)

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        add(3, "uses a raw IP address instead of a domain")
    if "@" in parts.netloc:
        add(3, "'@' in the authority (credential-obfuscation trick)")
    if "xn--" in host:
        add(2, "punycode/IDN homograph (xn--) — possible look-alike domain")
    if len(labels) >= 4:
        add(1, f"many subdomains ({len(labels)} labels)")
    if len(host) > 40:
        add(1, "unusually long hostname")
    keyword_hits = sorted(w for w in CREDENTIAL_WORDS if w in host)
    if keyword_hits:
        add(2, "credential/action keywords in host: " + ", ".join(keyword_hits))
    tld = labels[-1] if labels else ""
    if tld in SUSPICIOUS_TLDS:
        add(2, f"suspicious TLD .{tld}")
    if host in SHORTENERS:
        add(1, "URL shortener (hides the real destination)")
    if host.count("-") >= 3:
        add(1, "many hyphens in the hostname")
    domain = labels[-2] if len(labels) >= 2 else host
    if sum(c.isdigit() for c in domain) >= 4:
        add(1, "many digits in the registrable domain")
    if parts.scheme == "http" and keyword_hits:
        add(2, "credential-related page served over plain HTTP")

    # --- brand impersonation: a known brand used outside its real domain ---
    registrable_main = labels[-2] if len(labels) >= 2 else host
    for brand in KNOWN_BRANDS:
        if brand in labels and registrable_main != brand:
            add(4, f"brand '{brand}' used as a subdomain of a different domain (impersonation)")
            break
        if brand in registrable_main and registrable_main != brand:
            add(2, f"registrable domain looks like a look-alike of '{brand}'")
            break

    # --- typosquat via leet substitution (g00gle -> google) ---
    scan_labels = labels[:-1] if len(labels) > 1 else labels
    for lbl in scan_labels:
        if any(c.isdigit() for c in lbl):
            norm = lbl.translate(_LEET)
            if norm != lbl and norm in KNOWN_BRANDS:
                add(3, f"possible typosquat of '{norm}' (looks like '{lbl}')")
                break

    res.risk = "high" if res.score >= 5 else "medium" if res.score >= 3 else "low"
    return res
