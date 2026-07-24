"""
VirusTotal reputation checker (standard library only).

Looks up a file hash, URL, IP, or domain against the VirusTotal API v3 and
summarises the analysis verdicts. Requires a free API key:

    set VT_API_KEY=your_key        (Windows)   or pass key=...

Read-only lookups of indicators you're authorized to investigate.
"""

from __future__ import annotations

import base64
import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field

API = "https://www.virustotal.com/api/v3"


@dataclass
class VTResult:
    indicator: str
    kind: str
    stats: dict = field(default_factory=dict)     # malicious/suspicious/harmless/...
    extra: dict = field(default_factory=dict)

    @property
    def malicious(self) -> int:
        return int(self.stats.get("malicious", 0))

    def as_text(self) -> str:
        lines = [f"Indicator : {self.indicator}  ({self.kind})"]
        if self.stats:
            total = sum(self.stats.values())
            lines.append(f"Verdicts  : {self.malicious}/{total} engines flagged it malicious")
            lines.append("  " + ", ".join(f"{k}={v}" for k, v in self.stats.items()))
        for k, v in self.extra.items():
            lines.append(f"  {k}: {v}")
        verdict = ("MALICIOUS" if self.malicious >= 3 else
                   "suspicious" if self.malicious >= 1 else "clean")
        lines.append(f"Assessment: {verdict}")
        return "\n".join(lines)


def _api_key(key: str | None) -> str:
    key = key or os.environ.get("VT_API_KEY")
    if not key:
        raise ValueError("No VirusTotal API key. Set VT_API_KEY env var or pass key=...")
    return key


def _get(endpoint: str, key: str, timeout: float = 20.0) -> dict:
    req = urllib.request.Request(API + endpoint, headers={"x-apikey": key})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise ValueError("indicator not found in VirusTotal") from exc
        if exc.code == 401:
            raise ValueError("VirusTotal rejected the API key (401)") from exc
        raise ConnectionError(f"VirusTotal HTTP {exc.code}") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise ConnectionError(f"VirusTotal request failed: {exc}") from exc


def _kind(indicator: str) -> str:
    s = indicator.strip()
    if re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", s):
        return "hash"
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s):
        return "ip"
    if s.startswith(("http://", "https://")):
        return "url"
    return "domain"


def check(indicator: str, key: str | None = None) -> VTResult:
    api_key = _api_key(key)
    kind = _kind(indicator)
    if kind == "hash":
        endpoint = f"/files/{indicator}"
    elif kind == "ip":
        endpoint = f"/ip_addresses/{indicator}"
    elif kind == "url":
        url_id = base64.urlsafe_b64encode(indicator.encode()).rstrip(b"=").decode()
        endpoint = f"/urls/{url_id}"
    else:
        endpoint = f"/domains/{indicator}"

    data = _get(endpoint, api_key).get("data", {}).get("attributes", {})
    stats = data.get("last_analysis_stats", {})
    extra = {}
    for field_name in ("meaningful_name", "type_description", "as_owner", "country",
                       "reputation"):
        if field_name in data:
            extra[field_name] = data[field_name]
    return VTResult(indicator=indicator, kind=kind, stats=stats, extra=extra)
