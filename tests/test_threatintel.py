"""Offline tests for the Threat Intel Toolkit."""

import pytest

from threatintel import phishing, vt_check


def test_phishing_high_risk():
    r = phishing.analyze("http://paypal-verify-login.tk/account@192.168.0.1")
    assert r.risk == "high" and r.score >= 5
    assert r.reasons


def test_phishing_clean_low_risk():
    r = phishing.analyze("https://github.com")
    assert r.risk == "low" and r.score == 0


def test_phishing_flags_at_symbol():
    r = phishing.analyze("http://good.com@evil.com/")
    assert any("@" in reason for reason in r.reasons)


def test_phishing_brand_impersonation_subdomain():
    r = phishing.analyze("http://www.paypal.com.secure-login.tk/verify")
    assert r.risk == "high"
    assert any("impersonation" in reason for reason in r.reasons)


def test_phishing_typosquat_leet():
    r = phishing.analyze("https://g00gle.com/login")
    assert any("typosquat" in reason for reason in r.reasons)


def test_phishing_legit_brand_is_low_risk():
    # accuracy fix: a real brand on its OWN domain must not be false-flagged
    r = phishing.analyze("https://www.paypal.com/account")
    assert r.risk == "low"
    assert not any("impersonation" in reason for reason in r.reasons)


def test_vt_indicator_routing():
    assert vt_check._kind("44d88612fea8a8f36de82e1278abb02f") == "hash"
    assert vt_check._kind("8.8.8.8") == "ip"
    assert vt_check._kind("https://example.com") == "url"
    assert vt_check._kind("example.com") == "domain"


def test_vt_requires_key(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    with pytest.raises(ValueError):
        vt_check.check("example.com", key=None)
