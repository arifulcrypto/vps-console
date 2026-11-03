import json
import re
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from app import validation as v
from app.checks import assess
from app.security import LoginThrottle, SecretBox, hash_password, mask, verify_password

ROOT = Path(__file__).resolve().parent.parent / "app"


def test_password_hash():
    h = hash_password("s3cret-pass")
    assert h.startswith("scrypt$") and "s3cret" not in h
    assert verify_password("s3cret-pass", h)
    assert not verify_password("wrong", h)
    assert not verify_password("x", "garbage")


def test_secret_box():
    box = SecretBox(Fernet.generate_key().decode())
    token = box.encrypt("rootpw")
    assert "rootpw" not in token and box.decrypt(token) == "rootpw"
    with pytest.raises(ValueError):
        SecretBox(Fernet.generate_key().decode()).decrypt(token)


def test_throttle():
    t = LoginThrottle(limit=2, window=60)
    t.fail("a")
    assert not t.blocked("a")
    t.fail("a")
    assert t.blocked("a") and not t.blocked("b")
    t.reset("a")
    assert not t.blocked("a")


def test_mask():
    assert mask("abcdefghij") == "…hij"


def test_validation():
    assert v.host("203.0.113.10") == "203.0.113.10"
    assert v.host("Node.Example.com.") == "node.example.com"
    for bad in ("10.0.0.1", "127.0.0.1", "a;b", "$(id)", "x"):
        with pytest.raises(v.InvalidInput):
            v.host(bad)
    assert v.ports("22, 443 443") == [22, 443]
    with pytest.raises(v.InvalidInput):
        v.ports("70000")
    with pytest.raises(v.InvalidInput):
        v.username("root;rm")
    with pytest.raises(v.InvalidInput):
        v.path("/tmp/$(x)")


def _catalog(lang):
    return json.loads((ROOT / "locales" / f"{lang}.json").read_text(encoding="utf-8"))


def test_catalogs_match():
    en, zh = _catalog("en"), _catalog("zh")
    assert set(en) == set(zh)
    for key in en:
        assert set(re.findall(r"\{(\w+)\}", en[key])) == set(re.findall(r"\{(\w+)\}", zh[key])), key


def test_template_keys_exist():
    en = _catalog("en")
    missing = set()
    for tpl in (ROOT / "templates").rglob("*.html"):
        for key in re.findall(r"t\('([a-z0-9_.]+)'", tpl.read_text(encoding="utf-8")):
            if not key.endswith(".") and not key.endswith("_") and key not in en:
                missing.add(f"{tpl.name}:{key}")
    assert not missing, sorted(missing)


def test_dynamic_keys_exist():
    en = _catalog("en")
    source = (ROOT / "checks" / "assess.py").read_text()
    codes = set(re.findall(r'finding\("\w+", "(\w+)"', source))
    codes |= {f"port_{p}_busy" for p in assess.SKILL_PORTS.values()}
    codes.discard("port_{purpose}_busy")
    assert codes, "no finding codes found"
    for code in codes:
        assert f"f.{code}" in en, code
    groups = {
        "verdict": ["down", "no_china_data", "ip_blocked", "port_blocked", "tls_interference", "reachable"],
        "progress": ["start", "ssh", "facts", "routes", "reach", "forward_route", "globalping", "cloudflare",
                     "proxies"],
        "ssh": ["no_credentials", "bad_key", "auth_failed", "timeout", "refused", "connect_failed",
                "host_key_changed", "key_install_failed"],
        "kind": ["mobile", "datacenter", "proxy_flagged", "isp"],
        "preset": ["fast", "complete", "stealth443", "visiontls", "residential"],
        "save": ["skill_default", "lxd_info", "custom"],
    }
    for prefix, names in groups.items():
        for name in names:
            assert f"{prefix}.{name}" in en, f"{prefix}.{name}"
