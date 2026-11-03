import asyncio
import time

from conftest import csrf_of

VLESS = ("vless://11111111-2222-3333-4444-555555555555@203.0.113.10:443?encryption=none&flow=xtls-rprx-vision"
         "&security=reality&sni=addons.mozilla.org&fp=chrome&pbk=PUBKEY&sid=ab12&type=tcp#JP")


def test_health_and_headers(client):
    r = client.get("/healthz")
    assert r.json() == {"ok": True, "version": "testsha"}
    home = client.get("/")
    assert home.status_code == 200
    assert "default-src 'self'" in home.headers["content-security-policy"]
    assert home.headers["x-frame-options"] == "DENY"


def test_tools_need_login(client):
    for path in ("/check", "/generate", "/convert", "/history", "/admin", "/account"):
        r = client.get(path, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"].startswith("/login"), path


def test_login_rejects_bad_password_and_csrf(client):
    page = client.get("/login")
    r = client.post("/login", data={"username": "admin", "password": "nope", "csrf": csrf_of(page.text)})
    assert r.status_code == 401
    r = client.post("/login", data={"username": "admin", "password": "nope", "csrf": "forged"})
    assert r.status_code == 403


def test_open_redirect_blocked(client):
    page = client.get("/login")
    from conftest import ADMIN_PASSWORD

    r = client.post("/login", data={"username": "admin", "password": ADMIN_PASSWORD, "next": "//evil.example",
                                    "csrf": csrf_of(page.text)}, follow_redirects=False)
    assert r.headers["location"] == "/"


def test_pages_render_in_both_languages(admin):
    for lang in ("en", "zh"):
        admin.get(f"/lang/{lang}")
        for path in ("/", "/check", "/generate", "/convert", "/history", "/admin", "/account"):
            r = admin.get(path)
            assert r.status_code == 200, (lang, path)
            assert "{{" not in r.text
    assert "检测服务器" in admin.get("/check").text


def test_check_validation_errors(admin):
    page = admin.get("/check")
    r = admin.post("/check", data={"csrf": csrf_of(page.text), "host": "10.0.0.1", "password": "x"})
    assert r.status_code == 400
    r = admin.post("/check", data={"csrf": csrf_of(page.text), "host": "203.0.113.10"})
    assert r.status_code == 400


def test_generate_flow(admin):
    page = admin.get("/generate")
    r = admin.post("/generate", data={"csrf": csrf_of(page.text), "ip": "203.0.113.10", "preset": "fast",
                                      "save_location": "skill_default", "ssh_pass": "hunter2"})
    assert r.status_code == 200
    assert "vps_deployer.py --config" in r.text and "hunter2" not in r.text
    hist = admin.get("/history").text
    assert "fast · 203.0.113.10" in hist
    r = admin.post("/generate", data={"csrf": csrf_of(page.text), "ip": "203.0.113.10", "preset": "complete"})
    assert r.status_code == 400


def test_convert_and_subscription(admin):
    page = admin.get("/convert")
    r = admin.post("/convert", data={"csrf": csrf_of(page.text), "links": VLESS, "target": "mihomo",
                                     "dedupe": "1", "china_direct": "1", "ai_group": "1", "mlkem": "1",
                                     "publish": "1", "title": "Test"})
    assert r.status_code == 200
    assert "support-x25519mlkem768: true" in r.text
    import re

    url = re.search(r"https://tools\.example\.com/s/([A-Za-z0-9_-]+)", r.text)
    assert url
    admin.cookies.clear()
    sub = admin.get(f"/s/{url.group(1)}")
    assert sub.status_code == 200 and "proxies:" in sub.text
    b64 = admin.get(f"/s/{url.group(1)}?format=base64")
    assert b64.status_code == 200
    assert admin.get("/s/notatoken").status_code == 404


def test_convert_empty(admin):
    page = admin.get("/convert")
    r = admin.post("/convert", data={"csrf": csrf_of(page.text), "links": "nothing here"})
    assert r.status_code == 400


def test_probe_secret_never_rendered(admin, app):
    box = app.state.box
    asyncio.run(app.state.db.execute(
        "INSERT INTO probes (name, region, host, port, username, auth_type, secret_enc, host_key, enabled, "
        "secret_set_at, created_at) VALUES (?,?,?,?,?,?,?,?,1,?,?)",
        ("CN", "Guangzhou", "203.0.113.50", 22, "root", "password", box.encrypt("rootsecret-xyz"), "", time.time(),
         time.time())))
    page = admin.get("/admin").text
    assert "rootsecret-xyz" not in page
    assert "203.0.113.50" in page
    stored = asyncio.run(app.state.db.fetchone("SELECT secret_enc FROM probes"))
    assert "rootsecret-xyz" not in stored["secret_enc"]


def test_job_page_renders_result(admin, app):
    result = {
        "mode": "quick", "ip": "203.0.113.10", "ssh": {"ok": False, "code": "auth_failed"},
        "ipinfo": {"ok": True, "ip": "203.0.113.10", "city": "Tokyo", "region": "Tokyo", "country": "Japan",
                   "asn": "AS1", "isp": "X", "org": "X", "kind": "datacenter"},
        "reach": {"verdict": "port_blocked", "ports": ["443"], "ports_tested": [22, 443], "probe_error": "",
                  "abroad": {"icmp": {"ok": True, "avg": 10.0}, "ports": {"22": 5.0, "443": 6.0},
                             "tls": {"443": "ok"}},
                  "china": {"icmp": {"ok": True, "avg": 60.0}, "ports": {"22": 50.0, "443": None},
                            "tls": {"443": "fail"}, "source": "probe"},
                  "globalping": None},
        "links": [{"name": "ITDOG ping", "url": "https://www.itdog.cn/ping/203.0.113.10"}],
        "routes": [{"city": "Shanghai", "carrier": "telecom", "line": "CN2 GIA", "premium": True, "rtt": 40.0,
                    "detour": False, "transit": [], "hops": []}],
        "duration_s": 3.2,
    }

    async def seed():
        await app.state.db.create_job("job1", "check", "quick", "203.0.113.10", {"ssh_port": "22"})
        await app.state.db.update_job("job1", status="done", result=result)

    asyncio.run(seed())
    page = admin.get("/jobs/job1")
    assert page.status_code == 200
    assert "CN2 GIA" in page.text and "443" in page.text
    md = admin.get("/jobs/job1/report.md")
    assert "port_blocked" in md.text
    gen = admin.get("/generate?job=job1")
    assert 'value="203.0.113.10"' in gen.text
