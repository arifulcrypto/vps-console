import datetime as dt

from app.checks import assess, reach, routes
from app.checks.facts import parse_facts, parse_listeners, parse_versions

SAMPLE = """@@os
PRETTY_NAME="Ubuntu 20.04.6 LTS"
ID=ubuntu
VERSION_ID="20.04"
@@kernel
5.4.0-216-generic
x86_64
@@virt
kvm
@@container
none
@@cpu
2
 AMD EPYC 7551 32-Core Processor
@@mem
               total        used        free      shared  buff/cache   available
Mem:      4100000000  1000000000   500000000    10000000  2600000000  2900000000
Swap:     1610612736           0  1610612736
@@swap
/swapfile 1610612736 0
@@swappiness
60
@@disk
23000000000 10000000000 12000000000
@@uptime
86400.5
0.10 0.05 0.01
@@net
cubic
fq_codel
reno cubic bbr
@@ip
eth0 inet 203.0.113.10/24
docker0 inet 172.17.0.1/16
eth0 inet6 2001:db8::10/64
@@listen
tcp   LISTEN 0      4096   0.0.0.0:22   0.0.0.0:*    users:(("sshd",pid=1,fd=3))
tcp   LISTEN 0      4096         *:443        *:*    users:(("caddy",pid=2,fd=3))
tcp   LISTEN 0      4096   127.0.0.1:8080 0.0.0.0:*    users:(("app",pid=3,fd=3))
udp   UNCONN 0      0      0.0.0.0:8443 0.0.0.0:*    users:(("xray",pid=4,fd=3))
@@services
x-ui active enabled
nginx inactive not-found
ufw active enabled
@@versions
xray_xui=Xray 26.6.27 (Xray, Penetrates Everything.) 3e3f2c3 (go1.25 linux/amd64)
x-ui=v3.11.0
caddy=v2.9.1 h1:abc
snap=yes
@@legacy
/etc/caddy/233boy
/usr/local/x-ui
@@bootstatus
@@kvm
yes
"""


def test_parse_facts():
    f = parse_facts(SAMPLE)
    assert f["os"]["id"] == "ubuntu" and f["os"]["version_id"] == "20.04"
    assert f["cpu"]["count"] == 2
    assert f["mem"]["total"] == 4100000000
    assert f["swap"]["total"] == 1610612736
    assert f["disk"]["avail"] == 12000000000
    assert f["net"]["cc"] == "cubic" and "bbr" in f["net"]["available_cc"]
    assert f["ips"]["ipv4"] == ["203.0.113.10"]
    assert f["versions"]["xray"] == "26.6.27"
    assert f["versions"]["x-ui"] == "3.11.0"
    assert "nginx" not in f["services"]
    assert f["services"]["ufw"]["active"] == "active"


def test_listeners_public_flag():
    items = parse_listeners(SAMPLE.split("@@listen\n")[1].split("@@services")[0])
    by_port = {i["port"]: i for i in items}
    assert by_port[443]["process"] == "caddy" and by_port[443]["public"]
    assert not by_port[8080]["public"]
    assert by_port[8443]["proto"] == "udp"


def test_versions_ignore_missing():
    assert parse_versions("nginx=bash: nginx: command not found") == {}


def test_assess_findings():
    f = parse_facts(SAMPLE)
    codes = {x["code"]: x for x in assess.assess(f, today=dt.date(2026, 11, 3))}
    assert codes["os_ended"]["level"] == "bad"
    assert codes["lxd_possible"]["params"]["containers"] >= 1
    assert "bbr_off" in codes
    assert codes["port_https_busy"]["params"]["process"] == "caddy"
    assert codes["version_old"]["params"]["name"] == "xray"
    assert codes["version_tested"]["params"]["name"] == "x-ui"
    assert "firewall_active" in codes
    assert "swappiness_high" in codes
    assert assess.score(list(codes.values())) == "bad"


def test_os_status_best_and_unknown():
    best = assess.os_status({"id": "debian", "version_id": "13", "pretty_name": "Debian 13"}, dt.date(2026, 11, 3))
    assert best["code"] == "os_best"
    other = assess.os_status({"id": "alpine", "version_id": "3.20", "pretty_name": "Alpine"})
    assert other["code"] == "os_unknown"


def test_lxd_refused_in_container():
    f = parse_facts(SAMPLE)
    f["virt"] = "openvz"
    assert assess.lxd_plan(f)["possible"] is False


MTR = """Start: 2026-11-03T10:00:00+0000
HOST: vps                          Loss%   Snt   Last   Avg  Best  Wrst StDev
  1. AS???    10.0.0.1              0.0%     3    0.5   0.5   0.4   0.6   0.1
  2. AS2914   129.250.2.1           0.0%     3    1.0   1.2   1.0   1.5   0.2
  3. AS4809   59.43.246.1           0.0%     3   40.1  40.0  39.9  40.2   0.1
  4. AS???    ???                  100.0%    3    0.0   0.0   0.0   0.0   0.0
  5. AS4812   202.96.209.133        0.0%     3   45.0  45.1  44.9  45.3   0.2
"""


def test_mtr_parse_and_classify():
    hops = routes.parse_mtr(MTR)
    assert len(hops) == 5
    assert hops[3]["ip"] == "" and hops[3]["rtt"] is None
    c = routes.classify(hops, "telecom", "JP")
    assert c["line"] == "CN2 GIA" and c["premium"] is True
    assert c["rtt"] == 45.1 and not c["detour"]
    assert "NTT" in c["transit"]


def test_classify_gt_and_detour():
    hops = [{"n": 1, "asn": "", "ip": "202.97.1.1", "loss": 0, "rtt": 180.0},
            {"n": 2, "asn": "", "ip": "59.43.1.1", "loss": 0, "rtt": 190.0}]
    c = routes.classify(hops, "telecom", "HK")
    assert c["line"] == "CN2 GT"
    assert c["detour"] is True


def test_traceroute_parse():
    text = " 1  10.0.0.1  0.345 ms\n 2  *\n 3  219.158.1.1  60.1 ms\n"
    hops = routes.parse_traceroute(text)
    assert [h["ip"] for h in hops] == ["10.0.0.1", "", "219.158.1.1"]
    assert routes.classify(hops, "unicom")["line"] == "CU 4837"


def _abroad(ports, icmp=True):
    return {"icmp": {"ok": icmp}, "ports": ports}


def test_reach_verdicts():
    abroad = _abroad({"22": 10.0, "443": 12.0})
    assert reach.classify(_abroad({"22": None}, False), None)["verdict"] == "down"
    assert reach.classify(abroad, None)["verdict"] == "no_china_data"
    blocked = {"icmp": {"ok": False}, "ports": {"22": None, "443": None}, "tls": {}}
    assert reach.classify(abroad, blocked)["verdict"] == "ip_blocked"
    port = {"icmp": {"ok": True}, "ports": {"22": 50.0, "443": None}, "tls": {}}
    v = reach.classify(abroad, port)
    assert v["verdict"] == "port_blocked" and v["ports"] == ["443"]
    tls = {"icmp": {"ok": True}, "ports": {"22": 50.0, "443": 55.0}, "tls": {"443": "reset"}}
    assert reach.classify(abroad, tls, {"443": "ok"})["verdict"] == "tls_interference"
    assert reach.classify(abroad, tls, {"443": "fail"})["verdict"] == "reachable"


def test_probe_output_parse():
    out = ("PING\n4 packets transmitted, 4 received, 0% packet loss, time 3004ms\n"
           "rtt min/avg/max/mdev = 160.1/161.5/163.0/1.1 ms\nTCP 22 open 162\nTCP 443 fail 4001\nTLS 443 reset\n")
    r = reach.parse_probe(out)
    assert r["icmp"]["ok"] and r["icmp"]["avg"] == 161.5
    assert r["ports"] == {"22": 162.0, "443": None}
    assert r["tls"] == {"443": "reset"}


def test_probe_script_quotes_sni():
    script = reach.probe_script("203.0.113.10", [443], {443: "a.example.com"})
    assert "/dev/tcp/203.0.113.10/443" in script
    assert "-servername a.example.com" in script


def test_manual_links():
    links = reach.manual_links("203.0.113.10", [22, 443])
    urls = [x["url"] for x in links]
    assert "https://www.itdog.cn/tcping/203.0.113.10:443" in urls
    assert any(u.startswith("https://tcp.ping.pe/") for u in urls)


def test_virt_first_line_and_bbr_module():
    text = SAMPLE.replace("@@container\nnone\n", "@@container\nnone\n") + "@@bbrmod\n/lib/modules/5.4/tcp_bbr.ko\n"
    f = parse_facts(text)
    assert f["virt"] == "kvm" and f["container"] == "none"
    assert assess.lxd_plan(f)["possible"] is True
    f["net"]["available_cc"] = ["reno", "cubic"]
    codes = {x["code"] for x in assess.assess(f, today=dt.date(2026, 11, 3))}
    assert "bbr_off" in codes and "bbr_missing" not in codes


def test_closed_ports_are_not_blocks():
    abroad = _abroad({"22": 10.0, "443": None})
    china = {"icmp": {"ok": True}, "ports": {"22": 40.0, "443": None}, "tls": {}}
    v = reach.classify(abroad, china)
    assert v["verdict"] == "reachable" and v["closed"] == ["443"]


def test_tls_check_ignores_failed_handshake():
    script = reach.probe_script("203.0.113.10", [22], {22: ""})
    assert "Cipher is [A-Z]" in script and "Protocol version" not in script


def test_exposed_services_and_docker_ufw():
    f = parse_facts(SAMPLE)
    f["listeners"].append({"proto": "tcp", "addr": "0.0.0.0", "port": 6379, "process": "docker-proxy", "public": True})
    f["listeners"].append({"proto": "tcp", "addr": "127.0.0.1", "port": 3306, "process": "mysqld", "public": False})
    found = assess.assess(f, today=dt.date(2026, 11, 3))
    exposed = [x for x in found if x["code"] == "exposed_service"]
    assert [x["params"]["port"] for x in exposed] == [6379]
    assert any(x["code"] == "docker_bypasses_ufw" for x in found)
