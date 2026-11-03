"""Build ready-to-paste prompts and config files for the two skills.

The site never deploys. It fills in the skill's inputs from the form and the
latest check, then hands the operator a prompt plus a JSON config for:
- vps-deploy-skill  scripts/vps_deployer.py --config <file>
- vps-lxc-skill     scripts/vps_lxc.py --config <file>

Secrets stay out (env vars or placeholders) unless the operator ticks
"include secrets", because prompts get pasted into chat tools and logs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

DEPLOY_REPO = "https://github.com/arifulcrypto/vps-deploy-skill"
LXC_REPO = "https://github.com/arifulcrypto/vps-lxc-skill"

PRESETS = {
    "fast": {"profile": "unified", "enable_hy2": True, "needs_domain": False},
    "complete": {"profile": "unified", "enable_hy2": True, "needs_domain": True, "cdn_transport": "ws"},
    "stealth443": {"profile": "reality-self", "enable_hy2": True, "needs_domain": True, "cdn_transport": "both"},
    "visiontls": {"profile": "vision-tls", "enable_hy2": False, "needs_domain": True},
    "residential": {"profile": "unified", "enable_hy2": False, "needs_domain": False, "exit_all": True},
}

SAVE_LOCATIONS = {
    "skill_default": "./output/{ip}/",
    "lxd_info": "/root/02project/01LXD_vps_info/{ip}/",
    "custom": "{custom}",
}


@dataclass
class PlanInput:
    ip: str
    ssh_port: int = 22
    ssh_user: str = "root"
    ssh_auth: str = "password"  # password | key
    ssh_key_path: str = ""
    preset: str = "fast"
    domain: str = ""
    cdn_domain: str = ""
    manage_dns: bool = False
    cert_mode: str = "http-01"
    client_isp: str = "unicom"
    extra_protocols: list[str] = field(default_factory=list)
    exit_proxy: str = ""  # host:port; credentials come from secrets or stay placeholders
    exit_protocol: str = "socks"
    panel_private: bool = False
    lang: str = "en"
    save_location: str = "skill_default"
    custom_path: str = ""
    use_lxc: bool = False
    lxc_count: int = 2
    lxc_memory_mb: int = 1024
    lxc_disk_gb: int = 10
    traffic_limit_gb: int = 0
    traffic_reset_day: int = 1
    include_secrets: bool = False
    secrets: dict = field(default_factory=dict, repr=False)


def output_dir(plan: PlanInput) -> str:
    if plan.save_location == "custom" and plan.custom_path:
        return plan.custom_path.replace("{ip}", plan.ip)
    template = SAVE_LOCATIONS.get(plan.save_location, SAVE_LOCATIONS["skill_default"])
    if "{custom}" in template:
        template = SAVE_LOCATIONS["skill_default"]
    return template.format(ip=plan.ip)


def _secret(plan: PlanInput, key: str, env: str) -> str | None:
    """The real value when the operator opted in, otherwise a placeholder.

    ssh_pass and cf_token return None instead: both skills read them from
    VPS_SSH_PASS and CF_TOKEN, so they can stay out of the file entirely.
    """
    if plan.include_secrets and plan.secrets.get(key):
        return plan.secrets[key]
    if key in ENV_BACKED:
        return None
    return f"<{env}>"


ENV_BACKED = {"ssh_pass", "cf_token"}


def _put(cfg: dict, key: str, value) -> None:
    if value is not None:
        cfg[key] = value


def deploy_config(plan: PlanInput) -> dict:
    preset = PRESETS.get(plan.preset, PRESETS["fast"])
    cfg: dict = {"ip": plan.ip, "ssh_port": plan.ssh_port, "ssh_user": plan.ssh_user,
                 "profile": preset["profile"], "enable_hy2": preset["enable_hy2"]}
    if plan.ssh_auth == "key":
        cfg["ssh_key"] = plan.ssh_key_path or "~/.ssh/id_ed25519"
    else:
        _put(cfg, "ssh_pass", _secret(plan, "ssh_pass", "VPS_SSH_PASS"))
    if plan.domain:
        cfg["domain"] = plan.domain
        if preset.get("cdn_transport"):
            cfg["cdn_transport"] = preset["cdn_transport"]
    if plan.cdn_domain and preset["profile"] == "reality-self":
        cfg["cdn_domain"] = plan.cdn_domain
    if plan.cert_mode == "dns-01" or plan.manage_dns:
        _put(cfg, "cf_token", _secret(plan, "cf_token", "CF_TOKEN"))
    if plan.cert_mode == "dns-01":
        cfg["cert_mode"] = "dns-01"
    if plan.manage_dns:
        cfg["manage_dns"] = True
    if plan.client_isp:
        cfg["client_isp"] = plan.client_isp
    if plan.extra_protocols:
        cfg["extra_protocols"] = plan.extra_protocols
    if plan.exit_proxy:
        host, _, port = plan.exit_proxy.rpartition(":")
        cfg["exit_proxy"] = {
            "server": host, "port": int(port or 0), "protocol": plan.exit_protocol,
            "username": _secret(plan, "exit_user", "EXIT_PROXY_USER"),
            "password": _secret(plan, "exit_pass", "EXIT_PROXY_PASS"),
        }
        if preset.get("exit_all"):
            cfg["exit_all"] = True
    if plan.panel_private:
        cfg["panel_private"] = True
    cfg["output_dir"] = output_dir(plan)
    cfg["lang"] = plan.lang
    return cfg


def lxc_config(plan: PlanInput) -> dict:
    cfg = {"ip": plan.ip, "ssh_port": plan.ssh_port, "ssh_user": plan.ssh_user,
           "count": plan.lxc_count, "memory": plan.lxc_memory_mb, "disk": plan.lxc_disk_gb,
           "output_dir": f"/root/02project/01LXD_vps_info/{plan.ip}/"}
    if plan.ssh_auth == "key":
        cfg["ssh_key"] = plan.ssh_key_path or "~/.ssh/id_ed25519"
    else:
        _put(cfg, "ssh_pass", _secret(plan, "ssh_pass", "VPS_SSH_PASS"))
    if plan.traffic_limit_gb:
        cfg["traffic_limit_gb"] = plan.traffic_limit_gb
        cfg["traffic_reset_day"] = plan.traffic_reset_day
    return cfg


def _fact_lines(check: dict | None) -> list[str]:
    if not check:
        return ["- No pre-check was run. Run `--dry-run` first and read its warnings."]
    facts = check.get("facts", {})
    lines = []
    if facts:
        os_name = facts.get("os", {}).get("pretty_name", "?")
        mem = facts.get("mem", {}).get("total", 0) / 1024**3
        disk = facts.get("disk", {}).get("avail", 0) / 1024**3
        lines.append(f"- System: {os_name}, kernel {facts.get('kernel', '?')}, {facts.get('virt', '?')}, "
                     f"{facts.get('cpu', {}).get('count', '?')} vCPU, {mem:.1f} GB RAM, {disk:.0f} GB disk free")
        busy = list(dict.fromkeys(f"{i['port']}/{i['proto']} ({i['process'] or '?'})"
                                  for i in facts.get("listeners", []) if i["public"]))
        if busy:
            lines.append("- Public ports already in use: " + ", ".join(busy[:20]))
        if facts.get("versions"):
            lines.append("- Installed: " + ", ".join(f"{k} {v}" for k, v in facts["versions"].items()))
    for f in check.get("findings", []):
        if f["level"] in ("warn", "bad"):
            params = ", ".join(f"{k}={v}" for k, v in f.get("params", {}).items())
            lines.append(f"- {f['level'].upper()} {f['code']}" + (f" ({params})" if params else ""))
    reach = check.get("reach", {}).get("verdict")
    if reach:
        lines.append(f"- China reachability: {reach}")
    for r in check.get("routes", [])[:9]:
        lines.append(f"- Return route {r.get('city')} {r.get('carrier')}: {r.get('line')}"
                     + (f", {r['rtt']:.0f} ms" if r.get("rtt") else ""))
    return lines or ["- Pre-check found nothing to flag."]


def build_prompt(plan: PlanInput, check: dict | None = None, config_name: str = "") -> str:
    cfg = deploy_config(plan)
    name = config_name or f"deploy_{plan.ip.replace('.', '_').replace(':', '_')}.json"
    out_dir = output_dir(plan)
    env_lines = []
    if plan.ssh_auth == "password" and "ssh_pass" not in cfg:
        env_lines.append("export VPS_SSH_PASS='<root password>'")
    if (plan.cert_mode == "dns-01" or plan.manage_dns) and "cf_token" not in cfg:
        env_lines.append("export CF_TOKEN='<Cloudflare token with Zone:DNS:Edit on this zone>'")
    placeholders = "exit_proxy" in cfg and str(cfg["exit_proxy"].get("password", "")).startswith("<")
    parts = [
        f"Use vps-deploy-skill ({DEPLOY_REPO}) to deploy a proxy node on {plan.ip}. "
        "Follow its SKILL.md runbook and call its scripts; do not improvise remote commands.",
        "",
        "## Pre-check results from VPS Console",
        *_fact_lines(check),
        "",
    ]
    step = 1
    steps = []
    if plan.use_lxc:
        lxc = lxc_config(plan)
        lxc_name = f"lxc_{plan.ip.replace('.', '_').replace(':', '_')}.json"
        steps += [
            f"{step}. First split the host with vps-lxc-skill ({LXC_REPO}). Save this as `{lxc_name}`:",
            "```json", json.dumps(lxc, indent=2, ensure_ascii=False), "```",
            f"   Run `python3 scripts/vps_lxc.py --config {lxc_name} --dry-run`, show me the plan, "
            f"then run it without `--dry-run`.",
            "   Then deploy each container with `python3 scripts/vps_deployer.py --from-lxc "
            "<that run's result.json> --container <name> --config "
            f"{name}`.",
        ]
        step += 1
    steps += [
        f"{step}. Save this config as `{name}` in the vps-deploy-skill folder:",
        "```json", json.dumps(cfg, indent=2, ensure_ascii=False), "```",
    ]
    step += 1
    if env_lines or placeholders:
        text = f"{step}. Secrets are not in the file."
        if env_lines:
            text += " The skill reads these environment variables; ask me for the values:"
        steps.append(text)
        if env_lines:
            steps += ["```bash", *env_lines, "```"]
        if placeholders:
            steps.append("   Replace `<EXIT_PROXY_USER>` and `<EXIT_PROXY_PASS>` in the file with values I give you. "
                         "Never commit that file.")
        step += 1
    steps += [
        f"{step}. Run `python3 scripts/vps_deployer.py --config {name} --dry-run` and show me any port "
        "conflicts or warnings before changing the server.",
        f"{step + 1}. Run it again without `--dry-run`.",
        f"{step + 2}. Results go to `{out_dir}` on the machine running the skill (folder 0700, files 0600): "
        "`vps_{ip}_info.txt`, `result.json`, `clash_config.yaml`, QR codes. The server keeps its own "
        "state in `/etc/vps-skill/state.json`, so re-runs keep the same links.",
        f"{step + 3}. Give me the panel URL, node links and the YAML path. After a reboot, follow the skill's "
        "Reboot Rules (read `/var/lib/vps-skill/boot-status` after 3 minutes).",
        "",
        "Rules: ask before stopping any existing service; keep IPs, passwords and tokens out of commits, "
        "issues and PRs.",
    ]
    return "\n".join(parts + ["## Steps", *steps])
