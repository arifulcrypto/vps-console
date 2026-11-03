"""Checks, results, prompt generator, subscription converter, history."""

from __future__ import annotations

import base64
import json
import re
import secrets
import time

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import PlainTextResponse, RedirectResponse, Response

from .. import probes as probe_store
from .. import validation as v
from ..checks.server_check import CheckOptions, run_server_check
from ..checks.ssh import SSHTarget
from ..generators import links as link_codec
from ..generators import mihomo
from ..generators.qr import svg_data_uri
from ..generators.skill_prompt import PRESETS, SAVE_LOCATIONS, PlanInput, build_prompt, deploy_config, lxc_config
from ..report import to_markdown
from ..subfetch import FetchError, fetch_subscription
from ..web import render, require_admin, require_csrf

router = APIRouter()
admin_only = [Depends(require_admin)]
admin_post = [Depends(require_admin), Depends(require_csrf)]


# Check ------------------------------------------------------------------

@router.get("/check", dependencies=admin_only)
async def check_form(request: Request):
    db = request.app.state.db
    probe_rows = await db.fetchall("SELECT name, region FROM probes WHERE enabled = 1")
    return render(request, "tools/check.html", probes=probe_rows, error=None, form={})


@router.post("/check", dependencies=admin_post)
async def check_start(
    request: Request,
    mode: str = Form("quick"),
    host: str = Form(""),
    ssh_port: str = Form("22"),
    ssh_user: str = Form("root"),
    auth: str = Form("password"),
    password: str = Form(""),
    private_key: str = Form(""),
    skip_ssh: str = Form(""),
    ports: str = Form(""),
    sni: str = Form(""),
    domain: str = Form(""),
    cf_token: str = Form(""),
    proxies: str = Form(""),
    proxy_scheme: str = Form("socks5"),
    use_probe: str = Form(""),
):
    db = request.app.state.db
    form = {"mode": mode, "host": host, "ssh_port": ssh_port, "ssh_user": ssh_user, "ports": ports,
            "sni": sni, "domain": domain, "proxy_scheme": proxy_scheme}
    try:
        mode = "deep" if mode == "deep" else "quick"
        target = None
        if host:
            h = await v.resolve_public(v.host(host))
            if not skip_ssh:
                target = SSHTarget(host=h, port=v.port(ssh_port, "ssh_port"), username=v.username(ssh_user),
                                   password=password if auth == "password" else None,
                                   private_key=private_key if auth == "key" else None)
                if not (target.password or target.private_key):
                    raise v.InvalidInput("password", "missing_secret")
        opts = CheckOptions(
            mode=mode,
            ports=v.ports(ports),
            sni=v.domain(sni, "sni"),
            domain=v.domain(domain),
            cf_token=cf_token.strip(),
            proxies=[line.strip() for line in proxies.splitlines() if line.strip()],
            proxy_scheme=proxy_scheme if proxy_scheme in ("socks5", "http") else "socks5",
            routes=target is not None,
        )
        if not (host or opts.domain or opts.cf_token or opts.proxies):
            raise v.InvalidInput("host", "nothing_to_check")
        bare_host = h if host and not target else ""
        target_label = target.host if target else (bare_host or opts.domain or "proxies")
    except v.InvalidInput as exc:
        probe_rows = await db.fetchall("SELECT name, region FROM probes WHERE enabled = 1")
        return render(request, "tools/check.html", status_code=400, probes=probe_rows,
                      error={"field": exc.field, "code": exc.code}, form=form)

    box = request.app.state.box
    probe = await probe_store.active_probe(db, box) if use_probe else None
    opts.globalping_token = await _setting_secret(request, "globalping_token")

    async def work(progress):
        return await run_server_check(target, opts, probe, progress, host=bare_host)

    public_inputs = {"mode": mode, "host": host, "ssh_port": ssh_port, "ssh_user": ssh_user, "ports": ports,
                     "sni": sni, "domain": domain, "proxy_count": len(opts.proxies), "has_cf": bool(opts.cf_token),
                     "probe": bool(probe)}
    job_id = await request.app.state.jobs.start("check", mode, target_label, public_inputs, work)
    return RedirectResponse(f"/jobs/{job_id}", status_code=303)


async def _setting_secret(request: Request, key: str) -> str:
    raw = await request.app.state.db.get_setting(key)
    if not raw:
        return ""
    try:
        return request.app.state.box.decrypt(raw)
    except ValueError:
        return ""


# Jobs -------------------------------------------------------------------

async def _job_or_404(request: Request, job_id: str) -> dict:
    job = await request.app.state.db.get_job(job_id)
    if not job:
        raise HTTPException(404)
    return job


@router.get("/jobs/{job_id}", dependencies=admin_only)
async def job_page(request: Request, job_id: str):
    job = await _job_or_404(request, job_id)
    return render(request, "tools/job.html", job=job, r=job["result"])


@router.get("/jobs/{job_id}/status", dependencies=admin_only)
async def job_status(request: Request, job_id: str):
    job = await _job_or_404(request, job_id)
    if job["status"] == "running":
        return render(request, "partials/job_progress.html", job=job)
    return Response(status_code=200, headers={"HX-Refresh": "true"})


@router.get("/jobs/{job_id}/report.{fmt}", dependencies=admin_only)
async def job_report(request: Request, job_id: str, fmt: str):
    job = await _job_or_404(request, job_id)
    name = f"check_{re.sub(r'[^A-Za-z0-9.-]', '_', job['target'])}_{job_id}"
    if fmt == "json":
        body = json.dumps({"target": job["target"], "mode": job["mode"], "created_at": job["created_at"],
                           "inputs": job["inputs"], "result": job["result"]}, indent=2, ensure_ascii=False)
        return _download(body, f"{name}.json", "application/json")
    if fmt == "md":
        return _download(to_markdown(job), f"{name}.md", "text/markdown")
    raise HTTPException(404)


def _download(body: str, filename: str, media: str) -> Response:
    return Response(body, media_type=f"{media}; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


# Prompt generator -------------------------------------------------------

@router.get("/generate", dependencies=admin_only)
async def generate_form(request: Request, job: str = ""):
    prefill = {}
    if job:
        j = await request.app.state.db.get_job(job)
        if j:
            prefill = {"ip": j["result"].get("ip", ""), "ssh_port": j["inputs"].get("ssh_port", "22"),
                       "ssh_user": j["inputs"].get("ssh_user", "root"), "domain": j["inputs"].get("domain", ""),
                       "job": job}
    return render(request, "tools/generate.html", presets=PRESETS, saves=SAVE_LOCATIONS, form=prefill, error=None)


@router.post("/generate", dependencies=admin_post)
async def generate(request: Request):
    form = await request.form()
    f = {k: str(val) for k, val in form.items() if k != "csrf"}
    db = request.app.state.db
    try:
        plan = PlanInput(
            ip=v.host(f.get("ip", ""), "ip"),
            ssh_port=v.port(f.get("ssh_port", "22"), "ssh_port"),
            ssh_user=v.username(f.get("ssh_user", "root")),
            ssh_auth="key" if f.get("ssh_auth") == "key" else "password",
            ssh_key_path=v.path(f.get("ssh_key_path", ""), "ssh_key_path"),
            preset=f.get("preset", "fast") if f.get("preset") in PRESETS else "fast",
            domain=v.domain(f.get("domain", "")),
            cdn_domain=v.domain(f.get("cdn_domain", ""), "cdn_domain"),
            manage_dns=bool(f.get("manage_dns")),
            cert_mode="dns-01" if f.get("cert_mode") == "dns-01" else "http-01",
            client_isp=f.get("client_isp", "unicom") if f.get("client_isp") in ("unicom", "mobile", "telecom",
                                                                                  "overseas") else "unicom",
            extra_protocols=[p for p in ("vmess", "trojan") if f.get(f"extra_{p}")],
            exit_proxy=_exit_proxy(f.get("exit_proxy", "")),
            exit_protocol="http" if f.get("exit_protocol") == "http" else "socks",
            panel_private=bool(f.get("panel_private")),
            lang="zh" if f.get("out_lang") == "zh" else "en",
            save_location=f.get("save_location", "skill_default") if f.get("save_location") in SAVE_LOCATIONS
            else "skill_default",
            custom_path=v.path(f.get("custom_path", ""), "custom_path"),
            use_lxc=bool(f.get("use_lxc")),
            lxc_count=max(1, min(6, int(f.get("lxc_count") or 2))),
            lxc_memory_mb=max(256, min(65536, int(f.get("lxc_memory_mb") or 1024))),
            lxc_disk_gb=max(3, min(2000, int(f.get("lxc_disk_gb") or 10))),
            traffic_limit_gb=max(0, int(f.get("traffic_limit_gb") or 0)),
            traffic_reset_day=max(1, min(28, int(f.get("traffic_reset_day") or 1))),
            include_secrets=bool(f.get("include_secrets")),
            secrets={k: f.get(k, "") for k in ("ssh_pass", "cf_token", "exit_user", "exit_pass")},
        )
        if PRESETS[plan.preset]["needs_domain"] and not plan.domain:
            raise v.InvalidInput("domain", "domain_required")
        if plan.preset == "residential" and not plan.exit_proxy:
            raise v.InvalidInput("exit_proxy", "exit_required")
    except (v.InvalidInput, ValueError) as exc:
        err = {"field": getattr(exc, "field", "form"), "code": getattr(exc, "code", "invalid")}
        return render(request, "tools/generate.html", status_code=400, presets=PRESETS, saves=SAVE_LOCATIONS,
                      form=f, error=err)
    check = None
    job_id = f.get("job", "")
    if job_id:
        j = await db.get_job(job_id)
        check = j["result"] if j else None
    prompt = build_prompt(plan, check)
    cfg = deploy_config(plan)
    bundle = {"prompt": prompt, "deploy_config": cfg}
    if plan.use_lxc:
        bundle["lxc_config"] = lxc_config(plan)
    out_id = secrets.token_urlsafe(9)
    # Prompts with secrets are shown once and never stored.
    if not plan.include_secrets:
        await db.execute(
            "INSERT INTO outputs (id, job_id, kind, title, filename, content, created_at) VALUES (?,?,?,?,?,?,?)",
            (out_id, job_id or None, "prompt", f"{plan.preset} · {plan.ip}",
             f"prompt_{plan.ip.replace(':', '_')}.md", json.dumps(bundle, ensure_ascii=False), time.time()),
        )
    return render(request, "tools/generated.html", bundle=bundle, out_id=out_id, stored=not plan.include_secrets,
                  plan=plan)


def _exit_proxy(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    host, _, port = value.rpartition(":")
    return f"{v.host(host, 'exit_proxy')}:{v.port(port, 'exit_proxy')}"


@router.get("/outputs/{out_id}", dependencies=admin_only)
async def output_page(request: Request, out_id: str):
    row = await request.app.state.db.fetchone("SELECT * FROM outputs WHERE id = ?", (out_id,))
    if not row:
        raise HTTPException(404)
    bundle = json.loads(row["content"])
    if row["kind"] == "prompt":
        return render(request, "tools/generated.html", bundle=bundle, out_id=out_id, stored=True, plan=None)
    return render(request, "tools/converted.html", **bundle, out_id=out_id, sub_url=None)


@router.get("/outputs/{out_id}/{part}", dependencies=admin_only)
async def output_download(request: Request, out_id: str, part: str):
    row = await request.app.state.db.fetchone("SELECT * FROM outputs WHERE id = ?", (out_id,))
    if not row:
        raise HTTPException(404)
    bundle = json.loads(row["content"])
    if part == "prompt.md" and "prompt" in bundle:
        return _download(bundle["prompt"], row["filename"], "text/markdown")
    if part == "deploy.json" and "deploy_config" in bundle:
        return _download(json.dumps(bundle["deploy_config"], indent=2, ensure_ascii=False),
                         "deploy_config.json", "application/json")
    if part == "lxc.json" and "lxc_config" in bundle:
        return _download(json.dumps(bundle["lxc_config"], indent=2, ensure_ascii=False),
                         "lxc_config.json", "application/json")
    if part == "config.yaml" and "yaml" in bundle:
        return _download(bundle["yaml"], "config.yaml", "application/yaml")
    if part == "links.txt" and "links" in bundle:
        return _download("\n".join(bundle["links"]) + "\n", "links.txt", "text/plain")
    raise HTTPException(404)


@router.post("/outputs/{out_id}/delete", dependencies=admin_post)
async def output_delete(request: Request, out_id: str):
    await request.app.state.db.execute("DELETE FROM outputs WHERE id = ?", (out_id,))
    return RedirectResponse("/history", status_code=303)


# Subscription converter -------------------------------------------------

@router.get("/convert", dependencies=admin_only)
async def convert_form(request: Request):
    return render(request, "tools/convert.html", form={}, error=None)


@router.post("/convert", dependencies=admin_post)
async def convert(request: Request):
    form = await request.form()
    f = {k: str(val) for k, val in form.items() if k != "csrf"}
    errors: list[str] = []
    proxies: list[dict] = []
    mlkem = bool(f.get("mlkem"))
    try:
        for url in [u.strip() for u in f.get("sub_urls", "").splitlines() if u.strip()][:10]:
            try:
                text = await fetch_subscription(url, f.get("user_agent", "") or "clash-verge/v2.5.8")
            except FetchError as exc:
                errors.append(f"{url[:50]}…: {exc}")
                continue
            got, errs = link_codec.parse_text(text, mlkem)
            proxies += got
            errors += errs
        got, errs = link_codec.parse_text(f.get("links", ""), mlkem)
        proxies += got
        errors += errs
        renames = []
        for line in f.get("renames", "").splitlines():
            if "->" in line:
                a, b = line.split("->", 1)
                renames.append((a.strip(), b.strip()))
        opts = mihomo.ConvertOptions(
            include=f.get("include", ""), exclude=f.get("exclude", ""), renames=renames,
            prefix=f.get("prefix", ""), add_flags=bool(f.get("add_flags")), dedupe=bool(f.get("dedupe")),
            sort=bool(f.get("sort")), residential_pattern=f.get("residential_pattern", "")
            or mihomo.ConvertOptions.residential_pattern,
            groups=f.get("groups", "full") if f.get("groups") in ("full", "simple", "region") else "full",
            china_direct=bool(f.get("china_direct")), block_ads=bool(f.get("block_ads")),
            ai_group=bool(f.get("ai_group")), streaming_group=bool(f.get("streaming_group")),
            telegram_group=bool(f.get("telegram_group")), fake_ip=f.get("dns_mode", "fake-ip") == "fake-ip",
            ipv6=bool(f.get("ipv6")), mixed_port=v.port(f.get("mixed_port", "7890") or "7890", "mixed_port"),
            allow_lan=bool(f.get("allow_lan")), lang="zh" if f.get("out_lang") == "zh" else "en",
        )
        proxies = mihomo.transform(proxies, opts)
    except (ValueError, v.InvalidInput) as exc:
        return render(request, "tools/convert.html", status_code=400, form=f,
                      error={"field": "form", "code": "invalid", "detail": str(exc)})
    if not proxies:
        return render(request, "tools/convert.html", status_code=400, form=f,
                      error={"field": "links", "code": "no_nodes", "detail": "; ".join(errors[:5])})
    target = f.get("target", "mihomo")
    config = mihomo.build_config(proxies, opts)
    problems = mihomo.check_config(config)
    if target == "provider":
        yaml_text = mihomo.dump({"proxies": proxies})
    else:
        yaml_text = mihomo.dump(config)
    node_links = []
    for p in proxies:
        try:
            node_links.append(link_codec.to_link(p))
        except (ValueError, KeyError):
            pass
    nodes = [{"name": p["name"], "type": p.get("type"), "server": p.get("server"), "port": p.get("port")}
             for p in proxies]
    bundle = {"yaml": yaml_text, "links": node_links, "nodes": nodes, "errors": errors[:20],
              "problems": problems, "target": target}
    out_id = secrets.token_urlsafe(9)
    title = f.get("title", "").strip()[:60] or f"{len(proxies)} nodes"
    await request.app.state.db.execute(
        "INSERT INTO outputs (id, job_id, kind, title, filename, content, created_at) VALUES (?,?,?,?,?,?,?)",
        (out_id, None, "convert", title, "config.yaml", json.dumps(bundle, ensure_ascii=False), time.time()),
    )
    sub_url = None
    if f.get("publish"):
        token = secrets.token_urlsafe(24)
        await request.app.state.db.execute(
            "INSERT INTO subscriptions (token, title, content, created_at) VALUES (?,?,?,?)",
            (token, title, json.dumps({"yaml": yaml_text, "links": node_links}, ensure_ascii=False), time.time()),
        )
        sub_url = f"{request.app.state.settings.base_url}/s/{token}"
    return render(request, "tools/converted.html", **bundle, out_id=out_id, sub_url=sub_url,
                  sub_qr=svg_data_uri(sub_url) if sub_url else None,
                  qrs=[svg_data_uri(link) for link in node_links])


# Hosted subscriptions (public, protected by an unguessable token) -------

@router.get("/s/{token}")
async def subscription(request: Request, token: str, format: str = "yaml"):
    row = await request.app.state.db.fetchone("SELECT * FROM subscriptions WHERE token = ?", (token,))
    if not row:
        raise HTTPException(404)
    data = json.loads(row["content"])
    if format == "base64":
        return PlainTextResponse(base64.b64encode("\n".join(data["links"]).encode()).decode())
    return Response(data["yaml"], media_type="text/yaml; charset=utf-8",
                    headers={"Content-Disposition": 'inline; filename="config.yaml"',
                             "profile-update-interval": "24"})


@router.post("/subscriptions/{token}/delete", dependencies=admin_post)
async def subscription_delete(request: Request, token: str):
    await request.app.state.db.execute("DELETE FROM subscriptions WHERE token = ?", (token,))
    return RedirectResponse("/history", status_code=303)


# History ----------------------------------------------------------------

@router.get("/history", dependencies=admin_only)
async def history(request: Request):
    db = request.app.state.db
    jobs = await db.fetchall("SELECT id, kind, mode, target, status, created_at FROM jobs "
                             "ORDER BY created_at DESC LIMIT 100")
    outputs = await db.fetchall("SELECT id, kind, title, created_at FROM outputs ORDER BY created_at DESC LIMIT 100")
    subs = await db.fetchall("SELECT token, title, created_at FROM subscriptions ORDER BY created_at DESC")
    base = request.app.state.settings.base_url
    return render(request, "tools/history.html", jobs=jobs, outputs=outputs, subs=subs, base=base)


@router.post("/jobs/{job_id}/delete", dependencies=admin_post)
async def job_delete(request: Request, job_id: str):
    await request.app.state.db.execute("DELETE FROM jobs WHERE id = ?", (job_id,))
    return RedirectResponse("/history", status_code=303)
