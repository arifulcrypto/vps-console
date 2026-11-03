# Architecture

## Goal

Do the mechanical work of the two VPS skills without a language model: collect
facts, test the network, and fill in the skill's inputs. The model only gets
the final prompt.

## Overview

```text
Browser (phone)  ──HTTPS──>  Cloudflare (orange)  ──>  Caddy :443 (CF IPs only)
                                                        └─> uvicorn 127.0.0.1:8091
                                                             FastAPI app
                                                             ├─ SQLite  /var/lib/vps-console/app.db
                                                             ├─ keys    /etc/vps-console/*.key
                                                             ├─ SSH ──> target VPS (read-only)
                                                             ├─ SSH ──> China probe (tests)
                                                             └─ HTTPS ─> ip-api, Globalping, Cloudflare API
```

## Modules

| Path | Role |
| --- | --- |
| `app/checks/facts.py` | One read-only shell script, one SSH round trip, parsed into a facts dict |
| `app/checks/assess.py` | Facts → findings (OS support, LXD fit, swap, BBR, ports, versions). Data in `app/data/software.json` |
| `app/checks/routes.py` | Return routes from the target to 9 carrier addresses (mtr with AS numbers, traceroute fallback) |
| `app/checks/reach.py` | TCP/TLS/ICMP from abroad (this server) and from the China probe; block classification |
| `app/checks/globalping.py` | Globalping probes in China when no own probe exists, and in deep mode |
| `app/checks/proxy.py` | Proxy test: exit IP, type, sticky or rotating |
| `app/checks/cloudflare.py` | Token verify, zones, DNS records, live resolution. Never writes |
| `app/checks/server_check.py` | Orchestrates one check job |
| `app/generators/skill_prompt.py` | Presets → vps-deploy-skill / vps-lxc-skill config + prompt |
| `app/generators/links.py`, `mihomo.py` | Subscription converter |
| `app/probes.py` | Encrypted probe storage, password → key swap |
| `app/jobs.py` | asyncio background jobs, polled by htmx |

## Key decisions

- **Server-rendered pages + htmx** instead of a SPA: one language (Python), no
  build step, fast on phones, works without JavaScript except for progress polling.
- **SQLite** with forward-only migrations in `app/db.py`: one admin, low write volume.
- **Checks never deploy.** Deployment stays in the skills, which already handle
  rollback, reboot rules and state. The site produces their config and a prompt.
- **Secrets:** target credentials only in memory for the job. Probe logins are
  encrypted at rest with a key outside the database; by default a probe password
  is used once to install a dedicated ed25519 key, then dropped. Host keys are
  pinned on first save.
- **Prompts without secrets by default.** Both skills read `VPS_SSH_PASS` and
  `CF_TOKEN` from the environment, so generated configs omit them. A prompt with
  secrets is displayed once and not stored.
- **Save locations.** The skills write results on the machine running them
  (`./output/<ip>/` by default, or `/root/02project/01LXD_vps_info/<ip>/`). The
  target keeps `/etc/vps-skill/state.json` itself, so no target path is asked for.
  The site keeps each generated bundle under History for download.
- **GFW classification** compares the same ports from abroad and from China:
  all fail from China → IP block; some ports → port block; TCP ok but TLS cut →
  TLS interference. Protocol-level detection after a working TLS handshake needs
  a real client inside China and is out of scope; the UI says so.
- **Converter output** mirrors vps-deploy-skill's `clash_generator.py`: metered
  residential/relay nodes are never in url-test groups; split DNS keeps
  foreign lookups off domestic resolvers.
- **Origin protection:** Caddy accepts only Cloudflare address ranges for this
  host, so `CF-Connecting-IP` can be trusted for login throttling.

## Deployment

`main` → GitHub Actions (lint, tests) → deploy job SSHes to the server with a key
whose `authorized_keys` entry is restricted to `/usr/local/sbin/vps-console-deploy`.
That script checks out the exact commit (must be on `origin/main`), installs
requirements into the conda env `/opt/vps-console/env`, restarts the service,
checks `/healthz` reports the new commit, and rolls back otherwise.
See `deploy/`.
