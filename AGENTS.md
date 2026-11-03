# AGENTS.md

Rules for anyone (human or agent) changing this repository.

## What this is

VPS Console: a mobile-first FastAPI site with one admin account. It checks a VPS
(read-only), tests reachability from China, tests proxies and Cloudflare tokens,
converts subscriptions, and generates prompts plus config files for
[vps-deploy-skill](https://github.com/arifulcrypto/vps-deploy-skill) and
[vps-lxc-skill](https://github.com/arifulcrypto/vps-lxc-skill). It never deploys.

Read `docs/architecture.md` before larger changes and update `docs/progress.md`
when you finish one.

## Hard rules

1. **Checks are read-only.** Nothing run on a target may install, start, stop or
   edit anything. The only remote write is adding or removing this app's own SSH
   key on a probe, and only when the admin asks for it.
2. **Secrets never persist in plain text.** Target SSH passwords, keys,
   Cloudflare tokens and proxy credentials used in a check live only in memory
   for that job. Stored secrets (probe logins, Globalping token) are Fernet-encrypted
   with the key in `/etc/vps-console/fernet.key` and are never rendered back.
   Job results and outputs must not contain credentials.
3. **Public repository.** Never commit server IPs, domains other than
   placeholders (`example.com`, `203.0.113.0/24`), tokens, passwords, or
   `var/`. Deploy details live in GitHub secrets.
4. **Everything that reaches a shell or socket is validated** in
   `app/validation.py`. Use `shlex.quote` for anything else interpolated into
   remote commands.
5. **Both languages.** Every UI string goes through `t('key')`. Add each key to
   both `app/locales/en.json` and `app/locales/zh.json`; `tests/test_security_i18n.py`
   fails otherwise. English is the default.
6. **Mobile first.** Check every page at 360 px width. No horizontal page scroll;
   tables scroll inside their own box.
7. **No external scripts or styles** at runtime. `htmx` is vendored in
   `app/static/`. The CSP forbids inline scripts.

## Workflow

- Branch from `main`, open a PR, let CI pass, merge. `main` deploys automatically.
- Prefer CI over local runs. If you do run locally:

```bash
conda create -n vps-console python=3.12 -y
conda activate vps-console
pip install -r requirements-dev.txt
ruff check . && pytest
VPSC_DATA_DIR=./var uvicorn --factory app.main:get_app --port 8091
python -m app.cli set-admin      # prints a one-time password
```

## Verification commands (what CI runs)

```bash
ruff check .
pytest
python -m compileall -q app
```

## Commit style

Short imperative subject, body explaining why. One logical change per commit
so it can be reverted alone.
