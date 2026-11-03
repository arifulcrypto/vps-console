"""Shared web helpers: templates, auth and CSRF dependencies."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from urllib.parse import quote

from fastapi import Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .i18n import pick, translate
from .security import csrf_matches, new_csrf_token

templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent / "templates"))


def _fmt_bytes(value) -> str:
    try:
        value = float(value)
    except (TypeError, ValueError):
        return "?"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit in ("B", "KB", "MB") else f"{value:.1f} {unit}"
        value /= 1024
    return "?"


def _fmt_time(ts) -> str:
    if not ts:
        return ""
    return dt.datetime.fromtimestamp(float(ts), dt.UTC).strftime("%Y-%m-%d %H:%M UTC")


templates.env.filters["bytes"] = _fmt_bytes
templates.env.filters["time"] = _fmt_time
templates.env.filters["tojson_pretty"] = lambda v: json.dumps(v, indent=2, ensure_ascii=False)


class LoginRequired(Exception):
    def __init__(self, next_url: str):
        self.next_url = next_url


class CSRFError(Exception):
    pass


def lang_of(request: Request) -> str:
    return pick(request.cookies.get("lang"))


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf")
    if not token:
        token = new_csrf_token()
        request.session["csrf"] = token
    return token


def is_admin(request: Request) -> bool:
    return bool(request.session.get("admin"))


def client_ip(request: Request) -> str:
    # Caddy only accepts Cloudflare addresses, so this header is trustworthy in production.
    return request.headers.get("cf-connecting-ip") or (request.client.host if request.client else "?")


async def require_admin(request: Request) -> None:
    if not is_admin(request):
        raise LoginRequired(request.url.path + (f"?{request.url.query}" if request.url.query else ""))


async def require_csrf(request: Request) -> None:
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    submitted = request.headers.get("x-csrf-token")
    if not submitted:
        form = await request.form()
        submitted = form.get("csrf")
    if not csrf_matches(request.session.get("csrf"), submitted):
        raise CSRFError()


def render(request: Request, name: str, status_code: int = 200, **ctx) -> HTMLResponse:
    lang = lang_of(request)

    def t(key: str, **params) -> str:
        return translate(lang, key, **params)

    settings = request.app.state.settings
    base = {
        "request": request,
        "t": t,
        "lang": lang,
        "csrf": csrf_token(request),
        "admin": is_admin(request),
        "version": settings.version[:7],
        "path": request.url.path,
        "next_q": quote(request.url.path),
    }
    return templates.TemplateResponse(request, name, {**base, **ctx}, status_code=status_code)
