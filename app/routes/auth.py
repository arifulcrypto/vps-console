"""Home, language switch, login and logout."""

from __future__ import annotations

import time

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse

from ..i18n import pick
from ..security import hash_password, verify_password
from ..web import client_ip, is_admin, render, require_admin, require_csrf

router = APIRouter()


def _safe_next(value: str | None) -> str:
    if value and value.startswith("/") and not value.startswith("//"):
        return value
    return "/"


@router.get("/")
async def home(request: Request):
    if not is_admin(request):
        return render(request, "home.html")
    db = request.app.state.db
    jobs = await db.fetchall("SELECT id, kind, mode, target, status, created_at FROM jobs "
                             "ORDER BY created_at DESC LIMIT 5")
    probes = await db.fetchall("SELECT name, region, enabled FROM probes WHERE enabled = 1")
    return render(request, "dashboard.html", jobs=jobs, probes=probes)


@router.get("/lang/{code}")
async def set_lang(request: Request, code: str, next: str = "/"):
    response = RedirectResponse(_safe_next(next), status_code=303)
    response.set_cookie("lang", pick(code), max_age=365 * 86400, samesite="lax",
                        secure=request.app.state.settings.secure_cookies)
    return response


@router.get("/login")
async def login_form(request: Request, next: str = "/"):
    return render(request, "login.html", next=_safe_next(next), error="")


@router.post("/login", dependencies=[Depends(require_csrf)])
async def login(request: Request, username: str = Form(...), password: str = Form(...), next: str = Form("/")):
    throttle = request.app.state.throttle
    key = client_ip(request)
    if throttle.blocked(key):
        return render(request, "login.html", status_code=429, next=_safe_next(next), error="login.throttled")
    row = await request.app.state.db.fetchone("SELECT * FROM admin WHERE id = 1")
    if not row or row["username"] != username or not verify_password(password, row["password_hash"]):
        throttle.fail(key)
        return render(request, "login.html", status_code=401, next=_safe_next(next), error="login.failed")
    throttle.reset(key)
    request.session.clear()
    request.session["admin"] = True
    request.session["login_at"] = time.time()
    return RedirectResponse(_safe_next(next), status_code=303)


@router.post("/logout", dependencies=[Depends(require_csrf)])
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", status_code=303)


@router.get("/account", dependencies=[Depends(require_admin)])
async def account_form(request: Request):
    return render(request, "admin/account.html", message="", error="")


@router.post("/account", dependencies=[Depends(require_admin), Depends(require_csrf)])
async def account_save(request: Request, current: str = Form(...), new: str = Form(...), confirm: str = Form(...)):
    db = request.app.state.db
    row = await db.fetchone("SELECT * FROM admin WHERE id = 1")
    if not verify_password(current, row["password_hash"]):
        return render(request, "admin/account.html", status_code=400, message="", error="account.wrong_current")
    if new != confirm or len(new) < 12:
        return render(request, "admin/account.html", status_code=400, message="", error="account.weak")
    await db.execute("UPDATE admin SET password_hash = ?, updated_at = ? WHERE id = 1",
                     (hash_password(new), time.time()))
    return render(request, "admin/account.html", message="account.saved", error="")
