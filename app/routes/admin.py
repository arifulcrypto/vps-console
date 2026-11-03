"""Admin: test servers (probes) and settings. Secrets are write-only."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse

from .. import probes as store
from .. import validation as v
from ..checks.ssh import SSHError
from ..web import render, require_admin, require_csrf

router = APIRouter(prefix="/admin")
admin_only = [Depends(require_admin)]
admin_post = [Depends(require_admin), Depends(require_csrf)]


async def _page(request: Request, status_code: int = 200, message: str = "", error: str = "", test=None,
                form: dict | None = None):
    db = request.app.state.db
    gp = await db.fetchone("SELECT updated_at FROM settings WHERE key = 'globalping_token'")
    return render(request, "admin/index.html", status_code=status_code, probes=await store.list_probes(db),
                  gp_set=gp["updated_at"] if gp else None, message=message, error=error, test=test,
                  form=form or {})


@router.get("", dependencies=admin_only)
async def index(request: Request):
    return await _page(request)


@router.post("/probes", dependencies=admin_post)
async def probe_add(request: Request, name: str = Form(...), region: str = Form(""), host: str = Form(...),
                    port: str = Form("22"), username: str = Form("root"), auth_type: str = Form("password"),
                    secret: str = Form(...), switch_to_key: str = Form(""), probe_id: str = Form("")):
    form = {"name": name, "region": region, "host": host, "port": port, "username": username}
    try:
        h = v.host(host)
        p = v.port(port)
        u = v.username(username)
        if not secret.strip():
            raise v.InvalidInput("secret", "missing_secret")
        await store.save_probe(request.app.state.db, request.app.state.box, name=name.strip()[:40] or h,
                               region=region.strip()[:40], host=h, port=p, username=u,
                               auth_type="key" if auth_type == "key" else "password",
                               secret=secret.strip() + ("\n" if auth_type == "key" else ""),
                               switch_to_key=bool(switch_to_key), probe_id=int(probe_id) if probe_id else None)
    except v.InvalidInput as exc:
        return await _page(request, 400, error=f"err.{exc.code}", form=form)
    except SSHError as exc:
        return await _page(request, 400, error=f"ssh.{exc.code}", form=form)
    return await _page(request, message="admin.probe_saved")


@router.post("/probes/{probe_id}/meta", dependencies=admin_post)
async def probe_meta(request: Request, probe_id: int, name: str = Form(...), region: str = Form(""),
                     enabled: str = Form("")):
    await store.update_meta(request.app.state.db, probe_id, name.strip()[:40], region.strip()[:40], bool(enabled))
    return RedirectResponse("/admin", status_code=303)


@router.post("/probes/{probe_id}/test", dependencies=admin_post)
async def probe_test(request: Request, probe_id: int):
    result = await store.test_probe(request.app.state.db, request.app.state.box, probe_id)
    return await _page(request, test={"id": probe_id, **result})


@router.post("/probes/{probe_id}/delete", dependencies=admin_post)
async def probe_delete(request: Request, probe_id: int):
    await store.delete_probe(request.app.state.db, request.app.state.box, probe_id)
    return RedirectResponse("/admin", status_code=303)


@router.post("/settings", dependencies=admin_post)
async def settings_save(request: Request, globalping_token: str = Form(""), clear_globalping: str = Form("")):
    db = request.app.state.db
    if clear_globalping:
        await db.execute("DELETE FROM settings WHERE key = 'globalping_token'")
    elif globalping_token.strip():
        await db.set_setting("globalping_token", request.app.state.box.encrypt(globalping_token.strip()), secret=True)
    return await _page(request, message="admin.settings_saved")
