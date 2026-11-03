"""FastAPI application factory."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from .config import Settings, load_settings
from .db import Database
from .jobs import JobManager
from .routes import admin, auth, tools
from .security import LoginThrottle, SecretBox
from .web import CSRFError, LoginRequired

STATIC = Path(__file__).resolve().parent / "static"

CSP = (
    "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
    "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    db = Database(settings.db_path)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await db.migrate()
        await app.state.jobs.recover()
        yield

    app = FastAPI(title="VPS Console", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.settings = settings
    app.state.db = db
    app.state.box = SecretBox(settings.encryption_key())
    app.state.jobs = JobManager(db, settings.max_concurrent_jobs)
    app.state.throttle = LoginThrottle()

    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.session_key(),
        session_cookie="vpsc_session",
        max_age=12 * 3600,
        same_site="strict",
        https_only=settings.secure_cookies,
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("Content-Security-Policy", CSP)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if not request.url.path.startswith("/static/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.exception_handler(LoginRequired)
    async def _login_required(request: Request, exc: LoginRequired):
        if request.headers.get("hx-request"):
            return PlainTextResponse("login required", status_code=401, headers={"HX-Redirect": "/login"})
        from urllib.parse import quote

        return RedirectResponse(f"/login?next={quote(exc.next_url)}", status_code=303)

    @app.exception_handler(CSRFError)
    async def _csrf(request: Request, exc: CSRFError):
        return PlainTextResponse("Form expired. Reload the page and try again.", status_code=403)

    @app.get("/healthz")
    async def healthz():
        return JSONResponse({"ok": True, "version": settings.version})

    app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")
    app.include_router(auth.router)
    app.include_router(tools.router)
    app.include_router(admin.router)
    logging.basicConfig(level=logging.INFO)
    return app


app = None


def get_app() -> FastAPI:
    """Entry point for uvicorn --factory."""
    return create_app()
