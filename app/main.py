from __future__ import annotations

import base64
import io
import os
import re
import urllib.parse

import qrcode
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import amnezia_fmt, awg, configedit, extras, hostinfo, keys
from .auth import Auth, LoginThrottle, require_session
from .backend import ContainerNotFound, make_backend

BASE_DIR = os.path.dirname(__file__)

ENDPOINT_HOST = os.environ.get("AWG_ENDPOINT_HOST", "")
ENDPOINT_PORT = os.environ.get("AWG_ENDPOINT_PORT", "51820")

# Placeholder protocols: management is coming later.
PLACEHOLDERS = {
    "amnezia-xray": "Xray (VLESS)",
    "amnezia-openvpn": "OpenVPN",
}

# Actions are allowed on Amnezia containers only.
SAFE_CONTAINER = re.compile(r"^amnezia-[a-z0-9][a-z0-9-]*$")
SELF_NAME = os.environ.get("PANEL_CONTAINER_NAME", "amnezia-web-panel")


def create_app() -> FastAPI:
    app = FastAPI(title="amnezia-web-panel", version="0.1.0",
                  docs_url=None, redoc_url=None, openapi_url=None)
    backend_kind = os.environ.get("PANEL_BACKEND", "mock")
    app.state.backend_kind = backend_kind
    app.state.backend = make_backend(backend_kind)
    # Prod: PBKDF2 hash from .env. Plaintext PANEL_PASSWORD is for development only.
    password = os.environ.get("PANEL_PASSWORD_HASH", "") or os.environ.get("PANEL_PASSWORD", "")
    if not password:
        if backend_kind == "mock":
            password = "admin"
        else:
            raise RuntimeError("PANEL_PASSWORD_HASH is required")
    app.state.auth = Auth(password)
    app.state.templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))
    app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
    _register_routes(app)
    return app


def _qr_data_uri(text: str, error_correction: str = "M") -> str:
    level = {"L": qrcode.constants.ERROR_CORRECT_L,
             "M": qrcode.constants.ERROR_CORRECT_M}[error_correction]
    qr = qrcode.QRCode(error_correction=level, border=1)
    qr.add_data(text)
    qr.make(fit=True)
    img = qr.make_image()
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def _register_routes(app: FastAPI) -> None:
    templates: Jinja2Templates = app.state.templates
    throttle = LoginThrottle()

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        return resp

    def render(request: Request, page: str, **ctx):
        return templates.TemplateResponse(request, page, ctx)

    @app.get("/login", response_class=HTMLResponse)
    def login_page(request: Request, error: str = ""):
        return render(request, "login.html", error=error, hide_sidebar=True)

    @app.post("/login")
    def login(request: Request, password: str = Form(...)):
        auth: Auth = request.app.state.auth
        ip = request.client.host if request.client else "unknown"
        if not throttle.allowed(ip):
            return RedirectResponse("/login?error=rate", status_code=303)
        if not auth.check_password(password):
            throttle.record_failure(ip)
            return RedirectResponse("/login?error=1", status_code=303)
        throttle.reset(ip)
        resp = RedirectResponse("/", status_code=303)
        resp.set_cookie("panel_session", auth.make_token(), httponly=True, samesite="lax", max_age=12 * 3600)
        return resp

    @app.get("/logout")
    def logout(request: Request):
        # Single-admin panel: rotating the secret invalidates every outstanding
        # token server-side, so a copied cookie dies at logout, not at TTL expiry.
        request.app.state.auth.rotate_secret()
        resp = RedirectResponse("/login", status_code=303)
        resp.delete_cookie("panel_session")
        return resp

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request):
        if (r := require_session(request)) is not None:
            return r
        backend = app.state.backend
        services = backend.list_services()
        host = hostinfo.fetch_host_info(app.state.backend_kind)
        return render(request, "services.html", services=services, host=host,
                      manageable=set(keys.MANAGEABLE), endpoint_host=ENDPOINT_HOST,
                      self_name=SELF_NAME, config_specs=set(configedit.SPECS))

    @app.post("/services/{name}/restart")
    def restart_service(request: Request, name: str):
        if (r := require_session(request)) is not None:
            return r
        # Amnezia containers only; the panel must not restart itself (drops sessions).
        if not SAFE_CONTAINER.match(name) or name == SELF_NAME:
            return RedirectResponse("/", status_code=303)
        try:
            app.state.backend.restart(name)
        except ContainerNotFound:
            pass
        return RedirectResponse("/", status_code=303)

    @app.get("/services/{name}/logs", response_class=HTMLResponse)
    def service_logs(request: Request, name: str):
        if (r := require_session(request)) is not None:
            return r
        if not SAFE_CONTAINER.match(name):
            return RedirectResponse("/", status_code=303)
        try:
            logs = app.state.backend.logs(name, tail=300)
        except ContainerNotFound:
            logs = "container not found"
        except Exception as exc:  # docker API errors — show instead of a bare 500
            logs = f"error fetching logs: {exc}"
        return render(request, "logs.html", name=name, logs=logs)

    @app.get("/keys/{container}", response_class=HTMLResponse)
    def keys_page(request: Request, container: str, error: str = "", created_name: str = "",
                        config: str = "", qr: str = ""):
        if (r := require_session(request)) is not None:
            return r
        if container in PLACEHOLDERS:
            installed = any(s.name == container for s in app.state.backend.list_services())
            return render(request, "keys.html", container=container, clients=[], error="",
                          created_name="", config="", qr="", placeholder=True,
                          placeholder_name=PLACEHOLDERS[container], installed=installed)
        if container not in keys.MANAGEABLE:
            return RedirectResponse("/", status_code=303)
        backend = app.state.backend
        installed = any(s.name == container for s in backend.list_services())
        if not installed:
            return render(request, "keys.html", container=container, clients=[], error="",
                          created_name="", config="", qr="", placeholder=False,
                          placeholder_name="", installed=False, missing=True)
        try:
            clients = keys.list_clients(backend, container)
        except ContainerNotFound:
            return render(request, "keys.html", container=container, clients=[], error="",
                          created_name="", config="", qr="", placeholder=False,
                          placeholder_name="", installed=False, missing=True)
        except keys.AWGError as exc:
            clients, error = [], str(exc)
        proto_info = {}
        try:
            iface = awg.parse_wg_conf(configedit.read_config(backend, container)).interface
            proto_info = {"port": iface.get("ListenPort", ""), "subnet": iface.get("Address", "")}
        except Exception:
            pass
        return render(request, "keys.html", container=container, clients=clients, error=error,
                      created_name=created_name, config=config, qr=qr, proto_info=proto_info,
                      placeholder=False, placeholder_name="", installed=True, missing=False)

    @app.post("/keys/{container}/create")
    def create_key(request: Request, container: str, name: str = Form(...)):
        if (r := require_session(request)) is not None:
            return r
        if container not in keys.MANAGEABLE:
            return RedirectResponse("/", status_code=303)
        try:
            if not any(s.name == container for s in app.state.backend.list_services()):
                return RedirectResponse(f"/keys/{container}", status_code=303)
            client_name, config_text, vpn_link = keys.create_client(
                app.state.backend, container, name, ENDPOINT_HOST, ENDPOINT_PORT)
        except keys.AWGError as exc:
            return RedirectResponse(
                f"/keys/{container}?error={urllib.parse.quote(str(exc))}", status_code=303)
        except Exception as exc:
            # Surface the real cause on the page instead of a bare 500.
            return RedirectResponse(
                f"/keys/{container}?error={urllib.parse.quote(f'{type(exc).__name__}: {exc}')}",
                status_code=303)
        # One-time view: config lives only in this page, never stored by the panel.
        vpn_frames = [_qr_data_uri(f, "L") for f in amnezia_fmt.vpn_qr_frames(vpn_link)]
        return render(request, "created.html", container=container,
                      created_name=client_name, config=config_text,
                      qr=_qr_data_uri(config_text),
                      vpn_link=vpn_link, vpn_frames=vpn_frames,
                      endpoint_ok=bool(ENDPOINT_HOST))

    @app.post("/keys/{container}/revoke")
    def revoke_key(request: Request, container: str, client_id: str = Form(...)):
        if (r := require_session(request)) is not None:
            return r
        if container not in keys.MANAGEABLE:
            return RedirectResponse("/", status_code=303)
        try:
            keys.revoke_client(app.state.backend, container, client_id)
        except ContainerNotFound:
            return RedirectResponse(f"/keys/{container}", status_code=303)
        except keys.AWGError as exc:
            return RedirectResponse(
                f"/keys/{container}?error={urllib.parse.quote(str(exc))}", status_code=303)
        return RedirectResponse(f"/keys/{container}", status_code=303)

    @app.get("/extras")
    def extras_root(request: Request):
        if (r := require_session(request)) is not None:
            return r
        return RedirectResponse("/extras/mtproxy", status_code=303)

    @app.get("/extras/{service}", response_class=HTMLResponse)
    def extras_page(request: Request, service: str):
        if (r := require_session(request)) is not None:
            return r
        if service not in ("mtproxy", "telemt", "dns"):
            return RedirectResponse("/extras/mtproxy", status_code=303)
        backend = app.state.backend
        host = ENDPOINT_HOST or request.url.hostname or ""
        proxy = dns = None
        qrs = {}
        if service == "mtproxy":
            proxy = extras.mtproxy_info(backend, host)
            qrs = {l.tg_link: _qr_data_uri(l.tg_link) for l in proxy.links}
        elif service == "telemt":
            proxy = extras.telemt_info(backend, host)
            qrs = {l.tg_link: _qr_data_uri(l.tg_link) for l in proxy.links}
        else:
            dns = extras.dns_info(backend)
        return render(request, "extras.html", service=service, proxy=proxy, dns=dns,
                      qrs=qrs, endpoint_host=host)

    @app.get("/config/{container}", response_class=HTMLResponse)
    def config_page(request: Request, container: str, applied: str = "", err: str = ""):
        if (r := require_session(request)) is not None:
            return r
        if container not in configedit.SPECS:
            return RedirectResponse("/", status_code=303)
        backend = app.state.backend
        try:
            text = configedit.read_config(backend, container)
            backups = configedit.list_backups(backend, container)
        except Exception:
            return RedirectResponse("/", status_code=303)
        cfg = awg.parse_wg_conf(text) if configedit.SPECS[container].fmt == "awg" else None
        fmt = configedit.SPECS[container].fmt
        back_url = f"/keys/{container}" if fmt == "awg" else "/extras/telemt"
        return render(request, "config.html", spec_container=container, text=text,
                      errors=[err] if err else [], backups=backups, applied=applied,
                      field_specs=configedit.FIELD_SPECS,
                      field_sections=configedit.FIELD_SECTIONS,
                      interface=cfg.interface if cfg else {},
                      fmt=fmt, back_url=back_url)

    @app.post("/config/{container}", response_class=HTMLResponse)
    def config_save(request: Request, container: str, text: str = Form(...)):
        if (r := require_session(request)) is not None:
            return r
        if container not in configedit.SPECS:
            return RedirectResponse("/", status_code=303)
        backend = app.state.backend
        fmt = configedit.SPECS[container].fmt
        back_url = f"/keys/{container}" if fmt == "awg" else "/extras/telemt"
        try:
            configedit.apply_config(backend, container, text)
        except keys.AWGError as exc:
            # Keep the field form populated from the submitted text on errors.
            submitted = awg.parse_wg_conf(text).interface if fmt == "awg" else {}
            return render(request, "config.html", spec_container=container, text=text,
                          errors=str(exc).split("; "),
                          backups=configedit.list_backups(backend, container),
                          applied="", field_specs=configedit.FIELD_SPECS,
                          field_sections=configedit.FIELD_SECTIONS,
                          interface=submitted, fmt=fmt, back_url=back_url)
        return RedirectResponse(f"/config/{container}?applied=1", status_code=303)

    @app.post("/config/{container}/restore")
    def config_restore(request: Request, container: str, backup: str = Form(...)):
        if (r := require_session(request)) is not None:
            return r
        if container not in configedit.SPECS:
            return RedirectResponse("/", status_code=303)
        try:
            configedit.restore_backup(app.state.backend, container, backup)
        except keys.AWGError as exc:
            return RedirectResponse(
                f"/config/{container}?err={urllib.parse.quote(str(exc))}", status_code=303)
        return RedirectResponse(f"/config/{container}?applied=restored", status_code=303)

    @app.get("/healthz")
    def healthz():
        return {"ok": True}


app = create_app()
