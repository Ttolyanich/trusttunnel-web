"""Клиентская часть: /login, /register, /dashboard, конфиги, скачивание."""
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response

from . import conninfo, db, endpoint, security, webauth
from .templating import templates

router = APIRouter()


def _brand() -> str:
    return db.get_setting("brand_name", "TrustTunnel")


@router.get("/", response_class=HTMLResponse)
def index(request: Request):
    if webauth.current_user(request):
        return RedirectResponse("/dashboard", 302)
    return RedirectResponse("/login", 302)


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse(
        request, "login.html",
        {"brand": _brand(), "registration_enabled": db.get_setting("registration_enabled") == "1", "error": None},
    )


@router.post("/login")
def login(request: Request, email: str = Form(), password: str = Form()):
    user = db.get_user_by_email(email)
    if user is None or not security.verify_password(password, user["password_hash"]):
        return templates.TemplateResponse(
            request, "login.html",
            {"brand": _brand(), "registration_enabled": db.get_setting("registration_enabled") == "1",
             "error": "Неверный e-mail или пароль"},
            status_code=401,
        )
    if user["status"] != "active":
        return templates.TemplateResponse(
            request, "login.html",
            {"brand": _brand(), "registration_enabled": db.get_setting("registration_enabled") == "1",
             "error": "Аккаунт заблокирован"},
            status_code=403,
        )
    resp = RedirectResponse("/dashboard", 302)
    resp.set_cookie(
        webauth.USER_COOKIE, security.create_session_token(str(user["id"]), "user"),
        httponly=True, samesite="lax", max_age=60 * 60 * 24 * 30,
    )
    return resp


@router.get("/register", response_class=HTMLResponse)
def register_form(request: Request):
    if db.get_setting("registration_enabled") != "1":
        return RedirectResponse("/login", 302)
    return templates.TemplateResponse(
        request, "register.html", {"brand": _brand(), "error": None},
    )


@router.post("/register")
def register(request: Request, email: str = Form(), password: str = Form()):
    if db.get_setting("registration_enabled") != "1":
        return RedirectResponse("/login", 302)
    email = email.strip().lower()
    if len(password) < 6:
        return templates.TemplateResponse(
            request, "register.html", {"brand": _brand(), "error": "Пароль слишком короткий (мин. 6)"},
            status_code=400,
        )
    if db.get_user_by_email(email):
        return templates.TemplateResponse(
            request, "register.html", {"brand": _brand(), "error": "Такой e-mail уже зарегистрирован"},
            status_code=400,
        )
    user_id = db.create_user(email, security.hash_password(password))
    resp = RedirectResponse("/dashboard", 302)
    resp.set_cookie(
        webauth.USER_COOKIE, security.create_session_token(str(user_id), "user"),
        httponly=True, samesite="lax", max_age=60 * 60 * 24 * 30,
    )
    return resp


@router.get("/logout")
def logout():
    resp = RedirectResponse("/login", 302)
    resp.delete_cookie(webauth.USER_COOKIE)
    return resp


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    user = webauth.current_user(request)
    if not user:
        return RedirectResponse("/login", 302)
    settings = db.get_settings()
    configs = [conninfo.connection_info(c, settings) | {"id": c["id"]}
               for c in db.list_user_configs(user["id"])]
    return templates.TemplateResponse(
        request, "dashboard.html",
        {
            "brand": _brand(), "user": user, "configs": configs,
            "endpoint_ready": bool(endpoint.effective_domain(settings)),
            "error": request.query_params.get("error"),
        },
    )


@router.post("/configs")
def create_config(request: Request, label: str = Form("")):
    user = webauth.current_user(request)
    if not user:
        return RedirectResponse("/login", 302)
    suffix = security.new_token(4)
    db.create_config(
        user["id"],
        tt_username=f"u{user['id']}-{suffix}",
        tt_password=security.new_token(9),
        label=label.strip() or None,
    )
    endpoint.manager.apply_credentials()
    return RedirectResponse("/dashboard", 302)


@router.post("/configs/{config_id}/delete")
def delete_config(request: Request, config_id: int):
    user = webauth.current_user(request)
    if not user:
        return RedirectResponse("/login", 302)
    cfg = db.get_config(config_id)
    if cfg and cfg["user_id"] == user["id"]:
        db.delete_config(config_id)
        endpoint.manager.apply_credentials()
    return RedirectResponse("/dashboard", 302)


@router.get("/config/{config_id}/download")
def download_config(request: Request, config_id: int, fmt: str = "txt"):
    user = webauth.current_user(request)
    if not user:
        return RedirectResponse("/login", 302)
    cfg = db.get_config(config_id)
    if not cfg or cfg["user_id"] != user["id"]:
        return PlainTextResponse("Not found", status_code=404)
    info = conninfo.connection_info(cfg, db.get_settings())
    raw_name = cfg["label"] or cfg["tt_username"]
    safe = "".join(ch for ch in raw_name if ch.isascii() and (ch.isalnum() or ch in "-_")) or cfg["tt_username"]
    if fmt == "json":
        body, media, ext = conninfo.as_download_json(info), "application/json", "json"
    else:
        body, media, ext = conninfo.as_download_text(info, _brand()), "text/plain; charset=utf-8", "txt"
    return Response(
        content=body, media_type=media,
        headers={"Content-Disposition": f'attachment; filename="trusttunnel-{safe}.{ext}"'},
    )
