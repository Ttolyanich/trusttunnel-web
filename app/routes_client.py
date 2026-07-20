"""Клиентская часть: /login, /register, /dashboard, конфиги, сброс пароля, скачивание."""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response

from . import conninfo, db, endpoint, mailer, security, webauth
from .templating import templates

router = APIRouter()


def _brand() -> str:
    return db.get_setting("brand_name", "TrustTunnel")


@router.get("/", response_class=HTMLResponse)
def index(request: Request):
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


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse(
        request, "login.html",
        {"brand": _brand(), "registration_enabled": db.get_setting("registration_enabled") == "1",
         "error": None, "msg": request.query_params.get("msg")},
    )


@router.post("/login")
def login(request: Request, email: str = Form(), password: str = Form()):
    user = db.get_user_by_email(email)
    if user is None or not security.verify_password(password, user["password_hash"]):
        return templates.TemplateResponse(
            request, "login.html",
            {"brand": _brand(), "registration_enabled": db.get_setting("registration_enabled") == "1",
             "error": "Неверный e-mail или пароль", "msg": None},
            status_code=401,
        )
    if user["status"] == "pending":
        return templates.TemplateResponse(
            request, "login.html",
            {"brand": _brand(), "registration_enabled": db.get_setting("registration_enabled") == "1",
             "error": "Ваш аккаунт ожидает подтверждения администратором", "msg": None},
            status_code=403,
        )
    elif user["status"] != "active":
        return templates.TemplateResponse(
            request, "login.html",
            {"brand": _brand(), "registration_enabled": db.get_setting("registration_enabled") == "1",
             "error": "Аккаунт заблокирован", "msg": None},
            status_code=403,
        )
    resp = RedirectResponse("/", 302)
    resp.set_cookie(
        webauth.USER_COOKIE, security.create_session_token(str(user["id"]), "user"),
        httponly=True, samesite="lax", max_age=60 * 60 * 24 * 30,
    )
    return resp


@router.get("/register", response_class=HTMLResponse)
def register_form(request: Request):
    if db.get_setting("registration_enabled") != "1":
        return RedirectResponse("/login", 302)
    import random
    import hashlib
    a = random.randint(1, 9)
    b = random.randint(1, 9)
    ans = a + b
    salt = "trusttunnel-captcha-salt"
    h = hashlib.sha256(f"{ans}-{salt}".encode()).hexdigest()
    resp = templates.TemplateResponse(
        request, "register.html",
        {"brand": _brand(), "error": None, "captcha_a": a, "captcha_b": b},
    )
    resp.set_cookie("captcha_hash", h, max_age=300, httponly=True, samesite="lax")
    return resp


@router.post("/register")
def register(request: Request, email: str = Form(), password: str = Form(), captcha: str = Form()):
    if db.get_setting("registration_enabled") != "1":
        return RedirectResponse("/login", 302)
    import random
    import hashlib
    
    # Верификация капчи
    cookie_hash = request.cookies.get("captcha_hash")
    salt = "trusttunnel-captcha-salt"
    user_hash = hashlib.sha256(f"{captcha.strip()}-{salt}".encode()).hexdigest()
    if not cookie_hash or user_hash != cookie_hash:
        a = random.randint(1, 9)
        b = random.randint(1, 9)
        ans = a + b
        new_hash = hashlib.sha256(f"{ans}-{salt}".encode()).hexdigest()
        resp = templates.TemplateResponse(
            request, "register.html",
            {"brand": _brand(), "error": "Неверный ответ на проверочный вопрос", "captcha_a": a, "captcha_b": b},
            status_code=400,
        )
        resp.set_cookie("captcha_hash", new_hash, max_age=300, httponly=True, samesite="lax")
        return resp
        
    email = email.strip().lower()
    if len(password) < 6:
        a = random.randint(1, 9)
        b = random.randint(1, 9)
        ans = a + b
        new_hash = hashlib.sha256(f"{ans}-{salt}".encode()).hexdigest()
        resp = templates.TemplateResponse(
            request, "register.html",
            {"brand": _brand(), "error": "Пароль слишком короткий (мин. 6)", "captcha_a": a, "captcha_b": b},
            status_code=400,
        )
        resp.set_cookie("captcha_hash", new_hash, max_age=300, httponly=True, samesite="lax")
        return resp
        
    if db.get_user_by_email(email):
        a = random.randint(1, 9)
        b = random.randint(1, 9)
        ans = a + b
        new_hash = hashlib.sha256(f"{ans}-{salt}".encode()).hexdigest()
        resp = templates.TemplateResponse(
            request, "register.html",
            {"brand": _brand(), "error": "Такой e-mail уже зарегистрирован", "captcha_a": a, "captcha_b": b},
            status_code=400,
        )
        resp.set_cookie("captcha_hash", new_hash, max_age=300, httponly=True, samesite="lax")
        return resp
        
    db.create_user(email, security.hash_password(password), status="pending")
    resp = RedirectResponse("/login?msg=Регистрация успешна. Ожидайте подтверждения аккаунта администратором.", 302)
    resp.delete_cookie("captcha_hash")
    return resp


@router.get("/logout")
def logout():
    resp = RedirectResponse("/login", 302)
    resp.delete_cookie(webauth.USER_COOKIE)
    return resp


@router.get("/forgot", response_class=HTMLResponse)
def forgot_form(request: Request):
    return templates.TemplateResponse(request, "forgot.html", {"brand": _brand(), "sent": False})


@router.post("/forgot")
def forgot(request: Request, email: str = Form()):
    email = email.strip().lower()
    user = db.get_user_by_email(email)
    if user is not None:
        token = security.new_token(16)
        expires = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
        db.create_email_token(token, user["id"], "reset", expires)
        base = (db.get_setting("portal_url") or str(request.base_url).rstrip("/")).rstrip("/")
        link = f"{base}/reset?token={token}"
        if mailer.is_configured():
            try:
                mailer.send_mail(email, f"Сброс пароля — {_brand()}",
                                 f"Для сброса пароля перейдите по ссылке (действует 24 часа):\n\n{link}\n")
            except Exception as e:  # не палим наличие аккаунта, но логируем
                print(f"[mail] reset send failed for {email}: {e}")
        else:
            print(f"[mail] SMTP не настроен. Ссылка сброса для {email}: {link}")
    # Ответ одинаков независимо от наличия аккаунта.
    return templates.TemplateResponse(request, "forgot.html", {"brand": _brand(), "sent": True, "email": email})


@router.get("/reset", response_class=HTMLResponse)
def reset_form(request: Request, token: str = ""):
    return templates.TemplateResponse(
        request, "reset.html", {"brand": _brand(), "token": token, "error": None, "done": False},
    )


@router.post("/reset")
def reset(request: Request, token: str = Form(), password: str = Form()):
    row = db.get_email_token(token)
    ctx = {"brand": _brand(), "token": token, "error": None, "done": False}
    if not row or row["purpose"] != "reset" or row["expires_at"] < datetime.now(timezone.utc).isoformat():
        ctx["error"] = "Ссылка недействительна или устарела"
        return templates.TemplateResponse(request, "reset.html", ctx, status_code=400)
    if len(password) < 6:
        ctx["error"] = "Пароль слишком короткий (мин. 6)"
        return templates.TemplateResponse(request, "reset.html", ctx, status_code=400)
    db.set_user_password(row["user_id"], security.hash_password(password))
    db.delete_email_token(token)
    return templates.TemplateResponse(
        request, "reset.html", {"brand": _brand(), "token": "", "error": None, "done": True},
    )


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    return RedirectResponse("/", 302)


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
    return RedirectResponse("/", 302)


@router.post("/configs/{config_id}/delete")
def delete_config(request: Request, config_id: int):
    user = webauth.current_user(request)
    if not user:
        return RedirectResponse("/login", 302)
    cfg = db.get_config(config_id)
    if cfg and cfg["user_id"] == user["id"]:
        db.delete_config(config_id)
        endpoint.manager.apply_credentials()
    return RedirectResponse("/", 302)


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
