"""Отправка почты по SMTP-настройкам из БД. Используется для писем сброса пароля."""
import smtplib
from email.message import EmailMessage

from . import db


def is_configured() -> bool:
    return bool(db.get_setting("smtp_host"))


def send_mail(to: str, subject: str, body: str) -> None:
    """Синхронная отправка (роут выполняется в threadpool). Бросает при ошибке."""
    host = db.get_setting("smtp_host")
    if not host:
        raise RuntimeError("SMTP не настроен")
    port = int(db.get_setting("smtp_port") or "587")
    tls = (db.get_setting("smtp_tls") or "starttls").lower()
    user = db.get_setting("smtp_user")
    password = db.get_setting("smtp_password")
    sender = db.get_setting("smtp_from") or user

    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)

    if tls == "ssl":
        server: smtplib.SMTP = smtplib.SMTP_SSL(host, port, timeout=15)
    else:
        server = smtplib.SMTP(host, port, timeout=15)
    try:
        if tls == "starttls":
            server.starttls()
        if user:
            server.login(user, password)
        server.send_message(msg)
    finally:
        server.quit()
