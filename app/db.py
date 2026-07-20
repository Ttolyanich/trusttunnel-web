"""Слой доступа к данным поверх stdlib sqlite3 (WAL). Никаких внешних БД."""
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from . import config, security

# ── Настройки по умолчанию (таблица settings — key/value) ────────────────────
DEFAULT_SETTINGS: dict[str, str] = {
    # Сертификаты / домены
    "cert_mode": "external",          # external | letsencrypt
    "panel_domain": "",               # домен, за которым живёт панель (домен A)
    "connection_hidden": "0",         # прятать подключение за отдельным доменом (домен B)
    "conn_domain": "",                # домен сертификата endpoint'а (что видит DPI)
    "le_email": "",                   # e-mail для Let's Encrypt (режим letsencrypt)
    # Параметры подключения, которые показываем клиенту
    "conn_address": "",               # host/IP сервера (пусто → panel_domain/PUBLIC_ADDRESS)
    "conn_port": "8443",
    "conn_sni": "",                   # custom SNI (пусто = не нужен)
    "conn_protocol": "QUIC",
    # Какие поля показывать клиенту в кабинете
    "show_address": "1",
    "show_port": "1",
    "show_domain": "1",
    "show_sni": "1",
    "show_username": "1",
    "show_password": "1",
    "show_protocol": "1",
    # Прочее
    "registration_enabled": "1",      # открытая регистрация в клиентской части
    "brand_name": "TrustTunnel",      # заголовок в интерфейсе
    # SMTP (для писем сброса пароля)
    "smtp_host": "",
    "smtp_port": "587",
    "smtp_user": "",
    "smtp_password": "",
    "smtp_from": "",
    "smtp_tls": "starttls",           # starttls | ssl | none
    "portal_url": "",                 # публичный URL панели для ссылок в письмах
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS admins (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'active',   -- active | blocked
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS configs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tt_username TEXT NOT NULL UNIQUE,
    tt_password TEXT NOT NULL,          -- plaintext: требование credentials.toml
    label       TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    revoked_at  TEXT
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS email_tokens (
    token      TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose    TEXT NOT NULL,          -- reset
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_configs_user   ON configs(user_id);
CREATE INDEX IF NOT EXISTS idx_configs_active ON configs(revoked_at);
"""


@contextmanager
def connect():
    """Соединение с включёнными внешними ключами и Row-фабрикой."""
    conn = sqlite3.connect(config.DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    """Создать схему, включить WAL, засеять настройки и bootstrap-админа."""
    Path(config.DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    with connect() as conn:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(_SCHEMA)
        # Настройки: добавляем только отсутствующие ключи (не затираем правки админа).
        for key, value in DEFAULT_SETTINGS.items():
            conn.execute(
                "INSERT OR IGNORE INTO settings(key, value) VALUES (?, ?)", (key, value)
            )
        # Bootstrap-админ — если админов ещё нет.
        n = conn.execute("SELECT COUNT(*) AS c FROM admins").fetchone()["c"]
        if n == 0:
            conn.execute(
                "INSERT INTO admins(email, password_hash) VALUES (?, ?)",
                (
                    config.BOOTSTRAP_ADMIN_EMAIL.strip().lower(),
                    security.hash_password(config.BOOTSTRAP_ADMIN_PASSWORD),
                ),
            )


# ── Настройки ────────────────────────────────────────────────────────────────
def get_settings() -> dict[str, str]:
    with connect() as conn:
        rows = conn.execute("SELECT key, value FROM settings").fetchall()
    merged = dict(DEFAULT_SETTINGS)
    merged.update({r["key"]: r["value"] for r in rows if r["value"] is not None})
    return merged


def get_setting(key: str, default: str = "") -> str:
    with connect() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    if row is None or row["value"] is None:
        return DEFAULT_SETTINGS.get(key, default)
    return row["value"]


def set_settings(items: dict[str, str]) -> None:
    with connect() as conn:
        for key, value in items.items():
            conn.execute(
                "INSERT INTO settings(key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )


# ── Админы ───────────────────────────────────────────────────────────────────
def get_admin_by_email(email: str) -> sqlite3.Row | None:
    with connect() as conn:
        return conn.execute(
            "SELECT * FROM admins WHERE email = ?", (email.strip().lower(),)
        ).fetchone()


def set_admin_password(admin_id: int, password_hash: str) -> None:
    with connect() as conn:
        conn.execute(
            "UPDATE admins SET password_hash = ? WHERE id = ?", (password_hash, admin_id)
        )


def list_admins() -> list[sqlite3.Row]:
    with connect() as conn:
        return conn.execute("SELECT id, email, created_at FROM admins ORDER BY id DESC").fetchall()


def create_admin(email: str, password_hash: str) -> int:
    with connect() as conn:
        cur = conn.execute(
            "INSERT INTO admins(email, password_hash) VALUES (?, ?)",
            (email.strip().lower(), password_hash),
        )
        return cur.lastrowid


def delete_admin(admin_id: int) -> None:
    with connect() as conn:
        conn.execute("DELETE FROM admins WHERE id = ?", (admin_id,))


# ── Пользователи ─────────────────────────────────────────────────────────────
def get_user_by_email(email: str) -> sqlite3.Row | None:
    with connect() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE email = ?", (email.strip().lower(),)
        ).fetchone()


def get_user(user_id: int) -> sqlite3.Row | None:
    with connect() as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def create_user(email: str, password_hash: str, status: str = "active") -> int:
    with connect() as conn:
        cur = conn.execute(
            "INSERT INTO users(email, password_hash, status) VALUES (?, ?, ?)",
            (email.strip().lower(), password_hash, status),
        )
        return cur.lastrowid


def list_users() -> list[sqlite3.Row]:
    with connect() as conn:
        return conn.execute(
            "SELECT u.*, "
            "(SELECT COUNT(*) FROM configs c WHERE c.user_id = u.id AND c.revoked_at IS NULL) "
            "AS config_count "
            "FROM users u ORDER BY u.id DESC"
        ).fetchall()


def set_user_status(user_id: int, status: str) -> None:
    with connect() as conn:
        conn.execute("UPDATE users SET status = ? WHERE id = ?", (status, user_id))


def set_user_password(user_id: int, password_hash: str) -> None:
    with connect() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id)
        )


def set_user_email(user_id: int, email: str) -> None:
    with connect() as conn:
        conn.execute(
            "UPDATE users SET email = ? WHERE id = ?", (email.strip().lower(), user_id)
        )


def delete_user(user_id: int) -> None:
    with connect() as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))


# ── Конфиги ──────────────────────────────────────────────────────────────────
def create_config(user_id: int, tt_username: str, tt_password: str, label: str | None) -> int:
    with connect() as conn:
        cur = conn.execute(
            "INSERT INTO configs(user_id, tt_username, tt_password, label) VALUES (?, ?, ?, ?)",
            (user_id, tt_username, tt_password, label),
        )
        return cur.lastrowid


def get_config(config_id: int) -> sqlite3.Row | None:
    with connect() as conn:
        return conn.execute("SELECT * FROM configs WHERE id = ?", (config_id,)).fetchone()


def list_user_configs(user_id: int) -> list[sqlite3.Row]:
    with connect() as conn:
        return conn.execute(
            "SELECT * FROM configs WHERE user_id = ? AND revoked_at IS NULL ORDER BY id DESC",
            (user_id,),
        ).fetchall()


def list_all_configs() -> list[sqlite3.Row]:
    with connect() as conn:
        return conn.execute(
            "SELECT c.*, u.email AS user_email FROM configs c "
            "JOIN users u ON u.id = c.user_id "
            "WHERE c.revoked_at IS NULL ORDER BY c.id DESC"
        ).fetchall()


def delete_config(config_id: int) -> None:
    with connect() as conn:
        conn.execute("DELETE FROM configs WHERE id = ?", (config_id,))


def active_credentials() -> list[dict]:
    """Все креды активных конфигов активных (не заблокированных) юзеров → credentials.toml."""
    with connect() as conn:
        rows = conn.execute(
            "SELECT c.tt_username AS username, c.tt_password AS password "
            "FROM configs c JOIN users u ON u.id = c.user_id "
            "WHERE c.revoked_at IS NULL AND u.status = 'active'"
        ).fetchall()
    return [{"username": r["username"], "password": r["password"]} for r in rows]


def create_email_token(token: str, user_id: int, purpose: str, expires_at: str) -> None:
    with connect() as conn:
        conn.execute(
            "INSERT INTO email_tokens(token, user_id, purpose, expires_at) VALUES (?, ?, ?, ?)",
            (token, user_id, purpose, expires_at),
        )


def get_email_token(token: str) -> sqlite3.Row | None:
    with connect() as conn:
        return conn.execute("SELECT * FROM email_tokens WHERE token = ?", (token,)).fetchone()


def delete_email_token(token: str) -> None:
    with connect() as conn:
        conn.execute("DELETE FROM email_tokens WHERE token = ?", (token,))


def counts() -> dict[str, int]:
    with connect() as conn:
        users = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        blocked = conn.execute(
            "SELECT COUNT(*) AS c FROM users WHERE status = 'blocked'"
        ).fetchone()["c"]
        cfgs = conn.execute(
            "SELECT COUNT(*) AS c FROM configs WHERE revoked_at IS NULL"
        ).fetchone()["c"]
    return {"users": users, "blocked": blocked, "configs": cfgs}
