#!/usr/bin/env python3
"""Импорт пользователей и конфигов в базу trusttunnel-web из JSON.

Формат входного JSON (например, экспорт из старого Postgres-стека):

    {
      "users":   [{"email": "...", "password_hash": "$argon2...", "status": "active"}],
      "configs": [{"user_email": "...", "tt_username": "...", "tt_password": "...", "label": null}]
    }

password_hash из исходного trusttunnel-panel — argon2 — переносится как есть
(тот же алгоритм). Если хеша нет, укажите "password" — он будет захеширован.

Запуск:
    python import_data.py --db /data/trusttunnel-web.db --input export.json
"""
import argparse
import json
import sqlite3
import sys


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True, help="путь к SQLite-базе trusttunnel-web")
    ap.add_argument("--input", required=True, help="JSON-файл экспорта")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    data = json.loads(open(args.input, encoding="utf-8").read())
    users = data.get("users", [])
    configs = data.get("configs", [])

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")

    hasher = None

    def ensure_hash(u: dict) -> str:
        nonlocal hasher
        if u.get("password_hash"):
            return u["password_hash"]
        if u.get("password"):
            if hasher is None:
                from argon2 import PasswordHasher  # локальный импорт — нужен только тут
                hasher = PasswordHasher()
            return hasher.hash(u["password"])
        raise SystemExit(f"user {u.get('email')}: нет ни password_hash, ни password")

    added_u = skipped_u = added_c = 0
    email_to_id: dict[str, int] = {}

    for u in users:
        email = (u["email"] or "").strip().lower()
        row = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if row:
            email_to_id[email] = row["id"]
            skipped_u += 1
            continue
        cur = conn.execute(
            "INSERT INTO users(email, password_hash, status) VALUES (?, ?, ?)",
            (email, ensure_hash(u), u.get("status", "active")),
        )
        email_to_id[email] = cur.lastrowid
        added_u += 1

    for c in configs:
        email = (c["user_email"] or "").strip().lower()
        uid = email_to_id.get(email)
        if uid is None:
            row = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
            uid = row["id"] if row else None
        if uid is None:
            print(f"! конфиг {c.get('tt_username')} — пользователь {email} не найден, пропуск")
            continue
        exists = conn.execute(
            "SELECT 1 FROM configs WHERE tt_username = ?", (c["tt_username"],)
        ).fetchone()
        if exists:
            continue
        conn.execute(
            "INSERT INTO configs(user_id, tt_username, tt_password, label) VALUES (?, ?, ?, ?)",
            (uid, c["tt_username"], c["tt_password"], c.get("label")),
        )
        added_c += 1

    if args.dry_run:
        conn.rollback()
        print("[dry-run] изменения откатаны")
    else:
        conn.commit()
    conn.close()

    print(f"users:   +{added_u} добавлено, {skipped_u} уже было")
    print(f"configs: +{added_c} добавлено")
    return 0


if __name__ == "__main__":
    sys.exit(main())
