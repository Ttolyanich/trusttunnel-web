#!/usr/bin/env python3
"""Управление администраторами в базе trusttunnel-web.

Использование:
    python manage_admins.py --db /data/trusttunnel-web.db create <email> <password>
    python manage_admins.py --db /data/trusttunnel-web.db list
    python manage_admins.py --db /data/trusttunnel-web.db delete <email>
    python manage_admins.py --db /data/trusttunnel-web.db passwd <email> <password>
"""
import argparse
import sqlite3
from argon2 import PasswordHasher

def main() -> int:
    ap = argparse.ArgumentParser(description="Управление администраторами в базе trusttunnel-web.")
    ap.add_argument("--db", default="/data/trusttunnel-web.db", help="Путь к SQLite-базе (по умолчанию /data/trusttunnel-web.db)")
    
    subparsers = ap.add_subparsers(dest="command", required=True)
    
    # Create admin
    p_create = subparsers.add_parser("create", help="Создать нового администратора")
    p_create.add_argument("email", help="Email/логин нового администратора")
    p_create.add_argument("password", help="Пароль администратора")
    p_create.add_argument("--recovery-email", help="Почта восстановления (опционально)")
    
    # List admins
    subparsers.add_parser("list", help="Показать список всех администраторов")
    
    # Delete admin
    p_delete = subparsers.add_parser("delete", help="Удалить администратора")
    p_delete.add_argument("email", help="Email/логин администратора для удаления")
    
    # Change password
    p_passwd = subparsers.add_parser("passwd", help="Изменить пароль администратора")
    p_passwd.add_argument("email", help="Email/логин администратора")
    p_passwd.add_argument("password", help="Новый пароль")
    
    args = ap.parse_args()
    
    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row
    
    ph = PasswordHasher()
    
    if args.command == "create":
        email = args.email.strip().lower()
        rec_email = args.recovery_email.strip().lower() if args.recovery_email else None
        hashed = ph.hash(args.password)
        try:
            conn.execute("INSERT INTO admins(email, recovery_email, password_hash) VALUES (?, ?, ?)", (email, rec_email, hashed))
            conn.commit()
            print(f"Администратор {email} успешно создан.")
        except sqlite3.IntegrityError:
            print(f"Ошибка: Администратор с email/логином {email} уже существует.")
            return 1
            
    elif args.command == "list":
        rows = conn.execute("SELECT id, email, recovery_email, created_at FROM admins").fetchall()
        if not rows:
            print("Администраторов не найдено.")
            return 0
        print(f"{'ID':<5} | {'Email/Логин':<25} | {'Почта восстановления':<25} | {'Дата создания':<20}")
        print("-" * 84)
        for r in rows:
            rec = r['recovery_email'] or "—"
            print(f"{r['id']:<5} | {r['email']:<25} | {rec:<25} | {r['created_at']:<20}")
            
    elif args.command == "delete":
        email = args.email.strip().lower()
        res = conn.execute("DELETE FROM admins WHERE email = ? OR recovery_email = ?", (email, email))
        conn.commit()
        if res.rowcount > 0:
            print(f"Администратор {email} успешно удален.")
        else:
            print(f"Администратор {email} не найден.")
            return 1
            
    elif args.command == "passwd":
        email = args.email.strip().lower()
        hashed = ph.hash(args.password)
        res = conn.execute("UPDATE admins SET password_hash = ? WHERE email = ? OR recovery_email = ?", (hashed, email, email))
        conn.commit()
        if res.rowcount > 0:
            print(f"Пароль администратора {email} успешно обновлен.")
        else:
            print(f"Администратор {email} не найден.")
            return 1
            
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
