"""tt:// deeplink — компактная строка подключения для QR (совместимо с исходной панелью)."""
import base64


def build_deeplink(username: str, password: str, host: str, port: int) -> str:
    raw = f"{username}:{password}@{host}:{port}"
    return "tt://" + base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")
