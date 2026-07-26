"""Сборка client.toml для официального trusttunnel_client.exe.

Тот же контракт, что у trusttunnel-panel (форк, копия — не общий код). Веба
одно-нодовая, поэтому берём параметры подключения из conninfo.connection_info.

Формат (репо TrustTunnelClient):
    killswitch_enabled = false
    [endpoint]
    hostname = "<SNI>"; addresses = ["<host>:<port>"]
    username/password; upstream_protocol = "http2"|"http3"
    [listener.tun]
"""


def _quote(v: str) -> str:
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _upstream_protocol(protocol: str) -> str:
    p = (protocol or "").strip().lower()
    return "http3" if p in ("quic", "http3", "http/3", "h3") else "http2"


def build_client_toml(info: dict, killswitch: bool = False) -> str:
    """info = conninfo.connection_info(cfg, settings)."""
    sni = (info.get("sni") or "").strip() or (info.get("domain") or "").strip() \
        or (info.get("address") or "").strip()
    address = f"{info['address']}:{info['port']}"
    lines = [
        "# Сгенерировано trusttunnel-web. Не редактировать вручную.",
        f"killswitch_enabled = {'true' if killswitch else 'false'}",
        "killswitch_allow_ports = []",
        "",
        "[endpoint]",
        f"hostname = {_quote(sni)}",
        f"addresses = [{_quote(address)}]",
        f"username = {_quote(info['username'])}",
        f"password = {_quote(info['password'])}",
        f"upstream_protocol = {_quote(_upstream_protocol(info.get('protocol', 'QUIC')))}",
        "",
        "[listener.tun]",
        'included_routes = ["0.0.0.0/0", "2000::/3"]',
        "excluded_routes = []",
        "",
    ]
    return "\n".join(lines)
