# ─────────────────────────────────────────────────────────────────────────────
# trusttunnel-web — панель + VPN-endpoint в ОДНОМ образе.
#   • FastAPI/uvicorn отдаёт кабинет (/) и админку (/admin);
#   • тот же процесс супервизит trusttunnel_endpoint (data-plane);
#   • certbot нужен только для режима сертификатов "letsencrypt".
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

# Версия официального endpoint'а TrustTunnel (статический бинарь из releases).
ARG ENDPOINT_VERSION=1.0.33

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl certbot \
    && rm -rf /var/lib/apt/lists/*

# Скачиваем и распаковываем бинарь endpoint'а (в репозиторий не коммитим).
RUN mkdir -p /opt/trusttunnel \
    && curl -fsSL -o /tmp/tt.tar.gz \
        "https://github.com/TrustTunnel/TrustTunnel/releases/download/v${ENDPOINT_VERSION}/trusttunnel-v${ENDPOINT_VERSION}-linux-x86_64.tar.gz" \
    && tar -xzf /tmp/tt.tar.gz -C /tmp \
    && find /tmp -name trusttunnel_endpoint -exec cp {} /opt/trusttunnel/trusttunnel_endpoint \; \
    && chmod +x /opt/trusttunnel/trusttunnel_endpoint \
    && rm -rf /tmp/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

ENV DATA_DIR=/data \
    ENDPOINT_BIN=/opt/trusttunnel/trusttunnel_endpoint \
    ENDPOINT_WORKDIR=/opt/trusttunnel \
    CERT_DIR=/etc/letsencrypt

EXPOSE 8000 8443
VOLUME ["/data"]

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
