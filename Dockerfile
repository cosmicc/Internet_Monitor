FROM python:3.12-slim

ARG APP_UID=10001
ARG APP_GID=10001
ARG APP_VERSION=0.2.0

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    FLASK_ENV=production

LABEL org.opencontainers.image.title="Internet Monitor" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.source="https://github.com/cosmicc/Internet_Monitor"

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        dnsutils \
        fping && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY internet_monitor/ /app/internet_monitor/
COPY entrypoint.sh /entrypoint.sh

RUN groupadd --gid "${APP_GID}" internetmonitor && \
    useradd --uid "${APP_UID}" --gid internetmonitor --no-create-home \
        --home-dir /app --shell /usr/sbin/nologin internetmonitor && \
    chown -R internetmonitor:internetmonitor /app && \
    chmod +x /entrypoint.sh

USER internetmonitor

EXPOSE 5005

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -m internet_monitor.healthcheck || exit 1

ENTRYPOINT ["/entrypoint.sh"]
