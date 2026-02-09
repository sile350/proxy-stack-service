# ============================================================
# Dockerfile — 3Proxy + HAProxy Proxy Stack
# Базовый образ: Ubuntu 24.04 LTS (Noble Numbat)
# Multi-stage build, rootless-ready
# ============================================================

# ── Stage 1: Сборка 3proxy из исходников ────────────────────
FROM ubuntu:24.04 AS builder-3proxy

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        git \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ARG THREEPROXY_VERSION=0.9.4
RUN git clone --depth 1 --branch "${THREEPROXY_VERSION}" \
        https://github.com/3proxy/3proxy.git /build/3proxy \
    && cd /build/3proxy \
    && make -f Makefile.Linux \
    && strip bin/3proxy \
    && cp bin/3proxy /usr/local/bin/3proxy

# ── Stage 2: Runtime (Ubuntu 24.04) ────────────────────────
FROM ubuntu:24.04

LABEL maintainer="proxy-stack"
LABEL description="3Proxy + HAProxy TCP Proxy Stack on Ubuntu 24.04 (no TLS termination)"
LABEL org.opencontainers.image.base.name="ubuntu:24.04"

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

# Установка HAProxy, Python 3, gosu, утилит
RUN apt-get update && apt-get install -y --no-install-recommends \
        haproxy \
        python3 \
        python3-pip \
        python3-venv \
        tini \
        gosu \
        procps \
        curl \
        net-tools \
        iputils-ping \
        ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Копируем 3proxy из builder
COPY --from=builder-3proxy /usr/local/bin/3proxy /usr/local/bin/3proxy
RUN chmod 755 /usr/local/bin/3proxy

# Рабочие директории
RUN mkdir -p /opt/proxy-stack/lib \
             /var/log/proxy-stack \
             /var/run/proxy-stack \
             /opt/proxy-stack/3proxy

# Python зависимости (через venv, как рекомендует Ubuntu)
COPY requirements.txt /opt/proxy-stack/
RUN python3 -m venv /opt/proxy-stack/venv \
    && /opt/proxy-stack/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/proxy-stack/venv/bin/pip install --no-cache-dir -r /opt/proxy-stack/requirements.txt

# Код приложения
COPY proxy_stack.py /opt/proxy-stack/
COPY lib/ /opt/proxy-stack/lib/
COPY config.yml /opt/proxy-stack/

# Entrypoint-скрипт
COPY deploy/docker/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

WORKDIR /opt/proxy-stack

# Создание непривилегированного пользователя (Ubuntu-style)
# Группа proxy уже существует в Ubuntu 24.04, поэтому создаём только если нет
RUN getent group proxy >/dev/null || groupadd --system proxy \
    && id -u proxy >/dev/null 2>&1 || useradd --system --gid proxy --home-dir /opt/proxy-stack --shell /usr/sbin/nologin --no-create-home proxy \
    && chown -R proxy:proxy /opt/proxy-stack /var/log/proxy-stack /var/run/proxy-stack

# Порты: HTTP proxy, SOCKS proxy, monitoring, HAProxy stats
EXPOSE 3128 1080 9100 8404

# Health check
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -sf http://127.0.0.1:9100/health \
        | /opt/proxy-stack/venv/bin/python3 -c \
          "import sys,json; d=json.load(sys.stdin); sys.exit(0 if d['status']=='healthy' else 1)" \
        || exit 1

# PATH: venv Python первый в очереди
ENV PATH="/opt/proxy-stack/venv/bin:${PATH}"

# Entrypoint через tini (PID 1) → entrypoint.sh (фикс прав) → оркестратор
ENTRYPOINT ["tini", "--", "/entrypoint.sh"]

# По умолчанию: start в foreground-режиме (процесс не завершается)
CMD ["start", "-c", "/opt/proxy-stack/config.yml", "--foreground"]
