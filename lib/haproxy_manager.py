"""
Менеджер HAProxy — генерация конфига, запуск, остановка, валидация.

КЛЮЧЕВОЙ ПРИНЦИП: TCP mode (mode tcp) — без TLS-терминации.
Это сохраняет TLS-отпечатки клиента (JA3/JA4) и предотвращает
детектирование прокси по несоответствию fingerprint.
"""

from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

from lib.config_loader import StackConfig
from lib.utils import read_component_pid, is_process_alive, stop_process_by_pid

logger = logging.getLogger("proxy-stack.haproxy")

# ──────────────────────────────────────────────────────────────
# Шаблон конфигурации HAProxy
# ──────────────────────────────────────────────────────────────

HAPROXY_CONFIG_TEMPLATE = """\
# ============================================================
# HAProxy — TCP Load Balancer для 3proxy
# Автосгенерировано proxy_stack.py — НЕ РЕДАКТИРОВАТЬ ВРУЧНУЮ
# ============================================================
# ВАЖНО: mode tcp — пропускаем трафик как есть, без TLS-терминации.
# Это сохраняет TLS fingerprints клиента (JA3/JA4).

global
    log stdout format raw local0
    maxconn 4096
    # Безопасность
    stats socket {stats_socket} mode 660 level admin
    # Производительность
    nbthread 4
    spread-checks 5
    # Не завершать TLS — работаем в чистом TCP
    tune.ssl.default-dh-param 0

defaults
    mode tcp
    log global
    option tcplog
    option dontlognull
    option redispatch
    retries {retries}
    timeout connect {timeout_connect}
    timeout client  {timeout_client}
    timeout server  {timeout_server}
    timeout check   5s

# ── Stats (опционально) ─────────────────────────────────────
{stats_section}

# ── HTTP Proxy Frontend ─────────────────────────────────────
frontend ft_http_proxy
    bind {bind_addr}:{http_port}
{bind_v6_http}
    mode tcp
    # TCP connection rate limit (anti-detect)
    stick-table type ip size 100k expire 30s store conn_rate(10s)
    tcp-request connection reject if {{ src_conn_rate gt {rate_limit} }}
    tcp-request connection track-sc0 src
    default_backend bk_http_proxy

# ── SOCKS Frontend ──────────────────────────────────────────
frontend ft_socks_proxy
    bind {bind_addr}:{socks_port}
{bind_v6_socks}
    mode tcp
    stick-table type ip size 100k expire 30s store conn_rate(10s)
    tcp-request connection reject if {{ src_conn_rate gt {rate_limit} }}
    tcp-request connection track-sc0 src
    default_backend bk_socks_proxy

# ── HTTP Proxy Backend ──────────────────────────────────────
backend bk_http_proxy
    mode tcp
    balance {balance_algorithm}
    option tcp-check
{http_backends}

# ── SOCKS Proxy Backend ────────────────────────────────────
backend bk_socks_proxy
    mode tcp
    balance {balance_algorithm}
    option tcp-check
{socks_backends}
"""

STATS_SECTION_TEMPLATE = """\
frontend stats
    bind {stats_bind}
    mode http
    stats enable
    stats uri {stats_uri}
    stats realm HAProxy\\ Statistics
    stats auth {stats_auth}
    stats refresh 10s
    stats show-legends
    stats show-node
"""


class HAProxyManager:
    """Управляет HAProxy: генерация конфига, запуск, остановка, валидация."""

    def __init__(self, config: StackConfig):
        self.config = config
        self.ha = config.haproxy
        self._process = None

    # ── Пути ─────────────────────────────────────────────────

    def _config_path(self) -> str:
        if self.ha.config_path:
            return self.ha.config_path
        return os.path.join(self.config.work_dir, "haproxy.cfg")

    def _pid_path(self) -> str:
        return os.path.join(self.config.pid_dir, "haproxy.pid")

    def _stats_socket(self) -> str:
        return os.path.join(self.config.work_dir, "haproxy.sock")

    # ── Генерация ────────────────────────────────────────────

    def _build_stats_section(self) -> str:
        stats = self.ha.stats
        if not stats.enabled:
            return "# stats disabled"
        return STATS_SECTION_TEMPLATE.format(
            stats_bind=stats.bind,
            stats_uri=stats.uri,
            stats_auth=stats.auth,
        )

    def _build_backends(self, backend_type: str) -> str:
        """Строит список серверов бэкенда (http или socks)."""
        lines = []
        port_attr = f"{backend_type}_port"
        hc = self.ha.health_check

        from lib.three_proxy_manager import ThreeProxyManager
        mgr = ThreeProxyManager(self.config)

        for backend in mgr.get_backend_addresses():
            port = backend[port_attr]
            name = backend["name"]
            host = backend["host"]
            line = (
                f"    server {name}_{backend_type} {host}:{port} "
                f"check inter {hc.inter} fall {hc.fall} rise {hc.rise}"
            )
            lines.append(line)

        return "\n".join(lines)

    def generate_config(self) -> str:
        """Генерирует HAProxy конфиг и пишет на диск."""
        bind = self.config.network.bind_address
        enable_v6 = self.config.network.enable_ipv6
        bind_v6 = self.config.network.bind_address_v6

        http_port = self.ha.frontends.get("http", {}).get("bind_port", 3128)
        socks_port = self.ha.frontends.get("socks", {}).get("bind_port", 1080)

        # IPv6 bind lines
        bind_v6_http = f"    bind {bind_v6}:{http_port}" if enable_v6 else ""
        bind_v6_socks = f"    bind {bind_v6}:{socks_port}" if enable_v6 else ""

        # Rate limit из anti-detect конфига
        rate_limit = self.config.anti_detect.rate_limit.requests_per_second
        if not self.config.anti_detect.rate_limit.enabled:
            rate_limit = 10000  # Фактически отключено

        content = HAPROXY_CONFIG_TEMPLATE.format(
            stats_socket=self._stats_socket(),
            retries=self.ha.balance.retries,
            timeout_connect=self.ha.balance.timeout_connect,
            timeout_client=self.ha.balance.timeout_client,
            timeout_server=self.ha.balance.timeout_server,
            stats_section=self._build_stats_section(),
            bind_addr=bind,
            http_port=http_port,
            socks_port=socks_port,
            bind_v6_http=bind_v6_http,
            bind_v6_socks=bind_v6_socks,
            rate_limit=rate_limit,
            balance_algorithm=self.ha.balance.algorithm,
            http_backends=self._build_backends("http"),
            socks_backends=self._build_backends("socks"),
        )

        cfg_path = self._config_path()
        Path(cfg_path).parent.mkdir(parents=True, exist_ok=True)
        with open(cfg_path, "w", encoding="utf-8") as f:
            f.write(content)

        logger.info("HAProxy конфиг записан: %s", cfg_path)
        return cfg_path

    # ── Валидация ────────────────────────────────────────────

    def validate_config(self) -> bool:
        """Запускает haproxy -c для проверки конфига."""
        cfg_path = self._config_path()
        if not os.path.exists(cfg_path):
            logger.error("Конфиг HAProxy не найден: %s", cfg_path)
            return False

        try:
            result = subprocess.run(
                [self.ha.binary, "-c", "-f", cfg_path],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                logger.info("HAProxy конфиг валиден.")
                return True
            else:
                logger.error("HAProxy конфиг невалиден:\n%s", result.stderr)
                return False
        except FileNotFoundError:
            logger.error("HAProxy бинарник не найден: %s", self.ha.binary)
            return False
        except subprocess.TimeoutExpired:
            logger.error("Таймаут валидации HAProxy.")
            return False

    # ── Запуск / Остановка ───────────────────────────────────

    def start(self) -> bool:
        """Запускает HAProxy."""
        cfg_path = self._config_path()
        pid_path = self._pid_path()

        cmd = [
            self.ha.binary,
            "-D",               # daemon mode
            "-f", cfg_path,
            "-p", pid_path,
        ]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                logger.error("HAProxy не запустился:\n%s", result.stderr)
                return False

            pid = read_component_pid(pid_path)
            if pid and is_process_alive(pid):
                logger.info("HAProxy запущен (PID %d).", pid)
                return True
            else:
                logger.error("HAProxy: PID-файл пуст или процесс мёртв.")
                return False
        except Exception as exc:
            logger.error("Ошибка запуска HAProxy: %s", exc)
            return False

    def stop(self) -> bool:
        """Останавливает HAProxy."""
        pid = read_component_pid(self._pid_path())
        if not pid:
            logger.debug("HAProxy PID не найден, возможно уже остановлен.")
            return True
        ok = stop_process_by_pid(pid, "HAProxy")
        try:
            os.remove(self._pid_path())
        except FileNotFoundError:
            pass
        return ok

    def reload(self) -> bool:
        """Hot-reload конфигурации HAProxy (graceful)."""
        pid = read_component_pid(self._pid_path())
        if not pid or not is_process_alive(pid):
            logger.error("HAProxy не запущен, reload невозможен.")
            return False

        cfg_path = self._config_path()
        cmd = [
            self.ha.binary,
            "-D",
            "-f", cfg_path,
            "-p", self._pid_path(),
            "-sf", str(pid),    # Graceful reload
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                logger.info("HAProxy reloaded.")
                return True
            else:
                logger.error("HAProxy reload failed:\n%s", result.stderr)
                return False
        except Exception as exc:
            logger.error("Ошибка reload HAProxy: %s", exc)
            return False

    # ── Статус ───────────────────────────────────────────────

    def status(self) -> Dict[str, Any]:
        pid = read_component_pid(self._pid_path())
        alive = pid is not None and is_process_alive(pid)
        return {"pid": pid, "alive": alive}
