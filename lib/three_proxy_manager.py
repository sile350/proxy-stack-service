"""
Менеджер экземпляров 3proxy — генерация конфигов, запуск/остановка.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, List

from lib.config_loader import StackConfig
from lib.utils import (
    read_component_pid,
    is_process_alive,
    run_process,
    stop_process_by_pid,
)

logger = logging.getLogger("proxy-stack.3proxy")

# ──────────────────────────────────────────────────────────────
# Шаблон конфигурации 3proxy
# ──────────────────────────────────────────────────────────────

THREEPROXY_CONFIG_TEMPLATE = """\
#!/usr/local/bin/3proxy
# ============================================================
# 3proxy instance #{instance_id}
# Автосгенерировано proxy_stack.py — НЕ РЕДАКТИРОВАТЬ ВРУЧНУЮ
# ============================================================

# --- Системные ---
daemon
pidfile {pid_file}

# --- DNS ---
{dns_servers}
nscache {nscache}
nscache6 {nscache6}

# --- Таймауты ---
timeouts 1 5 30 60 180 1800 {timeout} {timeout}

# --- Лимиты ---
maxconn {maxconn}

# --- Лог ---
{log_section}

# --- Аутентификация ---
{auth_section}

# --- Анти-детект: заголовки ---
{header_section}

# --- Ограничение полосы ---
{band_section}

# --- Внешний адрес ---
{external_section}

# --- HTTP (CONNECT) прокси ---
proxy -p{http_port} -i{bind_addr}
{proxy_v6_line}

# --- SOCKS5 прокси ---
socks -p{socks_port} -i{bind_addr}
{socks_v6_line}

# --- Flush ---
flush
"""


class ThreeProxyManager:
    """Управляет жизненным циклом N экземпляров 3proxy."""

    def __init__(self, config: StackConfig):
        self.config = config
        self.cfg = config.three_proxy
        self._processes: Dict[int, Any] = {}  # instance_id → Popen

    # ── Пути ─────────────────────────────────────────────────

    def _instance_dir(self, instance_id: int) -> str:
        return os.path.join(self.config.work_dir, "3proxy", f"instance_{instance_id}")

    def _config_path(self, instance_id: int) -> str:
        return os.path.join(self._instance_dir(instance_id), "3proxy.cfg")

    def _pid_path(self, instance_id: int) -> str:
        return os.path.join(self.config.pid_dir, f"3proxy_{instance_id}.pid")

    def _log_path(self, instance_id: int) -> str:
        return os.path.join(self.config.log_dir, f"3proxy_{instance_id}.log")

    def _http_port(self, instance_id: int) -> int:
        return self.cfg.base_http_port + instance_id

    def _socks_port(self, instance_id: int) -> int:
        return self.cfg.base_socks_port + instance_id

    # ── Генерация конфига ────────────────────────────────────

    def _build_dns_section(self) -> str:
        lines = []
        for ns in self.cfg.dns.nserver:
            lines.append(f"nserver {ns}")
        return "\n".join(lines)

    def _build_log_section(self, instance_id: int) -> str:
        if not self.cfg.logging.enabled:
            return "# logging disabled"
        log_file = self._log_path(instance_id)
        fmt = self.cfg.logging.format
        rotate = self.cfg.logging.rotate
        return f'log "{log_file}" D\nlogformat "{fmt}"\nrotate {rotate}'

    def _build_auth_section(self) -> str:
        auth = self.cfg.auth
        if not auth.enabled:
            return "auth none\nallow *"

        lines = []
        if auth.type == "iponly":
            lines.append("auth iponly")
            lines.append("allow *")
        elif auth.type == "strong":
            lines.append("auth strong")
            for u in auth.users:
                # CL — пароль в открытом виде; CR — NT hash
                lines.append(f'users "{u.login}:CL:{u.password}"')
            lines.append("allow *")
        else:
            lines.append("auth none")
            lines.append("allow *")
        return "\n".join(lines)

    def _build_header_section(self) -> str:
        hdr = self.config.anti_detect.header_manipulation
        if not hdr.enabled:
            return "# header manipulation disabled"

        lines = []
        # Удаление заголовков, раскрывающих прокси
        for h in hdr.strip_headers:
            # В 3proxy используем parent proxy plugin или addheader/delheader
            # Через фичу «header» (3proxy >=0.9)
            lines.append(f'# strip: {h}')
        # Замечание: 3proxy напрямую не поддерживает удаление заголовков для
        # TCP-tunnel (CONNECT). Для HTTP-запросов мы можем подменить через plugin.
        # В TCP-passthrough режиме заголовки клиента сохраняются.
        # Реальная модификация происходит на уровне anti_detect middleware.
        lines.append("# Header stripping handled by HAProxy + anti-detect layer")
        return "\n".join(lines) if lines else "# no header manipulation"

    def _build_band_section(self) -> str:
        lim = self.cfg.limits
        lines = []
        if lim.bandlimin > 0:
            lines.append(f"bandlimin {lim.bandlimin}")
        if lim.bandlimout > 0:
            lines.append(f"bandlimout {lim.bandlimout}")
        return "\n".join(lines) if lines else "# no bandwidth limits"

    def generate_config(self, instance_id: int) -> str:
        """Генерирует конфиг для одного экземпляра и записывает на диск."""
        inst_dir = self._instance_dir(instance_id)
        Path(inst_dir).mkdir(parents=True, exist_ok=True)

        bind = self.config.network.bind_address
        enable_v6 = self.config.network.enable_ipv6
        bind_v6 = self.config.network.bind_address_v6

        # IPv6 строки для proxy и socks
        proxy_v6 = f"proxy -p{self._http_port(instance_id)} -i{bind_v6}" if enable_v6 else ""
        socks_v6 = f"socks -p{self._socks_port(instance_id)} -i{bind_v6}" if enable_v6 else ""

        # Внешний интерфейс
        external_lines = []
        if bind != "0.0.0.0":
            external_lines.append(f"external {bind}")
        if enable_v6 and bind_v6 != "[::]":
            external_lines.append(f"external {bind_v6}")
        external_section = "\n".join(external_lines) if external_lines else "# external: all interfaces"

        content = THREEPROXY_CONFIG_TEMPLATE.format(
            instance_id=instance_id,
            pid_file=self._pid_path(instance_id),
            dns_servers=self._build_dns_section(),
            nscache=self.cfg.dns.nscache,
            nscache6=self.cfg.dns.nscache6,
            timeout=self.cfg.limits.timeout,
            maxconn=self.cfg.limits.maxconn,
            log_section=self._build_log_section(instance_id),
            auth_section=self._build_auth_section(),
            header_section=self._build_header_section(),
            band_section=self._build_band_section(),
            external_section=external_section,
            http_port=self._http_port(instance_id),
            socks_port=self._socks_port(instance_id),
            bind_addr=bind,
            proxy_v6_line=proxy_v6,
            socks_v6_line=socks_v6,
        )

        cfg_path = self._config_path(instance_id)
        with open(cfg_path, "w", encoding="utf-8") as f:
            f.write(content)

        logger.info("3proxy #%d конфиг записан: %s", instance_id, cfg_path)
        return cfg_path

    def generate_configs(self) -> List[str]:
        """Генерирует конфиги для всех экземпляров."""
        paths = []
        for i in range(self.cfg.instance_count):
            paths.append(self.generate_config(i))
        return paths

    # ── Запуск / Остановка ───────────────────────────────────

    def start_instance(self, instance_id: int) -> bool:
        """Запускает один экземпляр 3proxy."""
        cfg_path = self._config_path(instance_id)
        if not os.path.exists(cfg_path):
            logger.error("Конфиг не найден: %s", cfg_path)
            return False

        cmd = [self.cfg.binary, cfg_path]
        try:
            proc = run_process(cmd, f"3proxy #{instance_id}")
            self._processes[instance_id] = proc

            # 3proxy в daemon-режиме форкается, proc завершится,
            # реальный PID будет в pid-файле
            proc.wait(timeout=5)

            # Проверяем pid-файл
            pid = read_component_pid(self._pid_path(instance_id))
            if pid and is_process_alive(pid):
                logger.info("3proxy #%d запущен (PID %d), HTTP:%d SOCKS:%d",
                            instance_id, pid,
                            self._http_port(instance_id),
                            self._socks_port(instance_id))
                return True
            else:
                logger.error("3proxy #%d не запустился (PID-файл пуст/процесс мёртв).", instance_id)
                return False
        except Exception as exc:
            logger.error("Ошибка запуска 3proxy #%d: %s", instance_id, exc)
            return False

    def start_all(self) -> bool:
        """Запускает все экземпляры. Возвращает True если хотя бы один поднялся."""
        ok_count = 0
        for i in range(self.cfg.instance_count):
            if self.start_instance(i):
                ok_count += 1
        if ok_count == 0:
            logger.error("Ни один экземпляр 3proxy не запущен!")
            return False
        if ok_count < self.cfg.instance_count:
            logger.warning("Запущено %d из %d экземпляров 3proxy.", ok_count, self.cfg.instance_count)
        return True

    def stop_instance(self, instance_id: int) -> bool:
        pid = read_component_pid(self._pid_path(instance_id))
        if pid:
            ok = stop_process_by_pid(pid, f"3proxy #{instance_id}")
            # Удаляем pid-файл
            try:
                os.remove(self._pid_path(instance_id))
            except FileNotFoundError:
                pass
            return ok
        return True

    def stop_all(self) -> bool:
        ok = True
        for i in range(self.cfg.instance_count):
            if not self.stop_instance(i):
                ok = False
        return ok

    # ── Статус ───────────────────────────────────────────────

    def status(self) -> Dict[str, Dict]:
        """Возвращает статус каждого экземпляра."""
        result = {}
        for i in range(self.cfg.instance_count):
            pid = read_component_pid(self._pid_path(i))
            alive = pid is not None and is_process_alive(pid)
            result[f"3proxy #{i}"] = {
                "pid": pid,
                "alive": alive,
                "http_port": self._http_port(i),
                "socks_port": self._socks_port(i),
            }
        return result

    # ── Backend-адреса для HAProxy ───────────────────────────

    def get_backend_addresses(self) -> List[Dict[str, Any]]:
        """Возвращает список бэкендов для HAProxy и health-checker."""
        backends = []
        bind = "127.0.0.1"  # 3proxy слушает localhost для бэкенда
        for i in range(self.cfg.instance_count):
            backends.append({
                "name": f"3proxy_{i}",
                "host": bind,
                "http_port": self._http_port(i),
                "socks_port": self._socks_port(i),
            })
        return backends
