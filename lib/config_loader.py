"""
Загрузчик конфигурации — парсит YAML и строит типизированные объекты.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


# ──────────────────────────────────────────────────────────────
# Data classes
# ──────────────────────────────────────────────────────────────


@dataclass
class NetworkConfig:
    bind_address: str = "0.0.0.0"
    bind_address_v6: str = "[::]"
    enable_ipv6: bool = True


@dataclass
class HAProxyStats:
    enabled: bool = True
    bind: str = "127.0.0.1:8404"
    uri: str = "/stats"
    auth: str = "admin:proxy_stats_secret"

    def get(self, key: str, default=None):
        return getattr(self, key, default)


@dataclass
class HAProxyBalance:
    algorithm: str = "roundrobin"
    retries: int = 3
    timeout_connect: str = "5s"
    timeout_client: str = "60s"
    timeout_server: str = "60s"


@dataclass
class HAProxyHealthCheck:
    inter: str = "3s"
    fall: int = 3
    rise: int = 2


@dataclass
class HAProxyConfig:
    binary: str = "/usr/sbin/haproxy"
    config_path: str = ""
    stats: HAProxyStats = field(default_factory=HAProxyStats)
    frontends: Dict[str, Any] = field(default_factory=dict)
    balance: HAProxyBalance = field(default_factory=HAProxyBalance)
    health_check: HAProxyHealthCheck = field(default_factory=HAProxyHealthCheck)


@dataclass
class AuthUser:
    login: str = ""
    password: str = ""


@dataclass
class ThreeProxyAuth:
    enabled: bool = False
    type: str = "strong"
    users: List[AuthUser] = field(default_factory=list)


@dataclass
class ThreeProxyDNS:
    nserver: List[str] = field(default_factory=lambda: ["1.1.1.1", "8.8.8.8"])
    nscache: int = 65536
    nscache6: int = 65536


@dataclass
class ThreeProxyLimits:
    maxconn: int = 500
    timeout: int = 60
    bandlimin: int = 0
    bandlimout: int = 0


@dataclass
class ThreeProxyLogging:
    enabled: bool = True
    format: str = "L%Y%m%d%H%M%S %p %E %C:%c %R:%r %O %I %T"
    rotate: int = 7


@dataclass
class ThreeProxyConfig:
    binary: str = "/usr/local/bin/3proxy"
    instance_count: int = 3
    base_http_port: int = 13128
    base_socks_port: int = 11080
    auth: ThreeProxyAuth = field(default_factory=ThreeProxyAuth)
    dns: ThreeProxyDNS = field(default_factory=ThreeProxyDNS)
    limits: ThreeProxyLimits = field(default_factory=ThreeProxyLimits)
    logging: ThreeProxyLogging = field(default_factory=ThreeProxyLogging)


@dataclass
class UserAgentRotation:
    enabled: bool = True
    rotate_every: int = 60
    pool_file: str = ""


@dataclass
class HeaderManipulation:
    enabled: bool = True
    strip_headers: List[str] = field(default_factory=list)
    add_headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class RateLimit:
    enabled: bool = True
    requests_per_second: int = 50
    burst: int = 100
    per_ip: bool = True


@dataclass
class AntiDetectConfig:
    user_agent_rotation: UserAgentRotation = field(default_factory=UserAgentRotation)
    header_manipulation: HeaderManipulation = field(default_factory=HeaderManipulation)
    rate_limit: RateLimit = field(default_factory=RateLimit)


@dataclass
class AlertThresholds:
    cpu_percent: int = 80
    memory_percent: int = 85
    error_rate_percent: int = 5
    min_healthy_backends: int = 2


@dataclass
class Alerts:
    webhook_url: str = ""
    thresholds: AlertThresholds = field(default_factory=AlertThresholds)


@dataclass
class MonitoringConfig:
    enabled: bool = True
    bind: str = "127.0.0.1"
    port: int = 9100
    metrics_path: str = "/metrics"
    health_path: str = "/health"
    alerts: Alerts = field(default_factory=Alerts)


@dataclass
class StackConfig:
    """Корневой объект конфигурации стека."""
    work_dir: str = "/opt/proxy-stack"
    log_dir: str = "/var/log/proxy-stack"
    pid_dir: str = "/var/run/proxy-stack"
    run_user: str = "proxy"
    run_group: str = "proxy"
    network: NetworkConfig = field(default_factory=NetworkConfig)
    haproxy: HAProxyConfig = field(default_factory=HAProxyConfig)
    three_proxy: ThreeProxyConfig = field(default_factory=ThreeProxyConfig)
    anti_detect: AntiDetectConfig = field(default_factory=AntiDetectConfig)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)

    # Путь к исходному YAML (заполняется при загрузке)
    _config_path: str = ""


# ──────────────────────────────────────────────────────────────
# Parsing helpers
# ──────────────────────────────────────────────────────────────


def _parse_auth_users(raw: list) -> List[AuthUser]:
    return [AuthUser(login=u.get("login", ""), password=u.get("password", "")) for u in (raw or [])]


def _parse_haproxy(raw: dict) -> HAProxyConfig:
    stats_raw = raw.get("stats", {})
    balance_raw = raw.get("balance", {})
    hc_raw = raw.get("health_check", {})

    return HAProxyConfig(
        binary=raw.get("binary", "/usr/sbin/haproxy"),
        config_path=raw.get("config_path", ""),
        stats=HAProxyStats(**{k: v for k, v in stats_raw.items() if k in HAProxyStats.__dataclass_fields__}),
        frontends=raw.get("frontends", {}),
        balance=HAProxyBalance(**{k: v for k, v in balance_raw.items() if k in HAProxyBalance.__dataclass_fields__}),
        health_check=HAProxyHealthCheck(**{k: v for k, v in hc_raw.items() if k in HAProxyHealthCheck.__dataclass_fields__}),
    )


def _parse_three_proxy(raw: dict) -> ThreeProxyConfig:
    auth_raw = raw.get("auth", {})
    dns_raw = raw.get("dns", {})
    limits_raw = raw.get("limits", {})
    log_raw = raw.get("logging", {})

    auth = ThreeProxyAuth(
        enabled=auth_raw.get("enabled", False),
        type=auth_raw.get("type", "strong"),
        users=_parse_auth_users(auth_raw.get("users")),
    )
    dns = ThreeProxyDNS(**{k: v for k, v in dns_raw.items() if k in ThreeProxyDNS.__dataclass_fields__})
    limits = ThreeProxyLimits(**{k: v for k, v in limits_raw.items() if k in ThreeProxyLimits.__dataclass_fields__})
    log_cfg = ThreeProxyLogging(**{k: v for k, v in log_raw.items() if k in ThreeProxyLogging.__dataclass_fields__})

    return ThreeProxyConfig(
        binary=raw.get("binary", "/usr/local/bin/3proxy"),
        instance_count=raw.get("instance_count", 3),
        base_http_port=raw.get("base_http_port", 13128),
        base_socks_port=raw.get("base_socks_port", 11080),
        auth=auth,
        dns=dns,
        limits=limits,
        logging=log_cfg,
    )


def _parse_anti_detect(raw: dict) -> AntiDetectConfig:
    ua_raw = raw.get("user_agent_rotation", {})
    hdr_raw = raw.get("header_manipulation", {})
    rl_raw = raw.get("rate_limit", {})

    return AntiDetectConfig(
        user_agent_rotation=UserAgentRotation(**{k: v for k, v in ua_raw.items() if k in UserAgentRotation.__dataclass_fields__}),
        header_manipulation=HeaderManipulation(**{k: v for k, v in hdr_raw.items() if k in HeaderManipulation.__dataclass_fields__}),
        rate_limit=RateLimit(**{k: v for k, v in rl_raw.items() if k in RateLimit.__dataclass_fields__}),
    )


def _parse_monitoring(raw: dict) -> MonitoringConfig:
    alerts_raw = raw.get("alerts", {})
    thresholds_raw = alerts_raw.get("thresholds", {})

    alerts = Alerts(
        webhook_url=alerts_raw.get("webhook_url", ""),
        thresholds=AlertThresholds(**{k: v for k, v in thresholds_raw.items() if k in AlertThresholds.__dataclass_fields__}),
    )
    return MonitoringConfig(
        enabled=raw.get("enabled", True),
        bind=raw.get("bind", "127.0.0.1"),
        port=raw.get("port", 9100),
        metrics_path=raw.get("metrics_path", "/metrics"),
        health_path=raw.get("health_path", "/health"),
        alerts=alerts,
    )


# ──────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────


def load_config(path: Path) -> StackConfig:
    """Загружает YAML-файл конфигурации и возвращает StackConfig."""
    if not path.exists():
        raise FileNotFoundError(f"Конфигурационный файл не найден: {path}")

    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}

    general = raw.get("general", {})
    work_dir = general.get("work_dir", "/opt/proxy-stack")

    # Подстановка {{ work_dir }}
    ha_raw = raw.get("haproxy", {})
    if "config_path" in ha_raw:
        ha_raw["config_path"] = ha_raw["config_path"].replace("{{ work_dir }}", work_dir)

    config = StackConfig(
        work_dir=work_dir,
        log_dir=general.get("log_dir", "/var/log/proxy-stack"),
        pid_dir=general.get("pid_dir", "/var/run/proxy-stack"),
        run_user=general.get("run_user", "proxy"),
        run_group=general.get("run_group", "proxy"),
        network=NetworkConfig(**{k: v for k, v in raw.get("network", {}).items() if k in NetworkConfig.__dataclass_fields__}),
        haproxy=_parse_haproxy(ha_raw),
        three_proxy=_parse_three_proxy(raw.get("three_proxy", {})),
        anti_detect=_parse_anti_detect(raw.get("anti_detect", {})),
        monitoring=_parse_monitoring(raw.get("monitoring", {})),
    )
    config._config_path = str(path)

    return config
