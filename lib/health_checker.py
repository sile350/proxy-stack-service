"""
Health Checker — мониторинг состояния бэкендов 3proxy.

Проверяет:
- TCP connectivity к каждому экземпляру 3proxy (HTTP + SOCKS порты)
- Время отклика (latency)
- Уровень доступности (количество здоровых бэкендов)

Алерты при деградации.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from lib.config_loader import StackConfig

logger = logging.getLogger("proxy-stack.health")


@dataclass
class BackendHealth:
    """Состояние здоровья одного бэкенда."""
    name: str
    host: str
    http_port: int
    socks_port: int
    http_alive: bool = False
    socks_alive: bool = False
    http_latency_ms: float = 0.0
    socks_latency_ms: float = 0.0
    consecutive_failures: int = 0
    last_check: float = 0.0
    last_success: float = 0.0

    @property
    def is_healthy(self) -> bool:
        return self.http_alive and self.socks_alive


class HealthChecker:
    """
    Периодический health-checker для бэкендов.
    Работает в фоновом потоке.
    """

    def __init__(self, config: StackConfig):
        self.config = config
        self._backends: Dict[str, BackendHealth] = {}
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._check_interval: float = 5.0  # секунд
        self._tcp_timeout: float = 3.0
        self._on_alert: Optional[Callable] = None  # Callback для алертов
        self._lock = threading.RLock()

    def register_backends(self, backends: List[Dict[str, Any]]) -> None:
        """Регистрирует бэкенды для мониторинга."""
        with self._lock:
            for b in backends:
                name = b["name"]
                self._backends[name] = BackendHealth(
                    name=name,
                    host=b["host"],
                    http_port=b["http_port"],
                    socks_port=b["socks_port"],
                )
            logger.info("Зарегистрировано %d бэкендов для мониторинга.", len(self._backends))

    def set_alert_callback(self, callback: Callable) -> None:
        self._on_alert = callback

    # ── TCP проверка ─────────────────────────────────────────

    def _tcp_check(self, host: str, port: int) -> tuple[bool, float]:
        """
        Проверка TCP-подключения.
        Возвращает (alive, latency_ms).
        """
        start = time.monotonic()
        try:
            # Поддержка IPv6
            if ":" in host or host.startswith("["):
                clean_host = host.strip("[]")
                family = socket.AF_INET6
            else:
                clean_host = host
                family = socket.AF_INET

            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(self._tcp_timeout)
            sock.connect((clean_host, port))
            sock.close()
            latency = (time.monotonic() - start) * 1000
            return True, latency
        except (socket.timeout, ConnectionRefusedError, OSError) as exc:
            latency = (time.monotonic() - start) * 1000
            logger.debug("TCP check failed %s:%d — %s", host, port, exc)
            return False, latency

    # ── Проверка одного бэкенда ──────────────────────────────

    def _check_backend(self, backend: BackendHealth) -> None:
        """Проверяет один бэкенд (HTTP + SOCKS)."""
        now = time.monotonic()

        http_alive, http_lat = self._tcp_check(backend.host, backend.http_port)
        socks_alive, socks_lat = self._tcp_check(backend.host, backend.socks_port)

        with self._lock:
            backend.http_alive = http_alive
            backend.socks_alive = socks_alive
            backend.http_latency_ms = http_lat
            backend.socks_latency_ms = socks_lat
            backend.last_check = now

            if backend.is_healthy:
                backend.consecutive_failures = 0
                backend.last_success = now
            else:
                backend.consecutive_failures += 1
                if backend.consecutive_failures == 3:
                    logger.warning(
                        "Бэкенд %s ДЕГРАДИРОВАН (3 последовательных сбоя): HTTP=%s SOCKS=%s",
                        backend.name, http_alive, socks_alive,
                    )
                    self._fire_alert(backend)

    # ── Алерты ───────────────────────────────────────────────

    def _fire_alert(self, backend: BackendHealth) -> None:
        if self._on_alert:
            try:
                self._on_alert({
                    "type": "backend_degraded",
                    "backend": backend.name,
                    "http_alive": backend.http_alive,
                    "socks_alive": backend.socks_alive,
                    "consecutive_failures": backend.consecutive_failures,
                })
            except Exception as exc:
                logger.error("Ошибка отправки алерта: %s", exc)

    # ── Публичное API ────────────────────────────────────────

    def get_health_summary(self) -> Dict[str, Any]:
        """Возвращает сводку здоровья всех бэкендов."""
        with self._lock:
            backends_status = {}
            healthy_count = 0
            total = len(self._backends)

            for name, bh in self._backends.items():
                backends_status[name] = {
                    "healthy": bh.is_healthy,
                    "http_alive": bh.http_alive,
                    "socks_alive": bh.socks_alive,
                    "http_latency_ms": round(bh.http_latency_ms, 2),
                    "socks_latency_ms": round(bh.socks_latency_ms, 2),
                    "consecutive_failures": bh.consecutive_failures,
                }
                if bh.is_healthy:
                    healthy_count += 1

            min_healthy = self.config.monitoring.alerts.thresholds.min_healthy_backends
            overall = "healthy" if healthy_count >= min_healthy else "degraded"
            if healthy_count == 0:
                overall = "down"

            return {
                "status": overall,
                "healthy_backends": healthy_count,
                "total_backends": total,
                "backends": backends_status,
            }

    def get_metrics(self) -> Dict[str, float]:
        """Возвращает метрики для Prometheus."""
        with self._lock:
            metrics = {}
            healthy = 0
            for name, bh in self._backends.items():
                prefix = f"proxy_backend_{name}"
                metrics[f"{prefix}_http_alive"] = 1.0 if bh.http_alive else 0.0
                metrics[f"{prefix}_socks_alive"] = 1.0 if bh.socks_alive else 0.0
                metrics[f"{prefix}_http_latency_ms"] = bh.http_latency_ms
                metrics[f"{prefix}_socks_latency_ms"] = bh.socks_latency_ms
                metrics[f"{prefix}_consecutive_failures"] = float(bh.consecutive_failures)
                if bh.is_healthy:
                    healthy += 1
            metrics["proxy_healthy_backends"] = float(healthy)
            metrics["proxy_total_backends"] = float(len(self._backends))
            return metrics

    # ── Background loop ─────────────────────────────────────

    def _loop(self) -> None:
        logger.info("Health-checker запущен (интервал: %.1fs).", self._check_interval)
        while not self._stop_event.is_set():
            for backend in list(self._backends.values()):
                if self._stop_event.is_set():
                    break
                self._check_backend(backend)

            self._stop_event.wait(timeout=self._check_interval)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="health-checker")
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=10)
            self._thread = None
        logger.info("Health-checker остановлен.")
