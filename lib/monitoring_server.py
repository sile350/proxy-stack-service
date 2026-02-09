"""
Monitoring Server — HTTP-сервер для метрик (Prometheus) и health-check endpoint.

Endpoints:
    GET /metrics  — Prometheus-совместимые метрики
    GET /health   — JSON со статусом здоровья стека
"""

from __future__ import annotations

import json
import logging
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional

import psutil

from lib.config_loader import StackConfig
from lib.health_checker import HealthChecker

logger = logging.getLogger("proxy-stack.monitoring")


class _MetricsHandler(BaseHTTPRequestHandler):
    """HTTP handler для /metrics и /health."""

    # Ссылки на конфиг и health-checker (устанавливаются при создании сервера)
    config: Optional[StackConfig] = None
    health_checker: Optional[HealthChecker] = None

    def log_message(self, format, *args):
        # Подавляем стандартный вывод HTTPServer, используем наш логгер
        logger.debug("HTTP %s", format % args)

    def do_GET(self):
        if not self.config:
            self._respond(500, "text/plain", "Server misconfigured")
            return

        metrics_path = self.config.monitoring.metrics_path
        health_path = self.config.monitoring.health_path

        if self.path == metrics_path:
            self._handle_metrics()
        elif self.path == health_path:
            self._handle_health()
        else:
            self._respond(404, "text/plain", "Not Found")

    def _handle_metrics(self):
        """Prometheus text format metrics."""
        lines = []

        # Метрики бэкендов
        if self.health_checker:
            for name, value in self.health_checker.get_metrics().items():
                # Prometheus text format: metric_name value
                lines.append(f"{name} {value}")

        # Системные метрики
        try:
            cpu = psutil.cpu_percent(interval=0)
            mem = psutil.virtual_memory()
            lines.append(f"proxy_stack_cpu_percent {cpu}")
            lines.append(f"proxy_stack_memory_used_bytes {mem.used}")
            lines.append(f"proxy_stack_memory_total_bytes {mem.total}")
            lines.append(f"proxy_stack_memory_percent {mem.percent}")

            # Сетевые счётчики
            net = psutil.net_io_counters()
            lines.append(f"proxy_stack_net_bytes_sent {net.bytes_sent}")
            lines.append(f"proxy_stack_net_bytes_recv {net.bytes_recv}")
            lines.append(f"proxy_stack_net_connections {len(psutil.net_connections())}")
        except Exception as exc:
            logger.debug("Ошибка сбора системных метрик: %s", exc)

        lines.append(f"proxy_stack_uptime_seconds {time.monotonic()}")

        body = "\n".join(lines) + "\n"
        self._respond(200, "text/plain; version=0.0.4; charset=utf-8", body)

    def _handle_health(self):
        """JSON health endpoint."""
        if not self.health_checker:
            self._respond(503, "application/json", json.dumps({"status": "unknown"}))
            return

        summary = self.health_checker.get_health_summary()
        status_code = 200 if summary["status"] == "healthy" else 503

        body = json.dumps(summary, indent=2, ensure_ascii=False)
        self._respond(status_code, "application/json", body)

    def _respond(self, code: int, content_type: str, body: str):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body.encode("utf-8"))))
        # Анти-кеш
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))


class MonitoringServer:
    """
    Обёртка над HTTP-сервером для метрик и health-check.
    Работает в фоновом потоке.
    """

    def __init__(self, config: StackConfig, health_checker: HealthChecker):
        self.config = config
        self.health_checker = health_checker
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Запускает HTTP-сервер в фоновом потоке."""
        bind = self.config.monitoring.bind
        port = self.config.monitoring.port

        # Устанавливаем ссылки на объекты в handler-классе
        _MetricsHandler.config = self.config
        _MetricsHandler.health_checker = self.health_checker

        try:
            self._server = HTTPServer((bind, port), _MetricsHandler)
            self._thread = threading.Thread(
                target=self._server.serve_forever,
                daemon=True,
                name="monitoring-http",
            )
            self._thread.start()
            logger.info(
                "Monitoring server запущен: http://%s:%d (metrics: %s, health: %s)",
                bind, port,
                self.config.monitoring.metrics_path,
                self.config.monitoring.health_path,
            )
        except OSError as exc:
            logger.error("Не удалось запустить monitoring server на %s:%d — %s", bind, port, exc)

    def stop(self) -> None:
        """Останавливает HTTP-сервер."""
        if self._server:
            self._server.shutdown()
            self._server = None
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        logger.info("Monitoring server остановлен.")
