#!/usr/bin/env python3
"""
3Proxy + HAProxy Orchestrator
=============================
Основной модуль управления стеком прокси-серверов.

Архитектура:
    HAProxy (TCP passthrough, без TLS-терминации)
        ├── 3proxy instance #0  (HTTP + SOCKS)
        ├── 3proxy instance #1  (HTTP + SOCKS)
        └── 3proxy instance #2  (HTTP + SOCKS)

Использование:
    python proxy_stack.py start     — запуск стека
    python proxy_stack.py stop      — остановка
    python proxy_stack.py restart   — перезапуск
    python proxy_stack.py status    — статус компонентов
    python proxy_stack.py generate  — генерация конфигов без запуска
    python proxy_stack.py validate  — проверка конфигурации
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import time
from pathlib import Path
from typing import Optional

from lib.config_loader import StackConfig, load_config
from lib.three_proxy_manager import ThreeProxyManager
from lib.haproxy_manager import HAProxyManager
from lib.health_checker import HealthChecker
from lib.monitoring_server import MonitoringServer
from lib.anti_detect import AntiDetectEngine
from lib.utils import (
    ensure_directories,
    setup_logging,
    check_binary_exists,
    drop_privileges,
    write_pid_file,
    remove_pid_file,
    read_pid_file,
    is_process_alive,
)

logger = logging.getLogger("proxy-stack")

# ──────────────────────────────────────────────────────────────
# Orchestrator
# ──────────────────────────────────────────────────────────────


class ProxyStackOrchestrator:
    """Центральный оркестратор — управляет жизненным циклом всех компонентов."""

    def __init__(self, config: StackConfig):
        self.config = config
        self._running = False
        self._components: list = []

        # Менеджеры компонентов
        self.three_proxy_mgr = ThreeProxyManager(config)
        self.haproxy_mgr = HAProxyManager(config)
        self.anti_detect = AntiDetectEngine(config)
        self.health_checker = HealthChecker(config)
        self.monitoring: Optional[MonitoringServer] = None

    # ── Генерация конфигов ───────────────────────────────────

    def generate_configs(self) -> None:
        """Генерирует все конфигурационные файлы."""
        logger.info("Генерация конфигурационных файлов...")
        ensure_directories(self.config)

        # 3proxy instances
        self.three_proxy_mgr.generate_configs()

        # HAProxy
        self.haproxy_mgr.generate_config()

        logger.info("Конфигурационные файлы успешно сгенерированы.")

    # ── Валидация ────────────────────────────────────────────

    def validate(self) -> bool:
        """Проверяет конфигурацию и наличие бинарников."""
        ok = True

        # Бинарники
        if not check_binary_exists(self.config.haproxy.binary):
            logger.error("HAProxy не найден: %s", self.config.haproxy.binary)
            ok = False

        if not check_binary_exists(self.config.three_proxy.binary):
            logger.error("3proxy не найден: %s", self.config.three_proxy.binary)
            ok = False

        # Валидация конфига HAProxy
        if ok:
            if not self.haproxy_mgr.validate_config():
                logger.error("Конфигурация HAProxy невалидна.")
                ok = False

        if ok:
            logger.info("Валидация пройдена успешно.")
        return ok

    # ── Запуск ───────────────────────────────────────────────

    def start(self) -> int:
        """Запуск всего стека. Возвращает 0 при успехе."""
        if self._is_already_running():
            logger.error("Стек уже запущен (PID-файл существует).")
            return 1

        logger.info("=" * 60)
        logger.info("Запуск Proxy Stack")
        logger.info("=" * 60)

        # 1. Генерация конфигов
        self.generate_configs()

        # 2. Валидация
        if not self.validate():
            return 1

        # 3. Запуск 3proxy экземпляров
        logger.info("Запуск экземпляров 3proxy...")
        if not self.three_proxy_mgr.start_all():
            logger.error("Не удалось запустить 3proxy.")
            self.stop()
            return 1

        # Даём 3proxy время на инициализацию
        time.sleep(1)

        # 4. Запуск HAProxy
        logger.info("Запуск HAProxy...")
        if not self.haproxy_mgr.start():
            logger.error("Не удалось запустить HAProxy.")
            self.stop()
            return 1

        # 5. Запуск мониторинга
        if self.config.monitoring.enabled:
            logger.info("Запуск сервера мониторинга на порту %d...", self.config.monitoring.port)
            self.monitoring = MonitoringServer(self.config, self.health_checker)
            self.monitoring.start()

        # 6. Запуск anti-detect engine
        if self.config.anti_detect.user_agent_rotation.enabled:
            self.anti_detect.start()

        # 7. Запуск health-checker
        self.health_checker.register_backends(
            self.three_proxy_mgr.get_backend_addresses()
        )
        self.health_checker.start()

        self._running = True
        write_pid_file(self.config)

        logger.info("=" * 60)
        logger.info("Proxy Stack запущен успешно!")
        logger.info("  HTTP  прокси: %s:%d", self.config.network.bind_address, self.config.haproxy.frontends["http"]["bind_port"])
        logger.info("  SOCKS прокси: %s:%d", self.config.network.bind_address, self.config.haproxy.frontends["socks"]["bind_port"])
        if self.config.haproxy.stats.get("enabled"):
            logger.info("  HAProxy stats: http://%s%s", self.config.haproxy.stats["bind"], self.config.haproxy.stats["uri"])
        if self.config.monitoring.enabled:
            logger.info("  Мониторинг: http://%s:%d%s", self.config.monitoring.bind, self.config.monitoring.port, self.config.monitoring.metrics_path)
        logger.info("=" * 60)

        return 0

    # ── Остановка ────────────────────────────────────────────

    def stop(self) -> int:
        """Грациозная остановка всего стека."""
        logger.info("Остановка Proxy Stack...")

        errors = 0

        # Остановка в обратном порядке
        if self.monitoring:
            try:
                self.monitoring.stop()
            except Exception as exc:
                logger.warning("Ошибка остановки мониторинга: %s", exc)
                errors += 1

        self.health_checker.stop()
        self.anti_detect.stop()

        if not self.haproxy_mgr.stop():
            errors += 1

        if not self.three_proxy_mgr.stop_all():
            errors += 1

        remove_pid_file(self.config)
        self._running = False

        if errors:
            logger.warning("Стек остановлен с %d ошибками.", errors)
            return 1

        logger.info("Proxy Stack остановлен.")
        return 0

    # ── Перезапуск ───────────────────────────────────────────

    def restart(self) -> int:
        self.stop()
        time.sleep(2)
        return self.start()

    # ── Статус ───────────────────────────────────────────────

    def status(self) -> int:
        """Выводит статус всех компонентов."""
        print("=" * 60)
        print(" Proxy Stack — Статус компонентов")
        print("=" * 60)

        all_ok = True

        # Orchestrator PID
        pid = read_pid_file(self.config)
        if pid and is_process_alive(pid):
            print(f"  Оркестратор:  РАБОТАЕТ (PID {pid})")
        else:
            print("  Оркестратор:  ОСТАНОВЛЕН")
            all_ok = False

        # 3proxy instances
        statuses = self.three_proxy_mgr.status()
        for name, info in statuses.items():
            state = "РАБОТАЕТ" if info["alive"] else "ОСТАНОВЛЕН"
            pid_str = f" (PID {info['pid']})" if info["pid"] else ""
            print(f"  {name}:{' ' * (20 - len(name))}{state}{pid_str}")
            if not info["alive"]:
                all_ok = False

        # HAProxy
        ha_status = self.haproxy_mgr.status()
        state = "РАБОТАЕТ" if ha_status["alive"] else "ОСТАНОВЛЕН"
        pid_str = f" (PID {ha_status['pid']})" if ha_status["pid"] else ""
        print(f"  HAProxy:              {state}{pid_str}")
        if not ha_status["alive"]:
            all_ok = False

        print("=" * 60)
        overall = "ЗДОРОВ" if all_ok else "ДЕГРАДИРОВАН"
        print(f"  Общий статус: {overall}")
        print("=" * 60)

        return 0 if all_ok else 1

    # ── Вспомогательные ──────────────────────────────────────

    def _is_already_running(self) -> bool:
        pid = read_pid_file(self.config)
        return pid is not None and is_process_alive(pid)

    def setup_signals(self) -> None:
        """Регистрация обработчиков сигналов для graceful shutdown."""
        def _handler(signum, frame):
            sig_name = signal.Signals(signum).name
            logger.info("Получен сигнал %s, останавливаем...", sig_name)
            self.stop()
            sys.exit(0)

        signal.signal(signal.SIGTERM, _handler)
        signal.signal(signal.SIGINT, _handler)


# ──────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="proxy_stack",
        description="3Proxy + HAProxy Orchestrator — управление стеком прокси-серверов",
    )
    parser.add_argument(
        "action",
        choices=["start", "stop", "restart", "status", "generate", "validate"],
        help="Действие: start | stop | restart | status | generate | validate",
    )
    parser.add_argument(
        "-c", "--config",
        default="config.yml",
        help="Путь к конфигурационному файлу (по умолчанию: config.yml)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Подробный вывод (DEBUG)",
    )
    parser.add_argument(
        "--no-drop-privs",
        action="store_true",
        help="Не сбрасывать привилегии (для отладки)",
    )
    parser.add_argument(
        "--foreground",
        action="store_true",
        help="Не уходить в фон — держать процесс живым (для Docker/контейнеров)",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    # Определяем путь к конфигу относительно скрипта
    script_dir = Path(__file__).resolve().parent
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = script_dir / config_path

    # Загрузка конфигурации
    try:
        config = load_config(config_path)
    except Exception as exc:
        print(f"Ошибка загрузки конфигурации: {exc}", file=sys.stderr)
        return 1

    # Настройка логирования
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(config, level=log_level)

    # Оркестратор
    orch = ProxyStackOrchestrator(config)

    # Маршрутизация действий
    actions = {
        "start": orch.start,
        "stop": orch.stop,
        "restart": orch.restart,
        "status": orch.status,
        "generate": lambda: (orch.generate_configs(), 0)[1],
        "validate": lambda: 0 if orch.validate() else 1,
    }

    # Сигналы (для start/restart)
    if args.action in ("start", "restart"):
        orch.setup_signals()

    result = actions[args.action]()

    # Foreground-режим: после успешного старта держим процесс живым
    # (необходимо для Docker, где PID 1 не должен завершаться)
    if args.foreground and args.action in ("start", "restart") and result == 0:
        logger.info("Foreground-режим: процесс остаётся активным (Ctrl+C / SIGTERM для остановки)")
        try:
            while True:
                time.sleep(5)
                # Периодическая проверка: если все дети умерли — выходим
                health = orch.health_checker.get_health_summary()
                if health["healthy_backends"] == 0 and health["total_backends"] > 0:
                    logger.error("Все бэкенды недоступны, завершаем...")
                    orch.stop()
                    return 1
        except (KeyboardInterrupt, SystemExit):
            logger.info("Завершение foreground-режима...")
            orch.stop()
            return 0

    return result


if __name__ == "__main__":
    sys.exit(main())
