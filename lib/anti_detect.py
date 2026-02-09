"""
Anti-Detect Engine — ротация User-Agent, манипуляция заголовками, rate-limiting.

Работает как фоновый поток, периодически обновляя конфигурации 3proxy
и при необходимости выполняя hot-reload HAProxy.
"""

from __future__ import annotations

import logging
import os
import random
import threading
import time
from typing import Dict, List, Optional

from lib.config_loader import StackConfig

logger = logging.getLogger("proxy-stack.anti-detect")

# ──────────────────────────────────────────────────────────────
# Встроенный пул User-Agent (реалистичные, актуальные)
# ──────────────────────────────────────────────────────────────

BUILTIN_USER_AGENTS: List[str] = [
    # Chrome (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Chrome (macOS)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    # Chrome (Linux)
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    # Firefox (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    # Firefox (macOS)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0",
    # Firefox (Linux)
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    # Safari (macOS)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    # Edge (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
    # Mobile (Android)
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
    # Mobile (iOS)
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
]


# ──────────────────────────────────────────────────────────────
# Rate Limiter (in-process token bucket)
# ──────────────────────────────────────────────────────────────


class TokenBucketRateLimiter:
    """Потокобезопасный rate-limiter на основе token bucket."""

    def __init__(self, rate: float, burst: int):
        self.rate = rate        # токенов/сек
        self.burst = burst      # макс. токенов
        self._tokens = float(burst)
        self._last_time = time.monotonic()
        self._lock = threading.Lock()
        # Per-IP buckets
        self._per_ip: Dict[str, tuple] = {}  # ip → (tokens, last_time)

    def allow(self, ip: str = "") -> bool:
        """Проверяет, разрешён ли запрос. True = разрешён."""
        with self._lock:
            now = time.monotonic()

            if ip and ip in self._per_ip:
                tokens, last = self._per_ip[ip]
            else:
                tokens = float(self.burst)
                last = now

            # Пополнение токенов
            elapsed = now - last
            tokens = min(self.burst, tokens + elapsed * self.rate)

            if tokens >= 1.0:
                tokens -= 1.0
                if ip:
                    self._per_ip[ip] = (tokens, now)
                return True
            else:
                if ip:
                    self._per_ip[ip] = (tokens, now)
                return False

    def cleanup(self, max_age: float = 300.0) -> int:
        """Удаляет устаревшие IP-записи. Возвращает кол-во удалённых."""
        with self._lock:
            now = time.monotonic()
            expired = [ip for ip, (_, t) in self._per_ip.items() if now - t > max_age]
            for ip in expired:
                del self._per_ip[ip]
            return len(expired)


# ──────────────────────────────────────────────────────────────
# Anti-Detect Engine
# ──────────────────────────────────────────────────────────────


class AntiDetectEngine:
    """
    Фоновый движок анти-детекта:
    - Ротация User-Agent
    - Отслеживание заголовков
    - Rate-limiting
    """

    def __init__(self, config: StackConfig):
        self.config = config
        self.ad = config.anti_detect

        # User-Agent pool
        self._ua_pool: List[str] = []
        self._current_ua: str = ""
        self._ua_lock = threading.Lock()

        # Rate limiter
        self.rate_limiter: Optional[TokenBucketRateLimiter] = None
        if self.ad.rate_limit.enabled:
            self.rate_limiter = TokenBucketRateLimiter(
                rate=self.ad.rate_limit.requests_per_second,
                burst=self.ad.rate_limit.burst,
            )

        # Background thread
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        # Загрузка UA pool
        self._load_user_agents()

    def _load_user_agents(self) -> None:
        """Загружает пул User-Agent из файла или встроенного списка."""
        pool_file = self.ad.user_agent_rotation.pool_file
        if pool_file and os.path.isfile(pool_file):
            try:
                with open(pool_file, "r", encoding="utf-8") as f:
                    self._ua_pool = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                logger.info("Загружено %d User-Agent из %s", len(self._ua_pool), pool_file)
            except Exception as exc:
                logger.warning("Ошибка чтения %s: %s, используем встроенный пул.", pool_file, exc)
                self._ua_pool = BUILTIN_USER_AGENTS.copy()
        else:
            self._ua_pool = BUILTIN_USER_AGENTS.copy()

        if self._ua_pool:
            self._current_ua = random.choice(self._ua_pool)

    @property
    def current_user_agent(self) -> str:
        with self._ua_lock:
            return self._current_ua

    def rotate_user_agent(self) -> str:
        """Выбирает новый случайный UA из пула."""
        with self._ua_lock:
            if len(self._ua_pool) > 1:
                # Исключаем текущий, чтобы гарантировать ротацию
                pool = [ua for ua in self._ua_pool if ua != self._current_ua]
                self._current_ua = random.choice(pool)
            elif self._ua_pool:
                self._current_ua = self._ua_pool[0]
            logger.debug("UA ротация → %s", self._current_ua[:60])
            return self._current_ua

    def get_strip_headers(self) -> List[str]:
        """Возвращает список заголовков для удаления."""
        if self.ad.header_manipulation.enabled:
            return self.ad.header_manipulation.strip_headers
        return []

    def get_add_headers(self) -> Dict[str, str]:
        """Возвращает заголовки для добавления."""
        headers = {}
        if self.ad.header_manipulation.enabled:
            headers.update(self.ad.header_manipulation.add_headers)
        return headers

    def check_rate_limit(self, ip: str = "") -> bool:
        """Проверяет rate-limit. True = запрос разрешён."""
        if not self.rate_limiter:
            return True
        target_ip = ip if self.ad.rate_limit.per_ip else ""
        return self.rate_limiter.allow(target_ip)

    # ── Background loop ─────────────────────────────────────

    def _background_loop(self) -> None:
        """Фоновый цикл: ротация UA, очистка rate-limiter."""
        logger.info("Anti-detect engine запущен (ротация каждые %ds).", self.ad.user_agent_rotation.rotate_every)
        interval = self.ad.user_agent_rotation.rotate_every
        cleanup_counter = 0

        while not self._stop_event.is_set():
            self._stop_event.wait(timeout=interval)
            if self._stop_event.is_set():
                break

            # Ротация UA
            if self.ad.user_agent_rotation.enabled:
                self.rotate_user_agent()

            # Периодическая очистка rate-limiter (каждые 5 ротаций)
            cleanup_counter += 1
            if cleanup_counter >= 5 and self.rate_limiter:
                removed = self.rate_limiter.cleanup()
                if removed:
                    logger.debug("Rate-limiter: удалено %d устаревших IP.", removed)
                cleanup_counter = 0

    def start(self) -> None:
        """Запускает фоновый поток."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._background_loop, daemon=True, name="anti-detect")
        self._thread.start()

    def stop(self) -> None:
        """Останавливает фоновый поток."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        logger.info("Anti-detect engine остановлен.")
