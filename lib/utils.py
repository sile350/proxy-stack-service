"""
Утилиты общего назначения — файловые операции, PID, логирование, привилегии.
"""

from __future__ import annotations

import grp
import logging
import os
import pwd
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

from lib.config_loader import StackConfig

logger = logging.getLogger("proxy-stack")


# ──────────────────────────────────────────────────────────────
# Директории
# ──────────────────────────────────────────────────────────────


def ensure_directories(config: StackConfig) -> None:
    """Создаёт рабочие директории, если их нет."""
    dirs = [
        config.work_dir,
        config.log_dir,
        config.pid_dir,
        os.path.join(config.work_dir, "3proxy"),
    ]
    for d in dirs:
        Path(d).mkdir(parents=True, exist_ok=True)
        logger.debug("Директория: %s", d)


# ──────────────────────────────────────────────────────────────
# Логирование
# ──────────────────────────────────────────────────────────────


def setup_logging(config: StackConfig, level: int = logging.INFO) -> None:
    """Настраивает root-логгер: консоль + файл."""
    root = logging.getLogger()
    root.setLevel(level)

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Консоль
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level)
    ch.setFormatter(fmt)
    root.addHandler(ch)

    # Файл (если директория доступна)
    log_file = os.path.join(config.log_dir, "proxy-stack.log")
    try:
        Path(config.log_dir).mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(level)
        fh.setFormatter(fmt)
        root.addHandler(fh)
    except PermissionError:
        logger.warning("Нет доступа к %s, логирование только в консоль.", log_file)


# ──────────────────────────────────────────────────────────────
# Проверка бинарников
# ──────────────────────────────────────────────────────────────


def check_binary_exists(binary_path: str) -> bool:
    """Проверяет наличие исполняемого файла."""
    resolved = shutil.which(binary_path)
    if resolved:
        return True
    return os.path.isfile(binary_path) and os.access(binary_path, os.X_OK)


# ──────────────────────────────────────────────────────────────
# PID-файлы
# ──────────────────────────────────────────────────────────────


def _pid_path(config: StackConfig) -> str:
    return os.path.join(config.pid_dir, "proxy-stack.pid")


def write_pid_file(config: StackConfig) -> None:
    path = _pid_path(config)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        f.write(str(os.getpid()))
    logger.debug("PID-файл записан: %s", path)


def read_pid_file(config: StackConfig) -> Optional[int]:
    path = _pid_path(config)
    try:
        with open(path, "r") as f:
            return int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return None


def remove_pid_file(config: StackConfig) -> None:
    path = _pid_path(config)
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def is_process_alive(pid: int) -> bool:
    """Проверяет, жив ли процесс по PID."""
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def read_component_pid(pid_file: str) -> Optional[int]:
    """Читает PID из произвольного файла."""
    try:
        with open(pid_file, "r") as f:
            return int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return None


# ──────────────────────────────────────────────────────────────
# Привилегии
# ──────────────────────────────────────────────────────────────


def drop_privileges(user: str, group: str) -> None:
    """Сбрасывает привилегии до указанного пользователя/группы."""
    if os.getuid() != 0:
        logger.debug("Не root, пропускаем сброс привилегий.")
        return

    try:
        pw = pwd.getpwnam(user)
        gr = grp.getgrnam(group)
        os.setgroups([])
        os.setgid(gr.gr_gid)
        os.setuid(pw.pw_uid)
        logger.info("Привилегии сброшены до %s:%s", user, group)
    except KeyError:
        logger.warning("Пользователь/группа %s:%s не найдены, работаем от текущего пользователя.", user, group)
    except PermissionError:
        logger.warning("Не удалось сбросить привилегии (PermissionError).")


# ──────────────────────────────────────────────────────────────
# Запуск процессов
# ──────────────────────────────────────────────────────────────


def run_process(cmd: list, description: str, env: dict = None) -> subprocess.Popen:
    """Запускает процесс, возвращает Popen."""
    logger.info("Запуск: %s", " ".join(cmd))
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env or os.environ.copy(),
    )
    logger.debug("%s запущен, PID=%d", description, proc.pid)
    return proc


def stop_process_by_pid(pid: int, description: str, timeout: int = 10) -> bool:
    """Останавливает процесс: SIGTERM → ожидание → SIGKILL."""
    if not is_process_alive(pid):
        logger.debug("%s (PID %d) уже остановлен.", description, pid)
        return True

    logger.info("Остановка %s (PID %d)...", description, pid)

    # SIGTERM
    try:
        os.kill(pid, 15)  # SIGTERM
    except OSError:
        return True

    # Ожидание
    import time
    for _ in range(timeout * 10):
        if not is_process_alive(pid):
            logger.info("%s (PID %d) остановлен.", description, pid)
            return True
        time.sleep(0.1)

    # SIGKILL
    logger.warning("%s (PID %d) не завершился за %ds, отправляем SIGKILL.", description, pid, timeout)
    try:
        os.kill(pid, 9)  # SIGKILL
    except OSError:
        pass

    return not is_process_alive(pid)
