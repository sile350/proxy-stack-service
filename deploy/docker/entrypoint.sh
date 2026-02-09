#!/usr/bin/env bash
# ============================================================
# Docker entrypoint — Ubuntu 24.04
# 1. Фиксит права на Docker-тома (запускается от root)
# 2. Запускает оркестратор от пользователя proxy через gosu
# ============================================================
set -euo pipefail

# ── Информация о среде ───────────────────────────────────────
echo "=== Proxy Stack — Docker Entrypoint ==="
echo "  OS:      $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)"
echo "  User:    $(whoami) (UID=$(id -u))"
echo "  Python:  $(python3 --version 2>&1)"
echo "  3proxy:  $(3proxy --version 2>&1 | head -1 || echo 'installed')"
echo "  HAProxy: $(haproxy -v 2>&1 | head -1)"

# ── Фикс прав на Docker-тома ────────────────────────────────
# Docker-тома создаются от root; нужно передать их пользователю proxy
for dir in /var/log/proxy-stack /var/run/proxy-stack /opt/proxy-stack/3proxy; do
    mkdir -p "$dir" 2>/dev/null || true
    chown -R proxy:proxy "$dir" 2>/dev/null || true
done

echo "  Права:   исправлены"
echo "========================================="

# ── Запуск оркестратора от пользователя proxy ────────────────
# gosu меняет пользователя и exec'ит процесс (не создаёт лишний PID)
exec gosu proxy python3 /opt/proxy-stack/proxy_stack.py "$@"
