#!/usr/bin/env bash
# ============================================================
# Docker entrypoint — Ubuntu 24.04 runtime
# ============================================================
set -euo pipefail

echo "=== Proxy Stack — Docker Entrypoint (Ubuntu 24.04) ==="
echo "User: $(whoami) (UID=$(id -u), GID=$(id -g))"
echo "Python: $(python3 --version)"
echo "3proxy: $(3proxy --version 2>&1 || echo 'N/A')"
echo "HAProxy: $(haproxy -v 2>&1 | head -1 || echo 'N/A')"
echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"

# Убедимся что директории доступны
for dir in /var/log/proxy-stack /var/run/proxy-stack /opt/proxy-stack/3proxy; do
    mkdir -p "$dir" 2>/dev/null || true
done

# Запускаем оркестратор через venv Python
exec python3 /opt/proxy-stack/proxy_stack.py "$@"
