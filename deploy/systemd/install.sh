#!/usr/bin/env bash
# ============================================================
# Установочный скрипт Proxy Stack для Ubuntu 20.04 / 22.04 / 24.04
# Запускать от root: sudo bash install.sh
# ============================================================
set -euo pipefail

# ── Цвета ────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*" >&2; }

# ── Параметры ────────────────────────────────────────────────
INSTALL_DIR="/opt/proxy-stack"
LOG_DIR="/var/log/proxy-stack"
PID_DIR="/var/run/proxy-stack"
VENV_DIR="${INSTALL_DIR}/venv"
SERVICE_USER="proxy"
SERVICE_GROUP="proxy"
THREEPROXY_VERSION="0.9.4"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# ── Проверки ─────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    error "Скрипт должен быть запущен от root (sudo bash install.sh)"
    exit 1
fi

# Проверяем Ubuntu
if ! grep -qi "ubuntu" /etc/os-release 2>/dev/null; then
    warn "Этот скрипт предназначен для Ubuntu. На других дистрибутивах могут быть проблемы."
fi

UBUNTU_VERSION=$(grep VERSION_ID /etc/os-release 2>/dev/null | cut -d'"' -f2 || echo "unknown")
echo ""
echo "============================================================"
echo " Proxy Stack — Установка на Ubuntu ${UBUNTU_VERSION}"
echo "============================================================"
echo ""

# ── 1. Обновление системы и установка пакетов ────────────────
info "Обновление списка пакетов..."
apt-get update -qq

info "Установка системных зависимостей..."
apt-get install -y --no-install-recommends \
    haproxy \
    python3 \
    python3-pip \
    python3-venv \
    build-essential \
    git \
    curl \
    wget \
    procps \
    net-tools \
    ca-certificates \
    software-properties-common

# ── 2. Сборка 3proxy (если не установлен) ────────────────────
if command -v 3proxy &>/dev/null; then
    info "3proxy уже установлен: $(3proxy --version 2>&1 | head -1 || echo 'найден')"
else
    info "Сборка 3proxy ${THREEPROXY_VERSION} из исходников..."
    BUILD_DIR=$(mktemp -d)
    git clone --depth 1 --branch "${THREEPROXY_VERSION}" \
        https://github.com/3proxy/3proxy.git "${BUILD_DIR}/3proxy"
    cd "${BUILD_DIR}/3proxy"
    make -f Makefile.Linux
    strip bin/3proxy
    cp bin/3proxy /usr/local/bin/3proxy
    chmod 755 /usr/local/bin/3proxy
    cd /
    rm -rf "${BUILD_DIR}"
    info "3proxy установлен: /usr/local/bin/3proxy"
fi

# ── 3. Остановка штатного HAProxy (им управляет оркестратор) ──
info "Отключаем штатный systemd-сервис HAProxy (оркестратор запускает свой экземпляр)..."
systemctl stop haproxy.service 2>/dev/null || true
systemctl disable haproxy.service 2>/dev/null || true

# ── 4. Создание системного пользователя ──────────────────────
if ! id "${SERVICE_USER}" &>/dev/null; then
    info "Создание системного пользователя ${SERVICE_USER}..."
    groupadd --system "${SERVICE_GROUP}" 2>/dev/null || true
    useradd --system --gid "${SERVICE_GROUP}" \
            --home-dir "${INSTALL_DIR}" \
            --shell /usr/sbin/nologin \
            "${SERVICE_USER}"
else
    info "Пользователь ${SERVICE_USER} уже существует."
fi

# ── 5. Создание директорий ───────────────────────────────────
info "Создание рабочих директорий..."
mkdir -p "${INSTALL_DIR}" "${LOG_DIR}" "${PID_DIR}" "${INSTALL_DIR}/3proxy"

# ── 6. Копирование файлов проекта ────────────────────────────
info "Копирование файлов проекта в ${INSTALL_DIR}..."
cp "${PROJECT_ROOT}/proxy_stack.py" "${INSTALL_DIR}/"
cp -r "${PROJECT_ROOT}/lib" "${INSTALL_DIR}/"
cp "${PROJECT_ROOT}/config.yml" "${INSTALL_DIR}/"
cp "${PROJECT_ROOT}/requirements.txt" "${INSTALL_DIR}/"

# ── 7. Python virtual environment ────────────────────────────
info "Создание Python venv и установка зависимостей..."
python3 -m venv "${VENV_DIR}"
"${VENV_DIR}/bin/pip" install --upgrade pip --quiet
"${VENV_DIR}/bin/pip" install -r "${INSTALL_DIR}/requirements.txt" --quiet
info "Python venv: ${VENV_DIR}"

# ── 8. Настройка прав ────────────────────────────────────────
info "Настройка прав доступа..."
chown -R "${SERVICE_USER}:${SERVICE_GROUP}" "${INSTALL_DIR}" "${LOG_DIR}" "${PID_DIR}"
chmod 750 "${INSTALL_DIR}"
chmod 755 "${INSTALL_DIR}/proxy_stack.py"

# HAProxy и 3proxy нужны разрешения на привилегированные порты
# (оркестратор запускает их перед сбросом привилегий)
setcap 'cap_net_bind_service=+ep' /usr/sbin/haproxy 2>/dev/null || true
setcap 'cap_net_bind_service=+ep' /usr/local/bin/3proxy 2>/dev/null || true

# ── 9. Создание environment-файла ────────────────────────────
info "Создание /etc/proxy-stack.env..."
cat > /etc/proxy-stack.env <<'ENVEOF'
# Proxy Stack — environment variables
PYTHONUNBUFFERED=1
# Если нужны кастомные переменные — добавляйте ниже
ENVEOF
chmod 640 /etc/proxy-stack.env
chown root:${SERVICE_GROUP} /etc/proxy-stack.env

# ── 10. Установка systemd unit ───────────────────────────────
info "Установка systemd service..."
cp "${SCRIPT_DIR}/proxy-stack.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable proxy-stack.service

# ── 11. Настройка logrotate ──────────────────────────────────
info "Настройка logrotate..."
cat > /etc/logrotate.d/proxy-stack <<LOGEOF
${LOG_DIR}/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 ${SERVICE_USER} ${SERVICE_GROUP}
    sharedscripts
    postrotate
        systemctl reload proxy-stack 2>/dev/null || true
    endscript
}
LOGEOF

# ── 12. Настройка sysctl для производительности ──────────────
info "Настройка sysctl (сетевые параметры)..."
cat > /etc/sysctl.d/99-proxy-stack.conf <<'SYSEOF'
# Proxy Stack — сетевая оптимизация
# Увеличение буферов TCP
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# Увеличение бэклога соединений
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535

# TCP keepalive
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 60
net.ipv4.tcp_keepalive_probes = 3

# Быстрая утилизация TIME_WAIT
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15

# Увеличение диапазона локальных портов
net.ipv4.ip_local_port_range = 1024 65535

# IPv6
net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0
SYSEOF
sysctl --system --quiet 2>/dev/null || true

# ── 13. Настройка UFW (если активен) ─────────────────────────
if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
    info "Настройка UFW..."
    ufw allow 3128/tcp comment "Proxy Stack — HTTP Proxy"
    ufw allow 1080/tcp comment "Proxy Stack — SOCKS5 Proxy"
    # Мониторинг и stats только с localhost (не открываем)
    info "UFW правила добавлены (3128/tcp, 1080/tcp)."
else
    info "UFW не активен, пропускаем настройку firewall."
fi

# ── 14. Увеличение лимитов файлов ────────────────────────────
info "Настройка ulimits..."
cat > /etc/security/limits.d/proxy-stack.conf <<LIMEOF
${SERVICE_USER}  soft  nofile  65535
${SERVICE_USER}  hard  nofile  65535
${SERVICE_USER}  soft  nproc   4096
${SERVICE_USER}  hard  nproc   4096
LIMEOF

# ── Итого ────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo -e " ${GREEN}Установка завершена успешно!${NC}"
echo "============================================================"
echo ""
echo " Компоненты:"
echo "   3proxy:  $(3proxy --version 2>&1 | head -1 || echo '/usr/local/bin/3proxy')"
echo "   HAProxy: $(haproxy -v 2>&1 | head -1)"
echo "   Python:  $(${VENV_DIR}/bin/python3 --version)"
echo ""
echo " Команды управления:"
echo "   sudo systemctl start proxy-stack     — запуск"
echo "   sudo systemctl stop proxy-stack      — остановка"
echo "   sudo systemctl restart proxy-stack   — перезапуск"
echo "   sudo systemctl status proxy-stack    — статус"
echo "   sudo journalctl -u proxy-stack -f    — логи"
echo ""
echo " Конфигурация:  ${INSTALL_DIR}/config.yml"
echo " Логи:          ${LOG_DIR}/"
echo " Python venv:   ${VENV_DIR}/"
echo " Environment:   /etc/proxy-stack.env"
echo ""
echo " Проверка после запуска:"
echo "   curl -x http://localhost:3128 https://httpbin.org/ip"
echo "   curl -x socks5://localhost:1080 https://httpbin.org/ip"
echo "   curl http://localhost:9100/health"
echo ""
