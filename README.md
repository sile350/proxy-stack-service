# 3Proxy + HAProxy Proxy Stack

Оркестратор прокси-серверов, объединяющий **HAProxy** (TCP балансировщик нагрузки) с несколькими экземплярами **3proxy** (HTTP/SOCKS прокси) через единый Python-скрипт управления.

## Архитектура

```
Клиент
  │
  ▼
┌──────────────────────────────────────┐
│  HAProxy (TCP mode, без TLS-терм.)   │
│  ├── :3128  HTTP Proxy Frontend      │
│  └── :1080  SOCKS5 Proxy Frontend    │
│             │                        │
│     ┌───────┼────────┐               │
│     ▼       ▼        ▼               │
│  3proxy   3proxy   3proxy            │
│  #0       #1       #2               │
│  :13128   :13129   :13130  (HTTP)    │
│  :11080   :11081   :11082  (SOCKS)   │
└──────────────────────────────────────┘
         │
         ▼
    Целевой сервер
```

## Ключевые особенности

| Функция | Реализация |
|---------|-----------|
| **Без TLS-терминации** | HAProxy в `mode tcp` — пропускает TLS как есть, сохраняя JA3/JA4 fingerprints клиента |
| **Балансировка нагрузки** | Round-robin / leastconn / source-hash между 3 экземплярами 3proxy |
| **Анти-детект** | Ротация User-Agent, удаление proxy-заголовков (X-Forwarded-For, Via), rate-limiting |
| **Мониторинг** | Prometheus-совместимые метрики (`/metrics`), JSON health-check (`/health`) |
| **Health checks** | TCP-проверки каждые 3 секунды, автоматическое исключение мёртвых бэкендов |
| **systemd** | Hardened unit-файл для Ubuntu, автоперезапуск, journalctl, logrotate |
| **Docker** | Multi-stage build на Ubuntu 24.04, rootless, tini, venv, health check |
| **Dual-stack** | Полная поддержка IPv4 и IPv6 |

## Быстрый старт

> **Целевая платформа**: Ubuntu 20.04 / 22.04 / 24.04 LTS

### Вариант 1: Docker Compose на Ubuntu (рекомендуется)

```bash
# Установка Docker (если ещё не установлен)
sudo apt update
sudo apt install -y docker.io docker-compose-v2
sudo systemctl enable --now docker

# Клонируем / копируем проект
cd proxy-stack

# Настраиваем (опционально)
nano config.yml

# Сборка и запуск (Ubuntu 24.04 внутри контейнера)
docker compose up -d --build

# Проверка работоспособности
curl -x http://localhost:3128 https://httpbin.org/ip
curl -x socks5://localhost:1080 https://httpbin.org/ip

# Статус
docker compose ps
curl http://localhost:9100/health

# Логи
docker compose logs -f proxy-stack
```

### Вариант 2: Bare Metal на Ubuntu

```bash
# 1. Установка пакетов (Ubuntu 20.04+)
sudo apt update
sudo apt install -y haproxy python3 python3-pip python3-venv \
    build-essential git curl net-tools

# 2. Сборка 3proxy из исходников
git clone --depth 1 --branch 0.9.4 https://github.com/3proxy/3proxy.git
cd 3proxy && make -f Makefile.Linux
sudo cp bin/3proxy /usr/local/bin/3proxy
cd ..

# 3. Python venv и зависимости
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 4. Генерация и валидация конфигов
python3 proxy_stack.py generate -c config.yml
python3 proxy_stack.py validate -c config.yml

# 5. Запуск
sudo python3 proxy_stack.py start -c config.yml

# 6. Проверка
python3 proxy_stack.py status -c config.yml
curl -x http://localhost:3128 https://httpbin.org/ip

# 7. Остановка
sudo python3 proxy_stack.py stop -c config.yml
```

### Вариант 3: systemd на Ubuntu (production)

Установочный скрипт автоматически:
- установит все пакеты (`haproxy`, `python3`, `build-essential`...)
- соберёт 3proxy из исходников
- создаст Python venv
- настроит systemd, logrotate, sysctl, UFW, ulimits

```bash
# Одна команда — полная установка
sudo bash deploy/systemd/install.sh

# Управление
sudo systemctl start proxy-stack
sudo systemctl status proxy-stack
sudo journalctl -u proxy-stack -f

# Проверка
curl -x http://localhost:3128 https://httpbin.org/ip
curl http://localhost:9100/health
```

## Конфигурация

Вся конфигурация в одном файле `config.yml`:

```yaml
general:
  work_dir: /opt/proxy-stack
  log_dir: /var/log/proxy-stack

haproxy:
  frontends:
    http:
      bind_port: 3128    # Порт HTTP-прокси
    socks:
      bind_port: 1080    # Порт SOCKS5-прокси

three_proxy:
  instance_count: 3       # Количество экземпляров
  auth:
    enabled: false        # Включить аутентификацию

anti_detect:
  user_agent_rotation:
    enabled: true
    rotate_every: 60      # Секунд между ротациями
  rate_limit:
    enabled: true
    requests_per_second: 50

monitoring:
  enabled: true
  port: 9100
```

Полное описание всех параметров — в файле `config.yml` с комментариями.

## Мониторинг

### Prometheus метрики

```bash
curl http://localhost:9100/metrics
```

Пример вывода:
```
proxy_backend_3proxy_0_http_alive 1.0
proxy_backend_3proxy_0_socks_alive 1.0
proxy_backend_3proxy_0_http_latency_ms 0.42
proxy_healthy_backends 3.0
proxy_total_backends 3.0
proxy_stack_cpu_percent 2.3
proxy_stack_memory_percent 8.1
proxy_stack_net_connections 47
```

### Health Check

```bash
curl http://localhost:9100/health
```

```json
{
  "status": "healthy",
  "healthy_backends": 3,
  "total_backends": 3,
  "backends": {
    "3proxy_0": {"healthy": true, "http_latency_ms": 0.42},
    "3proxy_1": {"healthy": true, "http_latency_ms": 0.38},
    "3proxy_2": {"healthy": true, "http_latency_ms": 0.45}
  }
}
```

### HAProxy Stats

```
http://localhost:8404/stats
```

Логин/пароль по умолчанию: `admin` / `proxy_stats_secret` (настраивается в `config.yml`).

## Безопасность

### TLS Fingerprinting

HAProxy работает **исключительно в TCP mode** — весь TLS-трафик пропускается «как есть» без терминации. Это означает:

- JA3/JA4 fingerprints клиента **сохраняются** на всём пути до целевого сервера
- Невозможно обнаружить прокси по несоответствию TLS fingerprint
- HTTPS-трафик полностью зашифрован end-to-end

### Защита от обнаружения

- **Удаление заголовков**: `X-Forwarded-For`, `X-Real-IP`, `Via`, `Forwarded`
- **Ротация User-Agent**: 20+ реалистичных UA (Chrome, Firefox, Safari, Edge)
- **Rate limiting**: Token bucket с per-IP контролем через HAProxy `stick-table`
- **TCP connection rate**: Ограничение скорости новых подключений на уровне HAProxy

### systemd Hardening (Ubuntu)

Используются все доступные директивы hardening systemd >= 245 (Ubuntu 20.04+):

- `NoNewPrivileges=yes` — запрет повышения привилегий
- `ProtectSystem=strict` — read-only для `/usr`, `/boot`, `/etc`
- `PrivateTmp=yes` — изолированный `/tmp`
- `ProtectKernelLogs=yes` — защита `/dev/kmsg`
- `ProtectProc=invisible` — скрытие чужих процессов
- `MemoryDenyWriteExecute=yes` — запрет W^X
- `SystemCallFilter=@system-service` — белый список syscall
- `RestrictNamespaces=yes` — запрет создания namespaces
- `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` — только привязка портов
- `RuntimeDirectory=proxy-stack` — автоочистка PID-файлов
- `EnvironmentFile=/etc/proxy-stack.env` — переменные окружения

## Структура проекта

```
proxy-stack/
├── proxy_stack.py              # Главный оркестратор (CLI)
├── config.yml                  # Единый конфиг
├── requirements.txt            # Python зависимости
├── lib/
│   ├── __init__.py
│   ├── config_loader.py        # Парсер YAML → dataclasses
│   ├── three_proxy_manager.py  # Управление экземплярами 3proxy
│   ├── haproxy_manager.py      # Управление HAProxy
│   ├── anti_detect.py          # UA-ротация, заголовки, rate-limit
│   ├── health_checker.py       # TCP health checks
│   ├── monitoring_server.py    # HTTP /metrics + /health
│   └── utils.py                # PID, логи, процессы
├── Dockerfile                  # Multi-stage Docker build (Ubuntu 24.04)
├── docker-compose.yml          # Compose с dual-stack IPv6
└── deploy/
    ├── systemd/
    │   ├── proxy-stack.service # systemd unit (hardened)
    │   └── install.sh          # Установочный скрипт
    └── docker/
        └── entrypoint.sh       # Docker entrypoint
```

## CLI

```
python3 proxy_stack.py <action> [-c config.yml] [-v]

Действия:
  start     — Запуск стека (генерация конфигов + запуск всех компонентов)
  stop      — Грациозная остановка (SIGTERM → ожидание → SIGKILL)
  restart   — Перезапуск
  status    — Статус всех компонентов (PID, alive/dead)
  generate  — Генерация конфигов без запуска
  validate  — Проверка конфигурации + наличие бинарников

Опции:
  -c, --config    Путь к config.yml (по умолчанию: ./config.yml)
  -v, --verbose   Подробный вывод (DEBUG)
  --no-drop-privs Не сбрасывать привилегии
```

## Требования

| Компонент | Версия | Пакет Ubuntu |
|-----------|--------|-------------|
| **Ubuntu** | 20.04 / 22.04 / 24.04 LTS | — |
| **Python** | 3.9+ | `python3 python3-venv python3-pip` |
| **HAProxy** | 2.4+ | `haproxy` |
| **3proxy** | 0.9.4+ | Сборка из исходников (автоматически через `install.sh`) |
| **Docker** | 20.10+ (опционально) | `docker.io docker-compose-v2` |
| **systemd** | 245+ | Встроен в Ubuntu 20.04+ |

### Установка зависимостей вручную (Ubuntu)

```bash
sudo apt update && sudo apt install -y \
    haproxy python3 python3-pip python3-venv \
    build-essential git curl net-tools procps ca-certificates
```
