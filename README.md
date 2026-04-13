# tg-tor-proxy

Скрипт для обхода блокировки Telegram на VPN-серверах с **AmneziaWG** / **Xray** / **WireGuard**.

Маршрутизирует трафик Telegram от VPN-клиентов через **Tor** (с поддержкой obfs4-мостов для обхода блокировки самого Tor).

```
VPN клиент → AWG/Xray контейнер → iptables → redsocks → Tor → Telegram
```

---

## Возможности

- 🔍 **Авто-обнаружение** контейнеров AmneziaWG, Xray, V2Ray, Sing-Box
- 🧅 **Tor без мостов** — сначала проверяет прямое подключение
- 🌉 **obfs4-мосты** — если Tor заблокирован провайдером (DPI)
- ⚖️ **1-3 Tor инстанса** с round-robin балансировкой — до 40 VPN клиентов
- 🔄 **Watchdog** — мониторинг каждые 10с: SIGHUP при зависшем bootstrap, автоперезапуск Tor и Redsocks
- 🛡️ **Безопасность** — redsocks закрыт от внешнего доступа, запускается не от root, правила iptables переживают ребут
- ⚡ **Оптимизация латентности** — OptimisticData, CircuitStreamTimeout, keepalive каждые 30с
- 🔁 **Авто-обновление** — два канала (stable / testing), конфигурация применяется автоматически
- 🗑️ **Полное удаление** одним пунктом меню
- 📊 **Диагностика** — полный отчёт о состоянии всей цепочки
- 📡 **Live-мониторинг** Telegram-сессий в реальном времени

---

## Требования

- Ubuntu / Debian (проверено на Ubuntu 22.04)
- Docker с запущенным VPN-контейнером (AmneziaWG, Xray и др.)
- Права root

---

## Быстрая установка

```bash
curl -fsSL https://raw.githubusercontent.com/sysbedlam/tg-tor-proxy/main/tg-tor-proxy.sh \
  -o tg-tor-proxy.sh && chmod +x tg-tor-proxy.sh && sudo ./tg-tor-proxy.sh
```

> После установки команда `tg-tor-proxy` доступна глобально.

---

## Использование

### Интерактивное меню

```bash
sudo tg-tor-proxy
```

```
╔══════════════════════════════════════════════╗
║   tg-tor-proxy  v2.2.x                      ║
║   Telegram через Tor для VPN-клиентов        ║
╚══════════════════════════════════════════════╝

  Tor ● 100% (bridges) ×2   Redsocks ●   iptables ●

  Выберите действие:

  1)  Установить / настроить заново
  2)  Диагностика (полный отчёт)
  3)  Проверить Tor
  4)  Добавить / заменить мосты (obfs4 bridges)
  5)  Загрузить мосты из файла
  6)  Применить iptables правила (если слетели)
  7)  Показать активные Telegram-сессии (live)
  8)  Обновить tg-tor-proxy
  9)  Удалить всё (deinstall)
  0)  Выход
```

### Прямые команды (для автоматизации)

| Команда | Действие |
|---------|----------|
| `tg-tor-proxy --install` | Установить / настроить заново |
| `tg-tor-proxy --diagnose` | Полный диагностический отчёт |
| `tg-tor-proxy --check-tor` | Проверить Tor-подключение |
| `tg-tor-proxy --add-bridges "obfs4 ..."` | Добавить мосты строкой |
| `tg-tor-proxy --add-bridges-file FILE` | Загрузить мосты из файла |
| `tg-tor-proxy --apply-rules` | Применить iptables правила заново |
| `tg-tor-proxy --update` | Обновить до последней версии |
| `tg-tor-proxy --remove` | Удалить всё |

---

## Что происходит при установке

1. Ищет Docker-контейнеры с VPN (amnezia, awg, xray, v2ray, sing-box, outline)
2. Устанавливает пакеты: `tor`, `redsocks`, `obfs4proxy`, `netfilter-persistent`
3. Тестирует **прямое** подключение к Tor (без мостов)
   - Если работает → настраивает без мостов
   - Если заблокировано DPI → запрашивает obfs4-мосты
4. Спрашивает количество Tor-инстансов (1-3) под нагрузку
5. Настраивает **redsocks** (`0.0.0.0:12345+` → Tor SOCKS5), запускает от пользователя `redsocks`
6. Создаёт цепочку **iptables** `TELEGRAM_TOR` — перенаправляет 49 подсетей Telegram
7. Закрывает порты redsocks от внешнего доступа (INPUT chain)
8. Сохраняет правила iptables через `netfilter-persistent` (переживают ребут)
9. Устанавливает **systemd-сервисы** с автозапуском:
   - `tg-tor-watchdog` — постоянный демон мониторинга
   - `tg-tor-routes` — восстанавливает iptables при старте
   - `Restart=always` для Tor и Redsocks

---

## Масштабирование под нагрузку

При установке выбирается количество Tor-инстансов:

| Инстансов | Клиентов | Порты Tor | Порты Redsocks |
|-----------|----------|-----------|----------------|
| 1 | до 15 | 9050 | 12345 |
| 2 | 15–30 | 9050, 9052 | 12345, 12346 |
| 3 | 30–40+ | 9050, 9052, 9053 | 12345, 12346, 12347 |

Трафик распределяется через iptables round-robin (`-m statistic --mode nth`).

---

## Обновление

```bash
sudo tg-tor-proxy --update
```

Доступны два канала:
- **stable** (`main`) — проверенные версии
- **testing** (`fix/direct-mode-stability`) — новые функции перед выходом в stable

После обновления `auto_migrate()` автоматически применяет все изменения конфигурации — устанавливает недостающие пакеты, обновляет конфиги, перезапускает сервисы. Ничего делать вручную не нужно.

---

## Если Tor заблокирован (нужны мосты)

Получите obfs4-мосты **с другого устройства или сети**:

- **Веб**: [bridges.torproject.org](https://bridges.torproject.org/?transport=obfs4)
- **Email**: отправьте письмо на `bridges@torproject.org` с темой `get transport obfs4`
- **Telegram-бот**: [@GetBridgesBot](https://t.me/GetBridgesBot)

Формат строки моста:
```
obfs4 1.2.3.4:1234 FINGERPRINT cert=BASE64_STRING iat-mode=0
```

Добавить через меню (пункт 4) или командой:
```bash
sudo tg-tor-proxy --add-bridges "obfs4 1.2.3.4:1234 FP cert=... iat-mode=0"
```

---

## Диагностика

```bash
sudo tg-tor-proxy --diagnose
```

Пример вывода:
```
══ Services ══
  ● tg-tor-inst0  — active
  ● tg-tor-inst1  — active
  ● redsocks-inst0 — active
  ● redsocks-inst1 — active
  ● tg-tor-watchdog — active

══ Tor Status ══
  [inst0] Bootstrap: 100% | Mode: bridges
  [inst1] Bootstrap: 100% | Mode: bridges
  Tor exit IP: 185.220.101.x

══ Redsocks ══
  Active connections: 24
  Recent Telegram sessions (last 10):
    172.29.172.2:36540 → 149.154.167.41:443
    172.29.172.2:57510 → 149.154.167.51:5222

══ iptables Rules ══
  TELEGRAM_TOR chain: active (58 lines)
  PREROUTING: linked
  Redsocks ports: protected (INPUT DROP)
```

### Мониторинг сессий в реальном времени

```bash
journalctl -t redsocks -f
```

---

## Безопасность

| Угроза | Защита |
|--------|--------|
| Внешние подключения к redsocks | iptables INPUT: ACCEPT private, DROP остальное |
| redsocks от root | Запускается от user=redsocks/group=redsocks |
| Потеря правил после ребута | netfilter-persistent сохраняет rules.v4 |
| Tor exit node через ваш сервер | Не relay, не exit — только клиент |

---

## Удаление

```bash
sudo tg-tor-proxy --remove
```

Удаляет: iptables-правила, systemd-сервисы, конфиги redsocks/tor, пакеты (опционально).

---

## Технические детали

| Компонент | Роль |
|-----------|------|
| **iptables PREROUTING** | Перехватывает TCP к Telegram-IP → redsocks (round-robin) |
| **redsocks** | Прозрачный прокси: TCP → Tor SOCKS5 |
| **Tor + obfs4** | Туннель через цензуру к Telegram |
| **Watchdog** | SIGHUP если Tor завис, keepalive каждые 30с для тёплых цепочек |
| **auto_migrate()** | Применяет изменения конфигурации при обновлении версии |

### Оптимизация латентности Tor

```
OptimisticData 1        — отправка данных без ожидания ACK от каждого узла
CircuitStreamTimeout 15 — быстрое переключение на запасную цепочку
CircuitBuildTimeout 30  — быстрый отказ от медленных путей
KeepalivePeriod 30      — keepalive каждые 30с
```

### Telegram IP-подсети (49 штук)

Включены все официальные подсети Telegram: `149.154.160.0/20`, `91.108.*.0/22`, `95.161.64.0/20` и др.

---

## Лицензия

MIT
