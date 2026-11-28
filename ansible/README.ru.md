# Playbook и роли

`easy-ha-proxy.yml` и роли в `roles/` описывают шлюз: HAProxy, Certbot,
GeoIP ACL, Authelia, контейнер `haproxy-admin` и вспомогательные
systemd-демоны. Агент установки (`easy-ha-proxy-agent apply playbook`) читает
их на сервере — записи и теги playbook, defaults, шаблоны и файлы ролей — и
меняет только то, что отличается от хоста. Ansible не участвует.
[English version](README.md).

Устанавливают и обновляют командой `easy-ha-proxy`. Управляемая конфигурация
лежит в `/etc/easy-ha-proxy` (`vars.yml`, `authelia.yml`,
`authelia_users_initial.yml`, `websites.yml`, `tcp.yml`, `secrets.yml`,
`inventory.ini`) и никогда не попадает в Git.

## Запуск записей

Точечный запуск принимает теги playbook; `--check` показывает, что изменилось
бы, и ничего не меняет:

```bash
sudo easy-ha-proxy-agent apply playbook --check --tags status   --source /opt/easy-ha-proxy/source --config /etc/easy-ha-proxy
sudo easy-ha-proxy-agent apply playbook --tags ha-install,ha-cfg   --source /opt/easy-ha-proxy/source --config /etc/easy-ha-proxy
```

Запуск без тегов включает обновление пакетов ОС и никогда не перезагружает
сервер: помощник спрашивает после обновления и по умолчанию откладывает
перезагрузку.

| Назначение | Тег |
| --- | --- |
| Обновление ОС | `upgrade` |
| Установка Certbot и выпуск сертификатов | `cert` |
| Установка Certbot | `crt-install` |
| Certbot hooks | `crt-hooks` |
| Продление/выпуск | `crt-renew` |
| Установка HAProxy | `ha-install` |
| Конфигурация HAProxy | `ha-cfg` |
| AppArmor | `apparmor` |
| GeoIP ACL | `geo` |
| Установка Docker Engine/Compose | `docker` |
| Установка Authelia | `aut-install` или `authelia` |
| Установка UI и демонов | `ha-adm-install` |
| Конфигурация UI | `ha-adm-cfg` |
| Запуск UI | `ha-adm-start` |
| Health daemon | `ha-adm-healthd` |
| Control daemon | `ha-adm-controld` |
| Все helper-демоны (точечное обновление) | `ha-adm-daemons,aut-daemons` |
| Весь host-side service-контур | CLI: `update --component services` |
| Проверка состояния | `status` |
| Добавление сайта | `addsite` |

Точечный daemon-stage копирует все управляемые скрипты демонов идемпотентно:
неизменившиеся службы не перезапускаются. Полный status дополнительно
проверяет iptables loader, systemd timers, journald, Certbot, cron/logrotate,
версии APT/Snap и контрольные суммы остальных управляемых scripts/hooks/Lua.

Сценарии вне обычного обновления имеют тег `never` и запускаются явно: `aut-cfg`, `aut-daemons`, `aut-update`, `ha-adm-daemons`, `ha-adm-update`. Установщик только устанавливает и обновляет; сайты, пользователи, адреса администраторов и остальные настройки меняются в веб-панели (основной домен — командой `easy-ha-proxy migrate-domain`).

## Компоненты

### HAProxy

Роль `haproxy` устанавливает сервис, runtime socket, ACL, GeoIP-фильтрацию, rate/error limits и рендерит `/etc/haproxy/haproxy.cfg`. Конфигурация валидируется через `haproxy -c` перед применением.

### Сертификаты

Роль `cert` использует snap-версию Certbot, собирает `fullchain.pem + privkey.pem` для HAProxy и перезагружает сервис. Собранные PEM содержат приватный ключ и должны иметь режим не шире `0640`.

### Authelia

Authelia и Redis запускаются через Compose в `/opt/authelia`. Конфигурацию, начальных пользователей и SMTP `.env` создаёт установщик; секреты берутся из управляемого `secrets.yml`.

### haproxy-admin

UI слушает только `127.0.0.1:5000` и публикуется через HAProxy. Контейнер взаимодействует с root-демонами через UNIX-сокеты, в том числе:

- `haproxy-controld`, `haproxy-certd`, `haproxy-healthd`;
- `easy-ha-proxy-guardd`, `easy-ha-proxy-metricsd`, `easy-ha-proxy-alertd`,
  `easy-ha-proxy-backupd`, `easy-ha-proxy-updated`;
- `authelia-configd`, `authelia-usersd`, `authelia-bansd`.

Маршруты `/debug/` и `/debug/headers` по умолчанию выключены, а кнопка
диагностики скрыта. При прямом открытии `/debug/` UI показывает инструкцию.
Для временного включения добавьте в управляемый `vars.yml`:

```yaml
haproxy_admin_debug_routes: true
```

Затем выполните `sudo easy-ha-proxy update --no-fetch`. После диагностики
верните значение `false` и повторно примените конфигурацию.

## Диагностика

```bash
haproxy -c -f /etc/haproxy/haproxy.cfg
systemctl status haproxy haproxy-controld haproxy-certd haproxy-healthd
journalctl -u haproxy -u haproxy-controld -u haproxy-certd -n 200
docker compose -f /opt/authelia/docker-compose.yml ps
docker compose -f /opt/haproxy-admin/docker-compose.yml ps
```

Основные пути:

- HAProxy: `/etc/haproxy/haproxy.cfg`;
- сертификаты HAProxy: `/etc/haproxy/certs/`;
- Authelia: `/opt/authelia/`;
- UI: `/opt/haproxy-admin/`;
- HAProxy runtime socket: `/run/haproxy/admin.sock`.

## Безопасность

- Не публикуйте порты `5000` и `9091` наружу: авторизация рассчитана на вход через HAProxy/Authelia.
- После утечки приватного ключа недостаточно удалить PEM из Git — сертификат нужно перевыпустить, а старый ключ считать скомпрометированным.
- Изменяющие запросы UI защищены CSRF-токенами; независимо от этого доступ к UI должен быть ограничен доверенными пользователями и доменом.
