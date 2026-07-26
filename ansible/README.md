# Ручное развёртывание easy-ha-proxy

Главный плейбук `easy-ha-proxy.yml` устанавливает и настраивает HAProxy, Certbot, GeoIP ACL, Authelia, Docker-версию `haproxy-admin` и вспомогательные systemd-демоны.

Для одного сервера рекомендуется команда `easy-ha-proxy`, которая устанавливает локальный Ansible в venv и вызывает этот же playbook. Этот документ описывает ручной удалённый режим.

## Требования

- управляющая машина с Ansible;
- целевой Debian/Ubuntu-хост с SSH и `sudo`;
- коллекции `ansible.posix` и `community.docker`;
- Docker Compose v2 на целевом хосте для контейнерных сервисов;
- Ansible Vault password для файлов `group_vars/all/*.yml`.

Установка коллекций:

```bash
cd ansible
ansible-galaxy collection install -r requirements.yml
```

## Локальная конфигурация

`easy-ha-proxy.yml` по умолчанию ожидает группу `easy_ha_proxy` в ручном `inventory.ini` и загружает:

- `vars.yml` — домены, HAProxy, Certbot, SMTP и общие параметры;
- `authelia.yml` — несекретные параметры Authelia;
- `authelia_users_initial.yml` — начальные пользователи;
- `websites.yml` — HTTP/HTTPS-сайты;
- `tcp.yml` — TCP-прокси.

`inventory.ini`, `vars.yml`, `websites.yml`, `tcp.yml`,
`authelia_users_initial.yml` и весь `group_vars/` считаются локальными файлами
и исключены из Git. Даже зашифрованные Vault-файлы не публикуются: пароль Vault
может быть раскрыт или подобран отдельно.

Минимальный inventory:

```ini
[easy_ha_proxy]
proxy01 ansible_host=203.0.113.10 ansible_user=ansible
```

Перед первым запуском обязательно замените начальных пользователей и Argon2-хеши в `authelia_users_initial.yml`. Не храните рядом комментарии с исходными паролями.

## Проверка и запуск

Из каталога `ansible/`:

```bash
ansible-playbook --syntax-check -i inventory.ini easy-ha-proxy.yml
ansible-playbook -i inventory.ini easy-ha-proxy.yml --list-tags
ansible-playbook -i inventory.ini easy-ha-proxy.yml
```

Полный прогон обновляет пакеты, выпускает сертификаты и меняет системную
конфигурацию. При `ansible_connection=local` reboot всегда откладывается до решения
помощника или администратора. Автоматический reboot для узла, управляемого по SSH,
включается только явно: `-e easy_ha_proxy_reboot_after_upgrade=true`. Для точечных операций
используйте теги:

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

Примеры:

```bash
ansible-playbook -i inventory.ini easy-ha-proxy.yml -t ha-install,ha-cfg
ansible-playbook -i inventory.ini easy-ha-proxy.yml -t aut-install
ansible-playbook -i inventory.ini easy-ha-proxy.yml -t ha-adm-install,ha-adm-cfg,ha-adm-start
ansible-playbook -i inventory.ini easy-ha-proxy.yml -t addsite
ansible-playbook -i inventory.ini easy-ha-proxy.yml -t ha-adm-daemons,aut-daemons,status
ansible-playbook -i inventory.ini easy-ha-proxy.yml -t status
```

Точечный daemon-stage копирует все шесть управляемых скриптов идемпотентно:
неизменившиеся службы не перезапускаются. Полный status дополнительно
проверяет iptables loader, systemd timers, journald, Certbot, cron/logrotate,
версии APT/Snap и контрольные суммы остальных управляемых scripts/hooks/Lua.

Опасные или редкие сценарии имеют тег `never` и запускаются явно: `remove_site`, `aut-remove`, `aut-cfg`, `aut-users`, `ha-adm-update`, `ha-add-adm-ip`, `crt-rdg`, `crt-test`.

## Компоненты

### HAProxy

Роль `haproxy` устанавливает сервис, runtime socket, ACL, GeoIP-фильтрацию, rate/error limits и рендерит `/etc/haproxy/haproxy.cfg`. Конфигурация валидируется через `haproxy -c` перед применением.

### Сертификаты

Роль `cert` использует snap-версию Certbot, собирает `fullchain.pem + privkey.pem` для HAProxy и перезагружает сервис. Собранные PEM содержат приватный ключ и должны иметь режим не шире `0640`.

### Authelia

Authelia и Redis запускаются через Compose в `/opt/authelia`. Конфигурация, пользователи и SMTP `.env` создаются Ansible. Секреты должны приходить из Vault.

### haproxy-admin

UI слушает только `127.0.0.1:5000` и публикуется через HAProxy. Контейнер взаимодействует с root-демонами через UNIX-сокеты:

- `haproxy-controld`;
- `haproxy-certd`;
- `haproxy-healthd`;
- `authelia-configd`;
- `authelia-usersd`;
- `authelia-bansd`.

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
