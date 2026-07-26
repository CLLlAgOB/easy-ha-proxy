# easy-ha-proxy: быстрый старт

[English](QUICKSTART.md) | [Русский](QUICKSTART.ru.md)

Это краткий путь до первой поддерживаемой установки. Управление, миграция,
backup и restore подробно описаны в полном
[руководстве установщика](INSTALLER_README.ru.md).

## Перед началом

Целевая система должна использовать Debian 12+ либо Ubuntu 22.04+, systemd и
архитектуру `amd64` или `arm64`. Нужен root-доступ либо рабочий `sudo`.

Для production:

- направьте DNS A/AAAA-записи доменов админки и Authelia на сервер;
- откройте входящие TCP-порты 80 и 443;
- разрешите исходящий доступ к репозиториям пакетов, GitHub, Python package
  index, Ansible Galaxy, container registry, Snap, Let's Encrypt и DB-IP GeoIP
  во время установки и периодического обновления базы.

Для удалённой установки на рабочей машине нужны `bash`, `curl`, `ssh` и `scp`.

## 1. Скачайте и проверьте помощник

```bash
curl -fsSLo /tmp/easy-ha-proxy-install.sh \
  https://raw.githubusercontent.com/CLLlAgOB/easy-ha-proxy/main/install.sh
```

Просмотрите сохранённый файл удобным редактором, затем запустите:

```bash
bash /tmp/easy-ha-proxy-install.sh
```

В первом запросе выберите English или Русский. Enter оставляет язык по
умолчанию — English. Этот же выбор мастер первичной настройки
использует для notification emails Authelia.

Помощник определит состояние текущей машины: чистая, частично настроенная или
уже управляемая.

## 2. Выберите вариант установки

Установка или управление текущим сервером:

```bash
bash /tmp/easy-ha-proxy-install.sh local
```

Управление удалённым сервером через существующую конфигурацию SSH:

```bash
bash /tmp/easy-ha-proxy-install.sh remote admin@server.example.com
```

Приватный ключ и нестандартный порт:

```bash
bash /tmp/easy-ha-proxy-install.sh remote \
  --host 192.0.2.10 --user admin \
  --port 2222 --identity ~/.ssh/server
```

Безопасный скрытый запрос SSH-пароля:

```bash
bash /tmp/easy-ha-proxy-install.sh remote \
  --host 192.0.2.10 --user admin --ask-pass
```

## 3. Используйте test mode без публичного DNS

```bash
bash /tmp/easy-ha-proxy-install.sh local --test-mode
```

Test mode использует домены `.test` и локальную CA, пропускает публичную
DNS-проверку и первоначальный публичный выпуск, но устанавливает Certbot для
последующего использования отдельными сайтами. После установки помощник
напечатает готовую запись для файла `hosts` и путь к экспорту публичного
корневого CA.

Рабочий тестовый стек можно перевести в production без переустановки:

```bash
sudo easy-ha-proxy promote-production --new-domain example.com \
  --certificate-source internal --image latest
```

Выберите `letsencrypt`, когда публичный DNS готов. Неразрешённые DNS-имена
только откладывают первоначальный выпуск Let's Encrypt и не прерывают установку.

## 4. Заполните мастер настройки

Подготовьте:

- начальный источник сертификата панели: `letsencrypt` или `internal`;
- основной домен, домены админки и Authelia;
- email Let's Encrypt или администратора и часовой пояс;
- необязательные разрешённые IP/CIDR и страны GeoIP;
- логин, имя, email и пароль первого `superadmin`;
- необязательные настройки SMTP.

Сгенерированные секреты сохраняются в `/etc/easy-ha-proxy` с правами только
для root.

Определение страны и GeoIP-фильтрация HAProxy используют одну локальную базу
DB-IP Country Lite. Установщик локально формирует IPv4/IPv6 ACL и устанавливает
встроенные флаги; IP посетителей не отправляются публичным GeoIP-сервисам или
сервисам флагов.

Для приватной установки можно запустить локальный установщик с
`--certificate-source internal`. После первой установки пакет корневых и
промежуточных сертификатов внешнего CA вместе с серверными сертификатами можно
импортировать на `/haproxy/certs`.

## 5. Проверьте и обслуживайте установку

Релизное обновление из GitHub:

```bash
./install.sh remote --inventory ./inventory.ini --limit my_server \
  --action update --source github --image latest
```

Тест синхронизированных локальных изменений с уже опубликованным образом
`alpha`:

```bash
./install.sh remote --inventory ./inventory.ini --limit my_server \
  --sync-source . --apply --image alpha
```

```bash
sudo easy-ha-proxy status
sudo easy-ha-proxy plan
sudo easy-ha-proxy update
sudo easy-ha-proxy-assistant check-updates
```

После первого актуального полного update пользователь `superadmin` может также
открыть в HAProxy Admin страницу **Обновления**, проверить отдельные компоненты
и установить выбранное. При обновлении собственного контейнера страница
подключится повторно; автоматический reboot сервера не выполняется.

Не публикуйте напрямую порт UI `5000` и порт Authelia `9091`. Перед backup,
restore, миграцией домена или переносом legacy-конфигурации прочитайте полное
[руководство установщика](INSTALLER_README.ru.md).
