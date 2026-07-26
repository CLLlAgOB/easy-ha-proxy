# Интерактивный помощник easy-ha-proxy

[English](INSTALLER_README.md) | [Русский](INSTALLER_README.ru.md) | [Быстрый старт](QUICKSTART.ru.md)

`install.sh` — единая точка установки, диагностики и обновления
easy-ha-proxy. Он подходит для чистого сервера, уже работающей установки и
частично настроенной системы.

## Быстрый запуск

```bash
curl -fsSLo /tmp/easy-ha-proxy-install.sh \
  https://raw.githubusercontent.com/CLLlAgOB/easy-ha-proxy/main/install.sh
bash /tmp/easy-ha-proxy-install.sh
```

При запуске без параметров помощник:

1. Предлагает выбрать English или Русский; Enter выбирает English.
2. Ищет установленный CLI, конфигурацию, внутренний Python/Ansible venv,
   playbook и системные компоненты.
3. Определяет состояние: чистая, частично установленная или управляемая система.
4. Определяет режим конфигурации: production или test mode.
5. Показывает подходящие действия и запрашивает подтверждение перед изменениями.

Явные команды по умолчанию работают на английском. Для русского задайте
`EASY_HA_PROXY_LANGUAGE=ru`. Язык, выбранный при первой настройке, также
используется для notification templates Authelia. Он хранится в `authelia.yml`
как `authelia_notification_language: en` или `ru`; позже значение можно изменить и
повторно применить конфигурацию.

Если рядом со скриптом или в текущем каталоге найден `inventory.ini` (также
проверяется `ansible/inventory.ini`), помощник предлагает его как значение по
умолчанию для удалённого подключения.

## Чистый сервер

На чистой машине меню предлагает:

- локальную production-установку;
- тестовую установку на VM без публичного IP и DNS;
- подключение к удалённой машине;
- диагностический режим.

Явный запуск:

```bash
bash /tmp/easy-ha-proxy-install.sh install
bash /tmp/easy-ha-proxy-install.sh install-test
```

Тестовый режим использует домены `.test`, локальную CA и запись в файле
`hosts`. Публичная DNS-проверка и первоначальный публичный выпуск не
запускаются, но Certbot, таймер продления и deploy hooks устанавливаются.
При обычной установке мастер предлагает `letsencrypt` (по умолчанию) или
`internal` для первоначального сертификата панели и Authelia; выбор также
можно передать как `--certificate-source internal`.
После первой установки внешний пакет корневых/промежуточных CA и серверные
сертификаты импортируются через `/haproxy/certs`.

При первой удалённой установке источник и образ можно выбрать явно:

```bash
# Опубликованный релиз: GitHub и latest.
bash ./install.sh remote --inventory ./inventory.ini --limit my_server \
  --action install --source github --image latest

# Текущие локальные исходники и уже опубликованный тестовый образ alpha.
bash ./install.sh remote --inventory ./inventory.ini --limit my_server \
  --action install-test --source local --source-root . --image alpha
```

Без этих параметров исходники по умолчанию берутся из GitHub, а канал
Docker-образа спрашивает мастер. Тестовый образ должен уже существовать в
настроенном registry.

## Установленная система

Для локального интерактивного управления:

```bash
bash /tmp/easy-ha-proxy-install.sh local
```

После первой установки помощник также доступен постоянной командой:

```bash
sudo easy-ha-proxy-assistant
```

В меню установленной системы первым вынесен обычный сценарий: проверить все
источники обновлений и установить выбранное. Read-only проверка, status, настройка и
язык остались в главном меню. Точечные update и служебные операции убраны в подменю.

Помощник позволяет:

- показать полный статус systemd-сервисов и контейнеров;
- проверить наличие конфигурационных файлов;
- проверить `haproxy.cfg` и Docker Compose;
- выполнить Ansible check mode;
- сравнить установленный source с веткой `main` по commit или fingerprint;
- сравнить канонический HAProxy-шаблон с копией, используемой UI;
- сравнить локальные и registry digest всех контейнерных образов, включая
  повторно опубликованный тег `latest`;
- показать число обновляемых пакетов из текущего APT-кэша;
- обновить весь стек либо только веб-интерфейс;
- повторно запустить мастер конфигурации;
- восстановить отсутствующие или повреждённые компоненты.

Действия можно запускать без меню:

| Команда | Что выполняет | Изменяет систему |
|---|---|---|
| `bash /tmp/easy-ha-proxy-install.sh inspect` | Определяет тип установки, режим production/test, пути, версию source и статус всех helper-демонов с короткими SHA-256 версиями. | Нет |
| `bash /tmp/easy-ha-proxy-install.sh status` | Проверяет systemd services/timers, результаты oneshot-задач, SHA управляемых scripts/hooks/Lua, версии APT/Snap и Docker-контейнеры; при проблемах показывает журналы. | Нет |
| `bash /tmp/easy-ha-proxy-install.sh check-config` | Проверяет наличие и синтаксис YAML-файлов, права `secrets.yml`, конфигурацию HAProxy и Docker Compose. | Нет |
| `bash /tmp/easy-ha-proxy-install.sh plan` | Выполняет Ansible `--check` и показывает, что изменит обновление, без применения. | Нет |
| `bash /tmp/easy-ha-proxy-install.sh check-updates` | Сравнивает source с GitHub, версии helper-демонов, шаблон UI, digest контейнеров и показывает обновления APT из локального кэша. | Нет; обращается к сети |
| `bash /tmp/easy-ha-proxy-install.sh smart-update` | Выполняет полную проверку и предлагает только компоненты с найденными обновлениями. | Да, после выбора и подтверждения |
| `sudo easy-ha-proxy language --language ru --apply` | Сохраняет и применяет язык помощника, UI по умолчанию и писем Authelia. | Да |
| `bash /tmp/easy-ha-proxy-install.sh update` | Получает актуальный source из GitHub, обновляет зависимости и применяет весь управляемый стек. | Да, после подтверждения |
| `bash /tmp/easy-ha-proxy-install.sh apply-current` | Применяет уже установленный или переданный через `sync-source` source без загрузки изменений из GitHub. | Да, после подтверждения |
| `bash /tmp/easy-ha-proxy-install.sh update-ui` | Применяет UI и совместимые с ним HAProxy/Authelia helper-компоненты, не обновляя source из GitHub. | Да, после подтверждения |
| `bash /tmp/easy-ha-proxy-install.sh reboot` | Планирует ранее отложенную обязательную перезагрузку текущего сервера и корректно завершает текущую сессию. | Да, после подтверждения |
| `bash /tmp/easy-ha-proxy-install.sh backup-full` | Создаёт зашифрованный полный DR-backup; отдельно спрашивает про SSH-ключи и консистентную паузу. | Создаёт архив; может кратко приостановить managed-компоненты |
| `sudo easy-ha-proxy restore-full ARCHIVE --mode auto --apply` | Восстанавливает backup на сервере с установленным CLI. Для чистого сервера используйте controller-команду `bash ./install.sh restore-full`, описанную ниже. | Да, после `RESTORE`; предварительно создаёт rollback |
| `bash /tmp/easy-ha-proxy-install.sh configure` | Повторно запускает мастер настроек, сохраняет новую конфигурацию и применяет её. | Да, после подтверждения |
| `bash /tmp/easy-ha-proxy-install.sh migrate-domain` | Создаёт план безопасной замены основного домена, проверяет его и после отдельного подтверждения применяет миграцию. | Только после подтверждения |
| `sudo easy-ha-proxy promote-production` | Переводит test-стек в production на месте, сохраняя сайты, TCP-прокси, пользователей, секреты и backend. | Только после `PROMOTE` |
| `bash /tmp/easy-ha-proxy-install.sh repair` | Повторно выполняет установку в текущем production/test-режиме, сохраняя существующую конфигурацию. Используется для восстановления отсутствующих компонентов. | Да, после подтверждения |
| `bash /tmp/easy-ha-proxy-install.sh install-reset` | Заново запускает production-мастер после backup текущей конфигурации и с сохранением managed-данных. | Да, после подтверждения |

Изменяющие действия запрашивают подтверждение. Команды диагностики не изменяют
конфигурацию; `check-updates` обращается к GitHub и registry, но не выполняет
`git pull` или `docker pull`, а также читает локальный APT-кэш.
`status` намеренно проверяет только health и не обращается к container registry.
После обновления пакетов ОС помощник спрашивает о перезагрузке; по умолчанию
выбрано «нет». Если она отложена, позже используйте действие `reboot` или
выполните `sudo systemctl reboot`.

Обычное обновление заменяет программные файлы в
`/opt/easy-ha-proxy/source` и заново формирует runtime-файлы из существующей
root-конфигурации `/etc/easy-ha-proxy`; конфигурация не заменяется файлами из
GitHub или из `--sync-source`. Изменения, сделанные через web UI, сначала
синхронизируются обратно в управляемую часть конфигурации HAProxy. Новый
параметр может отсутствовать в старом YAML: пока администратор явно не сохранит
другое значение, используется default из роли или шаблона. Явные операции
миграции, restore, смены языка, домена, канала и настройки меняют только
относящиеся к ним параметры и предварительно создают backup конфигурации.

Чтобы запланировать отложенную перезагрузку с управляющего компьютера и
проконтролировать удалённый сервер, выполните:

```bash
./install.sh remote \
  --inventory ./ansible/inventory.ini \
  --limit my_server \
  --action reboot
```

Если SSH-ключ или агент позволяют подключаться без повторного запроса пароля,
controller ожидает, пока сервер сообщит новый boot ID и SSH снова станет
доступен. В режиме только с паролем он лишь подтверждает, что перезагрузка
запланирована; после запуска сервера подключитесь или запустите помощник заново.

### Диагностическая страница UI

Техническая страница `/debug/` по умолчанию выключена, поэтому кнопка
«Диагностика» на главной странице скрыта. При прямом переходе отображается
безопасная заглушка с инструкцией, а `/debug/headers` остаётся недоступен.

Для временного включения добавьте в `/etc/easy-ha-proxy/vars.yml`:

```yaml
haproxy_admin_debug_routes: true
```

Затем примените текущий source:

```bash
sudo easy-ha-proxy update --no-fetch
```

После завершения диагностики верните значение `false` и повторите команду.

## Удалённая машина

Интерактивный помощник можно запустить на сервере через SSH:

```bash
bash /tmp/easy-ha-proxy-install.sh remote admin@192.0.2.10
```

Скрипт временно копирует на сервер локальный установщик и помощник, запускает
их через `sudo`, а после завершения удаляет временные файлы.
При запуске из checkout используются локальные версии этих файлов — публикация
последних изменений на GitHub для диагностики удалённой машины не требуется.

### Пароль SSH

```bash
bash /tmp/easy-ha-proxy-install.sh remote \
  --host 192.0.2.10 --user admin --ask-pass
```

Пароль запрашивает OpenSSH в терминале. Он не передаётся аргументом и не
сохраняется скриптом.

### Приватный ключ

```bash
bash /tmp/easy-ha-proxy-install.sh remote \
  --host 192.0.2.10 --user admin \
  --port 2222 --identity ~/.ssh/server
```

### Ansible INI inventory

```bash
bash /tmp/easy-ha-proxy-install.sh remote \
  --inventory ./ansible/inventory.ini --limit my_server
```

Поддерживаются:

- `ansible_host`;
- `ansible_user`;
- `ansible_port` и `ansible_ssh_port`;
- `ansible_ssh_private_key_file`;
- inline-переменные хоста, `[group:vars]` и `[all:vars]`.

Если в inventory один хост, `--limit` не нужен. `ansible_password` не читается;
используйте `--ask-pass`.

Проверка распознанного подключения без SSH:

```bash
bash /tmp/easy-ha-proxy-install.sh remote \
  --inventory ./ansible/inventory.ini --limit my_server --dry-run
```

Удалённое действие можно запустить без меню:

```bash
bash /tmp/easy-ha-proxy-install.sh remote \
  --inventory ./ansible/inventory.ini --limit my_server \
  --action status
```

Для немедленной тестовой установки:

```bash
bash /tmp/easy-ha-proxy-install.sh remote \
  --test-mode admin@192.168.56.10
```

### Автоматическое скачивание legacy snapshot

После создания snapshot через удалённый помощник архив по умолчанию
автоматически:

1. Упаковывается на сервере во временный файл с режимом `0600`.
2. Скачивается в `$HOME/easy-ha-proxy-backups/legacy-<дата>/`.
3. Проверяется по `SHA256SUMS`.
4. Распаковывается в подкаталог `live/`.
5. Удаляется из временного каталога сервера.

Достаточно одной команды:

```bash
bash /tmp/easy-ha-proxy-install.sh remote \
  --inventory ./inventory.ini \
  --action snapshot-legacy
```

Другой локальный каталог:

```bash
bash /tmp/easy-ha-proxy-install.sh remote \
  --inventory ./inventory.ini \
  --action snapshot-legacy \
  --snapshot-dir "$HOME/my-protected-backups"
```

Чтобы оставить snapshot только на сервере:

```bash
bash /tmp/easy-ha-proxy-install.sh remote \
  --inventory ./inventory.ini \
  --action snapshot-legacy \
  --no-fetch-snapshot
```

Каталог со snapshot содержит сертификаты, приватные ключи и конфигурационные
секреты. Не размещайте его внутри Git-репозитория и не меняйте режим `0700`.

### Подготовка конфигурации из legacy snapshot

После успешного скачивания выполните:

```bash
bash ./install.sh prepare-legacy
```

Скрипт автоматически выбирает последний snapshot. Конкретный каталог `live/`
можно передать явно:

```bash
bash ./install.sh prepare-legacy \
  "$HOME/easy-ha-proxy-backups/legacy-<дата>/live"
```

Результат создаётся рядом со snapshot в `prepared-config/` с режимом каталога
`0700` и файлов `0600`. При подготовке:

- `vars.yml`, `websites.yml` и `tcp.yml` берутся из live-конфигурации UI;
- текущая база пользователей преобразуется в `authelia_users_initial.yml`;
- несекретные настройки Authelia восстанавливаются из live-конфига;
- действующие Authelia/SMTP-секреты переносятся без вывода значений;
- создаются локальный inventory и migration metadata.

Это локальная операция: данные не отправляются на сервер, Ansible не
запускается, сервисы не изменяются. `prepared-config` также содержит секреты и
не должен попадать в Git.

### Check mode подготовленной legacy-конфигурации

После создания `prepared-config`:

```bash
bash ./install.sh plan-legacy
```

Команда автоматически выбирает последний `prepared-config` и найденный
удалённый `inventory.ini`, показывает пути и запрашивает подтверждение. Затем
выполняются:

1. `ansible-playbook --syntax-check`;
2. ограниченный набор update/config тегов с `--check`;
3. read-only status-задачи.

`--diff` намеренно не используется, чтобы шаблоны с секретами не попали в
вывод. Полный лог сохраняется рядом со snapshot как
`legacy-plan-<дата>.log` с режимом `0600`. Apply не выполняется.

Явные пути:

```bash
bash ./install.sh plan-legacy \
  "$HOME/easy-ha-proxy-backups/legacy-<дата>/prepared-config" \
  ./inventory.ini
```

Если полный plan показывает изменение `Copy HAProxy configuration`, перед
любым apply выполните отдельный защищённый diff:

```bash
bash ./install.sh diff-legacy-haproxy
```

Команда запускает только тег `ha-cfg` с `--check --diff`, валидирует
отрендеренный конфиг через `haproxy -c` и сохраняет результат как
`legacy-haproxy-diff-<дата>.log` с режимом `0600`. HAProxy не
перезагружается.

### Принятие legacy-сервера под управление

Когда полный `plan-legacy` завершился без ошибок, а HAProxy diff проверен:

```bash
bash ./install.sh stage-legacy
```

Команда автоматически выбирает последний `prepared-config` и найденный
inventory. Явные пути и alias хоста можно передать так:

```bash
bash ./install.sh stage-legacy \
  "$HOME/easy-ha-proxy-backups/legacy-<дата>/prepared-config" \
  ./inventory.ini \
  my_server
```

Перед изменением сервера выводятся целевой хост и пути; продолжение требует
ввести `STAGE`. Команда:

- передаёт локальную проверенную версию исходников без controller inventory,
  Vault, backups, устаревших PEM и архивов;
- помещает подготовленную конфигурацию в `/etc/easy-ha-proxy` с правами
  `0700/0600`;
- создаёт `/opt/easy-ha-proxy/source`, изолированный Python venv и команды
  `easy-ha-proxy`/`easy-ha-proxy-assistant`;
- останавливается, если целевые каталоги уже существуют.

На этом этапе playbook не запускается, Docker-образы не скачиваются,
HAProxy/Authelia/UI не перезапускаются и действующие конфигурации не меняются.
После успешного staging выполните на сервере только read-only проверку:

```bash
sudo easy-ha-proxy plan
```

Если этот plan завершился с `failed=0`, сервисы работают, а среди реальных
конфигурационных изменений осталась только синхронизация
`haproxy.cfg.j2` для UI, завершите принятие сервера:

```bash
bash ./install.sh finalize-legacy
```

Команда требует точного подтверждения `APPLY`, выполняет только теги
`ha-adm-cfg,status` и сохраняет защищённый лог
`legacy-finalize-<дата>.log`. Она не обновляет Docker, не скачивает образы и
не меняет активный `/etc/haproxy/haproxy.cfg`; синхронизируется шаблон, который
UI будет использовать при последующих изменениях сайтов.

### Синхронизация локальной версии исходников

Каналы исходников и образа независимы. `github` обновляет managed checkout из
`main`, `local` применяет уже синхронизированное на сервер дерево, `latest`
означает релизный UI-образ, а `alpha` — тестовый.

Чтобы передать ещё не опубликованные изменения и сразу применить их с уже
опубликованным образом `alpha`:

```bash
bash ./install.sh remote \
  --inventory ./inventory.ini \
  --limit my_server \
  --sync-source . \
  --apply \
  --image alpha
```

После подтверждения `SYNC` существующий source атомарно переносится в
`source.before-sync.<дата>`, а новый занимает `/opt/easy-ha-proxy/source`.
С `--apply` установщик сохраняет канал `local`, переключает UI на `alpha`,
обновляет runtime-зависимости и применяет весь стек. Без `--apply` конфигурация,
образы и сервисы не меняются, playbook не запускается. Затем при необходимости
можно отдельно проверить состояние и план:

```bash
bash ./install.sh remote \
  --inventory ansible/inventory.ini \
  --limit my_server \
  --action check-updates

bash ./install.sh remote \
  --inventory ansible/inventory.ini \
  --limit my_server \
  --action plan
```

Обычное релизное обновление явно возвращает GitHub и `latest`:

```bash
bash ./install.sh remote --inventory ./inventory.ini --limit my_server \
  --action update --source github --image latest
```

Выбранные каналы сохраняются в managed metadata. `apply-current` остаётся
синонимом применения уже загруженной source-версии без обращения к GitHub.
`update-ui` также не обновляет source: он получает выбранный образ
веб-интерфейса и применяет только необходимый совместимый защитный контур
(HAProxy admin-header, внутренний секрет и helper-демоны).

При удалённом входе в меню, `repair` или перезапуске мастера controller
сравнивает контрольную сумму локальных файлов инсталлятора с файлами в
`/opt/easy-ha-proxy/source`. Если они отличаются, перед продолжением
предлагается атомарно загрузить текущую локальную версию; прежнее дерево
сохраняется как `source.before-<action>.<дата>`. Параметр `--source local`
выбирает эту синхронизацию явно, а `--source github` заставляет `repair`
сначала обновить managed checkout из GitHub.

### Локальная база GeoIP

UI и country ACL HAProxy используют один релиз DB-IP Country Lite MMDB из
`/etc/haproxy/geoip/current/`. Постоянный ежедневный systemd-таймер повторяет
проверку в начале месяца, но ничего не скачивает после активации базы текущего
месяца. Updater проверяет IPv4/IPv6, атомарно переключает MMDB и ACL, делает
reload HAProxy только при изменении ACL и откатывается, если HAProxy либо HTTPS
проверки панели/Authelia не проходят.

```bash
sudo systemctl status easy-ha-proxy-geoip-update.timer
sudo systemctl start easy-ha-proxy-geoip-update.service
sudo journalctl -u easy-ha-proxy-geoip-update.service -n 50 --no-pager
```

Локальная база остаётся включённой для показа стран в UI, даже если фильтрация
доступа выключена. GeoIP приблизителен и не заменяет аутентификацию или IP allow
list.

Мини-FAQ по обновлению GeoIP:

- **MMDB попадёт в Git или Docker-образ?** Нет. `*.mmdb` и `*.mmdb.gz`
  игнорируются; лицензированные данные скачивает сам управляемый сервер.
- **Что будет со старым updater через GitHub/IPdeny?** Следующий полный apply
  удалит его Ansible cron-запись и установит DB-IP systemd-таймер. Старый
  `allowed.geo` остаётся рабочим, пока новый релиз не пройдёт проверки.
- **Ежедневный timer каждый день скачивает и пересобирает базу?** Нет. Если месяц
  и список стран не изменились, выполняется только быстрая локальная проверка
  состояния и контрольных сумм.
  Полный проход нужен для новой месячной базы или изменённого списка стран.
- **Как принудительно проверить обновление?** Выполните
  `sudo /usr/local/bin/update-geoip.sh --force-download` и посмотрите journal.
- **Что будет при недоступном источнике или плохом релизе?** На установленной
  системе остаётся активной прежняя версия. Первая установка может продолжить
  работу без отображения стран только при выключенной GeoIP-фильтрации HAProxy.
- **Как обновить совсем старую неуправляемую установку?** Не запускайте полный
  apply напрямую. Сначала пройдите `snapshot-legacy`, `prepare-legacy`,
  `plan-legacy`, `stage-legacy` и `finalize-legacy`; после принятия сервера под
  управление выполните обычное полное обновление, которое перенесёт GeoIP и UI.

## Точечные обновления в HAProxy Admin

После одной актуальной полной установки/обновления пользователь `superadmin`
может открыть страницу **Обновления**. Read-only проверка обращается только к
настроенному Git remote, registry двух управляемых Compose-стеков и текущему
APT-кэшу. Она отдельно показывает управляемые исходники, host-сервисы, демоны,
Authelia, HAProxy Admin и пакеты ОС. Неопределённые состояния сети/registry
видны в отчёте, но выбрать их для установки нельзя.

Для применения нужен свежий план с ограниченным сроком, подтверждение возможных
перезапусков и точный текст `UPDATE`. `easy-ha-proxy-updated.service`
асинхронно запускает только фиксированные CLI-компоненты, хранит ограниченный
лог на хосте и продолжает задание при самообновлении контейнера HAProxy Admin.
Полный source-update поглощает вложенные варианты сервисов/контейнеров, а пакеты
ОС всегда ставятся последними. Брокер не принимает произвольные команды и не
перезагружает сервер; он также блокирует source/host update при ожидающем
применении HAProxy и использует общий operation-lock с backup/restore.

Web-страница не загружает checkout разработчика. Для незакоммиченных локальных
изменений по-прежнему используйте controller-команду `--sync-source . --apply`;
после этого web работает с уже синхронизированными исходниками и опубликованным
образом канала `alpha`/`latest`.

## Полный зашифрованный backup и перенос на новый сервер

### Web-интерфейс

После обычной установки пользователь с ролью `superadmin` может открыть в
HAProxy Admin страницу **Бэкап и восстановление**. На ней доступны два основных
сценария:

1. Создать согласованный зашифрованный снимок, дождаться завершения задания на
   хосте и скачать архив `.enc` вместе с контрольной суммой `.sha256`.
2. На этом же сервере выбрать сохранённый снимок кнопкой **Восстановить**. На
   другой свежеустановленный сервер easy-ha-proxy загрузить скачанный файл
   `.enc`, ввести парольную фразу для проверки без изменения файлов, сверить
   исходный hostname, дату и наличие SSH-ключей, затем ввести `RESTORE`, заменить
   управляемое состояние и выполнить полное применение конфигурации.

Привилегированные операции выполняет `easy-ha-proxy-backupd.service`. Приложение
может передавать только фиксированные идентификаторы заданий и потоково работать
с файлами через отдельный spool, который не входит в backup; произвольные root-
пути и команды не принимаются. Задания и серверные архивы переживают перезапуск
контейнера приложения. Одновременно выполняется только одно задание
backup/inspect/restore, забытые uploads автоматически удаляются, а парольная
фраза передаётся worker-процессу через stdin и не записывается в состояние,
аргументы процесса, environment или логи.

Для восстановления через браузер уже должен быть установлен управляющий стек
easy-ha-proxy. Для действительно пустой ОС используйте controller-команду
`restore-full ... fresh` ниже. Web restore точно заменяет только фиксированные
управляемые каталоги easy-ha-proxy и не удаляет посторонние данные ОС, SSH, home
или сторонних Docker-контейнеров. Согласованный защищённый снимок до restore
создаётся при приостановленных managed-службах и автоматически применяется при
ошибке распаковки или применения конфигурации. После успеха или успешного отката
локальный safety-снимок удаляется; он сохраняется в
`/var/backups/easy-ha-proxy/pre-restore-*` только при ошибке самого
автоматического отката.

Для disaster recovery и переноса управляемой установки используется отдельный
полный backup:

```bash
bash ./install.sh backup-full inventory-production.ini proxy01
```

Команда спрашивает:

1. включать ли SSH host/private/authorized keys;
2. разрешить ли короткую паузу managed-контейнеров и helper-демонов для
   консистентного снимка;
3. парольную фразу шифрования (минимум 12 символов) с повторным вводом.

На сервере создаётся каталог
`/var/backups/easy-ha-proxy/full-<дата>/`, а зашифрованный архив и файл
`.sha256` автоматически скачиваются в
`$HOME/easy-ha-proxy-backups/full-<дата>/`.

В core payload входят:

- `/etc/easy-ha-proxy` со всеми конфигами, metadata и secrets;
- точная версия `/opt/easy-ha-proxy/source` без переносимого venv;
- HAProxy, GeoIP, managed iptables ban-rules, AppArmor, rsyslog, logrotate и
  sysctl;
- `/etc/letsencrypt` целиком: accounts, renewal-конфиги и все скрипты из
  `renewal-hooks/pre`, `renewal-hooks/deploy`, `renewal-hooks/post`;
- Authelia: configuration, users database, Redis data, шаблоны и логи;
- HAProxy Admin: runtime-конфиги, данные и backups;
- systemd units/drop-ins и все managed helper-скрипты;
- манифест ОС, пакетов, systemd, Docker-контейнеров и image digest.

Docker-образы, системные пакеты и Python venv в архив не копируются: при
восстановлении они воспроизводятся установщиком для архитектуры нового сервера.
`/etc/iptables/rules.v4` и `/etc/iptables/rules.v6` намеренно не считаются
переносимым конфигом: на Docker-хосте это runtime-снимки с цепочками `DOCKER`,
bridge-именами и подсетями конкретной машины. Если они есть в старом backup,
restore сохранит их как `*.restored-disabled.*`, но не будет применять через
`iptables-persistent`.

### Восстановление на чистый сервер

Нужен Debian/Ubuntu с systemd, SSH-доступом и `sudo`. Установленная
easy-ha-proxy на нём не требуется:

```bash
bash ./install.sh restore-full \
  "$HOME/easy-ha-proxy-backups/full-<дата>/easy-ha-proxy-full-<дата>.tar.gz.enc" \
  inventory_NEW.ini \
  new_server \
  fresh
```

### Восстановление поверх текущего сервера

```bash
bash ./install.sh restore-full \
  "$HOME/easy-ha-proxy-backups/full-<дата>/easy-ha-proxy-full-<дата>.tar.gz.enc" \
  inventory-production.ini \
  my_server \
  overlay
```

Режим `auto` (по умолчанию) выбирает `overlay`, если найдена managed-установка,
и `fresh` в остальных случаях. Перед передачей требуется ввести `UPLOAD`, а
перед распаковкой — `RESTORE`. Восстановитель:

1. проверяет внешний SHA-256, расшифровывает архив, проверяет внутренние
   контрольные суммы, разрешённые пути, распакованный объём и свободное место до
   остановки managed-служб;
2. создаёт временный защищённый rollback текущих файлов в
   `/var/backups/easy-ha-proxy/pre-restore-<дата>-<pid>/`; после успеха он
   удаляется и остаётся для консольного восстановления только при ошибке
   автоматического отката;
3. отдельно спрашивает, применять ли SSH payload;
4. при восстановлении SSH объединяет существующие `authorized_keys`, чтобы не
   удалить ключ доступа к новому серверу, и не перезапускает sshd;
5. разворачивает данные, сохраняет исходники из backup как
   `/opt/easy-ha-proxy/source.from-backup.<дата>.<pid>`, активирует актуальный
   recovery source с управляющего компьютера, пересоздаёт venv, устанавливает
   зависимости и применяет восстановленную конфигурацию; runtime-снимки
   `/etc/iptables/rules.v4`/`rules.v6` при этом отключаются до запуска Ansible,
   чтобы не перетереть Docker NAT-цепочки нового сервера;
6. не перевыпускает сертификаты автоматически: используются восстановленные
   сертификаты и Certbot renewal state.

Парольная фраза нигде не сохраняется и не восстанавливается. Храните её
отдельно от `.enc` и `.sha256`; без неё backup непригоден для восстановления.
Если восстановлены SSH host keys, fingerprint нового сервера станет таким же,
как у исходного; удалите прежнюю запись нового хоста из `known_hosts` только
после проверки fingerprint по доверенному каналу.

## Смена основного домена

Смена корневого домена выполняется отдельным управляемым сценарием:

```bash
bash ./install.sh remote \
  --inventory ansible/inventory.ini \
  --limit my_server \
  --action migrate-domain
```

На сервере также можно выполнить:

```bash
sudo easy-ha-proxy migrate-domain
```

Например, при переходе с `old.example.com` на `new.example.net` команда:

1. берёт актуальные `vars.yml`, `websites.yml` и `tcp.yml` из runtime-конфига
   UI, чтобы не потерять сайты, добавленные после первоначальной установки;
2. заменяет старый суффикс в HAProxy-сайтах, alternate names, backend host,
   Authelia domain/cookie/ACL, metadata и служебных URL;
3. не изменяет `secrets.yml` и базу пользователей Authelia;
4. показывает полный список замен;
5. проверяет новые A/AAAA через публичные DNS-резолверы; отсутствие записей
   становится предупреждением, а выпуск Let's Encrypt откладывается;
6. создаёт временную конфигурацию и запускает syntax-check плюс Ansible
   check mode без `--diff`;
7. только после точного подтверждения `MIGRATE` создаёт защищённый backup,
   выпускает новые сертификаты и применяет доменные настройки;
8. при ошибке восстанавливает предыдущие managed/runtime-конфиги и пытается
   повторно применить старый домен.

Старые сертификаты сразу не удаляются: это позволяет выполнить ручной откат.
Сессии Authelia, привязанные к прежнему cookie-domain, могут потребовать
повторного входа.

Только предварительный план с рабочей машины:

```bash
bash ./install.sh remote \
  --inventory ansible/inventory.ini \
  --limit my_server \
  --action migrate-domain \
  --new-domain new.example.net \
  --plan-only
```

Публичные DNS-записи нужно создать до использования Let's Encrypt. Production
с Internal CA может использовать приватный DNS или файл hosts. Неразрешённое
имя показывается как предупреждение и не останавливает установку или миграцию;
`--skip-dns-check` полностью отключает эту диагностику.

### Перевод test mode в production

Тестовая установка не является одноразовой. Её можно повысить на месте:

```bash
sudo easy-ha-proxy promote-production \
  --new-domain example.com \
  --certificate-source internal \
  --image latest
```

Удалённо:

```bash
bash ./install.sh remote --inventory ./inventory.ini --limit my_server \
  --action promote-production --new-domain example.com \
  --certificate-source internal --image latest
```

Команда берёт актуальные сайты и TCP-прокси из runtime UI, заменяет тестовый
суффикс, сохраняет пользователей, секреты и backend-настройки, переключает
режим и канал образа, запускает Ansible check mode и требует точного
подтверждения `PROMOTE`. Выберите `letsencrypt` при готовом публичном DNS или
оставьте `internal` для закрытой production-сети. `--plan-only` ничего не
изменяет.

## Что считается установленной системой

Полная управляемая установка требует одновременно:

- команды `/usr/local/bin/easy-ha-proxy` либо внутреннего CLI;
- `/etc/easy-ha-proxy/metadata.yml`;
- `/opt/easy-ha-proxy/venv/bin/python`;
- `/opt/easy-ha-proxy/source/ansible/easy-ha-proxy.yml`.

Кроме этих файлов конфигурация отмечается завершённой только после успешного
основного playbook. Если подготовка или установка была прервана, следующий
запуск показывает recovery-меню:

- продолжить с сохранённой конфигурацией и уже подготовленными исходниками;
- заново пройти production- или test-мастер после backup старой конфигурации;
- проверить конфигурацию и сервисы.

Если локальный инсталлятор отличается от подготовленного на сервере, перед
recovery-меню предлагается обновить его. Проверка основана на содержимом
файлов, поэтому обнаруживает и ещё не закоммиченные локальные изменения.

Повторный мастер сохраняет текущие сайты, TCP-прокси, пользователей, секреты,
правила Authelia, почтовые настройки, неизвестные будущие параметры и значения,
которые мастер явно не менял. Существующие YAML проверяются до backup и записи;
ошибка YAML останавливает операцию без замены или ротации секретов.
Обычные системные службы показываются отдельно как справочная информация:
активные systemd journal, AppArmor, cron или rsyslog не означают, что
easy-ha-proxy уже установлен.

Если одновременно найдены рабочие конфиги HAProxy, Authelia и haproxy-admin,
но нового CLI ещё нет, система определяется как «работающая legacy-установка».
Отсутствие `/etc/easy-ha-proxy` в этом случае не считается ошибкой.

Для legacy доступны только безопасные действия:

- валидация реально используемых HAProxy и Compose-конфигов;
- диагностика systemd, Docker и портов 80/443/5000/9091;
- защищённый snapshot в `/var/backups/easy-ha-proxy`;
- просмотр плана миграции;
- проверка обновлений без установки.

Production/test installer в legacy-меню намеренно не предлагается. Сначала
нужно сохранить snapshot, перенести исходные Ansible-переменные и Vault-секреты
в новый формат, выполнить check mode и проверить diff.

Если найдена только часть компонентов и рабочий legacy-стек не подтверждён,
помощник показывает состояние «частичная/незавершённая установка».

## Ограничения

- Целевая система: Debian 12+ или Ubuntu 22.04+, systemd, `amd64`/`arm64`.
- Для Let's Encrypt нужны корректные публичные A/AAAA-записи и доступные порты
  80/443. Production с Internal CA может использовать приватный DNS.
- Для удалённого запуска нужны `curl`, `ssh` и `scp`; Ansible на рабочем
  компьютере не требуется.
- Репозиторий должен быть доступен целевой машине. Для анонимной загрузки raw
  файлов GitHub репозиторий должен быть публичным.
- Проверка контейнеров сравнивает локальный `RepoDigest` с удалённым manifest
  digest через `docker buildx imagetools inspect`; фактический pull выполняется
  только при `update` или `update-ui`.
- В выводе показываются все контейнеры сервера и их имена. Полный `update`
  обновляет образы Compose-стеков easy-ha-proxy (UI и Authelia); сторонние
  контейнеры показываются только для информации и автоматически не меняются.
