package cli

import (
	"os"
	"strings"
)

// InstallerLanguage returns the configured CLI language ("en" or "ru").
func InstallerLanguage() string {
	lang := strings.ToLower(strings.TrimSpace(os.Getenv("EASY_HA_PROXY_LANGUAGE")))
	if lang == "ru" {
		return "ru"
	}
	return "en"
}

var ruMessages = map[string]string{
	"Value is required.": "Значение обязательно.",
	"Enter yes or no.":   "Введите yes/да или no/нет.",
	"Enter a full DNS name, for example example.com.":               "Введите полное DNS-имя, например example.com.",
	"Enter a valid email address.":                                  "Введите корректный адрес электронной почты.",
	"Use only letters, digits and . _ @ - (maximum 64 characters).": "Используйте только буквы, цифры и . _ @ - (не более 64 символов).",
	"Port must be an integer.":                                      "Порт должен быть целым числом.",
	"Port must be between 1 and 65535.":                             "Порт должен быть в диапазоне 1–65535.",
	"Enter a valid IPv4 or IPv6 address.":                           "Введите корректный IPv4- или IPv6-адрес.",
	"First Authelia administrator password: ":                       "Пароль первого администратора Authelia: ",
	"Use at least 12 characters.":                                   "Используйте не менее 12 символов.",
	"Repeat password: ":                                             "Повторите пароль: ",
	"Passwords do not match.":                                       "Пароли не совпадают.",
	"Root domain":                                                   "Корневой домен",
	"Administration domain":                                         "Домен панели управления",
	"Authelia portal domain":                                        "Домен портала Authelia",
	"Administrator email":                                           "Email администратора",
	"Let's Encrypt email":                                           "Email для Let's Encrypt",
	"Let's Encrypt / administrator email":                           "Email для Let's Encrypt / администратора",
	"Certificate source":                                            "Источник сертификатов",
	"Initial certificate source":                                    "Начальный источник сертификата",
	"Docker image channel":                                          "Канал Docker-образа",
	"Enter latest or alpha.":                                        "Введите latest или alpha.",
	"Enter letsencrypt or internal.":                                "Введите letsencrypt или internal.",
	"Timezone":                                                      "Часовой пояс",
	"Server LAN/host-only IP":                                       "LAN/host-only IP сервера",
	"Admin allowed IP/CIDR list, comma-separated [all authenticated users]: ":                "Разрешённые IP/CIDR админки через запятую [все аутентифицированные пользователи]: ",
	"GeoIP allowed country codes, comma-separated [disabled; examples: RU,PL,BY]: ":          "Разрешённые коды стран GeoIP через запятую [выключено; примеры: RU,PL,BY]: ",
	"Existing initial Authelia users are preserved. Manage active users through the web UI.": "Существующие начальные пользователи Authelia сохранены. Управляйте активными пользователями через веб-интерфейс.",
	"First administrator login":                                "Логин первого администратора",
	"Administrator display name":                               "Отображаемое имя администратора",
	"Configure email notifications through the internal relay": "Настроить почтовые уведомления через внутренний relay",
	"SMTP server":   "SMTP-сервер",
	"SMTP port":     "SMTP-порт",
	"SMTP username": "Пользователь SMTP",
	"SMTP password [leave empty to preserve current]: ": "Пароль SMTP [оставьте пустым, чтобы сохранить текущий]: ",
	"SMTP password: ":        "Пароль SMTP: ",
	"Mail sender":            "Отправитель писем",
	"Notification recipient": "Получатель уведомлений",
	"The LAN/host-only IP and hosts-file setup are ready. Continue":                                        "LAN/host-only IP и файл hosts настроены. Продолжить",
	"Private DNS/hosts are configured and the internal CA trust plan is ready. Continue":                   "Приватный DNS/hosts настроен, план добавления внутреннего CA в доверенные готов. Продолжить",
	"DNS is configured and TCP ports 80/443 are reachable. Continue":                                       "DNS настроен, TCP-порты 80/443 доступны. Продолжить",
	"DNS is not ready. Continue installation and skip initial Let's Encrypt issuance for unresolved names": "DNS ещё не готов. Продолжить установку и пропустить первоначальный выпуск Let's Encrypt для неразрешённых имён",
	"DNS preflight was skipped. Continue installation":                                                     "Предварительная проверка DNS пропущена. Продолжить установку",
	"easy-ha-proxy installation completed.":                                                                "Установка easy-ha-proxy завершена.",
	"The operating system requires a reboot to finish applying updates.":                                   "Для завершения применения обновлений требуется перезагрузка сервера.",
	"Reboot the server now": "Перезагрузить сервер сейчас",
	"Reboot deferred. Run 'sudo systemctl reboot' manually or choose 'Reboot server' in the assistant.": "Перезагрузка отложена. Выполните 'sudo systemctl reboot' вручную или выберите «Перезагрузить сервер» в помощнике.",
	"A server reboot has been scheduled in {seconds} seconds. The current session will close cleanly.":  "Перезагрузка сервера запланирована через {seconds} секунд. Текущая сессия будет завершена корректно.",
	"A reboot is already scheduled; the current session will close.":                                    "Перезагрузка уже запланирована; текущая сессия будет завершена.",
	"No reboot is currently required.": "В данный момент перезагрузка не требуется.",
	"Security notification":            "Уведомление безопасности",
}

// T translates an installer message while keeping English as the source.
func T(message string) string {
	if InstallerLanguage() == "ru" {
		if translated, ok := ruMessages[message]; ok {
			return translated
		}
	}
	return message
}
