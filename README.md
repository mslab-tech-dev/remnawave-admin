<div align="center">

<img src="remnawave-admin.webp" alt="Remnawave Admin" width="100%" />

# Remnawave Admin

**Панель управления и Telegram-бот поверх вашей панели Remnawave**

Пользователи, ноды, анти-абуз, почта и мониторинг — в одном месте

[![Stars](https://img.shields.io/github/stars/mslab-tech-dev/remnawave-admin?style=flat-square&logo=github&logoColor=white&labelColor=1f2430&color=f5c518)](https://github.com/mslab-tech-dev/remnawave-admin/stargazers) [![Release](https://img.shields.io/github/v/release/mslab-tech-dev/remnawave-admin?style=flat-square&logo=github&logoColor=white&labelColor=1f2430&color=3fb950)](https://github.com/mslab-tech-dev/remnawave-admin/releases/latest) [![License](https://img.shields.io/badge/License-AGPL_v3-blue?style=flat-square&logo=gnu&logoColor=white)](LICENSE)

### [🌐 Документация fork](https://mslab-tech-dev.github.io/remnawave-admin/) · [💬 Сообщество Remnawave](https://t.me/remnawave_admin)

[English](README_EN.md) · Русский

</div>

---

> [!IMPORTANT]
> Этот репозиторий — самостоятельно поддерживаемый fork открытой версии Remnawave Admin 5.2.0. Новые изменения и образы публикуются владельцем fork.
>

Панель Remnawave отвечает за пользователей и конфигурацию. Remnawave Admin берёт на себя всё остальное: собирает подключения с нод, ищет разделение подписок и торренты, принимает меры, шлёт уведомления, хранит историю и показывает, что происходит.

Работает поверх вашей панели по API, данные держит в своей базе.

## Возможности

🛡 **Анти-абуз.** Анализаторы подключений ищут разделение подписки и накрутку пробных: одновременные подключения, «невозможные путешествия», сети, устройства, HWID, User-Agent. Меры — от предупреждения клиенту до ограничения скорости и отключения — можно включить автоматически, а каждое нарушение разобрать в его карточке.

🧲 **Торренты.** Тег роутинга Xray и разбор трафика на ноде: шифрованный BitTorrent тоже видно, а лаунчеры игр и синхронизацию файлов можно отметить как «не торрент».

🛰 **Агент на нодах.** Логи Xray, метрики хоста, удалённый терминал и каталог скриптов, ограничение скорости на ноде, качество канала до клиентов. Ставится одной строкой из панели.

🚨 **Атаки и сбои.** Детектор DDoS-атак на ноды, тревоги о падении нод и о проблемах с каналом.

📧 **Почтовый сервер.** Свой MX, DKIM, приём входящих, проверка SPF/DKIM/DMARC — без внешних SMTP-провайдеров.

📈 **Мониторинг и аналитика.** Метрики Prometheus и дашборды Grafana, гео-карта подключений, рейтинг хостеров, аналитика по пользователям и нодам.

🤖 **Telegram-бот.** Управление из чата, уведомления с кнопками действий, раскладка по топикам форума.

🔌 **API и интеграции.** Свой API с ключами и правами, webhook с подписью, нарушения в кабинете Bedolaga.

А также: конструктор автоматизаций, бэкапы по расписанию, журнал действий, роли и права, 2FA, темы оформления, русский и английский.

## Как начать

1. Склонируйте этот fork и следуйте [инструкции установки](docs/guide/installation.md).
2. Используйте опубликованные образы `ghcr.io/mslab-tech-dev/remnawave-admin*` либо соберите их Actions fork.
3. Документация fork: [GitHub Pages](https://mslab-tech-dev.github.io/remnawave-admin/).

Вопросы по fork — в [Issues](https://github.com/mslab-tech-dev/remnawave-admin/issues). Общий чат сообщества Remnawave: [Telegram](https://t.me/remnawave_admin).

## Основа fork

Fork основан на открытой версии 5.2.0 оригинального проекта. Оригинальные release notes сохранены как история исходной версии; дальнейшие обновления этого fork публикуются в [его releases](https://github.com/mslab-tech-dev/remnawave-admin/releases).

## Лицензия

Код этого репозитория — GNU AGPL v3.0 с исключением для плагинов (§7), см. [LICENSE](LICENSE); версии до 2.15.x включительно остаются под MIT.

<div align="center">

Сделано для сообщества Remnawave

</div>
