<div align="center">

<img src="remnawave-admin.webp" alt="Remnawave Admin" width="100%" />

# Remnawave Admin

**A control panel and Telegram bot on top of your Remnawave panel**

Users, nodes, anti-abuse, mail and monitoring in one place

[![Stars](https://img.shields.io/github/stars/mslab-tech-dev/remnawave-admin?style=flat-square&logo=github&logoColor=white&labelColor=1f2430&color=f5c518)](https://github.com/mslab-tech-dev/remnawave-admin/stargazers) [![Release](https://img.shields.io/github/v/release/mslab-tech-dev/remnawave-admin?style=flat-square&logo=github&logoColor=white&labelColor=1f2430&color=3fb950)](https://github.com/mslab-tech-dev/remnawave-admin/releases/latest) [![License](https://img.shields.io/badge/License-AGPL_v3-blue?style=flat-square&logo=gnu&logoColor=white)](LICENSE)

### [🌐 Fork documentation](https://mslab-tech-dev.github.io/remnawave-admin/en/) · [💬 Remnawave community](https://t.me/remnawave_admin)

English · [Русский](README.md)

</div>

---

> [!IMPORTANT]
> This repository is a separately maintained fork of the open Remnawave Admin 5.2.0 release. New changes and images are published by the fork owner.
>

The Remnawave panel owns users and configuration. Remnawave Admin takes care of everything else: it collects connections from your nodes, hunts for subscription sharing and torrents, takes measures, sends notifications, keeps the history and shows you what is going on.

It works on top of your panel over the API and keeps its data in its own database.

## Features

🛡 **Anti-abuse.** Connection analyzers look for subscription sharing and trial farming: simultaneous connections, impossible travel, networks, devices, HWID, User-Agent. Measures, from a warning to the client to speed limits and disabling, can run automatically, and every violation can be reviewed on its card.

🧲 **Torrents.** An Xray routing tag plus traffic inspection on the node: encrypted BitTorrent shows up too, and game launchers or file sync can be marked as “not a torrent”.

🛰 **Node agent.** Xray logs, host metrics, a remote terminal and a script catalogue, speed limits on the node, channel quality towards clients. Installed with one line from the panel.

🚨 **Attacks and outages.** A DDoS detector for nodes, alerts when nodes go down or the channel degrades.

📧 **Mail server.** Your own MX, DKIM, inbound mail, SPF/DKIM/DMARC checks, with no external SMTP provider.

📈 **Monitoring and analytics.** Prometheus metrics and Grafana dashboards, a connection geo map, a hoster rating, analytics for users and nodes.

🤖 **Telegram bot.** Control from the chat, notifications with action buttons, routing to forum topics.

🔌 **API and integrations.** Its own API with keys and permissions, signed webhooks, violations in the Bedolaga cabinet.

Also: an automation builder, scheduled backups, an action log, roles and permissions, 2FA, themes, Russian and English.

## Getting started

1. Clone this fork and follow the [installation guide](docs/en/guide/installation.md).
2. Use images published at `ghcr.io/mslab-tech-dev/remnawave-admin*` or build them with this fork's Actions.
3. Fork documentation: [GitHub Pages](https://mslab-tech-dev.github.io/remnawave-admin/en/).

For fork issues, use [GitHub Issues](https://github.com/mslab-tech-dev/remnawave-admin/issues). The general Remnawave community chat is on [Telegram](https://t.me/remnawave_admin).

## Fork base

This fork is based on the original project's open 5.2.0 release. Original release notes remain as history for that base; future fork updates are published in [this fork's releases](https://github.com/mslab-tech-dev/remnawave-admin/releases).

## Licence

The code in this repository is GNU AGPL v3.0 with a plugin exception (§7) — see [LICENSE](LICENSE); versions up to and including 2.15.x remain under MIT.

<div align="center">

Built for the Remnawave community

</div>
