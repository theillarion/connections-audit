# conn-audit

Сбор IP, которые стучатся в сервер: `conntrack -E` + `tcpdump` SYN, SQLite, отчёты и экспорт в nftables/ipset.

## Установка одной командой

```sh
sudo sh -c "$(curl -fsSL https://raw.githubusercontent.com/theillarion/tg-net-bot/master/conn-audit/install.sh)"
```

С фиксированным коммитом:

```sh
COMMIT=<sha>
sudo sh -c "$(curl -fsSL https://raw.githubusercontent.com/theillarion/tg-net-bot/$COMMIT/conn-audit/install.sh)"
```

## Обновление

Повтори ту же команду. `install.sh` скачает свежий `conn_audit.py`, перезапишет его и перезапустит сервис. База не удаляется.

Если хочешь зафиксировать источник Python-файла:

```sh
sudo env REPO_RAW=https://raw.githubusercontent.com/theillarion/tg-net-bot/<sha>/conn-audit \
  sh -c "$(curl -fsSL https://raw.githubusercontent.com/theillarion/tg-net-bot/<sha>/conn-audit/install.sh)"
```

## Что ставится

- `/usr/local/sbin/conn_audit.py`
- `/var/lib/conn-audit/conn_audit.db`
- `/var/lib/conn-audit/reports/daily.csv`
- systemd:
  - `conn-audit-live.service` — постоянный сбор;
  - `conn-audit-collect.timer` — разбор логов раз в сутки;
  - `conn-audit-report.timer` — CSV-отчёт раз в сутки;
  - `conn-audit-prune.timer` — чистка раз в неделю.

## Проверка

```sh
systemctl status conn-audit-live --no-pager
journalctl -u conn-audit-live -f
/usr/local/sbin/conn_audit.py report --hours 1 --top 20
/usr/local/sbin/conn_audit.py doctor
```

`report` по умолчанию исключает свои/локальные IP. Показать всё: `--include-local`. Исключить вручную: `--exclude 1.2.3.4`.

## Удаление

```sh
sudo sh -c "$(curl -fsSL https://raw.githubusercontent.com/theillarion/tg-net-bot/master/conn-audit/uninstall.sh)"
# или с удалением базы:
# sudo sh -c "$(curl -fsSL .../uninstall.sh) --purge"
```

## Важно

- Запускать на хосте, не в контейнере: при `network_mode: host` host-овый `tcpdump` видит трафик 3x-ui.
- Если сервер за CDN — в базе будут IP CDN, а не клиента.
- Не запускай одновременно systemd-сервис и ручной `live` — будут дубли.
- Это не DPI: содержимое не разбирается, только факты соединений.
