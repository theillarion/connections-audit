#!/usr/bin/env bash
# Устанавливает conn_audit.py и systemd-сервисы:
#   conn-audit-live     — постоянно слушает conntrack + tcpdump SYN
#   conn-audit-collect  — раз в сутки разбирает логи (если появятся)
#   conn-audit-report   — раз в сутки пишет CSV-отчёт
#   conn-audit-prune    — раз в неделю чистит старые записи
set -euo pipefail

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "Запусти от root: sudo $0" >&2
    exit 1
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/conn_audit.py"
DST="/usr/local/sbin/conn_audit.py"
DATA="/var/lib/conn-audit"

if [ ! -f "$SRC" ]; then
    echo "Нет $SRC — положи install_conn_audit.sh и conn_audit.py в одну папку" >&2
    exit 1
fi
if ! command -v systemctl >/dev/null 2>&1; then
    echo "Нет systemd. Запусти вручную:"
    echo "  nohup $DST live --duration 0 --db $DATA/conn_audit.db >/var/log/conn-audit.log 2>&1 &"
    exit 1
fi

echo "[1/5] Зависимости..."
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 conntrack tcpdump sqlite3
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y python3 conntrack-tools tcpdump sqlite
elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache python3 conntrack-tools tcpdump sqlite
else
    echo "Неизвестный пакетный менеджер; поставь вручную: python3 conntrack tcpdump sqlite3" >&2
fi

for c in python3 conntrack tcpdump; do
    if ! command -v "$c" >/dev/null 2>&1; then
        echo "ВНИМАНИЕ: $c не найден. conn_audit.py сможет работать только с тем, что есть." >&2
    fi
done

echo "[2/5] Установка скрипта..."
install -m 0755 "$SRC" "$DST"
mkdir -p "$DATA/reports"
chmod 700 "$DATA"

echo "[3/5] systemd units..."
cat > /etc/systemd/system/conn-audit-live.service <<'EOF'
[Unit]
Description=conn-audit live collector (conntrack + tcpdump SYN)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/sbin/conn_audit.py live --duration 0 --db /var/lib/conn-audit/conn_audit.db
Restart=always
RestartSec=10
Nice=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/conn-audit-collect.service <<'EOF'
[Unit]
Description=conn-audit log collector
After=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=/usr/local/sbin/conn_audit.py collect --hours 48 --db /var/lib/conn-audit/conn_audit.db
Nice=10
EOF

cat > /etc/systemd/system/conn-audit-collect.timer <<'EOF'
[Unit]
Description=Daily conn-audit log collection

[Timer]
OnCalendar=*-*-* 04:15:00
Persistent=true
RandomizedDelaySec=10m

[Install]
WantedBy=timers.target
EOF

cat > /etc/systemd/system/conn-audit-report.service <<'EOF'
[Unit]
Description=conn-audit daily CSV report
After=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=/usr/local/sbin/conn_audit.py report --hours 24 --top 500 --csv
StandardOutput=append:/var/lib/conn-audit/reports/daily.csv
Nice=10
EOF

cat > /etc/systemd/system/conn-audit-report.timer <<'EOF'
[Unit]
Description=Daily conn-audit report

[Timer]
OnCalendar=*-*-* 06:30:00
Persistent=true
RandomizedDelaySec=10m

[Install]
WantedBy=timers.target
EOF

cat > /etc/systemd/system/conn-audit-prune.service <<'EOF'
[Unit]
Description=conn-audit prune
After=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=/usr/local/sbin/conn_audit.py prune --days 30 --db /var/lib/conn-audit/conn_audit.db
Nice=10
EOF

cat > /etc/systemd/system/conn-audit-prune.timer <<'EOF'
[Unit]
Description=Weekly conn-audit prune

[Timer]
OnCalendar=Sun *-*-* 05:00:00
Persistent=true
RandomizedDelaySec=10m

[Install]
WantedBy=timers.target
EOF

echo "[4/5] Включение..."
systemctl daemon-reload
systemctl enable --now conn-audit-live.service
systemctl restart conn-audit-live.service
systemctl enable --now conn-audit-collect.timer
systemctl enable --now conn-audit-report.timer
systemctl enable --now conn-audit-prune.timer

echo "[5/5] Проверка..."
sleep 2
systemctl --no-pager --lines=20 status conn-audit-live.service || true
echo
echo "Готово."
echo "  Статус:   systemctl status conn-audit-live"
echo "  Логи:     journalctl -u conn-audit-live -f"
echo "  Отчёт:    $DST report --hours 24 --top 50"
echo "  База:     $DATA/conn_audit.db"
echo "  CSV:      $DATA/reports/daily.csv (обновляется раз в сутки)"
