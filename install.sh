#!/bin/sh
# conn-audit installer — POSIX sh, можно запускать как:
#   sudo sh -c "$(curl -fsSL https://raw.githubusercontent.com/theillarion/tg-net-bot/master/conn-audit/install.sh)"
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "Запусти от root: sudo sh install.sh" >&2
    exit 1
fi

REPO_RAW=${REPO_RAW:-https://raw.githubusercontent.com/theillarion/tg-net-bot/master/conn-audit}
REPO_RAW=${REPO_RAW%/}
DATA=${DATA:-/var/lib/conn-audit}
BIN=${BIN:-/usr/local/sbin/conn_audit.py}
UNIT_DIR=${UNIT_DIR:-/etc/systemd/system}
SCTL=${SCTL:-systemctl}

say() { printf '%s\n' "$*"; }

fetch() {
    # fetch <url> <dest>
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$1" -o "$2"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$2" "$1"
    else
        echo "Нужен curl или wget" >&2
        return 1
    fi
}

say "conn-audit installer"
say "источник: $REPO_RAW"

say "[1/5] зависимости..."
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 conntrack tcpdump sqlite3 || true
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y python3 conntrack-tools tcpdump sqlite || true
elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache python3 conntrack-tools tcpdump sqlite || true
else
    say "WARN: неизвестный пакетный менеджер; поставь python3 conntrack tcpdump вручную"
fi

for c in python3 conntrack tcpdump; do
    if ! command -v "$c" >/dev/null 2>&1; then
        say "WARN: $c не найден — часть сбора работать не будет"
    fi
done

say "[2/5] скачиваю conn_audit.py..."
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT HUP INT TERM
fetch "$REPO_RAW/conn_audit.py" "$tmp"
if ! head -n 1 "$tmp" | grep -q python; then
    say "ERROR: скачался не Python-скрипт (проверь REPO_RAW)"
    exit 1
fi
mkdir -p "$(dirname "$BIN")"
install -m 0755 "$tmp" "$BIN"
rm -f "$tmp"
trap - EXIT HUP INT TERM

mkdir -p "$DATA/reports"
chmod 700 "$DATA"

say "[3/5] systemd units..."
if ! command -v "$SCTL" >/dev/null 2>&1; then
    say "systemd не найден. Запусти вручную:"
    say "  nohup $BIN live --duration 0 --db $DATA/conn_audit.db >/var/log/conn-audit.log 2>&1 &"
    exit 0
fi

mkdir -p "$UNIT_DIR"
cat > "$UNIT_DIR/conn-audit-live.service" <<EOF
[Unit]
Description=conn-audit live collector (conntrack + tcpdump SYN)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=$BIN live --duration 0 --db $DATA/conn_audit.db
Restart=always
RestartSec=10
Nice=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

cat > "$UNIT_DIR/conn-audit-collect.service" <<EOF
[Unit]
Description=conn-audit log collector
After=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=$BIN collect --hours 48 --db $DATA/conn_audit.db
Nice=10
EOF

cat > "$UNIT_DIR/conn-audit-collect.timer" <<'EOF'
[Unit]
Description=Daily conn-audit log collection

[Timer]
OnCalendar=*-*-* 04:15:00
Persistent=true
RandomizedDelaySec=10m

[Install]
WantedBy=timers.target
EOF

cat > "$UNIT_DIR/conn-audit-report.service" <<EOF
[Unit]
Description=conn-audit daily CSV report
After=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=$BIN report --hours 24 --top 500 --csv
StandardOutput=append:$DATA/reports/daily.csv
Nice=10
EOF

cat > "$UNIT_DIR/conn-audit-report.timer" <<'EOF'
[Unit]
Description=Daily conn-audit report

[Timer]
OnCalendar=*-*-* 06:30:00
Persistent=true
RandomizedDelaySec=10m

[Install]
WantedBy=timers.target
EOF

cat > "$UNIT_DIR/conn-audit-prune.service" <<EOF
[Unit]
Description=conn-audit prune
After=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=$BIN prune --days 30 --db $DATA/conn_audit.db
Nice=10
EOF

cat > "$UNIT_DIR/conn-audit-prune.timer" <<'EOF'
[Unit]
Description=Weekly conn-audit prune

[Timer]
OnCalendar=Sun *-*-* 05:00:00
Persistent=true
RandomizedDelaySec=10m

[Install]
WantedBy=timers.target
EOF

say "[4/5] включаю..."
"$SCTL" daemon-reload
"$SCTL" enable --now conn-audit-live.service
"$SCTL" restart conn-audit-live.service
"$SCTL" enable --now conn-audit-collect.timer
"$SCTL" enable --now conn-audit-report.timer
"$SCTL" enable --now conn-audit-prune.timer

say "[5/5] проверка..."
sleep 2
"$SCTL" --no-pager --lines=15 status conn-audit-live.service || true

say ""
say "Готово."
say "  Статус:  $SCTL status conn-audit-live"
say "  Логи:    journalctl -u conn-audit-live -f"
say "  Отчёт:   $BIN report --hours 24 --top 50"
say "  База:    $DATA/conn_audit.db"
say "  CSV:     $DATA/reports/daily.csv"
say "  Обновить: повтори этот же one-liner"
