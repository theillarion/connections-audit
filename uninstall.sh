#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "Запусти от root" >&2
    exit 1
fi

systemctl disable --now \
    conn-audit-live.service \
    conn-audit-collect.timer \
    conn-audit-report.timer \
    conn-audit-prune.timer 2>/dev/null || true

rm -f \
    /etc/systemd/system/conn-audit-live.service \
    /etc/systemd/system/conn-audit-collect.service \
    /etc/systemd/system/conn-audit-collect.timer \
    /etc/systemd/system/conn-audit-report.service \
    /etc/systemd/system/conn-audit-report.timer \
    /etc/systemd/system/conn-audit-prune.service \
    /etc/systemd/system/conn-audit-prune.timer

systemctl daemon-reload 2>/dev/null || true
rm -f /usr/local/sbin/conn_audit.py

if [ "${1:-}" = "--purge" ]; then
    rm -rf /var/lib/conn-audit
    echo "Удалено, включая базу."
else
    echo "Удалено. База оставлена: /var/lib/conn-audit (удалить: uninstall.sh --purge)"
fi
