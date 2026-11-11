#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
conn-audit — сбор IP, которые пытались подключиться к серверу.

Что умеет:
  collect   — разобрать уже существующие логи за последние N часов
              (kernel/nftables/iptables, Xray access.log, SSH auth.log,
               nginx access.log, fail2ban.log, текущий conntrack).
  live      — слушать новые попытки: conntrack -E + tcpdump SYN.
  report    — топ IP / подсетей / портов / источников, опционально ASN.
  export    — выгрузить в nftables / ipset / txt для блокировки.
  doctor    — показать, какие источники вообще доступны на сервере.
  prune     — почистить старые записи.
  selftest  — проверить парсеры на встроенных примерах.
  install   — напечатать systemd-юниты для постоянного сбора.

Только stdlib Python 3. Запускать от root (для conntrack/tcpdump/логов).
Историю за прошедшие сутки можно достать только из логов, которые уже
существовали. Если firewall-логи не были включены — запускай live и
собирай с этого момента.

Примеры:
  ./conn_audit.py doctor
  ./conn_audit.py collect --hours 24
  ./conn_audit.py live --duration 3600
  ./conn_audit.py report --hours 24 --top 50 --enrich
  ./conn_audit.py export --format nft --min-count 3 > block.nft
"""

import argparse
import csv
import datetime
import glob
import gzip
import hashlib
import ipaddress
import json
import os
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

DB_DEFAULT = "/var/lib/conn-audit/conn_audit.db"
VERSION = "1.0"

# --------------------------------------------------------------------------
# утилиты
# --------------------------------------------------------------------------

def now_ts():
    return int(time.time())


def fmt_ts(ts):
    if not ts:
        return "-"
    return datetime.datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M:%S")


def is_ip(value):
    try:
        ipaddress.ip_address(str(value).strip("[]"))
        return True
    except ValueError:
        return False


def norm_ip(value):
    try:
        return str(ipaddress.ip_address(str(value).strip("[]")))
    except ValueError:
        return None


MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def parse_syslog_ts(line):
    m = re.match(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})", line)
    if not m:
        return None
    mon = MONTHS.get(m.group(1))
    if not mon:
        return None
    day, hh, mm, ss = int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5))
    now = datetime.datetime.now()
    try:
        dt = datetime.datetime(now.year, mon, day, hh, mm, ss)
    except ValueError:
        return None
    if dt > now + datetime.timedelta(days=1):
        try:
            dt = dt.replace(year=now.year - 1)
        except ValueError:
            return None
    return int(dt.timestamp())


def parse_xray_ts(line):
    m = re.match(r"^(\d{4})/(\d{2})/(\d{2})[ T](\d{2}):(\d{2}):(\d{2})", line)
    if not m:
        return None
    try:
        dt = datetime.datetime(*[int(x) for x in m.groups()])
    except ValueError:
        return None
    return int(dt.timestamp())


def parse_nginx_ts(line):
    m = re.search(r"\[([^\]]+)\]", line)
    if not m:
        return None
    try:
        return int(datetime.datetime.strptime(m.group(1), "%d/%b/%Y:%H:%M:%S %z").timestamp())
    except ValueError:
        return None


def parse_iso_ts(line):
    m = re.match(r"^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})", line)
    if not m:
        return None
    try:
        return int(datetime.datetime.strptime(m.group(1) + " " + m.group(2), "%Y-%m-%d %H:%M:%S").timestamp())
    except ValueError:
        return None


# --------------------------------------------------------------------------
# база
# --------------------------------------------------------------------------

def db_connect(path, init=True, autocommit=False):
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(path, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=10000")
    if autocommit:
        # Live collectors write from several threads; each INSERT must release
        # the write lock immediately, otherwise one thread starves the other.
        conn.isolation_level = None
    if init:
        init_db(conn)
    return conn


def init_db(conn):
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS hits (
            ts      INTEGER NOT NULL,
            ip      TEXT    NOT NULL,
            port    INTEGER,
            proto   TEXT,
            source  TEXT    NOT NULL,
            detail  TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_hits_ts ON hits(ts);
        CREATE INDEX IF NOT EXISTS idx_hits_ip ON hits(ip);
        CREATE INDEX IF NOT EXISTS idx_hits_port ON hits(port);
        CREATE TABLE IF NOT EXISTS seen (
            hash TEXT PRIMARY KEY,
            ts   INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_seen_ts ON seen(ts);
        CREATE TABLE IF NOT EXISTS ip_cache (
            ip      TEXT PRIMARY KEY,
            asn     TEXT,
            org     TEXT,
            country TEXT,
            ts      INTEGER NOT NULL
        );
        """
    )
    conn.commit()


def add_hit(conn, ts, ip, port, proto, source, detail="", dedupe=True):
    ip = norm_ip(ip)
    if not ip:
        return False
    try:
        port = int(port) if port not in (None, "", "-") else None
    except (TypeError, ValueError):
        port = None
    proto = (proto or "").lower()[:8]
    detail = (detail or "")[:300]
    if dedupe:
        digest = hashlib.sha1(
            f"{source}|{ts}|{ip}|{port}|{proto}|{detail}".encode("utf-8", "replace")
        ).hexdigest()
        cur = conn.execute("INSERT OR IGNORE INTO seen(hash, ts) VALUES(?, ?)", (digest, ts))
        if cur.rowcount == 0:
            return False
    conn.execute(
        "INSERT INTO hits(ts, ip, port, proto, source, detail) VALUES(?,?,?,?,?,?)",
        (int(ts), ip, port, proto, source, detail),
    )
    return True


def commit_hits(conn, count, batch=200):
    if count and count % batch == 0:
        conn.commit()


# --------------------------------------------------------------------------
# парсеры
# --------------------------------------------------------------------------

def parse_kernel_line(line, default_ts=None):
    if "SRC=" not in line:
        return None
    kv = dict(re.findall(r"([A-Z0-9_]+)=(\"[^\"]*\"|\S+)", line))
    src = kv.get("SRC", "").strip('"')
    if not is_ip(src):
        return None
    # только входящие: у исходящих IN пустой, OUT заполнен
    if kv.get("IN", "") == "" and kv.get("OUT", "") != "":
        return None
    proto = (kv.get("PROTO") or kv.get("L4PROTO") or "").lower()
    port = kv.get("DPT") or kv.get("DPORT") or ""
    ts = parse_syslog_ts(line) or default_ts or now_ts()
    return {
        "ts": ts, "ip": src, "port": port, "proto": proto,
        "source": "kernel",
        "detail": (kv.get("PROTO", "") + " DPT=" + str(port)).strip(),
    }


def parse_xray_line(line, default_ts=None):
    ts = parse_xray_ts(line) or default_ts or now_ts()
    ip = port = None
    m = re.search(r"\bfrom\s+(\[[0-9a-fA-F:]+\]|[0-9a-fA-F:.]+):(\d+)", line)
    if not m:
        m = re.search(r"(\[[0-9a-fA-F:]+\]|[0-9a-fA-F:.]+):(\d+)\s+(?:accepted|rejected)", line)
    if not m:
        m = re.search(r"\b(\[[0-9a-fA-F:]+\]|[0-9a-fA-F:.]+):(\d+)\b", line)
    if m:
        ip = m.group(1).strip("[]")
        port = m.group(2)
    if not ip or not is_ip(ip):
        return None
    verdict = "accepted" if "accepted" in line else ("rejected" if "rejected" in line else "")
    return {
        "ts": ts, "ip": ip, "port": None, "proto": "tcp",
        "source": "xray", "detail": (verdict + " from:" + str(port)).strip(),
    }


def parse_ssh_line(line, default_ts=None):
    if "from " not in line and " by " not in line:
        return None
    m = re.search(r"\bfrom\s+(\[[0-9a-fA-F:]+\]|[0-9a-fA-F:.]+)", line)
    if not m:
        m = re.search(r"\bby\s+\S+\s+(\[[0-9a-fA-F:]+\]|[0-9a-fA-F:.]+)", line)
    if not m:
        return None
    ip = m.group(1).strip("[]")
    if not is_ip(ip):
        return None
    pm = re.search(r"\bport\s+(\d+)", line)
    ts = parse_syslog_ts(line) or default_ts or now_ts()
    sport = pm.group(1) if pm else ""
    return {
        "ts": ts, "ip": ip, "port": None,
        "proto": "tcp", "source": "ssh",
        "detail": ("failed/invalid " if ("Failed" in line or "Invalid" in line) else "ssh ") + "sport:" + str(sport),
    }


def parse_nginx_line(line, default_ts=None):
    m = re.match(
        r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d{3})',
        line,
    )
    if not m:
        return None
    ip = m.group(1)
    if not is_ip(ip):
        return None
    ts = parse_nginx_ts(line) or default_ts or now_ts()
    req = m.group(3)
    parts = req.split()
    detail = f"{m.group(4)} {parts[0] if parts else ''} {parts[1] if len(parts) > 1 else ''}"[:200]
    return {"ts": ts, "ip": ip, "port": None, "proto": "tcp", "source": "nginx", "detail": detail}


def parse_fail2ban_line(line, default_ts=None):
    if "Ban " not in line and "ban " not in line:
        return None
    m = re.search(r"\b[Bb]an\s+(\[[0-9a-fA-F:]+\]|[0-9a-fA-F:.]+)", line)
    if not m:
        return None
    ip = m.group(1).strip("[]")
    if not is_ip(ip):
        return None
    ts = parse_iso_ts(line) or default_ts or now_ts()
    return {"ts": ts, "ip": ip, "port": None, "proto": "", "source": "fail2ban", "detail": "ban"}


def parse_conntrack_line(line, default_ts=None):
    if "src=" not in line:
        return None
    proto = line.split(None, 1)[0].lower() if line.strip() else ""
    if proto not in ("tcp", "udp", "icmp", "icmpv6", "sctp"):
        proto = ""
    kv = dict(re.findall(r"(\w+)=(\S+)", line))
    src = kv.get("src")
    if not src or not is_ip(src):
        return None
    return {
        "ts": default_ts or now_ts(), "ip": src, "port": kv.get("dport"),
        "proto": proto, "source": "conntrack", "detail": line[:200],
    }


def parse_tcpdump_line(line, default_ts=None):
    m = re.search(
        r"\bIP6?\s+(\[[0-9a-fA-F:]+\]|[0-9a-fA-F:.]+)\.(\d+)\s+>\s+"
        r"(\[[0-9a-fA-F:]+\]|[0-9a-fA-F:.]+)\.(\d+):\s+Flags\s+\[S\]",
        line,
    )
    if not m:
        return None
    src = m.group(1).strip("[]")
    if not is_ip(src):
        return None
    return {
        "ts": default_ts or now_ts(), "ip": src, "port": m.group(4),
        "proto": "tcp", "source": "tcpdump", "detail": "SYN dst:" + m.group(3),
    }


# --------------------------------------------------------------------------
# collect
# --------------------------------------------------------------------------

def open_log(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def collect_file(conn, path, parser, source, since, stats):
    added = 0
    try:
        with open_log(path) as fh:
            for line in fh:
                rec = parser(line)
                if not rec or rec["ts"] < since:
                    continue
                if add_hit(conn, rec["ts"], rec["ip"], rec.get("port"), rec.get("proto"),
                           rec.get("source", source), rec.get("detail", ""), dedupe=True):
                    added += 1
    except (OSError, UnicodeError) as exc:
        print(f"  ! {path}: {exc}", file=sys.stderr)
        return 0
    stats[source] = stats.get(source, 0) + added
    return added


def conntrack_snapshot(conn, stats):
    if not shutil.which("conntrack"):
        return 0
    try:
        out = subprocess.run(["conntrack", "-L"], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return 0
    if out.returncode != 0:
        return 0
    added = 0
    bucket = now_ts() // 300
    for line in out.stdout.splitlines():
        rec = parse_conntrack_line(line)
        if not rec:
            continue
        # один и тот же текущий conntrack-сокет не должен плодить записи при каждом запуске
        if add_hit(conn, bucket * 300, rec["ip"], rec.get("port"), rec.get("proto"),
                   "conntrack", rec.get("detail", ""), dedupe=True):
            added += 1
    stats["conntrack"] = stats.get("conntrack", 0) + added
    return added


def cmd_collect(args):
    conn = db_connect(args.db)
    since = now_ts() - args.hours * 3600
    stats = {}
    wanted = set(args.source or ["kernel", "xray", "ssh", "nginx", "fail2ban", "conntrack"])

    if "kernel" in wanted:
        if shutil.which("journalctl"):
            try:
                out = subprocess.run(
                    ["journalctl", "-k", "--since", f"@{since}", "--no-pager", "-o", "short"],
                    capture_output=True, text=True, timeout=60,
                )
                if out.returncode == 0:
                    added = 0
                    for line in out.stdout.splitlines():
                        rec = parse_kernel_line(line)
                        if rec and rec["ts"] >= since and add_hit(
                            conn, rec["ts"], rec["ip"], rec.get("port"), rec.get("proto"),
                            "kernel", rec.get("detail", ""), dedupe=True):
                            added += 1
                    stats["kernel"] = stats.get("kernel", 0) + added
            except (OSError, subprocess.SubprocessError) as exc:
                print(f"  ! journalctl: {exc}", file=sys.stderr)
        for path in ("/var/log/kern.log", "/var/log/messages", "/var/log/syslog"):
            if os.path.exists(path):
                collect_file(conn, path, parse_kernel_line, "kernel", since, stats)
        for path in (args.kernel_log or []):
            if os.path.exists(path):
                collect_file(conn, path, parse_kernel_line, "kernel", since, stats)

    if "xray" in wanted:
        paths = []
        for pattern in (
            "/var/log/xray/access.log*",
            "/usr/local/x-ui/bin/access.log*",
            "/usr/local/x-ui/access.log*",
            "/opt/3x-ui/bin/access.log*",
        ):
            paths.extend(glob.glob(pattern))
        paths.extend(args.xray_log or [])
        for path in sorted(set(paths)):
            collect_file(conn, path, parse_xray_line, "xray", since, stats)

    if "ssh" in wanted:
        for path in ("/var/log/auth.log", "/var/log/secure"):
            if os.path.exists(path):
                collect_file(conn, path, parse_ssh_line, "ssh", since, stats)
        for path in (args.auth_log or []):
            if os.path.exists(path):
                collect_file(conn, path, parse_ssh_line, "ssh", since, stats)

    if "nginx" in wanted:
        paths = []
        for pattern in ("/var/log/nginx/access.log*", "/var/log/caddy/access.log*"):
            paths.extend(glob.glob(pattern))
        paths.extend(args.nginx_log or [])
        for path in sorted(set(paths)):
            collect_file(conn, path, parse_nginx_line, "nginx", since, stats)

    if "fail2ban" in wanted:
        paths = glob.glob("/var/log/fail2ban.log*") + (args.fail2ban_log or [])
        for path in sorted(set(paths)):
            collect_file(conn, path, parse_fail2ban_line, "fail2ban", since, stats)

    if "conntrack" in wanted:
        conntrack_snapshot(conn, stats)

    conn.commit()
    total = conn.execute("SELECT COUNT(*) FROM hits WHERE ts >= ?", (since,)).fetchone()[0]
    uniq = conn.execute("SELECT COUNT(DISTINCT ip) FROM hits WHERE ts >= ?", (since,)).fetchone()[0]
    print(f"Последние {args.hours} ч: записей {total}, уникальных IP {uniq}")
    for src in sorted(stats):
        print(f"  {src:10s} +{stats[src]}")
    if not stats:
        print("  Ничего не найдено. Скорее всего, логи firewall не включены —")
        print("  запусти: ./conn_audit.py live --duration 3600")
    conn.close()


# --------------------------------------------------------------------------
# live
# --------------------------------------------------------------------------

def live_reader(db_path, cmd, parser, source, stop, quiet, procs=None):
    # SQLite connection must be created inside the worker thread.
    try:
        conn = db_connect(db_path, autocommit=True)
    except Exception as exc:
        if not quiet:
            print(f"  ! {source}: db: {exc}", file=sys.stderr)
        return
    proc = None
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1,
        )
        if procs is not None:
            procs.append(proc)
    except OSError as exc:
        if not quiet:
            print(f"  ! {source}: {exc}", file=sys.stderr)
        return
    count = 0
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            if stop.is_set():
                break
            # conntrack -E emits NEW, UPDATE and DESTROY. UPDATE/DESTROY are the
            # reply direction (src=server, dport=client ephemeral); they are not
            # connection attempts and only add noise.
            if source == "conntrack" and "[NEW]" not in line:
                continue
            rec = parser(line)
            if not rec:
                continue
            if add_hit(conn, rec["ts"], rec["ip"], rec.get("port"), rec.get("proto"),
                       rec.get("source", source), rec.get("detail", ""), dedupe=False):
                count += 1
                if count % 50 == 0:
                    conn.commit()
                    if not quiet:
                        print(f"  {source}: {count} попыток", file=sys.stderr)
    finally:
        try:
            if proc.poll() is None:
                proc.terminate()
        except Exception:
            pass
        try:
            conn.commit()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass
        if proc.returncode not in (None, 0, -15) and not quiet:
            err = ""
            try:
                err = (proc.stderr.read() or "")[:300] if proc.stderr else ""
            except Exception:
                pass
            print(f"  ! {source} завершился: {err}", file=sys.stderr)


def cmd_live(args):
    conn = db_connect(args.db)
    conn.close()
    session_start = now_ts()
    stop = threading.Event()
    threads = []
    procs = []

    if not args.no_conntrack and shutil.which("conntrack"):
        t = threading.Thread(
            target=live_reader,
            args=(args.db, ["conntrack", "-E"],
                  parse_conntrack_line, "conntrack", stop, args.quiet, procs),
            daemon=True,
        )
        t.start()
        threads.append(t)

    if not args.no_tcpdump and shutil.which("tcpdump"):
        bpf = "tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0"
        cmd = ["tcpdump", "-i", args.iface, "-n", "-l", "-Q", "in", bpf]
        t = threading.Thread(
            target=live_reader,
            args=(args.db, cmd, parse_tcpdump_line, "tcpdump", stop, args.quiet, procs),
            daemon=True,
        )
        t.start()
        threads.append(t)

    if not threads:
        print("Нет ни conntrack, ни tcpdump. Установи: apt install conntrack tcpdump",
              file=sys.stderr)
        return 1

    names = []
    if not args.no_conntrack and shutil.which("conntrack"):
        names.append("conntrack")
    if not args.no_tcpdump and shutil.which("tcpdump"):
        names.append("tcpdump")
    print(f"Слушаю новые попытки ({', '.join(names)})...", file=sys.stderr)
    print("Ctrl-C — остановить; duration=0 — бесконечно.", file=sys.stderr)
    try:
        if args.duration and args.duration > 0:
            stop.wait(args.duration)
        else:
            while not stop.is_set():
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        for p in procs:
            try:
                if p.poll() is None:
                    p.terminate()
            except Exception:
                pass
        for t in threads:
            t.join(timeout=5)

    conn = db_connect(args.db)
    since = session_start
    total = conn.execute("SELECT COUNT(*) FROM hits WHERE ts >= ?", (since,)).fetchone()[0]
    uniq = conn.execute("SELECT COUNT(DISTINCT ip) FROM hits WHERE ts >= ?", (since,)).fetchone()[0]
    conn.close()
    print(f"Собрано за сессию: {total} записей, {uniq} уникальных IP.")
    return 0


# --------------------------------------------------------------------------
# report
# --------------------------------------------------------------------------

def print_table(headers, rows):
    if not rows:
        print("(пусто)")
        return
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    print("  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)))
    print("  ".join("-" * widths[i] for i in range(len(headers))))
    for row in rows:
        print("  ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(row)))


def enrich_ip(conn, ip):
    row = conn.execute("SELECT asn, org, country, ts FROM ip_cache WHERE ip=?", (ip,)).fetchone()
    if row and now_ts() - row[3] < 30 * 86400:
        return row[0] or "", row[1] or "", row[2] or ""
    asn = org = country = ""
    try:
        req = urllib.request.Request(
            f"https://ipinfo.io/{ip}/json",
            headers={"User-Agent": f"conn-audit/{VERSION}"},
        )
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = json.load(resp)
        org = data.get("org", "") or ""
        country = data.get("country", "") or ""
        m = re.match(r"^(AS\d+)\s+(.*)$", org)
        if m:
            asn, org = m.group(1), m.group(2)
        else:
            asn = org
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError, ValueError):
        pass
    conn.execute(
        "INSERT OR REPLACE INTO ip_cache(ip, asn, org, country, ts) VALUES(?,?,?,?,?)",
        (ip, asn, org, country, now_ts()),
    )
    conn.commit()
    time.sleep(0.35)
    return asn, org, country


def local_ip_set():
    """Свои адреса, loopback и адреса интерфейсов — их не считаем сканерами."""
    ips = {"127.0.0.1", "127.0.0.53", "::1"}
    for cmd in (["ip", "-o", "addr", "show"], ["hostname", "-I"]):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            continue
        for line in out.stdout.splitlines():
            for token in re.findall(r"[0-9a-fA-F:.]+", line):
                ip = norm_ip(token)
                if ip:
                    ips.add(ip)
    return ips


def is_external_ip(ip, exclude):
    ip = norm_ip(ip)
    if not ip or ip in exclude:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return bool(addr.is_global) and not (
        addr.is_private or addr.is_loopback or addr.is_link_local
        or addr.is_unspecified or addr.is_multicast
    )


def exclude_set(args):
    exclude = set()
    if not getattr(args, "include_local", False):
        exclude |= local_ip_set()
    for value in (getattr(args, "exclude", None) or []):
        ip = norm_ip(value)
        if ip:
            exclude.add(ip)
    return exclude


def where_since(since, exclude):
    where = "ts >= ?"
    params = [since]
    # Старые записи до фикса: conntrack UPDATE/DESTROY — это reply-направление,
    # а не попытки подключения. В detail лежит исходная строка conntrack.
    where += " AND NOT (source = 'conntrack' AND (detail LIKE '%[UPDATE]%' OR detail LIKE '%[DESTROY]%'))"
    if exclude:
        where += " AND ip NOT IN (%s)" % ",".join("?" * len(exclude))
        params.extend(sorted(exclude))
    return where, params


def cmd_report(args):
    conn = db_connect(args.db)
    since = now_ts() - args.hours * 3600
    exclude = exclude_set(args)
    filter_external = not getattr(args, "include_local", False)
    where, params = where_since(since, exclude)
    rows = []
    headers = []

    if args.by == "ip":
        q = f"""
            SELECT ip, COUNT(*) c, MIN(ts), MAX(ts),
                   GROUP_CONCAT(DISTINCT port), GROUP_CONCAT(DISTINCT source)
            FROM hits WHERE {where}
            GROUP BY ip HAVING c >= ?
            ORDER BY c DESC LIMIT ?
        """
        data = conn.execute(q, params + [args.min_count, args.top * 5]).fetchall()
        if filter_external:
            data = [row for row in data if is_external_ip(row[0], exclude)]
        data = data[: args.top]
        headers = ["IP", "попыток", "первый", "последний", "порты", "источники"]
        if args.enrich:
            headers += ["ASN", "Org", "Country"]
        for i, (ip, cnt, first, last, ports, sources) in enumerate(data):
            ports = (ports or "")[:40]
            sources = (sources or "")[:30]
            row = [ip, cnt, fmt_ts(first), fmt_ts(last), ports, sources]
            if args.enrich:
                row += list(enrich_ip(conn, ip))
            rows.append(row)

    elif args.by == "subnet":
        data = conn.execute(
            f"SELECT ip, COUNT(*) c, MIN(ts), MAX(ts) FROM hits WHERE {where} GROUP BY ip",
            params,
        ).fetchall()
        agg = {}
        for ip, cnt, first, last in data:
            if filter_external and not is_external_ip(ip, exclude):
                continue
            try:
                addr = ipaddress.ip_address(ip)
                net = ipaddress.ip_network(
                    f"{ip}/24" if addr.version == 4 else f"{ip}/64", strict=False
                )
            except ValueError:
                continue
            key = str(net)
            a = agg.setdefault(key, [0, first, last])
            a[0] += cnt
            a[1] = min(a[1], first)
            a[2] = max(a[2], last)
        data = sorted(agg.items(), key=lambda kv: kv[1][0], reverse=True)[: args.top]
        headers = ["подсеть", "попыток", "первый", "последний"]
        rows = [[k, v[0], fmt_ts(v[1]), fmt_ts(v[2])] for k, v in data]

    elif args.by == "port":
        data = conn.execute(
            f"""SELECT port, COUNT(*) c, COUNT(DISTINCT ip) u, MIN(ts), MAX(ts)
               FROM hits WHERE {where} AND port IS NOT NULL
               GROUP BY port ORDER BY c DESC LIMIT ?""",
            params + [args.top],
        ).fetchall()
        headers = ["порт", "попыток", "уник. IP", "первый", "последний"]
        rows = [[p, c, u, fmt_ts(f), fmt_ts(l)] for p, c, u, f, l in data]

    elif args.by == "source":
        data = conn.execute(
            f"""SELECT source, COUNT(*) c, COUNT(DISTINCT ip) u, MIN(ts), MAX(ts)
               FROM hits WHERE {where} GROUP BY source ORDER BY c DESC""",
            params,
        ).fetchall()
        headers = ["источник", "записей", "уник. IP", "первый", "последний"]
        rows = [[s, c, u, fmt_ts(f), fmt_ts(l)] for s, c, u, f, l in data]

    if args.json:
        payload = [dict(zip(headers, row)) for row in rows]
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    elif args.csv:
        writer = csv.writer(sys.stdout)
        writer.writerow(headers)
        writer.writerows(rows)
    else:
        print(f"Период: последние {args.hours} ч, с {fmt_ts(since)}")
        print_table(headers, rows)
    conn.close()


# --------------------------------------------------------------------------
# export
# --------------------------------------------------------------------------

def cmd_export(args):
    conn = db_connect(args.db)
    since = now_ts() - args.hours * 3600
    exclude = exclude_set(args)
    filter_external = not getattr(args, "include_local", False)
    where, params = where_since(since, exclude)
    data = conn.execute(
        f"""SELECT ip, COUNT(*) c FROM hits WHERE {where}
            GROUP BY ip HAVING c >= ? ORDER BY c DESC""",
        params + [args.min_count],
    ).fetchall()
    conn.close()

    v4, v6 = [], []
    for ip, _cnt in data:
        if filter_external and not is_external_ip(ip, exclude):
            continue
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        (v4 if addr.version == 4 else v6).append(str(addr))

    out = []
    if args.format == "txt":
        out = v4 + v6
    elif args.format == "ipset":
        out.append("# conn-audit ipset")
        out.append("create conn_audit_v4 hash:net family inet -exist")
        out.append("create conn_audit_v6 hash:net family inet6 -exist")
        for ip in v4:
            out.append(f"add conn_audit_v4 {ip}")
        for ip in v6:
            out.append(f"add conn_audit_v6 {ip}")
    elif args.format == "nft":
        out.append("# conn-audit nftables set")
        out.append("table inet conn_audit {")
        if v4:
            out.append("  set offenders_v4 {")
            out.append("    type ipv4_addr")
            out.append("    flags interval")
            out.append("    elements = {")
            for chunk in [v4[i:i + 6] for i in range(0, len(v4), 6)]:
                out.append("      " + ", ".join(chunk) + ",")
            out.append("    }")
            out.append("  }")
        if v6:
            out.append("  set offenders_v6 {")
            out.append("    type ipv6_addr")
            out.append("    flags interval")
            out.append("    elements = {")
            for chunk in [v6[i:i + 4] for i in range(0, len(v6), 4)]:
                out.append("      " + ", ".join(chunk) + ",")
            out.append("    }")
            out.append("  }")
        out.append("")
        out.append("  chain input {")
        out.append("    type filter hook input priority -10; policy accept;")
        if v4:
            out.append("    ip saddr @offenders_v4 counter drop")
        if v6:
            out.append("    ip6 saddr @offenders_v6 counter drop")
        out.append("  }")
        out.append("}")
    else:
        print(f"Неизвестный формат: {args.format}", file=sys.stderr)
        return 1

    text = "\n".join(out) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"Записано {len(v4) + len(v6)} IP в {args.output}")
    else:
        sys.stdout.write(text)
    return 0


# --------------------------------------------------------------------------
# doctor / prune / selftest / install
# --------------------------------------------------------------------------

def cmd_doctor(args):
    print(f"conn-audit {VERSION}")
    print(f"root: {'да' if os.geteuid() == 0 else 'НЕТ (нужен root)'}")
    print(f"db:   {args.db}")
    print("\nКоманды:")
    for cmd in ("journalctl", "nft", "iptables", "ip6tables", "conntrack", "tcpdump", "ss"):
        print(f"  {cmd:12s} {shutil.which(cmd) or '—'}")
    print("\nЛоги:")
    for path in (
        "/var/log/kern.log", "/var/log/messages", "/var/log/syslog",
        "/var/log/auth.log", "/var/log/secure",
        "/var/log/xray/access.log", "/usr/local/x-ui/bin/access.log",
        "/var/log/nginx/access.log", "/var/log/fail2ban.log",
    ):
        print(f"  {path:36s} {'есть' if os.path.exists(path) else '—'}")
    print("\nFirewall-логирование:")
    logged = 0
    if shutil.which("nft"):
        try:
            out = subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True, timeout=15)
            logged = sum(1 for l in out.stdout.splitlines() if re.search(r"\blog\b", l))
        except (OSError, subprocess.SubprocessError):
            pass
    if shutil.which("iptables"):
        try:
            out = subprocess.run(["iptables", "-S"], capture_output=True, text=True, timeout=15)
            logged += sum(1 for l in out.stdout.splitlines() if "-j LOG" in l)
        except (OSError, subprocess.SubprocessError):
            pass
    print(f"  правил с log: {logged}")
    if logged == 0:
        print("  ! Логирования нет: историю за сутки взять неоткуда.")
        print("    Запускай live или добавь nftables log-правило с limit.")
    if shutil.which("conntrack"):
        try:
            out = subprocess.run(["conntrack", "-C"], capture_output=True, text=True, timeout=10)
            print(f"  conntrack записей: {out.stdout.strip()}")
        except (OSError, subprocess.SubprocessError):
            pass
    if os.path.exists(args.db):
        conn = db_connect(args.db)
        for row in conn.execute("SELECT source, COUNT(*) FROM hits GROUP BY source"):
            print(f"  db {row[0]}: {row[1]}")
        conn.close()
    else:
        print("  db ещё нет — будет создана при collect/live.")


def cmd_prune(args):
    conn = db_connect(args.db)
    cutoff = now_ts() - args.days * 86400
    n1 = conn.execute("DELETE FROM hits WHERE ts < ?", (cutoff,)).rowcount
    n2 = conn.execute("DELETE FROM seen WHERE ts < ?", (cutoff,)).rowcount
    n3 = conn.execute("DELETE FROM ip_cache WHERE ts < ?", (now_ts() - 90 * 86400,)).rowcount
    conn.commit()
    conn.execute("VACUUM")
    conn.close()
    print(f"Удалено: hits={n1}, seen={n2}, ip_cache={n3}")


def cmd_selftest(args):
    samples = [
        ("kernel", parse_kernel_line,
         "Nov 11 23:00:00 host kernel: IN=eth0 OUT= MAC=aa:bb SRC=1.2.3.4 DST=5.6.7.8 LEN=60 PROTO=TCP SPT=12345 DPT=443 SYN"),
        ("kernel-nft", parse_kernel_line,
         "Nov 11 23:00:00 host kernel: IN=eth0 OUT= SRC=9.9.9.9 DST=5.6.7.8 L4PROTO=TCP SPORT=12345 DPORT=443"),
        ("xray", parse_xray_line,
         "2026/11/11 23:00:00 from 1.2.3.4:12345 accepted tcp:example.com:443 [vless-in >> direct]"),
        ("xray-nofrom", parse_xray_line,
         "2026/11/11 23:00:00 9.9.9.9:12345 accepted tcp:example.com:443 [vless-in >> direct]"),
        ("ssh", parse_ssh_line,
         "Nov 11 23:00:00 host sshd[1]: Failed password for root from 1.2.3.4 port 2222 ssh2"),
        ("nginx", parse_nginx_line,
         '1.2.3.4 - - [11/Nov/2026:23:00:00 +0300] "GET / HTTP/1.1" 404 0 "-" "curl/8"'),
        ("fail2ban", parse_fail2ban_line,
         "2026-11-11 23:00:00,000 fail2ban.actions [1]: NOTICE [sshd] Ban 1.2.3.4"),
        ("conntrack", parse_conntrack_line,
         "tcp 6 431999 ESTABLISHED src=1.2.3.4 dst=5.6.7.8 sport=12345 dport=443 [ASSURED]"),
        ("tcpdump", parse_tcpdump_line,
         "23:00:00.123456 IP 1.2.3.4.12345 > 5.6.7.8.443: Flags [S], seq 1, win 64240"),
        ("tcpdump-v6", parse_tcpdump_line,
         "23:00:00.123456 IP6 2001:db8::1.12345 > 2001:db8::2.443: Flags [S], seq 1"),
    ]
    with tempfile.TemporaryDirectory() as td:
        db = os.path.join(td, "test.db")
        conn = db_connect(db)
        for name, parser, line in samples:
            rec = parser(line)
            assert rec, f"{name}: parser вернул None"
            assert is_ip(rec["ip"]), f"{name}: плохой IP {rec['ip']}"
            assert add_hit(conn, rec["ts"], rec["ip"], rec.get("port"), rec.get("proto"),
                           rec["source"], rec.get("detail", "")), f"{name}: add_hit"
        conn.commit()
        n = conn.execute("SELECT COUNT(*) FROM hits").fetchone()[0]
        uniq = conn.execute("SELECT COUNT(DISTINCT ip) FROM hits").fetchone()[0]
        assert n == len(samples), f"hits={n}, ожидалось {len(samples)}"
        assert uniq == 3, f"uniq={uniq}"
        conn.close()

        # Регрессия на live-режим: два потока пишут каждый в своё соединение.
        def worker(num):
            c = db_connect(db, autocommit=True)
            for i in range(10):
                add_hit(c, now_ts(), f"10.0.0.{num}", 443, "tcp", "selftest", dedupe=False)
            c.close()

        threads = [threading.Thread(target=worker, args=(i,)) for i in (1, 2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        c = db_connect(db)
        total = c.execute("SELECT COUNT(*) FROM hits").fetchone()[0]
        c.close()
        assert total == len(samples) + 20, f"thread test: hits={total}"
    print(f"selftest OK: {len(samples)} парсеров, {n} записей, 2 потока x 10.")


INSTALL_UNITS = r"""
# /etc/systemd/system/conn-audit-live.service
[Unit]
Description=conn-audit live collector
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/sbin/conn_audit.py live --duration 0 --db /var/lib/conn-audit/conn_audit.db
Restart=always
RestartSec=10
Nice=10

[Install]
WantedBy=multi-user.target

# /etc/systemd/system/conn-audit-collect.service
[Unit]
Description=conn-audit log collector
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/conn_audit.py collect --hours 24 --db /var/lib/conn-audit/conn_audit.db

# /etc/systemd/system/conn-audit-collect.timer
[Unit]
Description=Daily conn-audit log collection

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=30m

[Install]
WantedBy=timers.target

# включить:
#   install -m 0755 conn_audit.py /usr/local/sbin/conn_audit.py
#   systemctl daemon-reload
#   systemctl enable --now conn-audit-live.service
#   systemctl enable --now conn-audit-collect.timer
"""


def cmd_install(args):
    print(INSTALL_UNITS)


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        description="Сбор IP, которые пытались подключиться к серверу.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--version", action="version", version=f"conn-audit {VERSION}")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("collect", help="разобрать существующие логи за N часов")
    c.add_argument("--db", default=DB_DEFAULT)
    c.add_argument("--hours", type=int, default=24)
    c.add_argument("--source", action="append", choices=[
        "kernel", "xray", "ssh", "nginx", "fail2ban", "conntrack"])
    c.add_argument("--kernel-log", action="append", help="доп. путь к kernel/syslog")
    c.add_argument("--xray-log", action="append", help="доп. путь к access.log Xray")
    c.add_argument("--auth-log", action="append", help="доп. путь к auth.log/secure")
    c.add_argument("--nginx-log", action="append", help="доп. путь к nginx access.log")
    c.add_argument("--fail2ban-log", action="append", help="доп. путь к fail2ban.log")
    c.add_argument("--quiet", action="store_true")
    c.set_defaults(func=cmd_collect)

    l = sub.add_parser("live", help="слушать новые попытки (conntrack + tcpdump)")
    l.add_argument("--db", default=DB_DEFAULT)
    l.add_argument("--duration", type=int, default=3600,
                   help="секунды; 0 = бесконечно (по умолчанию 3600)")
    l.add_argument("--iface", default="any")
    l.add_argument("--no-conntrack", action="store_true")
    l.add_argument("--no-tcpdump", action="store_true")
    l.add_argument("--quiet", action="store_true")
    l.set_defaults(func=cmd_live)

    r = sub.add_parser("report", help="отчёт по базе")
    r.add_argument("--db", default=DB_DEFAULT)
    r.add_argument("--hours", type=int, default=24)
    r.add_argument("--top", type=int, default=50)
    r.add_argument("--min-count", type=int, default=1)
    r.add_argument("--by", choices=["ip", "subnet", "port", "source"], default="ip")
    r.add_argument("--csv", action="store_true")
    r.add_argument("--json", action="store_true")
    r.add_argument("--enrich", action="store_true", help="ASN/org/country через ipinfo.io")
    r.add_argument("--include-local", action="store_true",
                   help="не фильтровать свои/локальные IP (по умолчанию отфильтрованы)")
    r.add_argument("--exclude", action="append", metavar="IP",
                   help="дополнительно исключить IP (можно несколько раз)")
    r.set_defaults(func=cmd_report)

    e = sub.add_parser("export", help="выгрузить в nft/ipset/txt")
    e.add_argument("--db", default=DB_DEFAULT)
    e.add_argument("--hours", type=int, default=24)
    e.add_argument("--min-count", type=int, default=1)
    e.add_argument("--format", choices=["nft", "ipset", "txt"], default="nft")
    e.add_argument("--output")
    e.add_argument("--include-local", action="store_true",
                   help="не фильтровать свои/локальные IP (по умолчанию отфильтрованы)")
    e.add_argument("--exclude", action="append", metavar="IP",
                   help="дополнительно исключить IP (можно несколько раз)")
    e.set_defaults(func=cmd_export)

    d = sub.add_parser("doctor", help="что доступно на сервере")
    d.add_argument("--db", default=DB_DEFAULT)
    d.set_defaults(func=cmd_doctor)

    pr = sub.add_parser("prune", help="почистить старые записи")
    pr.add_argument("--db", default=DB_DEFAULT)
    pr.add_argument("--days", type=int, default=30)
    pr.set_defaults(func=cmd_prune)

    st = sub.add_parser("selftest", help="проверить парсеры")
    st.set_defaults(func=cmd_selftest)

    ins = sub.add_parser("install", help="напечатать systemd-юниты")
    ins.set_defaults(func=cmd_install)

    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args) or 0
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
