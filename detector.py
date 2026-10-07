#!/usr/bin/env python3
"""
SSH brute-force detector. Reads an auth.log, flags IPs hammering sshd with a
sliding-window rule, prints alerts + a summary. Stdlib only.
"""

import argparse
import json
import re
import sys
from collections import Counter, deque
from datetime import datetime, timedelta

# e.g. "Failed password for root from 192.168.1.100 port 51234 ssh2"
# also handles "Failed password for invalid user admin from ..."
_FAILED_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+"
)

# accepted logins, just for the summary counts
_ACCEPTED_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port \d+"
)


def parse_syslog_ts(ts_str, year=None):
    """Parse 'Oct  7 15:23:41' into a datetime. auth.log has no year."""
    dt = datetime.strptime(ts_str, "%b %d %H:%M:%S")
    return dt.replace(year=year or datetime.now().year)


def parse_log(path):
    """Walk the log, split lines into failures / accepted / junk."""
    failures = []
    accepted = []
    stats = {"lines": 0, "unparsed": 0, "min_ts": None, "max_ts": None}

    with open(path, "r", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line:
                continue
            stats["lines"] += 1

            m = _FAILED_RE.match(line)
            if m:
                ts = parse_syslog_ts(m.group("ts"))
                failures.append({"ts": ts, "ip": m.group("ip"), "user": m.group("user")})
                _bump_range(stats, ts)
                continue

            m = _ACCEPTED_RE.match(line)
            if m:
                ts = parse_syslog_ts(m.group("ts"))
                accepted.append({"ts": ts, "ip": m.group("ip"), "user": m.group("user")})
                _bump_range(stats, ts)
                continue

            stats["unparsed"] += 1

    failures.sort(key=lambda e: e["ts"])
    return failures, accepted, stats


def _bump_range(stats, ts):
    if stats["min_ts"] is None or ts < stats["min_ts"]:
        stats["min_ts"] = ts
    if stats["max_ts"] is None or ts > stats["max_ts"]:
        stats["max_ts"] = ts


def detect(failures, threshold, window):
    """Flag IPs with >= threshold failures inside the window."""
    by_ip = {}
    for f in failures:
        by_ip.setdefault(f["ip"], []).append(f)

    alerts = []
    last_alerted = {}  # one alert per ip per window. no spam.

    for ip, events in by_ip.items():
        dq = deque()
        for ev in events:
            dq.append(ev)
            while dq and (ev["ts"] - dq[0]["ts"]) > window:
                dq.popleft()
            if len(dq) >= threshold:
                if ip not in last_alerted or (ev["ts"] - last_alerted[ip]) >= window:
                    users = sorted({e["user"] for e in dq})
                    alerts.append(
                        {
                            "ip": ip,
                            "failures_in_window": len(dq),
                            "window_start": dq[0]["ts"],
                            "window_end": ev["ts"],
                            "targeted_users": users,
                        }
                    )
                    last_alerted[ip] = ev["ts"]

    alerts.sort(key=lambda a: a["window_start"])
    return alerts


def summarize(failures, accepted, stats, alerts, top_n):
    ip_counts = Counter(f["ip"] for f in failures)
    user_counts = Counter(f["user"] for f in failures)
    return {
        "log_time_range": {
            "start": stats["min_ts"],
            "end": stats["max_ts"],
        },
        "lines_processed": stats["lines"],
        "lines_unparsed": stats["unparsed"],
        "failed_logins": len(failures),
        "accepted_logins": len(accepted),
        "unique_source_ips": len(ip_counts),
        "alerts_raised": len(alerts),
        "top_offending_ips": [
            {"ip": ip, "failures": n} for ip, n in ip_counts.most_common(top_n)
        ],
        "top_targeted_usernames": [
            {"user": u, "failures": n} for u, n in user_counts.most_common(top_n)
        ],
    }


def fmt_ts(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else "n/a"


def print_human(alerts, summary):
    print("=" * 70)
    print("SSH BRUTE-FORCE DETECTION REPORT")
    print("=" * 70)

    print(f"\n[+] Log window : {fmt_ts(summary['log_time_range']['start'])} "
          f"-> {fmt_ts(summary['log_time_range']['end'])}")
    print(f"[+] Lines processed : {summary['lines_processed']} "
          f"(unparsed: {summary['lines_unparsed']})")
    print(f"[+] Failed logins   : {summary['failed_logins']} "
          f"from {summary['unique_source_ips']} unique IPs")
    print(f"[+] Accepted logins : {summary['accepted_logins']}")

    print(f"\n[!] ALERTS ({summary['alerts_raised']})")
    print("-" * 70)
    if not alerts:
        print("No brute-force activity detected with current thresholds.")
    for a in alerts:
        print(f"  IP               : {a['ip']}")
        print(f"  Failures         : {a['failures_in_window']} within "
              f"{fmt_ts(a['window_start'])} -> {fmt_ts(a['window_end'])}")
        print(f"  Targeted users   : {', '.join(a['targeted_users'])}")
        print("-" * 70)

    print("\n[TOP] Offending IPs")
    for row in summary["top_offending_ips"]:
        print(f"  {row['ip']:>18}  {row['failures']:>5} failures")

    print("\n[TOP] Targeted usernames")
    for row in summary["top_targeted_usernames"]:
        print(f"  {row['user']:>18}  {row['failures']:>5} failures")
    print()


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Detect SSH brute-force attacks in Linux auth.log files."
    )
    ap.add_argument("logfile", help="Path to auth.log-style log file")
    ap.add_argument("--threshold", type=int, default=10,
                    help="Failures from one IP that trigger an alert (default: 10)")
    ap.add_argument("--window-minutes", type=int, default=10,
                    help="Sliding window in minutes (default: 10)")
    ap.add_argument("--top", type=int, default=5,
                    help="How many top IPs/usernames to show (default: 5)")
    ap.add_argument("--json", action="store_true",
                    help="Emit machine-readable JSON instead of text")
    args = ap.parse_args(argv)

    if args.threshold < 1 or args.window_minutes < 1:
        ap.error("threshold and window-minutes must be >= 1")

    window = timedelta(minutes=args.window_minutes)
    failures, accepted, stats = parse_log(args.logfile)
    alerts = detect(failures, args.threshold, window)
    summary = summarize(failures, accepted, stats, alerts, args.top)

    if args.json:
        out = {
            "alerts": [
                {**a,
                 "window_start": a["window_start"].isoformat(),
                 "window_end": a["window_end"].isoformat()}
                for a in alerts
            ],
            "summary": {
                **summary,
                "log_time_range": {
                    "start": summary["log_time_range"]["start"].isoformat()
                    if summary["log_time_range"]["start"] else None,
                    "end": summary["log_time_range"]["end"].isoformat()
                    if summary["log_time_range"]["end"] else None,
                },
            },
        }
        print(json.dumps(out, indent=2))
    else:
        print_human(alerts, summary)

    # exit 1 on alerts — cron-friendly
    return 1 if alerts else 0


if __name__ == "__main__":
    sys.exit(main())
