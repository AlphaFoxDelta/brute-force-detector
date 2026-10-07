#!/usr/bin/env python3
"""
Makes a fake auth.log for the detector demo.

Benign traffic, one loud brute-force (should alert), one slow scan
(shouldn't). Seeded, so it's the same every run.

Usage:  python3 generate_sample_log.py [--out sample_auth.log] [--seed 42]
"""

import argparse
import random
from datetime import datetime, timedelta

HOST = "webserver"

BENIGN_USERS = ["art", "deploy", "backup", "monitor"]
BENIGN_IPS = ["10.0.1.15", "10.0.1.22", "192.168.50.7"]

ATTACK1_IP = "45.148.10.88"    # loud attack — should alert
ATTACK1_USERS = ["root", "admin", "test", "ubuntu", "oracle", "guest"]
ATTACK2_IP = "185.220.101.4"  # low-and-slow — should stay quiet


def ts(dt):
    # "Oct  7 ..." — double space before single-digit days. %d chokes on it.
    return dt.strftime("%b %e %H:%M:%S")


def emit(lines, dt, msg):
    lines.append(f"{ts(dt)} {HOST} {msg}")


def main():
    ap = argparse.ArgumentParser(description="Generate a demo auth.log.")
    ap.add_argument("--out", default="sample_auth.log")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    lines = []
    start = datetime(2026, 10, 7, 8, 0, 0)
    pid = 1000

    def next_pid():
        nonlocal pid
        pid += rng.randint(1, 7)
        return pid

    # ---- benign background traffic over ~3 hours ----
    dt = start
    while dt < start + timedelta(hours=3):
        dt += timedelta(seconds=rng.randint(120, 600))
        user = rng.choice(BENIGN_USERS)
        ip = rng.choice(BENIGN_IPS)
        p = next_pid()
        emit(lines, dt, f"sshd[{p}]: Accepted publickey for {user} from {ip} "
                        f"port {rng.randint(40000, 60000)} ssh2: RSA SHA256:abc123")
        emit(lines, dt + timedelta(seconds=1),
             f"sshd[{p}]: pam_unix(sshd:session): session opened for user {user} by (uid=0)")
        # stray failures from typos. benign.
        if rng.random() < 0.25:
            dt2 = dt + timedelta(seconds=rng.randint(5, 40))
            emit(lines, dt2, f"sshd[{next_pid()}]: Failed password for {user} from {ip} "
                             f"port {rng.randint(40000, 60000)} ssh2")
        # cron noise
        if rng.random() < 0.3:
            dt3 = dt + timedelta(seconds=rng.randint(60, 180))
            emit(lines, dt3, f"CRON[{next_pid()}]: pam_unix(cron:session): session opened "
                             f"for user root by (uid=0)")

    # ---- attack #1: aggressive brute force, 48 attempts in ~8 minutes ----
    atk_start = start + timedelta(hours=1, minutes=12)
    for i in range(48):
        dt = atk_start + timedelta(seconds=i * 10 + rng.randint(0, 4))
        user = rng.choice(ATTACK1_USERS)
        invalid = "invalid user " if user not in ("root", "admin") else ""
        emit(lines, dt, f"sshd[{next_pid()}]: Failed password for {invalid}{user} "
                        f"from {ATTACK1_IP} port {rng.randint(30000, 50000)} ssh2")
        # real sshd spams disconnect lines mid-attack
        if i % 12 == 0:
            emit(lines, dt, f"sshd[{next_pid()}]: Disconnected from authenticating user "
                            f"root {ATTACK1_IP} port {rng.randint(30000, 50000)} [preauth]")

    # ---- attack #2: low-and-slow, 6 attempts spread over 2 hours (below threshold) ----
    slow_start = start + timedelta(minutes=30)
    for i in range(6):
        dt = slow_start + timedelta(minutes=i * 22 + rng.randint(0, 5))
        emit(lines, dt, f"sshd[{next_pid()}]: Failed password for invalid user "
                        f"scanner from {ATTACK2_IP} port {rng.randint(30000, 50000)} ssh2")

    # attacks were interleaved into the timeline — sort by time
    def line_ts(line):
        return datetime.strptime(" ".join(line[:15].split()), "%b %d %H:%M:%S").replace(year=2026)

    lines.sort(key=line_ts)

    with open(args.out, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"Wrote {len(lines)} lines to {args.out}")


if __name__ == "__main__":
    main()
