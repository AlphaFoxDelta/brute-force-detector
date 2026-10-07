# brute-force-detector

Reads a Linux auth.log, flags SSH brute-force attacks with a sliding-window
rule, and prints an alert + summary report. Python standard library only —
no dependencies.

## Why I built this

I wanted something on the blue-team side of my portfolio. Recon tools are
fun, but a SOC analyst's day-to-day is mostly logs, so I built the kind of
thing I'd actually want running on a box I look after: feed it auth.log,
get told who's hammering SSH.

The interesting part turned out to be defining "brute force" itself. Ten
failures in a minute is obviously an attack. Six failures spread over two
hours? Could be a patient attacker, could be noise. A fixed threshold can't
really tell the difference, and building the demo log forced me to think
about that instead of just counting lines.

## What it does

- Parses `Failed password` lines (both `for <user>` and `for invalid user
  <user>` forms), plus accepted logins for context in the summary
- Sliding window per source IP: alerts when failures hit `--threshold`
  (default 10) within `--window-minutes` (default 10)
- One alert per IP per window — a sustained attack doesn't spam you with
  an alert for every single attempt
- Summary report: log time range, totals, top offending IPs, top targeted
  usernames
- Exit code 1 when alerts fire (so you can hook it into cron), 0 otherwise
- `--json` for piping results into other tools

## Usage

Generate the demo log, then run the detector:

```bash
python3 generate_sample_log.py
python3 detector.py sample_auth.log
```

Sample output (from the generated demo log):

```
======================================================================
SSH BRUTE-FORCE DETECTION REPORT
======================================================================

[+] Log window : 2026-10-07 08:07:27 -> 2026-10-07 11:04:17
[+] Lines processed : 144 (unparsed: 47)
[+] Failed logins   : 65 from 4 unique IPs
[+] Accepted logins : 32

[!] ALERTS (1)
----------------------------------------------------------------------
  IP               : 45.148.10.88
  Failures         : 10 within 2026-10-07 09:12:00 -> 2026-10-07 09:13:33
  Targeted users   : admin, guest, oracle, root, test
----------------------------------------------------------------------

[TOP] Offending IPs
        45.148.10.88     48 failures
        192.168.50.7      8 failures
       185.220.101.4      6 failures
           10.0.1.15      3 failures

[TOP] Targeted usernames
                test     11 failures
               guest     11 failures
                root     10 failures
               admin      8 failures
             scanner      6 failures
```

The demo log has three scenarios baked in — check that the detector gets
each one right:

| Scenario | What should happen |
|---|---|
| 48 attempts in ~8 min from `45.148.10.88` | alert fires |
| 6 attempts over 2 h from `185.220.101.4` (low-and-slow) | no alert |
| Occasional stray failures from legit internal IPs | no alert |

More options:

```bash
# tune the sensitivity
python3 detector.py /var/log/auth.log --threshold 5 --window-minutes 5

# machine-readable output
python3 detector.py sample_auth.log --json

# full help
python3 detector.py --help
```

## What tripped me up

auth.log timestamps. They look like `Oct  7 15:23:41` — no year, and a
double space before single-digit days. My first parser used `%d` and blew
up on every line from the first nine days of any month. Dates: never as
simple as they look.

The other thing was alert suppression. My first version fired an alert on
every failed login past the threshold, so one real attack produced 48
alerts. Completely useless. Now it fires once per IP per window and stays
quiet until the window passes.

## What I'd do differently

- This reads a static file. The real version of this tails the live log
  and alerts while the attack is happening.
- It only understands classic syslog. Journald and IPv6 would need
  handling before this touches a modern box.
- Thresholds are hand-tuned. A distributed attack — lots of IPs, a few
  attempts each — sails right under this. Catching that needs baselines,
  not fixed counts, and that's a bigger project.
- Longer term: ship alerts as JSON/CEF to a SIEM, and optionally hand
  offending IPs to fail2ban. I left auto-blocking out on purpose — a bug
  in auto-block code can lock you out of your own server, and I'm not
  signing up for that in a portfolio project.

## A note on using this

Point it at logs you own or have permission to analyze. That's it.
