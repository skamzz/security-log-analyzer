# Security Log Analyzer

A Python tool that parses SSH authentication logs (`auth.log`), flags
suspicious IP addresses, classifies them by risk level, and exports CSV
files for a two-page Power BI dashboard.

## Features

- Extracts IP address, timestamp, and event type from each log line (regex)
- Aggregates activity per IP: attempts, failed logins, first and last seen
- Classifies suspicious IPs by risk level using a configurable threshold
- Builds a daily event summary
- Exports four CSV files ready to load into Power BI
- Includes a two-page Power BI dashboard (overview and per-IP drill-down)

## Key findings (sample log)

- 18,201 authentication-related events and 12,250 failed logins
- 500 IPs reached the attempt threshold: 226 Critical and 124 High
- A single IP (`188.87.35.25`) accounts for more than 2,000 attempts,
  far above any other source

## Detected events

| Event | Log pattern |
|---|---|
| `invalid_user` | `Invalid user` |
| `failed_password` | `Failed password` (lines for invalid users are skipped to avoid double counting) |
| `break_in_attempt` | `POSSIBLE BREAK-IN ATTEMPT` |
| `disconnect` | `Received disconnect` |
| `connection_closed` | `Connection closed by` |

`invalid_user`, `failed_password`, and `break_in_attempt` count as
authentication-related events (attempts). `disconnect` and
`connection_closed` are tracked separately as connection behavior.

> The sample log does not contain `failed_password` events, but the parser
> supports them so the tool works with other `auth.log` files.

## Risk classification

Only IPs with `total_attempts >= threshold` (default: 5) are reported.

| Level | Rule (default threshold = 5) |
|---|---|
| Critical | 10 or more failed logins (`threshold * 2`) |
| High | 5 or more failed logins |
| Medium | At least 1 failed login |
| Low | No failed logins (the threshold was reached through break-in warnings only) |

> `POSSIBLE BREAK-IN ATTEMPT` is an sshd warning triggered when a
> connecting IP has no consistent reverse DNS. It is counted as an attempt
> but is not a confirmed credential attack, so IPs with only these events
> are classified as Low even when their attempt count is high.

The threshold can be changed in `analyzer(log_lines, threshold=5)`.

## Output files

| File | Content |
|---|---|
| `suspicious_ips.csv` | ip, total_attempts, failed_logins, first_seen, last_seen, risk_level, risk_order |
| `daily_events.csv` | date, sort_key, total_events, failed_logins |
| `ip_event_breakdown.csv` | ip, invalid_user, break_in_attempt, disconnect |
| `connection_breakdown.csv` | ip, disconnect, connection_closed |

`risk_order` (1 = Critical to 4 = Low) and `sort_key` (month × 100 + day)
exist so Power BI can sort risk levels and dates correctly.

## Dashboard

The Power BI file has two independent pages. Filters on one page do not
affect the other.

**Page 1: Security Log Analyzer.** *What is happening in the environment?*
Overview of all events in the log file: total events, failed logins,
number of suspicious IPs, events over time, ranking of suspicious IPs
with a Risk Level filter, and a table of suspicious IPs.

**Page 2: IP Details.** *What happened with a specific IP address?*
Investigation view for a single IP: total attempts, failed logins, risk
level, first and last seen, event breakdown, and connection behavior.

Files in `powerbi/`:

- `security-log-analyzer.pbix`: interactive version
- `security-log-analyzer-overview.pdf`: default view, no filters
- `security-log-analyzer-filtered.pdf`: Risk Level = Critical on page 1,
  IP `103.21.218.221` selected on page 2

## Data notes

The dashboard uses two kinds of sources:

| Visual | Source |
|---|---|
| Total Events and Failed Logins cards, Events Over Time | `daily_events.csv` (all IPs) |
| Suspicious IPs card, Top Suspicious IPs, table | `suspicious_ips.csv` (IPs at or above the threshold) |
| IP Details: attempts, risk level, first/last seen | `suspicious_ips.csv` |
| Event Breakdown | `ip_event_breakdown.csv` |
| Connection Breakdown | `connection_breakdown.csv` |

Because of this, some totals differ by design. In the sample log:

- Total events: 18,201 (all IPs) vs 16,204 attempts (suspicious IPs only)
- Failed logins: 12,250 (all IPs) vs 10,485 (suspicious IPs only)
- The gap (about 2,000 events and 1,800 failed logins) comes from IPs
  below the threshold.

Other behavior to keep in mind:

- The Risk Level filter only affects visuals fed by `suspicious_ips.csv`.
  Total Events, Failed Logins, and Events Over Time do not change, because
  the daily summary has no per-IP risk information.
- On the IP Details page with no IP selected, Total Attempts comes from
  `suspicious_ips.csv` while Failed Logins shows the all-IP total from
  `daily_events.csv`. With an IP selected, both come from `suspicious_ips.csv`.
- `failed_logins` is always less than or equal to `total_events`, since
  failed logins are a subset of authentication-related events.
- Top Suspicious IPs ranks by `total_attempts`, while risk level depends
  on `failed_logins`. High-volume IPs with no failed logins therefore
  appear in the ranking as Low.

## Limitations

- Syslog timestamps do not include the year, so `first_seen` and `last_seen`
  are kept as text exactly as they appear in the log.
- `sort_key` assumes the log does not span a year boundary.
- IPv4 only.
- One log file per run.

## How to run

Requirements: Python 3 (standard library only, no extra packages).

1. Place the log file at `auth.log/auth.log` (or edit the path in the
   `__main__` block).
2. Make sure the `results/` folder exists.
3. From the project root, run:

```bash
python log_analyzer.py
```

To explore the dashboard, open the `.pbix` in Power BI Desktop. If prompted,
point the data sources to the CSV files in `results/`.

## Project structure

```
security-log-analyzer/
├── README.md
├── log_analyzer.py
├── auth.log/
│   └── auth.log
├── results/
│   ├── suspicious_ips.csv
│   ├── daily_events.csv
│   ├── ip_event_breakdown.csv
│   └── connection_breakdown.csv
└── powerbi/
    ├── security-log-analyzer.pbix
    ├── security-log-analyzer-overview.pdf
    └── security-log-analyzer-filtered.pdf
```

## Sample data

The sample comes from [Security Repo](https://www.secrepo.com) by
Mike Sconzo, licensed under
[CC BY 4.0](http://creativecommons.org/licenses/by/4.0/).
Source: https://secrepo.com/auth.log/auth.log.gz
The file was downloaded as `.gz` and decompressed to `auth.log`; its
content was not modified.

## Related project

The detection patterns in this tool also inspire an investigation game
I'm currently designing, where players analyze fictional security logs
to solve incidents. One of its cases is based on the same SSH brute
force pattern this analyzer detects.