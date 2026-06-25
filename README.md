# log-traut

A real-time log correlation and alerting engine written in Python. Parses events from multiple system log sources, evaluates them against a configurable rule set, and correlates events across sources to detect multi-stage attack chains.

## What it does

**Multi-source log parsing**

Parses three log sources through a common interface:

| Source | Events detected |
|---|---|
| sshd (journald) | Failed password attempts, successful logins |
| auditd | Privilege escalation via sudo |
| kernel | OOM kill events |

**Rule engine** (`engine.py`)

Rules are defined in `rules.yaml`. Each rule specifies a source, a regex pattern with named capture groups, a sliding-window threshold (e.g. 3 failures in 300s), and alert channels. The engine evaluates every parsed event against all matching rules and fires an alert when the threshold is crossed.

**Attack chain correlation** (`correlation_engine.py`)

Tracks sequences of related events across sources and links them into kill-chain stages:

```
Recon (brute force) → Initial Access (successful login) → Privilege Escalation (sudo)
```

When all three stages are observed from the same source IP within 600 seconds, a critical correlated threat alert fires.

**Anomaly detectors** (`analysis.c`)

| Rule | Trigger | Default threshold |
|---|---|---|
| `ssh_brute_force` | Failed SSH logins from single IP | 3 attempts in 300s |
| `ssh_success` | Successful SSH login | 1 event |
| `sudo_attempt` | sudo execution via auditd | 1 event |
| `kernel_oom` | OOM kill event | 1 event |

All thresholds are configurable in `rules.yaml`.

## Architecture

```
main.py              entry point, journald stream ingestion
engine.py            rule loading, threshold evaluation, alert dispatch
correlation_engine.py  attack chain tracking across sources
rules.yaml           rule definitions and alert configuration
parsers/
  base.py            parser interface
  ssh_parser.py      sshd log parser (IPv4 + IPv6)
  auditd_parser.py   auditd log parser
  kernel_parser.py   kernel log parser
```

Parsers are decoupled from the engine via a common interface - adding a new log source means implementing one class with a `parse(line)` method.

The correlation engine tracks attack stages per attacker IP using a chain model. For auditd events that carry no IP, the engine reverse-resolves the attacker by matching the acting username against known chains from earlier SSH stages.

## Usage

```bash
# Install dependencies
pip install pyyaml

# Run against live journald stream (requires systemd)
sudo python3 main.py

# Run the simulated attack chain test
python3 test.py
```

## Example output

```
=== Simulating Attack Chain ===
Event 3: Apr 03 11:40:10 server sshd[1002]: Failed password for invalid user ubuntu...
   Alert: SSH brute force: 10.0.0.50 failed 3 times in 300s

Event 4: Apr 03 11:41:00 server sshd[1010]: Accepted password for ubuntu...
   Alert: Login: ubuntu from 10.0.0.50

Event 5: type=USER_CMD msg=audit(1775216460.123:10001): user=ubuntu...
 CORRELATED THREAT DETECTED:
   Rapid attack progression from 10.0.0.50: brute force → successful login → privilege escalation in 50s
   Active threats: [{'ip': '10.0.0.50', 'stages': ['recon', 'initial_access', 'privilege_escalation'], 'duration': 50, 'user_targets': ['ubuntu']}]
```

## Notable implementation details

- **IPv6 support** - SSH parser handles both IPv4 and IPv6 addresses (`::1` loopback included), required for modern OpenSSH on Kali/Debian which uses `sshd-session` per-connection processes
- **Timezone-aware timestamps** - auditd epoch timestamps use `utcfromtimestamp` to match sshd's naive UTC output; using local time caused a 5h30m skew on IST systems that silently broke chain correlation
- **IP resolution for auditd events** - auditd lines carry no IP; the correlation engine reverse-looks up the attacker IP by matching the sudo user against target users already recorded in an active chain
- **Sliding window deduplication** - alerts include a cooldown to prevent repeated firing on the same event stream
