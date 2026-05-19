# test_correlation.py
from parsers import parse_line
from engine import RuleEngine

engine = RuleEngine("rules.yaml")

# Simulate attack progression
events = [
    # Stage 1: Recon (brute force)
    ("ssh", "Apr 03 11:40:00 server sshd[1000]: Failed password for invalid user admin from 10.0.0.50 port 12345 ssh2"),
    ("ssh", "Apr 03 11:40:05 server sshd[1001]: Failed password for invalid user root from 10.0.0.50 port 12346 ssh2"),
    ("ssh", "Apr 03 11:40:10 server sshd[1002]: Failed password for invalid user ubuntu from 10.0.0.50 port 12347 ssh2"),
    
    # Stage 2: Initial Access (success after brute force)
    ("ssh", "Apr 03 11:41:00 server sshd[1010]: Accepted password for ubuntu from 10.0.0.50 port 12348 ssh2"),
    
    # Stage 3: Privilege Escalation (sudo attempt)
    ("auditd", 'type=USER_CMD msg=audit(1775216460.123:10001): user=ubuntu terminal=pts/0 cwd="/home/ubuntu" exe="/usr/bin/sudo" cmd="sudo su -"'),
]

print("=== Simulating Attack Chain ===\n")

for i, (source, line) in enumerate(events, 1):
    print(f"Event {i}: {line[:60]}...")
    event = parse_line(source, line)
    
    if event:
        result = engine.check_event(event)
        if result:
            if result.get("type") == "correlated_threat":
                print(f"\n🚨 CORRELATED THREAT DETECTED:")
                print(f"   {result['chain_alert']['description']}")
                print(f"   Active threats: {result['active_threats']}")
            else:
                print(f"   Alert: {result['message']}")

    print("\n=== Final Correlator State ===")
    for threat in engine.correlator.get_active_threats():
        print(f"IP: {threat['ip']}")
        print(f"  Stages: {threat['stages']}")
        print(f"  Users: {threat['user_targets']}")
        print(f"  Duration: {threat['duration']}s")
    print()