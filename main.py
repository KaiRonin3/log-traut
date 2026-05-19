# main.py
import subprocess
from parsers import parse_line
from engine import RuleEngine

def main():
    engine = RuleEngine("rules.yaml")

    # Stream from journald — try 'sshd' first, fall back to 'ssh'
    # Run: `systemctl list-units | grep -i ssh` to confirm your unit name
    proc = subprocess.Popen(
        ['journalctl', '-u', 'ssh', '-f', '-n', '0'],
        stdout=subprocess.PIPE,
        text=True
    )

    print("Monitoring logs...")
    for line in proc.stdout:
        event = None  # reset each iteration — prevents stale event leaking into next loop

        # Route to appropriate parser based on log content
        if 'sshd' in line:
            event = parse_line("ssh", line)
        elif 'USER_CMD' in line or ('audit' in line and 'type=' in line):
            event = parse_line("auditd", line)
        elif 'kernel' in line:
            event = parse_line("kernel", line)

        if event:
            result = engine.check_event(event)
            if result:
                if result.get("type") == "correlated_threat":
                    print(f"[CRITICAL] {result['chain_alert']['description']}")
                    print(f"[CRITICAL] Recommendation: {result['chain_alert'].get('recommendation', '')}")
                else:
                    print(f"[ALERT] {result['message']}")

if __name__ == "__main__":
    main()