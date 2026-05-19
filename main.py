# main.py
import subprocess
from parsers import parse_line
from engine import RuleEngine

def main():
    engine = RuleEngine("rules.yaml")
    
    # Stream from journald
    proc = subprocess.Popen(
    ['journalctl', '-u', 'ssh', '-f', '-n', '0'],  # Use 'ssh' not 'sshd', -n 0 for no history
    stdout=subprocess.PIPE,
    text=True
    )
    
    print("Monitoring logs...")
    for line in proc.stdout:
        # Route to appropriate parser based on log content
        if 'sshd' in line:
            event = parse_line("ssh", line)
        elif 'audit' in line or 'USER_CMD' in line:
            event = parse_line("auditd", line)
        elif 'kernel' in line:
            event = parse_line("kernel", line)
        else:
            continue
        
        if event:
            result = engine.check_event(event)
            if result:
                print(f"[ALERT] {result['message']}")

if __name__ == "__main__":
    main()