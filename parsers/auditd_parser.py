# parsers/auditd_parser.py
import re
from typing import Optional, Dict, Any
from .base import BaseParser

class AuditdParser(BaseParser):
    def __init__(self):
        super().__init__("auditd")
        self.audit_ts_pattern = re.compile(r'msg=audit\((\d+)\.\d+:\d+\)')
        self.useradd_pattern = re.compile(r'type=ADD_USER.*acct="(?P<username>\w+)"')
        self.ssh_key_pattern = re.compile(r'type=PATH.*name="authorized_keys"')
    
    def parse(self, line: str) -> Optional[Dict[str, Any]]:
        # Sudo command execution
        if 'type=USER_CMD' in line and '/usr/bin/sudo' in line:
            user_match = re.search(r'user=(?P<user>\w+)', line)
            cmd_match = re.search(r'cmd="(?P<cmd>[^"]*)"', line)
            
            if user_match and cmd_match:
                return self._create_event(line, "sudo_attempt", {
                    "user": user_match.group("user"),
                    "cmd": cmd_match.group("cmd")
                })
        
        # User added to system
        match = self.useradd_pattern.search(line)
        if match:
            return self._create_event(line, "user_added", match.groupdict())
        
        # SSH authorized_keys modified (persistence)
        if self.ssh_key_pattern.search(line):
            return self._create_event(line, "ssh_key_modified", {})
        
        return None
    
    def _create_event(self, line: str, event_type: str, data: dict) -> Dict[str, Any]:
        from datetime import datetime
        ts_match = self.audit_ts_pattern.search(line)
        if ts_match:
            timestamp = datetime.utcfromtimestamp(int(ts_match.group(1))).isoformat()
        else:
            timestamp = datetime.now().isoformat()
        return {
            "timestamp": timestamp,
            "source": self.source_name,
            "raw": line.strip(),
            "parsed": data,
            "event_type": event_type,
            "severity": None,
            "rule_id": None
        }