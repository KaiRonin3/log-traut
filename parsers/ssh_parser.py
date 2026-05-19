import re
from typing import Optional, Dict, Any
from .base import BaseParser
import time

class SSHParser(BaseParser):
    def __init__(self):
        super().__init__("ssh")
        self.pid_pattern = re.compile(r'\[(\d+)\]')
        self.ip_pattern = re.compile(r'Failed password.*from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+port\s+(?P<port>\d+)')
        self.user_pattern = re.compile(r"user\s*=\s*'(?P<user>[^']+)'")
        self.success_pattern = re.compile(r'Accepted\s+(?:password|publickey)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)')
        self.dt_pattern = re.compile(r"\A([a-zA-Z]{3})\s*(\d{1,2})\s*(\d{2}:\d{2}:\d{2})")
        self._pending = {}
    
    def parse(self, line: str) -> Optional[Dict[str, Any]]:
        # Try failed password first
        if "Failed password" in line:
            return self._handle_failure(line)
        
        # Try successful login
        success_match = self.success_pattern.search(line)
        if success_match:
            return self._create_event(line, "ssh_success", success_match.groupdict())
        
        # Try user correlation for PAM lines
        user_match = self.user_pattern.search(line)
        if user_match:
            pid_match = self.pid_pattern.search(line)
            if pid_match:
                self._pending[pid_match.group(1)] = {
                    'user': user_match.group('user'),
                    'time': time.time()
                }
        
        return None
    
    def _handle_failure(self, line: str) -> Dict[str, Any]:
        # Your existing failure handling logic
        pid_match = self.pid_pattern.search(line)
        ip_match = self.ip_pattern.search(line)
        
        if not ip_match:
            return None
            
        data = ip_match.groupdict()
        pid = pid_match.group(1) if pid_match else "unknown"
        pending_data = self._pending.get(pid, {})
        
        dt_match = self.dt_pattern.search(line)
        timestamp = self._format_timestamp(dt_match) if dt_match else self.extract_timestamp(line)
        
        event = {
            "timestamp": timestamp,
            "source": self.source_name,
            "raw": line.strip(),
            "parsed": {
                "ip": data["ip"],
                "port": data["port"],
                "user": pending_data.get("user", "unknown"),
                "pid": pid
            },
            "event_type": "ssh_failure",
            "severity": None,
            "rule_id": None
        }
        
        if pid in self._pending:
            del self._pending[pid]
        
        return event
    
    def _create_event(self, line: str, event_type: str, data: dict) -> Dict[str, Any]:
        """Generic event creator."""
        dt_match = self.dt_pattern.search(line)
        timestamp = self._format_timestamp(dt_match) if dt_match else self.extract_timestamp(line)
        
        return {
            "timestamp": timestamp,
            "source": self.source_name,
            "raw": line.strip(),
            "parsed": data,
            "event_type": event_type,
            "severity": None,
            "rule_id": None
        }
    
    def _format_timestamp(self, dt_match) -> str:
        # Your existing timestamp formatting
        from datetime import datetime
        month_str, day, time_str = dt_match.groups()
        months = {
            'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
            'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
        }
        month = months.get(month_str, 1)
        year = datetime.now().year
        dt_str = f"{year}-{month:02d}-{int(day):02d} {time_str}"
        return datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S").isoformat()