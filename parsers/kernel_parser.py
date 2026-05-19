import re
from typing import Optional, Dict, Any
from .base import BaseParser

class KernelParser(BaseParser):
    def __init__(self):
        super().__init__("kernel")
        self.oom_pattern = re.compile(
            r'Out of memory: Kill process (?P<pid>\d+) \((?P<process>[^)]+)\)'
        )
        self.panic_pattern = re.compile(r'Kernel panic')
        self.dt_pattern = re.compile(r"\A([a-zA-Z]{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})")
    
    def parse(self, line: str) -> Optional[Dict[str, Any]]:
        # OOM kill
        oom_match = self.oom_pattern.search(line)
        if oom_match:
            return self._create_event(line, "oom_kill", oom_match.groupdict())
        
        if self.panic_pattern.search(line):
            return self._create_event(line, "kernel_panic", {})
        
        return None
    
    def _create_event(self, line: str, event_type: str, data: dict) -> Dict[str, Any]:
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
        from datetime import datetime
        month_str, day_str, time_str = dt_match.groups()
        months = {
            'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
            'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
        }
        month = months.get(month_str, 1)
        year = datetime.now().year
        dt_str = f"{year}-{month:02d}-{int(day_str):02d} {time_str}"
        return datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S").isoformat()