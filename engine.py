import re
from dataclasses import dataclass
from typing import List, Dict, Optional, Any
import yaml
from collections import defaultdict
import time
from correlation_engine import CorrelationEngine, AttackStage

@dataclass
class Rule:
    id: str
    name: str
    source: str
    pattern: re.Pattern
    extract_fields: List[str]
    threshold_count: int
    threshold_window: int
    severity: str
    alert_channels: List[str]
    message_template: str
    deduplicate_by: Optional[str]

class RuleEngine:
    def __init__(self, rules_path: str = "rules.yaml"):
        self.rules = self._load_rules(rules_path)
        self.event_counts = defaultdict(list)  
        self.last_alert = {}
        self.correlator = CorrelationEngine()
          
    def _load_rules(self, path: str) -> List[Rule]:
        with open(path) as f:
            config = yaml.safe_load(f)
        
        rules = []
        for r in config.get("rules", []):
            if not r.get("enabled", True):
                continue
            
            match = r.get("match", {})
            rules.append(Rule(
                id=r["id"],
                name=r["name"],
                source=r["source"],
                pattern=re.compile(match.get("pattern", "")),
                extract_fields=match.get("extract_fields", []),
                threshold_count=r["threshold"]["count"],
                threshold_window=r["threshold"]["window"],
                severity=r["severity"],
                alert_channels=r["alert"]["channels"],
                message_template=r["alert"]["message_template"],
                deduplicate_by=r["alert"].get("deduplicate_by")
            ))
        return rules
    
    def _get_key(self, event: Dict, rule: Rule) -> str:
        if rule.deduplicate_by:
            val = event['parsed'].get(rule.deduplicate_by, 'unknown')
            return f"{rule.id}:{val}"
        return rule.id

    def _check_threshold(self, event: Dict, rule: Rule) -> bool:
        now = time.time()
        key = self._get_key(event, rule)
        
        window_start = now - rule.threshold_window
        self.event_counts[key] = [t for t in self.event_counts[key] if t > window_start]
        self.event_counts[key].append(now)
        
        if len(self.event_counts[key]) >= rule.threshold_count:
            cooldown = 600
            if key not in self.last_alert or (now - self.last_alert[key]) > cooldown:
                self.last_alert[key] = now
                return True
        return False

    def check_event(self, event: Dict[str, Any]) -> Optional[Dict]:
        source = event.get("source")
        
        for rule in self.rules:
            if rule.source != source:
                continue
            
            match = rule.pattern.search(event.get("raw", ""))
            if not match:
                continue
            
            extracted = match.groupdict()
            event["parsed"].update(extracted)

            stage = self._classify_stage(event, rule)
            
            if self._check_threshold(event, rule):
                key = self._get_key(event, rule)
                event['trigger_count'] = len(self.event_counts[key])
                rule_alert = self._create_alert(event, rule)

                chain_alert = self.correlator.process_event(event, stage)

                if chain_alert:
                    return{
                        "type": "correlated_threat",
                        "rule alert": rule_alert,
                        "chain_alert": chain_alert,
                        "active threats": self.correlator.get_active_threats()
                    }

                return rule_alert
        
        return None  
    
    def _create_alert(self, event: Dict, rule: Rule) -> Dict:
        template_vars = {
            "ip": event["parsed"].get("ip", "unknown"),
            "cmd": event["parsed"].get("cmd", "unknown"),
            "user": event["parsed"].get("user", "unknown"),
            "port": event["parsed"].get("port", "unknown"),
            "pid": event["parsed"].get("pid", "unknown"),
            "count": event.get('trigger_count', 0),
            "process": event["parsed"].get("process", "unknown"),
            "window": rule.threshold_window
        }
        
        message = rule.message_template.format(**template_vars)
        
        return {
            "timestamp": event["timestamp"],
            "rule_id": rule.id,
            "rule_name": rule.name,
            "severity": rule.severity,
            "source": event["source"],
            "message": message,
            "channels": rule.alert_channels,
            "raw_event": event["raw"]
        }

    def _classify_stage(self, event: Dict, rule: Rule) -> str:
        stage_map = {
            "ssh_brute_force": AttackStage.RECON,
            "ssh_success": AttackStage.INITIAL_ACCESS,
            "sudo_attempt": AttackStage.PRIVILEGE_ESCALATION,
            "user_added": AttackStage.PERSISTENCE,
            "ssh_key_modified": AttackStage.PERSISTENCE,
        }
        return stage_map.get(rule.id, "unknown")