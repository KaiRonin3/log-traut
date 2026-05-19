import yaml
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Optional
import re

@dataclass
class Rule:
    id: str
    name: str
    enabled: bool
    source: str
    severity: str
    pattern: re.Pattern
    extract_fields: List[str]
    threshold_count: int
    threshold_window: int
    alert_channels: List[str]
    message_template: str
    deduplicate_by: Optional[str]

def load_rules(path: str = "rules.yaml") -> List[Rule]:
    with open(path) as f:
        config = yaml.safe_load(f)
    
    rules = []
    for r in config["rules"]:
        if not r.get("enabled", True):
            continue
            
        pattern = re.compile(r["match"]["pattern"])
        
        rules.append(Rule(
            id=r["id"],
            name=r["name"],
            enabled=r["enabled"],
            source=r["source"],
            severity=r["severity"],
            pattern=pattern,
            extract_fields=r["match"].get("extract_fields", []),
            threshold_count=r["threshold"]["count"],
            threshold_window=r["threshold"]["window"],
            alert_channels=r["alert"]["channels"],
            message_template=r["alert"]["message_template"],
            deduplicate_by=r["alert"].get("deduplicate_by")
        ))
    
    return rules

def load_global_config(path: str = "rules.yaml") -> Dict:
    with open(path) as f:
        config = yaml.safe_load(f)
    return config.get("global", {})

if __name__ == "__main__":
    global_config = load_global_config()
    rules = load_rules()
    
    print(f"Loaded {len(rules)} rules")
    for rule in rules:
        print(f"  - {rule.id}: {rule.name} (source: {rule.source})")