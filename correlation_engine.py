from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import time

class AttackStage:
    RECON = "recon"
    INITIAL_ACCESS = "initial_access" 
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PERSISTENCE = "persistence"
    EXFILTRATION = "exfiltration"

class AttackChain:
    def __init__(self, attacker_ip: str):
        self.attacker_ip = attacker_ip
        self.stages: List[Dict] = []
        self.first_seen = time.time()
        self.last_seen = time.time()
        self.target_users: set = set()
        self.successful_logins: List[Dict] = []
    
    def add_event(self, stage: str, event: Dict) -> Optional[Dict]:
        self.last_seen = time.time()
        
        stage_entry = {
            "stage": stage,
            "timestamp": event["timestamp"],
            "details": event["parsed"]
        }
        self.stages.append(stage_entry)
        
        if stage == AttackStage.INITIAL_ACCESS:
            self.successful_logins.append(event["parsed"])
            user = event["parsed"].get("user")
            if user:
                self.target_users.add(user)
        
        return self._check_concerning_patterns()
    
    def _check_concerning_patterns(self) -> Optional[Dict]:
        stage_names = [s["stage"] for s in self.stages]
        
        if (AttackStage.RECON in stage_names and 
            AttackStage.INITIAL_ACCESS in stage_names and
            AttackStage.PRIVILEGE_ESCALATION in stage_names):
            
            recon_time = next(s["timestamp"] for s in self.stages if s["stage"] == AttackStage.RECON)
            priv_time = next(s["timestamp"] for s in self.stages if s["stage"] == AttackStage.PRIVILEGE_ESCALATION)
            
            if isinstance(recon_time, str):
                recon_time = datetime.fromisoformat(recon_time).timestamp()
            if isinstance(priv_time, str):
                priv_time = datetime.fromisoformat(priv_time).timestamp()
            
            if priv_time - recon_time < 600: 
                return {
                    "severity": "critical",
                    "alert_type": "attack_chain",
                    "description": f"Rapid attack progression from {self.attacker_ip}: "
                                 f"brute force → successful login → privilege escalation "
                                 f"in {int(priv_time - recon_time)}s",
                    "chain": self.stages,
                    "recommendation": "Isolate host, disable compromised account, audit sudoers"
                }
        
        if len(self.target_users) >= 3:
            return {
                "severity": "high", 
                "alert_type": "lateral_recon",
                "description": f"IP {self.attacker_ip} attempting multiple users: {self.target_users}",
                "chain": self.stages
            }
        
        return None

class CorrelationEngine:
    def __init__(self, max_age: int = 3600):
        self.chains: Dict[str, AttackChain] = {}  
        self.max_age = max_age  
    
    def process_event(self, event: Dict, stage: str) -> Optional[Dict]:
        attacker = (event["parsed"].get("ip") or
                    event["parsed"].get("attacker_ip"))

        # For events without an IP (e.g. auditd sudo), try to resolve the
        # attacker IP by matching the acting user against a known chain.
        if not attacker:
            user = event["parsed"].get("user")
            if user:
                for ip, chain in self.chains.items():
                    if user in chain.target_users:
                        attacker = ip
                        # Inject so downstream code (alert messages etc.) can use it
                        event["parsed"]["attacker_ip"] = ip
                        break
        if not attacker:
            return None
        
        if attacker not in self.chains:
            self.chains[attacker] = AttackChain(attacker)
        
        alert = self.chains[attacker].add_event(stage, event)
        
        self._cleanup()
        
        return alert
    
    def _cleanup(self):
        now = time.time()
        stale = [ip for ip, chain in self.chains.items() 
                 if now - chain.last_seen > self.max_age]
        for ip in stale:
            del self.chains[ip]
    
    def get_active_threats(self) -> List[Dict]:
        return [
            {
                "ip": ip,
                "stages": [s["stage"] for s in chain.stages],
                "duration": int(chain.last_seen - chain.first_seen),
                "user_targets": list(chain.target_users)
            }
            for ip, chain in self.chains.items()
            if len(chain.stages) > 0
        ]