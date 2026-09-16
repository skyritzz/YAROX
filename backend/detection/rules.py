from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from models.event import Event
from models.investigation import Severity
from core.taxonomy import taxonomy_normalizer, CanonicalEventType

class BaseDetectionRule(ABC):
    def __init__(self):
        self.name = self.__class__.__name__

    @abstractmethod
    def match(self, event: Event) -> bool:
        pass

    @abstractmethod
    def explain(self, event: Event) -> Dict[str, Any]:
        """Returns evidence payload if matched: description, severity, mitre_technique_id, mitre_technique_name, mitre_tactic"""
        pass

class FailedLoginBruteForce(BaseDetectionRule):
    def __init__(self):
        super().__init__()
        # state: username -> list of timestamps
        self.failed_logins = defaultdict(list)
        self.threshold = 2
        self.window = timedelta(minutes=5)

    def match(self, event: Event) -> bool:
        c_type = taxonomy_normalizer.normalize(event.event_type, event.raw_log)
        if c_type == CanonicalEventType.AUTH_FAILURE or event.event_type.lower() in ['login failed', 'authentication failed', 'authentication failure', 'logon failure', 'auth_failure']:
            user = event.user_name or "unknown"
            now = event.timestamp
            if now.tzinfo is None:
                now = now.replace(tzinfo=timezone.utc)
            
            # Clean up old events with timezone awareness
            self.failed_logins[user] = [
                t if t.tzinfo is not None else t.replace(tzinfo=timezone.utc)
                for t in self.failed_logins[user]
            ]
            self.failed_logins[user] = [t for t in self.failed_logins[user] if now - t <= self.window]
            self.failed_logins[user].append(now)
            
            if len(self.failed_logins[user]) >= self.threshold:
                # Reset to prevent continuous triggers
                self.failed_logins[user] = []
                return True
        return False

    def explain(self, event: Event) -> Dict[str, Any]:
        return {
            "description": f"Multiple failed login attempts detected for user {event.user_name}.",
            "severity": Severity.HIGH,
            "mitre_technique_id": "T1110",
            "mitre_technique_name": "Brute Force",
            "mitre_tactic": "Credential Access",
            "evidence_type": "AUTHENTICATION_FAILURE"
        }

class PrivilegeEscalation(BaseDetectionRule):
    def match(self, event: Event) -> bool:
        c_type = taxonomy_normalizer.normalize(event.event_type, event.raw_log)
        evt_type = event.event_type.lower()
        if c_type == CanonicalEventType.PRIVILEGE_CHANGE or 'privilege' in evt_type or 'admin assignment' in evt_type or 'permission change' in evt_type:
            return True
        return False

    def explain(self, event: Event) -> Dict[str, Any]:
        return {
            "description": f"Suspicious privilege escalation or permission change detected on {event.hostname}.",
            "severity": Severity.CRITICAL,
            "mitre_technique_id": "T1068",
            "mitre_technique_name": "Exploitation for Privilege Escalation",
            "mitre_tactic": "Privilege Escalation",
            "evidence_type": "PRIVILEGE_CHANGE"
        }

class SuspiciousProcessExecution(BaseDetectionRule):
    def match(self, event: Event) -> bool:
        c_type = taxonomy_normalizer.normalize(event.event_type, event.raw_log)
        evt_type = event.event_type.lower()
        if c_type == CanonicalEventType.PROCESS_EXECUTION or evt_type in ['process create', 'process execution', 'process creation']:
            raw_dict = event.raw_log if isinstance(event.raw_log, dict) else {}
            metadata = raw_dict.get('metadata', {})
            raw = str(metadata.get('command_line', raw_dict.get('command_line', ''))).lower()
            if 'powershell' in raw or 'cmd.exe' in raw or '-enc' in raw or 'encodedcommand' in raw:
                return True
        return False

    def explain(self, event: Event) -> Dict[str, Any]:
        raw_dict = event.raw_log if isinstance(event.raw_log, dict) else {}
        metadata = raw_dict.get('metadata', {})
        cmdline = metadata.get('command_line') or raw_dict.get('command_line', 'Unknown')
        return {
            "description": f"Suspicious command line execution detected: {cmdline}",
            "severity": Severity.HIGH,
            "mitre_technique_id": "T1059",
            "mitre_technique_name": "Command and Scripting Interpreter",
            "mitre_tactic": "Execution",
            "evidence_type": "PROCESS_EXECUTION"
        }

class LateralMovement(BaseDetectionRule):
    def __init__(self):
        super().__init__()
        # State: user -> set of hosts accessed in a short window
        self.user_hosts = defaultdict(lambda: {"hosts": set(), "last_seen": datetime.now(timezone.utc)})
        self.window = timedelta(minutes=10)

    def match(self, event: Event) -> bool:
        c_type = taxonomy_normalizer.normalize(event.event_type, event.raw_log)
        evt_type = event.event_type.lower()
        if c_type in (CanonicalEventType.REMOTE_SESSION, CanonicalEventType.USER_LOGON) or any(k in evt_type for k in ('login', 'session', 'remote')):
            user = event.user_name
            host = event.hostname
            if user and host and user != "unknown" and host != "unknown":
                now = event.timestamp
                if now.tzinfo is None:
                    now = now.replace(tzinfo=timezone.utc)
                
                last_seen = self.user_hosts[user]["last_seen"]
                if last_seen.tzinfo is None:
                    last_seen = last_seen.replace(tzinfo=timezone.utc)
                
                # Check window
                if now - last_seen > self.window:
                    self.user_hosts[user]["hosts"].clear()
                    
                self.user_hosts[user]["hosts"].add(host)
                self.user_hosts[user]["last_seen"] = now
                
                # Trigger if same user accesses > 2 different hosts in 10 mins
                if len(self.user_hosts[user]["hosts"]) > 2:
                    self.user_hosts[user]["hosts"].clear() # reset
                    return True
        return False

    def explain(self, event: Event) -> Dict[str, Any]:
        return {
            "description": f"Rapid lateral movement detected for user {event.user_name} across multiple hosts.",
            "severity": Severity.CRITICAL,
            "mitre_technique_id": "T1021",
            "mitre_technique_name": "Remote Services",
            "mitre_tactic": "Lateral Movement",
            "evidence_type": "LATERAL_MOVEMENT"
        }
