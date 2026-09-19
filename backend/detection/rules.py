from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List, Tuple
import uuid
from datetime import datetime, timezone, timedelta
from models.event import Event
from models.investigation import Severity
from core.taxonomy import taxonomy_normalizer, CanonicalEventType
from detection.state import detection_state

def _event_time(event: Event) -> datetime:
    moment = event.timestamp
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=timezone.utc)


def _observation_id(event: Event) -> str:
    """
    Distinct identity for one observation. Events are normally persisted before detection
    runs, but an event that has not been written yet has no id; falling back to the row id
    alone would make every such observation the same member and stop the counter advancing.
    """
    return str(event.id) if getattr(event, "id", None) else f"transient:{uuid.uuid4()}"


class BaseDetectionRule(ABC):
    def __init__(self):
        self.name = self.__class__.__name__

    @abstractmethod
    async def match(self, event: Event) -> bool:
        """Rules are async because stateful windows live in shared storage (Redis)."""

    @abstractmethod
    def explain(self, event: Event) -> Dict[str, Any]:
        """Returns evidence payload if matched: description, severity, mitre_technique_id, mitre_technique_name, mitre_tactic"""
        pass

class FailedLoginBruteForce(BaseDetectionRule):
    """Failed-login burst for one user. The window is shared across processes."""

    def __init__(self):
        super().__init__()
        self.threshold = 2
        self.window = timedelta(minutes=5)

    async def match(self, event: Event) -> bool:
        c_type = taxonomy_normalizer.normalize(event.event_type, event.raw_log)
        if c_type == CanonicalEventType.AUTH_FAILURE or event.event_type.lower() in ['login failed', 'authentication failed', 'authentication failure', 'logon failure', 'auth_failure']:
            user = event.user_name or "unknown"
            count = await detection_state.observe(
                self.name, user, member=_observation_id(event), moment=_event_time(event),
                window_seconds=self.window.total_seconds(),
            )
            if count >= self.threshold:
                # Reset to prevent continuous triggers
                await detection_state.reset(self.name, user)
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
    async def match(self, event: Event) -> bool:
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
    async def match(self, event: Event) -> bool:
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
    """One user reaching several hosts inside a window. The window is shared across processes."""

    def __init__(self):
        super().__init__()
        self.host_threshold = 2  # fires when a user exceeds this many distinct hosts
        self.window = timedelta(minutes=10)

    async def match(self, event: Event) -> bool:
        c_type = taxonomy_normalizer.normalize(event.event_type, event.raw_log)
        evt_type = event.event_type.lower()
        if c_type in (CanonicalEventType.REMOTE_SESSION, CanonicalEventType.USER_LOGON) or any(k in evt_type for k in ('login', 'session', 'remote')):
            user = event.user_name
            host = event.hostname
            if user and host and user != "unknown" and host != "unknown":
                distinct_hosts = await detection_state.distinct_values(
                    self.name, user, value=host, moment=_event_time(event),
                    window_seconds=self.window.total_seconds(),
                )
                if distinct_hosts > self.host_threshold:
                    await detection_state.reset(self.name, user)
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
