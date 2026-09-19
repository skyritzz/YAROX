import enum
from typing import Dict, Any, Optional

class CanonicalEventType(str, enum.Enum):
    """
    Standard Canonical Event Taxonomy for YAROX.
    Normalizes heterogeneous telemetry sources and SIEM formats into standardized event types
    while preserving raw logs and vendor-specific payloads.
    """
    AUTH_FAILURE = "AUTH_FAILURE"
    AUTH_SUCCESS = "AUTH_SUCCESS"
    USER_LOGON = "USER_LOGON"
    PROCESS_EXECUTION = "PROCESS_EXECUTION"
    PRIVILEGE_CHANGE = "PRIVILEGE_CHANGE"
    REMOTE_SESSION = "REMOTE_SESSION"
    NETWORK_TRAFFIC = "NETWORK_TRAFFIC"
    SERVICE_HEARTBEAT = "SERVICE_HEARTBEAT"
    FILE_OPERATION = "FILE_OPERATION"
    SYSTEM_ALERT = "SYSTEM_ALERT"
    UNKNOWN = "UNKNOWN"

class EventTaxonomyNormalizer:
    """
    Maps raw and vendor-specific event types, descriptions, and Windows Event IDs
    to standard CanonicalEventType values.
    """
    
    # Keyword/phrase mappings (lowercase comparison)
    _TAXONOMY_MAP = {
        # Authentication Failures
        "authentication failure": CanonicalEventType.AUTH_FAILURE,
        "authentication failed": CanonicalEventType.AUTH_FAILURE,
        "login failed": CanonicalEventType.AUTH_FAILURE,
        "logon failure": CanonicalEventType.AUTH_FAILURE,
        "logon failed": CanonicalEventType.AUTH_FAILURE,
        "bad password": CanonicalEventType.AUTH_FAILURE,
        "failed login": CanonicalEventType.AUTH_FAILURE,
        "failed logon": CanonicalEventType.AUTH_FAILURE,
        "auth_failure": CanonicalEventType.AUTH_FAILURE,
        
        # User Logons & Successes
        "user logon": CanonicalEventType.USER_LOGON,
        "user login": CanonicalEventType.USER_LOGON,
        "login success": CanonicalEventType.AUTH_SUCCESS,
        "logon success": CanonicalEventType.AUTH_SUCCESS,
        "authentication success": CanonicalEventType.AUTH_SUCCESS,
        "interactive logon": CanonicalEventType.USER_LOGON,
        
        # Process Execution
        "process creation": CanonicalEventType.PROCESS_EXECUTION,
        "process create": CanonicalEventType.PROCESS_EXECUTION,
        "process execution": CanonicalEventType.PROCESS_EXECUTION,
        "process_create": CanonicalEventType.PROCESS_EXECUTION,
        "process_execution": CanonicalEventType.PROCESS_EXECUTION,
        "command execution": CanonicalEventType.PROCESS_EXECUTION,
        
        # Privilege Escalation & Changes
        "privilege escalation": CanonicalEventType.PRIVILEGE_CHANGE,
        "privilege change": CanonicalEventType.PRIVILEGE_CHANGE,
        "admin assignment": CanonicalEventType.PRIVILEGE_CHANGE,
        "permission change": CanonicalEventType.PRIVILEGE_CHANGE,
        "special privileges assigned": CanonicalEventType.PRIVILEGE_CHANGE,
        "privilege_change": CanonicalEventType.PRIVILEGE_CHANGE,
        
        # Remote Sessions & Lateral Movement
        "remote session": CanonicalEventType.REMOTE_SESSION,
        "remote logon": CanonicalEventType.REMOTE_SESSION,
        "remote interactive logon": CanonicalEventType.REMOTE_SESSION,
        "network logon": CanonicalEventType.REMOTE_SESSION,
        "rdp session": CanonicalEventType.REMOTE_SESSION,
        "ssh session": CanonicalEventType.REMOTE_SESSION,
        
        # Service & Maintenance
        "service heartbeat": CanonicalEventType.SERVICE_HEARTBEAT,
        "scheduled task": CanonicalEventType.SERVICE_HEARTBEAT,
        "maintenance sync": CanonicalEventType.SERVICE_HEARTBEAT,

        # Network / IDS (Suricata EVE connector, Phase 11 connector #2)
        "suricata alert": CanonicalEventType.SYSTEM_ALERT,
        "network flow": CanonicalEventType.NETWORK_TRAFFIC,
    }

    # Windows Event ID mappings
    _EVENT_ID_MAP = {
        4625: CanonicalEventType.AUTH_FAILURE,
        4624: CanonicalEventType.USER_LOGON,
        4688: CanonicalEventType.PROCESS_EXECUTION,
        4672: CanonicalEventType.PRIVILEGE_CHANGE,
        1: CanonicalEventType.PROCESS_EXECUTION, # Sysmon Process Create
        3: CanonicalEventType.NETWORK_TRAFFIC,   # Sysmon Network Connection
        11: CanonicalEventType.FILE_OPERATION,   # Sysmon File Create
    }

    @classmethod
    def normalize(cls, raw_event_type: Optional[str], raw_log: Optional[Dict[str, Any]] = None) -> CanonicalEventType:
        """
        Derives the CanonicalEventType from raw event_type strings and event IDs in raw_log.
        """
        # 1. Check raw_log for explicit EventID / event_id
        if raw_log and isinstance(raw_log, dict):
            event_id = raw_log.get("EventID") or raw_log.get("event_id") or raw_log.get("event_code")
            if event_id:
                try:
                    eid_int = int(event_id)
                    # Special check: EventID 4624 with logon_type 3 is network/remote session
                    if eid_int == 4624:
                        logon_type = raw_log.get("logon_type") or raw_log.get("LogonType")
                        if logon_type in (3, 10, "3", "10"):
                            return CanonicalEventType.REMOTE_SESSION
                    if eid_int in cls._EVENT_ID_MAP:
                        return cls._EVENT_ID_MAP[eid_int]
                except (ValueError, TypeError):
                    pass

        # 2. Check string mapping on event_type
        if raw_event_type and isinstance(raw_event_type, str):
            clean_str = raw_event_type.strip().lower()
            if clean_str in cls._TAXONOMY_MAP:
                return cls._TAXONOMY_MAP[clean_str]
            
            # Partial/keyword heuristics
            if any(k in clean_str for k in ("fail", "invalid", "bad pass", "denied")) and any(k in clean_str for k in ("auth", "login", "logon")):
                return CanonicalEventType.AUTH_FAILURE
            if any(k in clean_str for k in ("process", "command", "exec")) and any(k in clean_str for k in ("create", "start", "spawn", "exec")):
                return CanonicalEventType.PROCESS_EXECUTION
            if any(k in clean_str for k in ("privilege", "admin assign", "permission")):
                return CanonicalEventType.PRIVILEGE_CHANGE
            if any(k in clean_str for k in ("remote", "session", "rdp", "ssh", "lateral")):
                return CanonicalEventType.REMOTE_SESSION

        return CanonicalEventType.UNKNOWN

taxonomy_normalizer = EventTaxonomyNormalizer
