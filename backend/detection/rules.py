from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List, Tuple
import ipaddress
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


def _event_metadata(event: Event) -> Dict[str, Any]:
    """
    The authoritative source for structured per-event fields (command_line,
    process_name, ip_address, ...) is Event.metadata_ — schemas.canonical_event.
    CanonicalSecurityEvent treats metadata as a field distinct from raw_log, not
    nested inside it, and to_orm_kwargs() stores them as separate columns.

    Falls back to raw_log['metadata'] for legacy rows that pre-date the
    canonical contract and duplicated metadata inside raw_log instead (every
    replay dataset happens to do this, which is why it worked before). Reading
    only raw_log['metadata'] was a real defect, found during Phase 11 connector
    work: it silently missed metadata_ for any caller — like a real Sysmon
    connector — that correctly keeps raw_log as the untouched source payload
    and supplies metadata as a separate field rather than duplicating it.
    """
    metadata = getattr(event, "metadata_", None)
    if metadata:
        return metadata
    raw_log = event.raw_log if isinstance(event.raw_log, dict) else {}
    return raw_log.get("metadata") or {}


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

_ENCODED_COMMAND_CANONICAL = "-encodedcommand"

# .NET/PowerShell fileless download-and-execute "cradle": Invoke-Expression (its
# 'iex' alias) piping straight into a downloaded payload, or an explicit web-client
# download call, executed from process-creation telemetry. MITRE T1059.001 commonly
# cites exactly this pattern. Deliberately narrow, specific method/cmdlet names, not
# generic words — legitimate command lines essentially never contain any of these.
_DOWNLOAD_CRADLE_PATTERNS = (
    "invoke-expression", "iex(", "iex ",
    "downloadstring(", "downloadfile(", "downloaddata(",
)


def _has_encoded_command_flag(command_line_lower: str) -> bool:
    """
    True if a whitespace-delimited token in the command line is an unambiguous
    abbreviation of PowerShell's '-EncodedCommand' host flag (powershell.exe
    accepts any unambiguous prefix of its own parameters; '-enc' is the
    conventional minimum abbreviation seen in real encoded/obfuscated
    PowerShell invocations — see tests/test_sysmon_connector.py's own
    '-enc SQBFAFgA' fixture). Token-precise, not a bare substring search: it
    does not collide with an unrelated flag like some other tool's own
    '-Encoding' parameter ('-encodedcommand'.startswith('-encoding') is
    False — they diverge at the 7th character).
    """
    for token in command_line_lower.replace('"', ' ').split():
        if token.startswith('-') and len(token) >= 4 and _ENCODED_COMMAND_CANONICAL.startswith(token):
            return True
    return False


class SuspiciousProcessExecution(BaseDetectionRule):
    """
    Phase 15 / audit item D-1. Previously matched on bare substrings —
    ``'powershell' in raw or 'cmd.exe' in raw`` — which flagged literally any
    invocation of either interpreter regardless of arguments. Confirmed live
    (not assumed) to false-positive on ordinary, benign command lines with no
    suspicious content at all: ``cmd.exe /c echo build succeeded``,
    ``powershell.exe -File C:\\Scripts\\Get-DiskSpace.ps1``, a plain CI build
    step invoking ``cmd.exe`` — all matched under the old logic. In any
    environment where PowerShell/cmd.exe are used for routine administration,
    automation, or CI (i.e. almost all of them), this made the rule fire on
    a large fraction of ordinary activity — not real detection coverage, a
    100%-recall/100%-false-positive-rate rule is not distinguishing anything.

    Now matches only two specific, narrow, well-documented indicators, each
    still checked against the same free-text ``command_line`` (this
    connector-agnostic approach is unchanged; only which patterns count as
    "suspicious" changed):

    1. An encoded/obfuscated command execution flag (see
       ``_has_encoded_command_flag`` — unchanged in spirit from before, just
       token-precise instead of a raw substring search).
    2. A PowerShell fileless download-and-execute "cradle" (see
       ``_DOWNLOAD_CRADLE_PATTERNS``) — a detection capability that did not
       exist before this fix.

    **Known, deliberate coverage tradeoff** (documented per the governing
    instruction, not silently accepted): a plain, non-obfuscated malicious
    PowerShell/cmd invocation with no special flags — e.g. the actual
    malicious logic lives entirely inside a script file referenced via
    ``-File`` rather than appearing on the command line itself — is no
    longer flagged by this rule alone. This was never reliable coverage:
    the old rule caught that case only by also catching every legitimate
    script invocation, which is not a distinguishing signal. Closing that
    gap for real would need parent-process lineage, script-block logging,
    or file-content inspection, none of which this system currently
    ingests — out of scope for a keyword-matching rule.
    """

    async def match(self, event: Event) -> bool:
        c_type = taxonomy_normalizer.normalize(event.event_type, event.raw_log)
        evt_type = event.event_type.lower()
        if c_type == CanonicalEventType.PROCESS_EXECUTION or evt_type in ['process create', 'process execution', 'process creation']:
            raw_dict = event.raw_log if isinstance(event.raw_log, dict) else {}
            metadata = _event_metadata(event)
            raw = str(metadata.get('command_line', raw_dict.get('command_line', ''))).lower()
            if _has_encoded_command_flag(raw) or any(p in raw for p in _DOWNLOAD_CRADLE_PATTERNS):
                return True
        return False

    def explain(self, event: Event) -> Dict[str, Any]:
        raw_dict = event.raw_log if isinstance(event.raw_log, dict) else {}
        metadata = _event_metadata(event)
        cmdline = metadata.get('command_line') or raw_dict.get('command_line', 'Unknown')
        cmdline_lower = str(cmdline).lower()
        if _has_encoded_command_flag(cmdline_lower):
            indicator = "an encoded/obfuscated command execution flag (-EncodedCommand)"
        elif any(p in cmdline_lower for p in _DOWNLOAD_CRADLE_PATTERNS):
            indicator = "a fileless download-and-execute pattern (Invoke-Expression / web client download)"
        else:
            indicator = "a suspicious command-line pattern"  # defensive fallback; match() guarantees one of the above
        return {
            "description": f"Suspicious command line execution detected ({indicator}): {cmdline}",
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


_SEVERITY_FROM_EVENT_STRING = {
    "LOW": Severity.LOW, "MEDIUM": Severity.MEDIUM, "HIGH": Severity.HIGH, "CRITICAL": Severity.CRITICAL,
}


class NetworkIntrusionAlert(BaseDetectionRule):
    """
    Phase 13 / audit item D-4. Surfaces a SYSTEM_ALERT-classified event — today,
    exclusively a Suricata EVE 'alert' record (plugins/parsers/suricata.py) — as
    a case. Unlike every other rule in this file, the underlying "detection" was
    already performed by an external, purpose-built network intrusion detection
    engine (Suricata); this rule's job is to make that signature match
    investigatable, not to independently infer malicious intent from raw flow
    data. Deliberately does NOT exist for plain NETWORK_TRAFFIC (flow/connection)
    events with no IDS signature — see LargeExternalDataTransfer below for the
    (explicitly hedged, non-C2-claiming) volume heuristic that covers those.
    Per the governing instruction ("do not claim reliable C2 identification from
    generic network flows alone"), no rule in this file infers C2/intrusion from
    NETWORK_TRAFFIC telemetry on its own — only from an IDS's own signature match.

    MITRE mapping is necessarily approximate: a Suricata signature can represent
    almost any attacker technique, and this system has no per-signature technique
    database (no live threat-intel feed exists — see agents/threat_intel.py,
    which only searches YAROX's own prior-case memory and a static MITRE
    reference, never an external reputation/IOC service). T1071/Command and
    Control is used as the default label for "an IDS flagged this traffic," not
    an assertion that the specific technique was confirmed — explain()'s
    description says so explicitly, and the fact actually asserted (the
    signature text) is quoted verbatim from Suricata's own output.
    """

    async def match(self, event: Event) -> bool:
        c_type = taxonomy_normalizer.normalize(event.event_type, event.raw_log)
        return c_type == CanonicalEventType.SYSTEM_ALERT

    def explain(self, event: Event) -> Dict[str, Any]:
        metadata = _event_metadata(event)
        signature = metadata.get('signature') or 'Unspecified network intrusion signature'
        category = metadata.get('category')
        src_ip = metadata.get('source_ip')
        dst_ip = metadata.get('destination_ip') or metadata.get('ip_address')
        location = f" ({src_ip} -> {dst_ip})" if src_ip and dst_ip else ""
        category_text = f" [{category}]" if category else ""
        severity = _SEVERITY_FROM_EVENT_STRING.get(str(event.severity).upper(), Severity.MEDIUM)
        return {
            "description": (
                f"Network intrusion detection signature matched: \"{signature}\"{category_text}{location}. "
                "Severity reflects the source IDS's own classification; the specific attacker technique is "
                "not independently confirmed by YAROX."
            ),
            "severity": severity,
            "mitre_technique_id": "T1071",
            "mitre_technique_name": "Application Layer Protocol",
            "mitre_tactic": "Command and Control",
            "evidence_type": "NETWORK_INTRUSION_ALERT",
        }


_ARCHIVE_UTILITY_PROCESS_NAMES = {
    "7z.exe", "7za.exe", "7zr.exe", "7z", "7za",
    "winrar.exe", "rar.exe", "rar",
    "zip.exe", "zip", "unzip.exe",
    "gzip.exe", "gzip",
    "tar.exe", "tar",
}


class DataStagingViaArchiveUtility(BaseDetectionRule):
    """
    Phase 13 / audit item D-5. Flags invocation of a known archive/compression
    utility from process-creation telemetry (Sysmon EventID 1, or any other
    PROCESS_EXECUTION-classified source). Matches YAROX_REALITY_AUDIT.md D-5's
    confirmed gap: datasets/insider_threat's events.json includes a real
    '7z.exe' invocation that archives two separate file-share paths
    (\\FS-01\\HR\\Employee_Salaries.csv and \\FS-01\\Finance\\Q1_Report.xlsx)
    together in one command line, which produces zero detection today (no
    existing rule's keyword list covers archive utilities — SuspiciousProcess
    Execution only matches powershell/cmd.exe/-enc/encodedcommand).

    Archive utilities are used constantly for entirely legitimate reasons (backups,
    packaging build artifacts, routine file transfers) — this rule cannot and does
    not distinguish staging stolen data from routine use. It surfaces the fact (a
    compression tool ran, with its exact command line) as investigatable evidence,
    not a confirmed malicious finding — see the hedged language in explain() and
    the conservative MEDIUM severity (never escalated by this rule alone).
    """

    async def match(self, event: Event) -> bool:
        c_type = taxonomy_normalizer.normalize(event.event_type, event.raw_log)
        evt_type = event.event_type.lower()
        if c_type != CanonicalEventType.PROCESS_EXECUTION and evt_type not in ('process create', 'process execution', 'process creation'):
            return False
        metadata = _event_metadata(event)
        raw_dict = event.raw_log if isinstance(event.raw_log, dict) else {}
        process_name = str(metadata.get('process_name') or raw_dict.get('process_name') or '').strip().lower()
        return process_name in _ARCHIVE_UTILITY_PROCESS_NAMES

    def explain(self, event: Event) -> Dict[str, Any]:
        metadata = _event_metadata(event)
        raw_dict = event.raw_log if isinstance(event.raw_log, dict) else {}
        cmdline = metadata.get('command_line') or raw_dict.get('command_line', 'Unknown')
        process_name = metadata.get('process_name') or raw_dict.get('process_name', 'Unknown')
        return {
            "description": (
                f"Archive/compression utility '{process_name}' was invoked: {cmdline}. This may indicate "
                "legitimate use or data staging ahead of exfiltration; the command line is provided for "
                "analyst review, not a confirmed malicious finding."
            ),
            "severity": Severity.MEDIUM,
            "mitre_technique_id": "T1560",
            "mitre_technique_name": "Archive Collected Data",
            "mitre_tactic": "Collection",
            "evidence_type": "DATA_STAGING",
        }


# Ordered by how commonly each field name appears across sources: Suricata EVE
# 'flow' records use 'bytes_toserver'; the pre-existing generic-ingest fixture
# datasets/insider_threat/events.json uses 'bytes_sent'. No canonical field name
# exists for this yet (out of scope to add one for a single detection rule).
_OUTBOUND_BYTE_KEYS = ("bytes_toserver", "bytes_sent", "bytes_out", "bytes")

_EXTERNAL_TRANSFER_BYTES_THRESHOLD = 10 * 1024 * 1024  # 10 MB — see class docstring

_RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def _outbound_byte_count(metadata: Dict[str, Any], raw_dict: Dict[str, Any]) -> Optional[float]:
    for key in _OUTBOUND_BYTE_KEYS:
        value = metadata.get(key)
        if value is None:
            value = raw_dict.get(key)
        if value is None:
            continue
        try:
            return float(value)
        except (TypeError, ValueError):
            continue
    return None


def _is_internal_network_address(addr) -> bool:
    """
    True for a genuinely internal/local destination: RFC 1918 private ranges,
    loopback, link-local, or unspecified. Deliberately narrower than Python's
    own ``addr.is_private``, which *also* covers RFC 5737/RFC 2544 documentation
    and benchmarking ranges (e.g. 203.0.113.0/24, "TEST-NET-3") — exactly the
    kind of address commonly used in documentation and example telemetry as a
    stand-in for "some external host" (the pre-existing
    datasets/insider_threat/events.json fixture uses 203.0.113.50 for exactly
    that purpose). Using ``is_private`` as-is would make this rule permanently
    unable to fire on that entire category of realistic-looking example/
    documentation traffic. In real production telemetry this distinction is
    close to moot — genuine traffic essentially never targets a TEST-NET
    range — so this narrowing does not weaken the rule against real internal
    traffic, it only stops treating "the traffic used a reserved
    documentation address" as if it meant "the traffic stayed inside our
    network."
    """
    if addr.is_loopback or addr.is_link_local or addr.is_unspecified:
        return True
    if isinstance(addr, ipaddress.IPv4Address):
        return any(addr in net for net in _RFC1918_NETWORKS)
    return addr.is_private  # IPv6 ULA (fc00::/7) etc. - is_private is accurate enough for v6 here


class LargeExternalDataTransfer(BaseDetectionRule):
    """
    Phase 13 / audit item D-5. Flags a single NETWORK_TRAFFIC-classified event
    (Suricata EVE 'flow', or any other source populating the same byte-count
    metadata) that sent at least _EXTERNAL_TRANSFER_BYTES_THRESHOLD bytes to a
    destination address that is not a private/loopback/link-local/reserved IP
    (RFC 1918 / RFC 3927 / loopback — a purely structural check computed from
    the address itself via Python's ipaddress module, not a reputation or
    threat-intel lookup this system does not have — see CLAUDE.md Rule 6 on not
    fabricating threat-intel claims, and NetworkIntrusionAlert's docstring above
    on the same point).

    This is a volume heuristic, not a C2/exfiltration determination: it does
    not, and cannot, know whether the destination or transfer was legitimate (a
    backup, a software update, a video call, a cloud-sync client are all
    common, benign causes of a large outbound transfer to a public IP). Matches
    YAROX_REALITY_AUDIT.md D-5's confirmed gap: datasets/insider_threat's
    events.json includes a real 15 MB transfer (`bytes_sent: 15000000`) to
    203.0.113.50 over 'chrome.exe', which produces zero detection today.
    Deliberately conservative — MEDIUM severity, explicitly hedged description,
    no claim of C2 (see governing instruction: "do not claim reliable C2
    identification from generic network flows alone").
    """

    async def match(self, event: Event) -> bool:
        c_type = taxonomy_normalizer.normalize(event.event_type, event.raw_log)
        if c_type != CanonicalEventType.NETWORK_TRAFFIC:
            return False
        metadata = _event_metadata(event)
        raw_dict = event.raw_log if isinstance(event.raw_log, dict) else {}

        byte_count = _outbound_byte_count(metadata, raw_dict)
        if byte_count is None or byte_count < _EXTERNAL_TRANSFER_BYTES_THRESHOLD:
            return False

        dest = metadata.get('destination_ip') or metadata.get('ip_address') or raw_dict.get('destination_ip')
        if not dest:
            return False
        try:
            addr = ipaddress.ip_address(str(dest).strip())
        except ValueError:
            return False
        if _is_internal_network_address(addr) or addr.is_multicast:
            return False

        return True

    def explain(self, event: Event) -> Dict[str, Any]:
        metadata = _event_metadata(event)
        raw_dict = event.raw_log if isinstance(event.raw_log, dict) else {}
        byte_count = _outbound_byte_count(metadata, raw_dict)
        dest = metadata.get('destination_ip') or metadata.get('ip_address') or raw_dict.get('destination_ip')
        mb_text = f"{byte_count / (1024 * 1024):.1f} MB" if byte_count else "an unspecified volume"
        return {
            "description": (
                f"Large outbound network transfer observed to external address {dest} ({mb_text}). "
                "Volume-based heuristic only — does not confirm exfiltration, C2, or malicious intent; "
                "common benign causes (backups, updates, uploads) are not excluded."
            ),
            "severity": Severity.MEDIUM,
            "mitre_technique_id": "T1048",
            "mitre_technique_name": "Exfiltration Over Alternative Protocol",
            "mitre_tactic": "Exfiltration",
            "evidence_type": "POSSIBLE_DATA_EXFILTRATION",
        }


def _sigma_fields(event: Event) -> Dict[str, Any]:
    """
    The dict rules.sigma.engine.SigmaEngine matches against: event-level columns
    (hostname/user_name — real Event ORM columns, models/event.py) merged with
    metadata_. Phase 16 / D-3 fix: the pre-Phase-16 call site
    (detection/engine.py's _record_match) passed only ``_event_metadata(event)``,
    so any Sigma rule referencing Computer/User (extremely common in real rules,
    e.g. excluding SYSTEM/LOCAL SERVICE accounts) could never match — those
    fields were never even in the dict being searched. metadata_ keys win on
    collision (more specific than the coarse event-level columns).
    """
    fields: Dict[str, Any] = {"hostname": event.hostname, "user_name": event.user_name}
    fields.update(_event_metadata(event))
    return fields


class SigmaDetectionRule(BaseDetectionRule):
    """
    Phase 16 / D-3. Wraps rules.sigma.engine.sigma_engine so a genuine Sigma-only
    match — no native Python rule in this file also matching the same event —
    can independently create or correlate a case, through the exact same
    extension point every rule above already uses (DetectionEngine.rules), not
    a parallel detection path or a rewrite of the engine's own loop.

    This is distinct from detection/engine.py's separate, pre-existing inline
    ``sigma_engine.evaluate()`` call inside ``_record_match``, which continues
    unchanged: it still annotates whichever *native* rule's own evidence with
    "Matched Sigma Rule: ..." when a Sigma rule happens to also match the same
    event. Before this class existed, that inline call was the Sigma engine's
    *only* integration point — a Sigma rule could never be the reason a case
    got created at all, only decorate one a native rule already created (the
    exact "used only to bump importance score" characterization from the
    original D-3 audit finding). This class closes that gap.

    match()/explain() each independently recompute the Sigma evaluation from
    ``event`` rather than caching a match list on ``self`` between calls —
    ``self`` is one long-lived instance shared by every event
    (``detection_engine`` is a module-level singleton), so any state stored
    between match() and explain() would be a correctness hazard under
    concurrent event processing. Recomputing is cheap: a handful of rules,
    pure string/regex comparisons, no I/O.
    """

    async def match(self, event: Event) -> bool:
        from rules.sigma.engine import sigma_engine
        c_type = taxonomy_normalizer.normalize(event.event_type, event.raw_log)
        return bool(sigma_engine.evaluate(_sigma_fields(event), canonical_event_type=c_type.value))

    def explain(self, event: Event) -> Dict[str, Any]:
        from rules.sigma.engine import sigma_engine
        c_type = taxonomy_normalizer.normalize(event.event_type, event.raw_log)
        matches = sigma_engine.evaluate(_sigma_fields(event), canonical_event_type=c_type.value)
        # match() guarantees at least one match reaches explain() via DetectionEngine's
        # own if-match-then-explain sequencing; this empty case is a defensive fallback,
        # not an expected path.
        if not matches:
            return {
                "description": "Sigma rule match could not be re-evaluated for explanation.",
                "severity": Severity.MEDIUM,
                "mitre_technique_id": None,
                "mitre_technique_name": "Sigma Match",
                "mitre_tactic": "Uncategorized",
                "evidence_type": "SIGMA_MATCH",
            }

        _rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        rule = max(matches, key=lambda r: _rank.get(r.severity, 0))
        other_titles = [m.title for m in matches if m is not rule]
        extra = f" Also matched: {', '.join(other_titles)}." if other_titles else ""
        description_suffix = f" {rule.description}" if rule.description else ""

        mitre = rule.mitre
        return {
            "description": f"Sigma rule matched: \"{rule.title}\".{description_suffix}{extra}",
            "severity": _SEVERITY_FROM_EVENT_STRING.get(rule.severity, Severity.MEDIUM),
            # No fabricated technique ID when the rule's own tags don't resolve against
            # the local ATT&CK reference (security/mitre/knowledge_base.py) — None here,
            # not a placeholder string; detection/engine.py skips AttackTechnique
            # creation for a None id rather than writing a fake one.
            "mitre_technique_id": mitre.technique_id,
            "mitre_technique_name": mitre.technique_name or rule.title,
            "mitre_tactic": mitre.tactic or "Uncategorized",
            "evidence_type": "SIGMA_MATCH",
        }
