"""
Indicator extraction for investigation memory.

Indicators are read from the events linked to a case's evidence items (normalized
columns, the stored ``metadata`` and the raw payload), not from evidence type labels.
Detection evidence types such as ``PROCESS_EXECUTION`` describe *what* was detected;
the indicators live in the underlying telemetry.
"""
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set

IP_KEYS = ("ip_address", "client_address", "source_ip", "src_ip", "destination_ip", "dest_ip", "dst_ip", "remote_ip", "ip")
DOMAIN_KEYS = ("domain", "dns_query", "query_name", "server_name", "sni")
HASH_KEYS = ("sha256", "sha1", "md5", "hash", "file_hash", "hashes")
PROCESS_KEYS = ("process_name", "image", "parent_process_name")
COMMAND_KEYS = ("command_line", "commandline", "parent_command_line")

PLACEHOLDER_IDENTITIES = {"", "unknown", "system", "anonymous", "n/a", "-"}
HEX_HASH = re.compile(r"\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b", re.IGNORECASE)
DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.IGNORECASE)


@dataclass
class CaseIndicators:
    ips: Set[str] = field(default_factory=set)
    domains: Set[str] = field(default_factory=set)
    hashes: Set[str] = field(default_factory=set)
    users: Set[str] = field(default_factory=set)
    hosts: Set[str] = field(default_factory=set)
    processes: Set[str] = field(default_factory=set)
    commands: Set[str] = field(default_factory=set)

    def iocs(self) -> Set[str]:
        """Observable indicators used for IOC overlap (network, file and command artifacts)."""
        return self.ips | self.domains | self.hashes | self.commands

    def assets(self) -> Set[str]:
        """Affected identities and machines used for asset overlap."""
        return {f"user:{u}" for u in self.users} | {f"host:{h}" for h in self.hosts}


def _flatten(source: Any) -> Dict[str, Any]:
    """Case-insensitive, one-level-deep view of a payload and its ``metadata`` block."""
    result: Dict[str, Any] = {}
    if not isinstance(source, dict):
        return result
    for key, value in source.items():
        if isinstance(value, dict) and key.lower() in ("metadata", "eventdata", "event_data"):
            for inner_key, inner_value in value.items():
                result.setdefault(str(inner_key).lower(), inner_value)
        else:
            result.setdefault(str(key).lower(), value)
    return result


def _valid_ip(value: Any) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def _basename(path: str) -> str:
    return re.split(r"[\\/]", path.strip())[-1].lower()


def _identity(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    if cleaned.lower() in PLACEHOLDER_IDENTITIES:
        return None
    if "\\" in cleaned:  # DOMAIN\user
        cleaned = cleaned.split("\\")[-1]
    return cleaned.lower() or None


def indicators_from_event(event: Any, indicators: CaseIndicators) -> None:
    fields: Dict[str, Any] = {}
    fields.update(_flatten(getattr(event, "raw_log", None)))
    for key, value in _flatten(getattr(event, "metadata_", None)).items():
        fields.setdefault(key, value)

    user = _identity(getattr(event, "user_name", None))
    if user:
        indicators.users.add(user)
    host = _identity(getattr(event, "hostname", None))
    if host:
        indicators.hosts.add(host)

    for key in IP_KEYS:
        ip = _valid_ip(fields.get(key)) if fields.get(key) is not None else None
        if ip:
            indicators.ips.add(ip)
    for key in DOMAIN_KEYS:
        value = fields.get(key)
        if isinstance(value, str) and DOMAIN.match(value.strip().rstrip(".")):
            indicators.domains.add(value.strip().rstrip(".").lower())
    for key in HASH_KEYS:
        value = fields.get(key)
        if isinstance(value, str):
            indicators.hashes.update(h.lower() for h in HEX_HASH.findall(value))
    for key in PROCESS_KEYS:
        value = fields.get(key)
        if isinstance(value, str) and value.strip():
            indicators.processes.add(_basename(value))
    for key in COMMAND_KEYS:
        value = fields.get(key)
        if isinstance(value, str) and value.strip():
            indicators.commands.add(value.strip())


def extract_case_indicators(evidence_items: Iterable[Any]) -> CaseIndicators:
    """``evidence_items`` must have their ``event`` relationship loaded."""
    indicators = CaseIndicators()
    for item in evidence_items:
        if getattr(item, "event", None) is not None:
            indicators_from_event(item.event, indicators)
        artifact = getattr(item, "artifact", None)
        if isinstance(artifact, str):
            ip = _valid_ip(artifact)
            if ip:
                indicators.ips.add(ip)
            indicators.hashes.update(h.lower() for h in HEX_HASH.findall(artifact) if len(artifact.strip()) == len(h))
    return indicators


def sorted_list(values: Set[str]) -> List[str]:
    return sorted(values)
