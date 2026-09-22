"""
Sigma field-name -> YAROX canonical field mapping (Phase 16 / D-3).

Real Sigma rules (including the public SigmaHQ ruleset) are written against
Sysmon/Windows field names (``Image``, ``CommandLine``, ``ParentImage``,
...). YAROX's own canonical event contract uses different field names
(``process_name``, ``command_line``, ``parent_process``, ...) established by
the Sysmon/Suricata/Splunk connectors (Phase 11). Without this mapping,
every field reference in an unmodified Sigma rule would silently look up a
key that does not exist in YAROX's data and never match anything —
``rules/sigma/engine.py`` (pre-Phase-16) had no such layer at all.

Mappings are explicit and per ``logsource.category`` — a field name can mean
different things in different log sources (Sigma itself scopes fields this
way), and an unmapped field name is passed through unchanged rather than
silently dropped (a rule author who already used a YAROX-native field name
directly, or a field this table doesn't yet cover, still gets a literal
lookup attempt, not a guaranteed miss).
"""
from dataclasses import dataclass, field
from typing import Callable, Dict, Optional


def _strip_leading_path_separator(value: str) -> str:
    """'\\powershell.exe' -> 'powershell.exe'. YAROX's process_name/parent_process
    fields are already basenames (plugins/parsers/sysmon.py's _basename()), but
    real Sigma rules commonly write Image|endswith: '\\\\powershell.exe' assuming
    Image is a full path. Stripping a leading separator from the *expected value*
    (not the event data) lets 'endswith'/'contains' still match our basename-only
    field correctly. A rule using a multi-component suffix (e.g.
    'System32\\\\powershell.exe') still won't match a basename-only field — that
    is a genuine, documented limitation (see docs/PHASE_16_SIGMA_ENGINE.md), not
    silently patched over here."""
    return value.lstrip("\\/")


@dataclass(frozen=True)
class FieldMapping:
    yarox_field: str
    # Applied to the rule's *expected* value before comparison, not to event data —
    # keeps the transformation visible/testable and never mutates the real event.
    normalize_expected: Optional[Callable[[str], str]] = None


# Fields available on every event, merged into the match dict alongside metadata_
# (see rules/sigma/engine.py's build_event_fields()) — these are real Event ORM
# columns (models/event.py), not metadata_ keys, and were not even passed to the
# matcher before Phase 16.
_COMMON_FIELD_MAP: Dict[str, FieldMapping] = {
    "Computer": FieldMapping("hostname"),
    "Hostname": FieldMapping("hostname"),
    "User": FieldMapping("user_name"),
    "UserName": FieldMapping("user_name"),
}

# logsource.category "process_creation" (Sysmon EventID 1 / Windows Security 4688)
#
# Deliberately NOT mapped: "OriginalFileName". Real Sysmon EventID 1 carries this
# (the PE's internal filename metadata, used to catch a renamed binary — e.g.
# powershell.exe renamed to notepad.exe but OriginalFileName still says
# "PowerShell.EXE"), and real SigmaHQ rules commonly check it. YAROX's own Sysmon
# connector (plugins/parsers/sysmon.py) does not currently extract or pass this
# field through at all — mapping it to process_name (the same field Image maps
# to) would produce a coincidental, misleading match rather than reflecting that
# this signal genuinely isn't observed. Left unmapped: it resolves to "field not
# present" (None) and correctly never matches, rather than false-matching via
# reuse of a different field. See docs/PHASE_16_SIGMA_ENGINE.md's field mapping
# table and the real-rule validation section for the concrete rule this affects.
_PROCESS_CREATION_FIELD_MAP: Dict[str, FieldMapping] = {
    **_COMMON_FIELD_MAP,
    "Image": FieldMapping("process_name", normalize_expected=_strip_leading_path_separator),
    "CommandLine": FieldMapping("command_line"),
    "ParentImage": FieldMapping("parent_process", normalize_expected=_strip_leading_path_separator),
    "ParentCommandLine": FieldMapping("parent_command_line"),
    "Hashes": FieldMapping("hashes"),
}

# logsource.category "network_connection" (Sysmon EventID 3 / Suricata flow)
_NETWORK_CONNECTION_FIELD_MAP: Dict[str, FieldMapping] = {
    **_COMMON_FIELD_MAP,
    "Image": FieldMapping("process_name", normalize_expected=_strip_leading_path_separator),
    "DestinationIp": FieldMapping("destination_ip"),
    "DestinationPort": FieldMapping("destination_port"),
    "SourceIp": FieldMapping("source_ip"),
    "Protocol": FieldMapping("protocol"),
}

# logsource.category "file_event" (Sysmon EventID 11)
_FILE_EVENT_FIELD_MAP: Dict[str, FieldMapping] = {
    **_COMMON_FIELD_MAP,
    "Image": FieldMapping("process_name", normalize_expected=_strip_leading_path_separator),
    "TargetFilename": FieldMapping("target_filename"),
}

# Maps Sigma's logsource.category value to (a) the field table to use, and (b)
# the YAROX CanonicalEventType this rule should be restricted to (Phase 16's new
# logsource-category filtering — see engine.py). None means "no restriction."
LOGSOURCE_CATEGORY_FIELD_MAPS: Dict[str, Dict[str, FieldMapping]] = {
    "process_creation": _PROCESS_CREATION_FIELD_MAP,
    "network_connection": _NETWORK_CONNECTION_FIELD_MAP,
    "file_event": _FILE_EVENT_FIELD_MAP,
}

LOGSOURCE_CATEGORY_TO_CANONICAL_TYPE: Dict[str, str] = {
    "process_creation": "PROCESS_EXECUTION",
    "network_connection": "NETWORK_TRAFFIC",
    "file_event": "FILE_OPERATION",
}


def field_map_for_category(category: Optional[str]) -> Dict[str, FieldMapping]:
    """Falls back to the common (host/user only) map for an unrecognized or
    absent category — fields specific to that category won't resolve, but the
    rule doesn't crash; see SigmaRule's own unsupported-field tracking for how
    that's surfaced instead of silently mismatching."""
    if category and category in LOGSOURCE_CATEGORY_FIELD_MAPS:
        return LOGSOURCE_CATEGORY_FIELD_MAPS[category]
    return dict(_COMMON_FIELD_MAP)


def resolve_field(category: Optional[str], sigma_field_name: str) -> FieldMapping:
    """Returns the YAROX field to read and any expected-value normalizer for a
    given Sigma field name under a given logsource category. Unmapped field
    names pass through unchanged (see module docstring)."""
    mapping = field_map_for_category(category)
    return mapping.get(sigma_field_name, FieldMapping(sigma_field_name))
