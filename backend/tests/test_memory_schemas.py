"""
TimelineSection schema validation.

These tests were moved from test_memory_pipeline.py when memory knowledge building
stopped using an LLM (Phase 4). The schema is still used for stored memory timelines,
so its validation rules are still verified here.
"""
import pytest
from pydantic import ValidationError

from memory.case_inputs import timeline_hash
from schemas.memory import TimelineEvent, TimelineSection

def test_timeline_schema_structured_dictionaries_accepted():
    """
    Test C: Structured dictionaries/objects in important_events are accepted, validated as TimelineEvent,
    and serialized correctly.
    """
    structured_event = {
        "time": "2026-08-23T01:15:00Z",
        "action": "Privilege Escalation",
        "details": "User elevated from Guest to NT AUTHORITY\\SYSTEM",
        "description": "Exploitation of token privilege"
    }
    
    tl = TimelineSection(
        important_events=[structured_event],
        attack_story="Privilege escalation attack flow"
    )
    
    assert len(tl.important_events) == 1
    ev = tl.important_events[0]
    assert isinstance(ev, TimelineEvent)
    assert ev.action == "Privilege Escalation"
    assert ev.time == "2026-08-23T01:15:00Z"
    
    # Test JSON serialization / dumping
    dumped = tl.model_dump(mode="json")
    assert isinstance(dumped["important_events"][0], dict)
    assert dumped["important_events"][0]["action"] == "Privilege Escalation"
    
    # Test roundtrip reconstruction
    reconstructed = TimelineSection(**dumped)
    assert isinstance(reconstructed.important_events[0], TimelineEvent)
    assert reconstructed.important_events[0].action == "Privilege Escalation"


def test_timeline_schema_string_events_compatible():
    """
    Test D: Existing valid string timeline events remain fully supported for backward compatibility.
    """
    string_events = [
        "2026-08-23T01:00:00Z: Initial reconnaissance scan",
        "2026-08-23T01:05:00Z: Brute force login attempts"
    ]
    
    tl = TimelineSection(
        important_events=string_events,
        attack_story="Sequential attack story"
    )
    
    assert len(tl.important_events) == 2
    assert tl.important_events[0] == string_events[0]
    assert isinstance(tl.important_events[0], str)
    
    # Deterministic timeline hash works on stored timeline entries
    hash_str = timeline_hash(string_events)
    assert len(hash_str) == 64
    assert timeline_hash(string_events) == hash_str
    # Order is part of a timeline's meaning, so a reordered timeline hashes differently
    assert timeline_hash(list(reversed(string_events))) != hash_str
    assert timeline_hash([]) == ""


def test_timeline_schema_invalid_data_fails_safely():
    """
    Test E: Invalid timeline data fails predictably and safely.
    """
    with pytest.raises(ValidationError):
        # important_events must be a list
        TimelineSection(important_events="not-a-list")

    # Unsupported non-dict, non-string items should fail validation
    with pytest.raises(ValidationError):
        TimelineSection(important_events=[12345])


def test_timeline_rejects_integer_event():
    """Condition 1 regression: integer events are deterministically rejected."""
    with pytest.raises(ValidationError, match="unsupported type"):
        TimelineSection(important_events=["valid string", 12345])


def test_timeline_rejects_boolean_event():
    """Condition 1 regression: boolean events are deterministically rejected."""
    with pytest.raises(ValidationError, match="unsupported type"):
        TimelineSection(important_events=[True])


def test_timeline_rejects_none_event():
    """Condition 1 regression: None events are deterministically rejected."""
    with pytest.raises(ValidationError, match="unsupported type"):
        TimelineSection(important_events=[None])


def test_timeline_rejects_empty_dict_event():
    """Condition 1 regression: empty dict {} produces all-None TimelineEvent and is rejected."""
    with pytest.raises(ValidationError, match="empty TimelineEvent"):
        TimelineSection(important_events=[{}])


def test_timeline_rejects_unrecognized_key_dict():
    """Condition 1 regression: dict with only unrecognized keys produces empty TimelineEvent."""
    with pytest.raises(ValidationError, match="empty TimelineEvent"):
        TimelineSection(important_events=[{"foo": "bar", "baz": 99}])


def test_timeline_accepts_dict_with_at_least_one_recognized_field():
    """Condition 1 regression: dict with at least one recognized field is accepted."""
    tl = TimelineSection(important_events=[{"action": "Login attempt"}])
    assert len(tl.important_events) == 1
    assert isinstance(tl.important_events[0], TimelineEvent)
    assert tl.important_events[0].action == "Login attempt"
