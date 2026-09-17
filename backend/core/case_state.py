"""
Investigation lifecycle state machine.

Statuses are not free-form: every change must be an allowed transition.

    OPEN ──────────────► ANALYZING ──────────► WAITING_FOR_REVIEW
      │  ▲                   │  │                   │   │  ▲
      │  │                   │  └── failure ────────┘   │  │ re-analysis
      │  └──── reopen ───────┼──────────────────────────┼──┘
      ▼                      ▼                          ▼
   FALSE_POSITIVE ◄──────────┴──────────────────────► RESOLVED
"""
from typing import Dict, Set

from models.investigation import InvestigationStatus

S = InvestigationStatus

ALLOWED_TRANSITIONS: Dict[InvestigationStatus, Set[InvestigationStatus]] = {
    S.OPEN: {S.ANALYZING, S.RESOLVED, S.FALSE_POSITIVE},
    # ANALYZING -> OPEN is how a failed or stopped investigation returns the case to the queue
    S.ANALYZING: {S.WAITING_FOR_REVIEW, S.OPEN, S.FALSE_POSITIVE},
    S.WAITING_FOR_REVIEW: {S.RESOLVED, S.FALSE_POSITIVE, S.ANALYZING},
    S.RESOLVED: {S.OPEN},
    S.FALSE_POSITIVE: {S.OPEN},
}

# States an investigation run may start from (a closed case must be reopened first)
INVESTIGATABLE_STATES = {S.OPEN, S.ANALYZING, S.WAITING_FOR_REVIEW}

TERMINAL_STATES = {S.RESOLVED, S.FALSE_POSITIVE}


class InvalidStatusTransition(Exception):
    def __init__(self, current: InvestigationStatus, target: InvestigationStatus):
        self.current = current
        self.target = target
        allowed = sorted(t.value for t in ALLOWED_TRANSITIONS.get(current, set()))
        super().__init__(
            f"Invalid status transition {current.value} -> {target.value}. "
            f"Allowed from {current.value}: {allowed or 'none'}."
        )


def can_transition(current: InvestigationStatus, target: InvestigationStatus) -> bool:
    return target in ALLOWED_TRANSITIONS.get(current, set())


def validate_transition(current: InvestigationStatus, target: InvestigationStatus) -> None:
    if not can_transition(current, target):
        raise InvalidStatusTransition(current, target)
