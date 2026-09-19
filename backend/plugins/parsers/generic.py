from abc import ABC, abstractmethod
from typing import Dict, Any, Union

from schemas.canonical_event import CanonicalSecurityEvent

class ParserInterface(ABC):
    @abstractmethod
    def parse(self, raw_data: Union[Dict[str, Any], Any]) -> Dict[str, Any]:
        """
        Parses raw event data into the normalized schema.
        Returns a dictionary matching the Event ORM schema.
        """
        pass

class GenericJSONParser(ParserInterface):
    """
    Standard normalizer for incoming JSON telemetry and synthetic lab events.
    Delegates field extraction, defaulting and validation to the canonical
    event contract (schemas.canonical_event.CanonicalSecurityEvent, Phase 11);
    this class is now a thin adapter from raw dict -> Event ORM kwargs.
    May raise schemas.canonical_event.CanonicalEventValidationError.
    """
    def parse(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        event = CanonicalSecurityEvent.from_raw(raw_data)
        return event.to_orm_kwargs()

generic_parser = GenericJSONParser()
