"""
Bounded polling for an async condition to become true.

Extracted from three near-identical private copies duplicated across
tests/test_sysmon_connector.py, tests/test_suricata_connector.py and
tests/test_splunk_connector.py (each polling for durable storage/detection
after a real event-bus publish). scenarios.orchestrator needs the exact same
pattern as production code, not test-only code, which is what justifies
lifting it out of the test tree rather than leaving a fourth duplicate.
"""
import asyncio
from typing import Awaitable, Callable


async def wait_until(condition: Callable[[], Awaitable[bool]], timeout: float = 10.0, interval: float = 0.1) -> bool:
    """Polls ``condition`` (an async callable returning bool) until it is true or
    ``timeout`` seconds have elapsed. Returns whether it became true in time —
    callers must treat a False return as "unresolved," never as an implicit pass."""
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        if await condition():
            return True
        await asyncio.sleep(interval)
    return False
