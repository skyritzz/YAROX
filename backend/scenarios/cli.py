"""
CLI entry point for running a Phase 14 scenario against a live backend
process, matching evaluation/runner.py's own ``if __name__ == "__main__"``
convention — no new authenticated REST endpoint was added for this (see
docs/PHASE_14_SCENARIO_ORCHESTRATION.md's scope boundaries).

Usage (inside the backend container, so the real event bus/DB settings apply):
    python -m scenarios.cli --scenario suricata_intrusion_alert
    python -m scenarios.cli --scenario insider_threat_archive_and_transfer --investigation-timeout 480
    python -m scenarios.cli --scenario benign_negative_control --no-wait
    python -m scenarios.cli --list
"""
import argparse
import asyncio
import json
import sys

SCENARIOS = {
    "suricata_intrusion_alert": None,  # resolved lazily below (module-level constant)
    "insider_threat_archive_and_transfer": None,  # resolved lazily (async constructor)
    "benign_negative_control": None,
}


async def _resolve_scenario(scenario_id: str):
    from scenarios.definitions import BENIGN_NEGATIVE_CONTROL, SURICATA_INTRUSION_ALERT, build_insider_threat_scenario

    if scenario_id == "suricata_intrusion_alert":
        return SURICATA_INTRUSION_ALERT
    if scenario_id == "insider_threat_archive_and_transfer":
        return await build_insider_threat_scenario()
    if scenario_id == "benign_negative_control":
        return BENIGN_NEGATIVE_CONTROL
    raise ValueError(f"Unknown scenario '{scenario_id}'. Known: {sorted(SCENARIOS)}")


async def _run(args: argparse.Namespace) -> int:
    from core.events import RedisStreamEventBus, event_bus
    from consumers.db_writer import register_consumers
    from consumers.detection_consumer import register_detection_consumers
    from scenarios.orchestrator import scenario_orchestrator

    scenario = await _resolve_scenario(args.scenario)

    if isinstance(event_bus, RedisStreamEventBus):
        client = await event_bus._client()
        await client.delete(
            RedisStreamEventBus.stream_key("EventNormalized"),
            RedisStreamEventBus.stream_key("EventStored"),
        )
    register_consumers()
    register_detection_consumers()
    event_bus.start()
    try:
        result = await scenario_orchestrator.run(
            scenario,
            wait_for_investigation=not args.no_wait,
            event_storage_timeout=args.event_timeout,
            investigation_timeout=args.investigation_timeout,
            cleanup=args.cleanup,
        )
    finally:
        event_bus.stop()

    print(result.model_dump_json(indent=2))
    print(f"\n{'PASSED' if result.passed else 'FAILED'}: {scenario.scenario_id}", file=sys.stderr)
    if result.reasons:
        print("Reasons:", file=sys.stderr)
        for r in result.reasons:
            print(f"  - {r}", file=sys.stderr)
    if result.warnings:
        print("Warnings:", file=sys.stderr)
        for w in result.warnings:
            print(f"  - {w}", file=sys.stderr)
    return 0 if result.passed else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="YAROX Phase 14 scenario orchestration CLI")
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), help="Scenario to run")
    parser.add_argument("--list", action="store_true", help="List known scenario IDs and exit")
    parser.add_argument("--no-wait", action="store_true", help="Do not wait for the investigation to complete")
    parser.add_argument("--cleanup", action="store_true", help="Delete this execution's own data afterward")
    parser.add_argument("--event-timeout", type=float, default=20.0)
    parser.add_argument("--investigation-timeout", type=float, default=300.0)
    args = parser.parse_args()

    if args.list or not args.scenario:
        print(json.dumps(sorted(SCENARIOS), indent=2))
        return 0

    return asyncio.run(_run(args))


if __name__ == "__main__":
    sys.exit(main())
