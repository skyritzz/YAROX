import json
import time
import httpx
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

SYNTHETIC_SOURCE = "yarox-synthetic-lab"

class SyntheticTelemetryGenerator:
    """
    Safe Synthetic Telemetry Producer for the YAROX Isolated Security Lab.
    Generates controlled test telemetry without executing actual attacks or using offensive tooling.
    """
    def __init__(self, base_url: str = "http://localhost:8000", api_key: str = "yarox-dev-ingest-key-change-in-production-2026"):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    def create_event(
        self,
        event_type: str,
        hostname: str,
        user_name: str,
        severity: str,
        raw_log: Dict[str, Any],
        scenario_name: str
    ) -> Dict[str, Any]:
        """
        Constructs a structured synthetic security event with explicit lab markers.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        return {
            "timestamp": now_iso,
            "source": SYNTHETIC_SOURCE,
            "event_type": event_type,
            "hostname": hostname,
            "user_name": user_name,
            "severity": severity,
            "raw_log": raw_log,
            "metadata": {
                "telemetry_type": "SYNTHETIC_TEST",
                "lab": True,
                "scenario": scenario_name,
                "generated_at": now_iso
            }
        }

    def generate_scenario(self, scenario_name: str) -> List[Dict[str, Any]]:
        """
        Generates a sequence of synthetic security events for a specific test scenario.
        """
        events = []
        if scenario_name == "brute_force_auth":
            # 1. Multiple failed logins followed by escalation
            for i in range(4):
                events.append(self.create_event(
                    event_type="Authentication Failure",
                    hostname="AUTH-SRV-01",
                    user_name="admin",
                    severity="MEDIUM",
                    raw_log={
                        "EventID": 4625,
                        "status": "0xC000006D",
                        "sub_status": "0xC0000064",
                        "ip_address": "10.0.4.15",
                        "failure_reason": "Unknown user name or bad password",
                        "attempt": i + 1
                    },
                    scenario_name=scenario_name
                ))
            events.append(self.create_event(
                event_type="Privilege Escalation",
                hostname="AUTH-SRV-01",
                user_name="admin",
                severity="HIGH",
                raw_log={
                    "EventID": 4672,
                    "privileges": ["SeDebugPrivilege", "SeTcbPrivilege"],
                    "description": "Special privileges assigned to new logon"
                },
                scenario_name=scenario_name
            ))

        elif scenario_name == "suspicious_powershell":
            # 2. Suspicious process creation with encoded command
            events.append(self.create_event(
                event_type="Process Creation",
                hostname="WORKSTATION-SEC-09",
                user_name="asmith",
                severity="HIGH",
                raw_log={
                    "EventID": 4688,
                    "process_name": "powershell.exe",
                    "command_line": "powershell.exe -NoP -NonI -W Hidden -Enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgAWwBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAiAEgA...",
                    "parent_process": "explorer.exe",
                    "pid": 4812
                },
                scenario_name=scenario_name
            ))

        elif scenario_name == "lateral_movement":
            # 3. Remote service connections across multiple targets
            for target_host in ["DC-01", "FILE-SRV-01", "BACKUP-SRV"]:
                events.append(self.create_event(
                    event_type="Remote Session",
                    hostname=target_host,
                    user_name="svc_backup",
                    severity="CRITICAL",
                    raw_log={
                        "EventID": 4624,
                        "logon_type": 3,
                        "ip_address": "192.168.10.55",
                        "process_name": "WmiPrvSE.exe",
                        "description": "Network logon initiated via WMI"
                    },
                    scenario_name=scenario_name
                ))

        else:
            # Benign baseline traffic
            events.append(self.create_event(
                event_type="User Logon",
                hostname="LAPTOP-DEV-01",
                user_name="developer",
                severity="INFO",
                raw_log={
                    "EventID": 4624,
                    "logon_type": 2,
                    "description": "Successful interactive console logon"
                },
                scenario_name="benign_baseline"
            ))

        return events

    def send_event(self, event_data: Dict[str, Any]) -> httpx.Response:
        """
        Transmits a single synthetic telemetry event to the /events/ingest API.
        """
        headers = {
            "Content-Type": "application/json",
            "X-API-Key": self.api_key
        }
        with httpx.Client(timeout=10.0) as client:
            return client.post(f"{self.base_url}/events/ingest", json=event_data, headers=headers)

    def run_scenario(self, scenario_name: str, delay_seconds: float = 0.5) -> List[Dict[str, Any]]:
        """
        Transmits a scenario event stream to the YAROX ingestion gateway.
        """
        events = self.generate_scenario(scenario_name)
        results = []
        for ev in events:
            res = self.send_event(ev)
            results.append({
                "status_code": res.status_code,
                "response": res.json() if res.status_code == 202 else res.text,
                "event_type": ev["event_type"]
            })
            if delay_seconds > 0:
                time.sleep(delay_seconds)
        return results

if __name__ == "__main__":
    generator = SyntheticTelemetryGenerator()
    print("Transmitting synthetic 'brute_force_auth' scenario to YAROX Ingestion Gateway...")
    res = generator.run_scenario("brute_force_auth", delay_seconds=0.2)
    print(f"Delivered {len(res)} synthetic events: {res}")
