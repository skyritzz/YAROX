# YAROX Isolated Security Lab Architecture & Safety Policy

This document outlines the architecture, boundary controls, and safety protocols for the YAROX development security test lab.

---

## 1. Safety Principles & Policy

> [!IMPORTANT]
> **Strict Non-Destructive Lab Boundary:**
> 1. **No Offensive Tooling:** No Metasploit, Atomic Red Team, malware binaries, exploit frameworks, or weaponized payloads are installed or executed in this environment.
> 2. **Controlled Synthetic Telemetry:** Test logs are generated using structured synthetic event producers ([`telemetry_generator.py`](file:///Users/ayushisharma/Yarox/backend/security/lab/telemetry_generator.py)).
> 3. **Explicit Data Tagging:** All generated events are labeled with `"source": "yarox-synthetic-lab"` and `"metadata": {"telemetry_type": "SYNTHETIC_TEST", "lab": true}` to ensure synthetic events are never confused with real enterprise telemetry.
> 4. **No External Network Probing:** The lab does not execute outbound network scans or port probes against external networks or the host machine.

---

## 2. Lab Architecture Diagram

```
┌───────────────────────────────────────────────────────────────────────────┐
│                     ISOLATED DEV LAB ENVIRONMENT                          │
│                                                                           │
│   ┌──────────────────────────────────┐                                    │
│   │ Safe Synthetic Telemetry Producer │                                    │
│   │ (telemetry_generator.py)         │                                    │
│   │ - Produces JSON security events  │                                    │
│   │ - Signs with X-API-Key           │                                    │
│   └─────────────────┬────────────────┘                                    │
│                     │ HTTPS / HTTP POST                                   │
│                     │ X-API-Key: yarox-dev-ingest-key...                  │
│                     ▼                                                     │
│   ┌──────────────────────────────────────────────────────────────────┐    │
│   │ YAROX Ingestion Gateway (POST /events/ingest)                     │    │
│   │  ├── Rate Limiter (Redis fail-closed protection)                 │    │
│   │  └── Event Normalization (GenericJSONParser)                     │    │
│   │                          │                                       │    │
│   │                          ▼                                       │    │
│   │             [ InMemoryEventBus ] ──► "EventNormalized"           │    │
│   │                          │                                       │    │
│   │           ┌──────────────┴──────────────┐                        │    │
│   │           ▼                             ▼                        │    │
│   │   [ PostgreSQL Store ]         [ Detection Engine ]              │    │
│   │       (db_writer)                       │                        │    │
│   │                                         ▼                        │    │
│   │                             [ Multi-Agent Swarm ]                │    │
│   │                           (Triage, Timeline, Threat, Report)     │    │
│   └──────────────────────────────────────────────────────────────────┘    │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Supported Synthetic Scenarios

1. **`brute_force_auth`:** Simulates Windows Event ID `4625` authentication failure bursts followed by Event ID `4672` privilege escalation.
2. **`suspicious_powershell`:** Simulates Event ID `4688` process creation with base64 encoded command lines matching Sigma detection rules.
3. **`lateral_movement`:** Simulates Event ID `4624` (Logon Type 3) network logons across multiple servers using WMI.
4. **`benign_baseline`:** Simulates normal interactive developer logons to verify false-positive resilience.

---

## 4. How to Execute Synthetic Lab Telemetry

```bash
# Execute within the backend container or local environment:
python -m security.lab.telemetry_generator
```
