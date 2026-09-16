# YAROX Reality Audit

**Purpose:** Record what the YAROX codebase *actually does*, verified by reading code and running the system, and track restoration of every defect.
**Baseline audited:** commit `20cb693` plus uncommitted working tree, 2026-09-16/17.
**Method:** Full source read (backend, frontend, tests, migrations, compose), live stack run, database/Qdrant/Celery/Ollama inspection, test-suite execution, live replay of `credential_theft`.

Status vocabulary:

| Status | Meaning |
|---|---|
| **REAL** | Works end-to-end, verified by execution |
| **PARTIAL** | Real code path exists but is incomplete or has a verified defect |
| **FAKE** | Presents values or behavior that are not derived from real system state |
| **BROKEN** | Intended to work, verified not to work |
| **MISSING** | Claimed in docs/spec, no implementation |
| **UNKNOWN** | Could not be verified |

The "Restoration" column is updated as phases complete. `OPEN` = not yet addressed.

---

## 1. Baseline Evidence (Phase 0 runs)

| Check | Result |
|---|---|
| `docker compose ps` | 7 containers up; `yarox-minio` **unhealthy** |
| `curl /health` | 200, all components "Healthy" (hardcoded, see H-1) |
| Ollama from backend container | Reachable; `llama3.1` and `qwen2.5:7b` respond |
| `docker compose exec backend pytest -v tests/` | **7 collection errors** (`ModuleNotFoundError: core/api/memory/...`) |
| `docker compose exec backend python -m pytest tests/` | 71 passed, 15 warnings, 34s |
| Postgres state before replay | 200 events, 81 cases (74 WAITING_FOR_REVIEW, 1 OPEN, 6 RESOLVED) |
| Agent executions (historical) | 390 total; 370 completed, 19 degraded, 1 failed-less; degraded causes: 7 timeouts, 1 invalid JSON, 11 empty error |
| `investigation_memory` rows | **0** (despite 6 RESOLVED cases) |
| Qdrant `investigation_memory` points | 17, **all created by test runs**, none correspond to a real case |
| `agent_tool_calls.duration_ms` | 67/67 rows = **850** |
| `investigation_cases.confidence_score` | 68/81 = 0.75 exactly |
| Live replay `credential_theft` @100x (2026-09-16 18:33) | 1 case `09b762b7…`, **2 full concurrent investigations** (10 agent executions, 2 SOC Lead runs) on the same case; confidence 0.76 |
| Replay re-run | Events duplicated on each replay (6 copies of `2023-10-27T10:00:00Z`) |
| Test side-effects | Test run dispatched real Celery tasks against dev DB; one failed with FK violation after fixture deleted the case; 2 orphan Qdrant vectors created |

---

## 2. Infrastructure

| ID | Component | Status | Evidence | File / Symbol | Why it matters | Proposed fix | Restoration |
|---|---|---|---|---|---|---|---|
| I-1 | Docker Compose stack | REAL | All 7 services start | `docker-compose.yml` | Dev platform | — | — |
| I-2 | MinIO healthcheck | BROKEN | Health log: `exec: "curl": executable file not found` every 30s | `docker-compose.yml` minio.healthcheck | Permanent false "unhealthy"; masks real failures | Use `mc ready local` | OPEN |
| I-3 | MinIO usage | MISSING | No code imports a MinIO/S3 client; not in `requirements.txt` | — | Spec claims artifact storage | Either implement artifact store or mark not implemented | OPEN |
| I-4 | Celery worker | PARTIAL | Only `tasks.index_resolved_investigation_task` registered | `workers/celery_app.py` | Investigations run in API process | Phase 7 | OPEN |
| I-5 | Celery worker env | PARTIAL | Worker lacks `OLLAMA_BASE_URL`, `JWT_SECRET_KEY` env; `depends_on` not health-gated | `docker-compose.yml` celery_worker | Worker LLM calls use defaults; startup races | Share env block; gate on health | OPEN |
| I-6 | Python version | REAL (doc mismatch) | Container is 3.12; CLAUDE.md says 3.11 | `backend/Dockerfile` | Docs untruthful | Fix docs | OPEN |
| I-7 | Frontend version | REAL (doc mismatch) | `next@16.2.10`, docs say Next 15 | `frontend/package.json` | Docs untruthful | Fix docs | OPEN |
| I-8 | Stray files | — | `backend/yarox.db` (0 bytes), `test_ws.py` (unauthenticated WS script, will be rejected), 260MB of video in `assets/`,`media/` untracked | repo root | Repo hygiene | Keep media out of git; move/delete stray scripts with owner approval | OPEN |

## 3. API Layer

| ID | Component | Status | Evidence | File / Symbol | Why it matters | Proposed fix | Restoration |
|---|---|---|---|---|---|---|---|
| H-1 | `/health` | FAKE | Returns literal `"Healthy"` strings, no probes | `api/main.py` `health_check` | Operators cannot detect outages; frontend Infrastructure panel is fiction | Probe Postgres, Redis, Qdrant, MinIO, Ollama with timeouts; component status + overall | OPEN |
| A-1 | Route prefix | REAL (doc mismatch) | Routes are `/events/ingest`, `/investigations`, no `/api/v1` | `api/main.py` | Docs untruthful | Fix docs (prefix change is a breaking change; defer) | OPEN |
| A-2 | `POST /investigations/{id}/analyze` | BROKEN (unsafe) | Passes request-scoped `db` into `background_tasks.add_task(orchestrator.run_investigation, db, …)` | `api/investigations.py` `analyze_investigation` | Session lifetime owned by request; unsafe across tasks | Background task owns its own session; later Celery | OPEN |
| A-3 | `PATCH /investigations/{id}/status` | BROKEN | Accepts any enum value from any state, incl. `ANALYZING`, `WAITING_FOR_REVIEW` | `api/investigations.py` `update_investigation_status` | Analysts can fake analysis state; bypass review gate | Explicit transition table; 409 on invalid | OPEN |
| A-4 | Export PDF | PARTIAL | PDF "Executive Summary" is `case.description` (rule text), not SOC Lead output; frontend calls it via `window.open` without auth header → 401 | `export/report_generator.py`, `app/investigations/[id]/page.tsx` `handleExport` | Report and UI disagree; export button broken for authenticated API | Generate from persisted report; fetch with auth and download blob | OPEN |
| A-5 | Entity graph API | PARTIAL | Returns all entities/relationships globally, no per-case filter, entities deduped by name only | `api/investigations.py` `get_entity_graph` | Graph mixes unrelated cases | Per-case graph from evidence | OPEN |
| A-6 | Case management (notes/assign/severity/reopen/audit) | REAL | Tests pass; audit rows written | `api/investigations.py` | — | Add transition validation | — |
| A-7 | Auth (JWT, PBKDF2, RBAC) | REAL | `test_security_phase4a.py` | `core/auth.py`, `api/auth.py` | — | — | — |
| A-8 | Ingest API | REAL | API key constant-time compare, Redis rate limiter fail-closed, payload size cap | `api/ingest.py` | — | Metrics counters are process-local (PARTIAL) | — |
| A-9 | Replay API | PARTIAL | Start/pause/reset work; no resume; engines held in process dict `active_engines`; events not deduplicated across replays | `api/replay.py`, `replay/engine.py` | Duplicate evidence; multi-instance unsafe | Idempotent event IDs; document limits | OPEN |

## 4. Event Pipeline, Detection, Correlation

| ID | Component | Status | Evidence | File / Symbol | Why it matters | Proposed fix | Restoration |
|---|---|---|---|---|---|---|---|
| E-1 | Event bus | PARTIAL | `InMemoryEventBus` over `asyncio.Queue`; subscriber errors `print`ed and dropped | `core/events.py` | Lost on restart; single process only | Phase 10: Redis Streams | OPEN |
| E-2 | Event integrity hash | MISSING | No hash column on `events`; no SHA-256 over payload anywhere | `models/event.py` | Chain-of-custody claim is false | `payload_sha256` column + canonical JSON hashing + migration | OPEN |
| E-3 | Canonical event model | PARTIAL | `GenericJSONParser` returns ORM dict; `CanonicalEventType` taxonomy exists; no `CanonicalSecurityEvent` Pydantic model | `plugins/parsers/generic.py`, `core/taxonomy.py` | Connectors cannot target a stable contract | Phase 11 | OPEN |
| E-4 | Connectors (Sysmon, Suricata, Splunk HEC) | MISSING | `plugins/{agents,providers,replay,tools}` empty | `backend/plugins/` | Spec claims connector ecosystem | Phase 11 | OPEN |
| D-1 | Detection rules (4) | PARTIAL | Rules match; `DetectionEngine.process_event` returns on **first** matching rule; `SuspiciousProcessExecution` matches any `cmd.exe`/`powershell` command line | `detection/engine.py`, `detection/rules.py` | Multi-rule events lose detections; noisy | Evaluate all rules; tighten indicators | OPEN |
| D-2 | Detection state | PARTIAL | Brute-force and lateral-movement counters in process memory (`defaultdict`) | `detection/rules.py` `FailedLoginBruteForce.failed_logins`, `LateralMovement.user_hosts` | Two instances disagree; restart resets | Phase 10: Redis-backed windows | OPEN |
| D-3 | Sigma engine | PARTIAL | One YAML rule; only `contains`/`exact` selection; used only to bump importance score | `rules/sigma/engine.py` | Not a Sigma engine | Mark as partial | OPEN |
| D-4 | Network/C2 detection | MISSING | No rule for network connection / IDS alert; `NETWORK_TRAFFIC` never evaluated | `detection/rules.py` | Scenario 3 undetectable | Phase 13 | OPEN |
| C-1 | Correlation | PARTIAL | Matches `user_name` OR `hostname` within 24h of `updated_at` (wall clock), OPEN/ANALYZING only; no IP | `correlation/engine.py` `find_related_case` | Events arriving after review open duplicate cases; no network correlation | Add IP; define review-state merge policy | OPEN |
| C-2 | Investigation trigger | BROKEN | Every detection (new **or merged**) calls `asyncio.create_task(run_investigation)`; no lock. Reproduced: 2 concurrent investigations on case `09b762b7…` | `consumers/detection_consumer.py` `handle_event_stored` | Duplicate agent runs, racing status/report writes | Phase 5 lock; Phase 7 Celery | OPEN |

## 5. Agents & LLM

| ID | Component | Status | Evidence | File / Symbol | Why it matters | Proposed fix | Restoration |
|---|---|---|---|---|---|---|---|
| L-1 | LLM service config | FAKE (config) | `LLMService(model="llama3.1", base_url="http://host.docker.internal:11434")` constructor defaults; `settings.OLLAMA_MODEL/OLLAMA_BASE_URL` never read | `services/llm_service.py` | Configuration silently ignored | Provider built from settings | OPEN |
| L-2 | LLM failure handling | PARTIAL | Any exception → `print` + return `""`; no retry/backoff; no schema validation; agents `json.loads` raw text | `services/llm_service.py` `generate` | Transient failures become degraded agents | Phase 8 | OPEN |
| L-3 | Agent pipeline | REAL | Live replay: Memory → Triage/Timeline/ThreatIntel (concurrent) → SOC Lead completed with real LLM output | `agents/orchestrator.py` | Core value | — | — |
| L-4 | Agent execution confidence | FAKE | Hardcoded per agent: Timeline 0.9, ThreatIntel 0.85, SOC Lead 0.95, Memory 1.0 | `agents/*.py` `finish_execution(confidence=…)` | UI displays invented per-agent confidence | Derive or null | OPEN |
| L-5 | Degraded fallback content | PARTIAL | SOC Lead fallback emits 3 generic recommendations as report content; marked `degraded` in execution status only | `agents/report.py` | Fallback text can be mistaken for analysis | Typed degraded result, no invented recommendations | OPEN |
| L-6 | Triage guardrail | REAL | Prevents `LOW` when rule severity HIGH/CRITICAL (floors to MEDIUM) | `agents/triage.py` | Prompt-injection defense | Floor should be rule severity, not MEDIUM | OPEN |
| L-7 | Prompt sandboxing | REAL | `<untrusted_security_evidence>` tags + escape (spec says `<EVIDENCE_BOUNDARY>`) | `core/utils.py` | — | Fix docs | — |
| T-1 | Tool calls | FAKE | Only "tool" is `memory_search`; `emit_step("tool_call_complete")` creates `AgentToolCall(duration_ms=content.get("duration_ms", 850.0))`; no duration ever supplied → 67/67 rows = 850 | `agents/base.py` `emit_step`, `agents/threat_intel.py` | Fabricated performance data in UI | Measured tool runner | OPEN |
| T-2 | Execution metrics | FAKE (by omission) | `llm_execution_time_ms`, `tool_execution_time_ms`, `confidence_explanation` never written; UI renders `null/1000` as `0.00s` | `models/investigation.py` `AgentExecution`; `InvestigationExplorer.tsx` | UI shows 0.00s as if measured | Measure or display "Not available" | OPEN |
| V-1 | `evidence_ids` | MISSING | `emit_step(evidence_ids=None)` everywhere; not stored in `AgentReasoningStep`; WS replay hardcodes `[]` | `agents/base.py`, `websocket/investigation_ws.py` | No finding is traceable to evidence | Finding contract with validated evidence IDs | OPEN |
| V-2 | `EvidenceItem.related_agent` | MISSING | Never set → Explorer "Evidence" tab always empty | `api/investigations.py` `get_investigation_execution` | Empty UI tab | Use finding→evidence links | OPEN |
| R-1 | Report persistence | MISSING | SOC Lead JSON only lives inside `agent_reasoning_steps.content`; UI scrapes `decision_made` step; PDF uses `case.description` | `agents/report.py`, `app/reports/page.tsx` | Two sources of truth that disagree | `investigation_reports` table; UI+PDF read it | OPEN |
| M-1 | MITRE validation | BROKEN | `validate()` strips sub-technique (`T1059.001`→`T1059`); KB has ~12 entries | `security/mitre/knowledge_base.py` | Sub-techniques lost | Exact-ID lookup, parent fallback for name only | OPEN |
| S-1 | Confidence score | FAKE | `ConfidenceEngine.calculate_score(0.8, 0.7, p_score, 0.6)` — 3 of 4 inputs constants; 68/81 cases = 0.75 | `agents/orchestrator.py`, `scoring/confidence.py` | Headline number is fiction | Phase 9 derived formula | OPEN |

## 6. Memory

| ID | Component | Status | Evidence | File / Symbol | Why it matters | Proposed fix | Restoration |
|---|---|---|---|---|---|---|---|
| MEM-1 | IOC extraction | BROKEN | Filters `evidence_type in ('ip','domain','hash',...)`; detection emits `AUTHENTICATION_FAILURE`, `PROCESS_EXECUTION`, etc. → IOC sets always empty → identical `ioc_hash` for every case → `ioc_score=1.0` for every comparison | `agents/memory.py`, `agents/threat_intel.py`, `memory/knowledge_builder.py`, `api/investigations.py get_similar_investigations` | Every past case gets a false +0.15 similarity | Extract IOCs from linked events (IP, user, host, process, command); empty set → no IOC score | OPEN |
| MEM-2 | Indexing order | BROKEN | Qdrant upsert happens **before** Postgres insert; on FK failure the vector is orphaned | `memory/service.py` `index_knowledge` | Orphan vectors pollute retrieval | Postgres commit first, then Qdrant, mark indexed | OPEN |
| MEM-3 | Indexing task failure semantics | BROKEN | `except Exception: print` → task reports SUCCESS; no retry | `workers/tasks/memory_tasks.py` | Failures invisible | Raise, `autoretry_for`, backoff | OPEN |
| MEM-4 | Real memory content | BROKEN | 0 `investigation_memory` rows; 17 Qdrant points all from tests; 6 RESOLVED cases never indexed | DB/Qdrant | Memory Agent always returns "no matches" | Reindex resolved cases after fixes; purge orphans | OPEN |
| MEM-5 | Qdrant URL | FAKE (config) | `memory_service = InvestigationMemoryService(QdrantRepository())` → hardcoded `http://qdrant:6333`; `settings.QDRANT_URL` ignored | `memory/service.py` | Config ignored | Use settings | OPEN |
| MEM-6 | Self-match | PARTIAL | Memory Agent does not exclude the current case | `agents/memory.py` | Reopened resolved cases match themselves | Exclude own ID | OPEN |
| MEM-7 | `InvestigationMemory.investigation_id` lookup | PARTIAL | `scalar_one_or_none()` on all versions → raises `MultipleResultsFound` on 3rd index | `memory/service.py` | Reindex breaks after 2 versions | Filter `is_latest` | OPEN |

## 7. WebSocket / Realtime

| ID | Component | Status | Evidence | File / Symbol | Why it matters | Proposed fix | Restoration |
|---|---|---|---|---|---|---|---|
| W-1 | WS manager | PARTIAL | In-process `ScopedConnectionManager`; JWT via query param; replays stored steps on connect | `websocket/investigation_ws.py` | Worker processes cannot broadcast | Phase 6 Redis pub/sub fan-out | OPEN |
| W-2 | WS URL in frontend | PARTIAL | Hardcoded `ws://localhost:8000` | `context/LiveInvestigationContext.tsx` | Breaks outside localhost | Derive from `NEXT_PUBLIC_API_URL` | OPEN |

## 8. Tests

| ID | Component | Status | Evidence | File / Symbol | Why it matters | Proposed fix | Restoration |
|---|---|---|---|---|---|---|---|
| X-1 | Documented pytest command | BROKEN | 7 `ModuleNotFoundError` at collection | no `pytest.ini`/`conftest.py` | CI/devs cannot run tests | `pytest.ini` with `pythonpath = .` | OPEN |
| X-2 | Test isolation | BROKEN | Tests use `settings.DATABASE_URL` (dev DB); `test_celery_broker_dispatch_memory_indexing` sends real Celery task; `test_reopen_case_lifecycle` resolves without mocking `.delay` → worker FK failure; Qdrant test collections on dev Qdrant | `tests/test_memory_pipeline.py`, `tests/test_phase5_case_management.py` | Tests corrupt dev data | Test DB `yarox_test`, eager Celery, test Qdrant prefix, Redis DB 15, guard assertion | OPEN |
| X-3 | Mock-heavy tests | PARTIAL | Agent/evaluation tests patch `llm_service.generate`, use `AsyncMock` sessions | `evaluation/agent_eval.py`, several tests | Prove logic, not integration | Keep as unit tests; add real integration tests | OPEN |
| X-4 | Blocking sleep in async test | PARTIAL | `time.sleep(2)` inside async test | `tests/test_memory_pipeline.py` | Blocks loop | Remove with eager Celery | OPEN |

## 9. Frontend

| ID | Component | Status | Evidence | File / Symbol | Why it matters | Proposed fix | Restoration |
|---|---|---|---|---|---|---|---|
| F-1 | Embedded credentials | FAKE (security) | Auto-login with `analyst@yarox.local` / `YaroxAnalyst2026!` | `lib/api.ts` `getAuthToken` | Credential in client bundle; no real auth | Login page; token only from user login | OPEN |
| F-2 | Report recommended actions | FAKE | 6 hardcoded strings ("Disable compromised user account (jdoe)…", "Block 203.0.113.x…"), comment "demo data blended" | `app/reports/page.tsx` `recommendedActions` | Invented remediation shown as analysis | Render persisted report recommendations | OPEN |
| F-3 | Attack graph critical path | FAKE | `CRITICAL_LABELS = ["192.168.1.55","asmith","DB-SERVER-02","WmiPrvSE.exe"]` and label-specific layout nudges | `app/attack-graph/page.tsx` | Highlights attack path regardless of data | Backend graph; no invented criticality | OPEN |
| F-4 | Graph node tooltip | FAKE | Every node: "First seen: 2023-10-27 10:01:00 UTC", "Evidence Item" | `components/graph/CustomNodes.tsx` | Fabricated timestamps | Real first/last seen from backend | OPEN |
| F-5 | Dashboard agent cards | FAKE | `demoTasks` strings ("Reconstructing login sequence for jdoe", "Case #4A2F"); agents shown "active" whenever replay is playing; confidence fallback `87` | `app/page.tsx` `AGENTS`, `agentActive` | Agent activity invented | Derive from running executions | OPEN |
| F-6 | "N agents thinking" | FAKE | `activeAgentCount = isRunning ? 3 : 0` | `app/page.tsx` | Invented | Count running executions | OPEN |
| F-7 | "Live Gateway: Active" badge | FAKE | Static JSX | `app/page.tsx` | Invented status | Remove or use health | OPEN |
| F-8 | Infrastructure panel | FAKE (via H-1) | Reads hardcoded health | `app/page.tsx` | — | Real health | OPEN |
| F-9 | Architecture page | FAKE | Static `avgDuration: "~3s"`, `lastRun: "Active"` | `app/architecture/page.tsx` | Invented runtime metrics | Mark as static diagram, remove metrics | OPEN |
| F-10 | Explorer metrics | FAKE (by omission) | Renders `null` LLM/tool timings as `0.00s` | `components/InvestigationExplorer.tsx` | — | "Not available" | OPEN |
| F-11 | Investigation summary/timeline | PARTIAL | Scrapes reasoning steps (first `completed` execution; with duplicate runs picks arbitrary one) | `app/investigations/[id]/page.tsx` | Nondeterministic display | Read persisted report | OPEN |
| F-12 | Timeline "critical" highlighting | PARTIAL | Keyword heuristic on action text | `app/investigations/[id]/page.tsx` | Presentation heuristic, not evidence | Label as heuristic or remove | OPEN |
| F-13 | Events, evidence, investigations list pages | REAL | Read from API | `app/events`, `app/evidence`, `app/investigations` | — | — | — |

## 10. Repository Hygiene

| ID | Component | Status | Evidence | Why it matters | Proposed fix | Restoration |
|---|---|---|---|---|---|---|
| G-1 | Uncommitted work | PARTIAL | 30 modified files (+2784/-582), ~70 untracked incl. `core/auth.py`, `api/ingest.py`, `memory/*`, migrations, tests; HEAD commit `20cb693` imports untracked modules | Committed tree is not runnable; work at risk | Commit to restoration branch (media excluded) | OPEN |

---

## Restoration Log

Entries are appended per phase with evidence.
