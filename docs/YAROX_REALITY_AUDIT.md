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
| Agent executions (historical) | 390 total; 370 completed, 19 degraded, 1 other; degraded causes: 7 timeouts, 1 invalid JSON, 11 empty error |
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
| I-2 | MinIO healthcheck | BROKEN | Health log: `exec: "curl": executable file not found` every 30s | `docker-compose.yml` minio.healthcheck | Permanent false "unhealthy"; masks real failures | Use `mc ready local` | **FIXED (Phase 2)** — `mc ready local`; container reports healthy |
| I-3 | MinIO usage | MISSING | No code imports a MinIO/S3 client; not in `requirements.txt` | — | Spec claims artifact storage | Either implement artifact store or mark not implemented | OPEN |
| I-4 | Celery worker | PARTIAL | Only `tasks.index_resolved_investigation_task` registered | `workers/celery_app.py` | Investigations run in API process | Phase 7 | **FIXED (Phase 7)** — `workers.tasks.investigation_tasks.run_investigation_task` registered and running investigations; `celery_worker` is now a required health component |
| I-5 | Celery worker env | PARTIAL | Worker lacks `OLLAMA_BASE_URL`, `JWT_SECRET_KEY` env; `depends_on` not health-gated | `docker-compose.yml` celery_worker | Worker LLM calls use defaults; startup races | Share env block; gate on health | PARTIAL (Phase 2) — worker now receives `OLLAMA_BASE_URL`/`OLLAMA_MODEL`; health-gated `depends_on` OPEN |
| I-6 | Python version | REAL (doc mismatch) | Container is 3.12; CLAUDE.md says 3.11 | `backend/Dockerfile` | Docs untruthful | Fix docs | OPEN |
| I-7 | Frontend version | REAL (doc mismatch) | `next@16.2.10`, docs say Next 15 | `frontend/package.json` | Docs untruthful | Fix docs | OPEN |
| I-8 | Stray files | — | `backend/yarox.db` (0 bytes), `test_ws.py` (unauthenticated WS script, will be rejected), 260MB of video in `assets/`,`media/` untracked | repo root | Repo hygiene | Keep media out of git; move/delete stray scripts with owner approval | OPEN |

## 3. API Layer

| ID | Component | Status | Evidence | File / Symbol | Why it matters | Proposed fix | Restoration |
|---|---|---|---|---|---|---|---|
| H-1 | `/health` | FAKE | Returns literal `"Healthy"` strings, no probes | `api/main.py` `health_check` | Operators cannot detect outages; frontend Infrastructure panel is fiction | Probe Postgres, Redis, Qdrant, MinIO, Ollama with timeouts; component status + overall | **FIXED (Phase 2)** — `core/health.py` live probes; 503 when required component down |
| A-1 | Route prefix | REAL (doc mismatch) | Routes are `/events/ingest`, `/investigations`, no `/api/v1` | `api/main.py` | Docs untruthful | Fix docs (prefix change is a breaking change; defer) | OPEN |
| A-2 | `POST /investigations/{id}/analyze` | BROKEN (unsafe) | Passes request-scoped `db` into `background_tasks.add_task(orchestrator.run_investigation, db, …)` | `api/investigations.py` `analyze_investigation` | Session lifetime owned by request; unsafe across tasks | Background task owns its own session; later Celery | **FIXED (Phase 5)** — `services/investigation_runner.py` owns its session; the request session is never passed to a background task |
| A-3 | `PATCH /investigations/{id}/status` | BROKEN | Accepts any enum value from any state, incl. `ANALYZING`, `WAITING_FOR_REVIEW` | `api/investigations.py` `update_investigation_status` | Analysts can fake analysis state; bypass review gate | Explicit transition table; 409 on invalid | **FIXED (Phase 5)** — `core/case_state.py` transition table; invalid transitions return 409 and write no audit entry |
| A-4 | Export PDF | PARTIAL | PDF "Executive Summary" is `case.description` (rule text), not SOC Lead output; frontend calls it via `window.open` without auth header → 401 | `export/report_generator.py`, `app/investigations/[id]/page.tsx` `handleExport` | Report and UI disagree; export button broken for authenticated API | Generate from persisted report; fetch with auth and download blob | **FIXED (Phase 3)** — PDF rendered from persisted `InvestigationReport`; frontend downloads via authenticated blob request |
| A-5 | Entity graph API | PARTIAL | Returns all entities/relationships globally, no per-case filter, entities deduped by name only | `api/investigations.py` `get_entity_graph` | Graph mixes unrelated cases | Per-case graph from evidence | OPEN |
| A-6 | Case management (notes/assign/severity/reopen/audit) | REAL | Tests pass; audit rows written | `api/investigations.py` | — | Add transition validation | — |
| A-7 | Auth (JWT, PBKDF2, RBAC) | REAL | `test_security_phase4a.py` | `core/auth.py`, `api/auth.py` | — | — | — |
| A-8 | Ingest API | REAL | API key constant-time compare, Redis rate limiter fail-closed, payload size cap | `api/ingest.py` | — | Metrics counters are process-local (PARTIAL) | — |
| A-9 | Replay API | PARTIAL | Start/pause/reset work; no resume; engines held in process dict `active_engines`; events not deduplicated across replays | `api/replay.py`, `replay/engine.py` | Duplicate evidence; multi-instance unsafe | Idempotent event IDs; document limits | OPEN |

## 4. Event Pipeline, Detection, Correlation

| ID | Component | Status | Evidence | File / Symbol | Why it matters | Proposed fix | Restoration |
|---|---|---|---|---|---|---|---|
| E-1 | Event bus | PARTIAL | `InMemoryEventBus` over `asyncio.Queue`; subscriber errors `print`ed and dropped | `core/events.py` | Lost on restart; single process only | Phase 10: Redis Streams | OPEN |
| E-2 | Event integrity hash | MISSING | No hash column on `events`; no SHA-256 over payload anywhere | `models/event.py` | Chain-of-custody claim is false | `payload_sha256` column + canonical JSON hashing + migration | **FIXED (Phase 2)** — `events.payload_sha256`, `core/integrity.py`, `GET /events/{id}/integrity`; legacy rows NULL |
| E-3 | Canonical event model | PARTIAL | `GenericJSONParser` returns ORM dict; `CanonicalEventType` taxonomy exists; no `CanonicalSecurityEvent` Pydantic model | `plugins/parsers/generic.py`, `core/taxonomy.py` | Connectors cannot target a stable contract | Phase 11 | OPEN |
| E-4 | Connectors (Sysmon, Suricata, Splunk HEC) | MISSING | `plugins/{agents,providers,replay,tools}` empty | `backend/plugins/` | Spec claims connector ecosystem | Phase 11 | OPEN |
| D-1 | Detection rules (4) | PARTIAL | Rules match; `DetectionEngine.process_event` returns on **first** matching rule; `SuspiciousProcessExecution` matches any `cmd.exe`/`powershell` command line | `detection/engine.py`, `detection/rules.py` | Multi-rule events lose detections; noisy | Evaluate all rules; tighten indicators | OPEN |
| D-2 | Detection state | PARTIAL | Brute-force and lateral-movement counters in process memory (`defaultdict`) | `detection/rules.py` `FailedLoginBruteForce.failed_logins`, `LateralMovement.user_hosts` | Two instances disagree; restart resets | Phase 10: Redis-backed windows | OPEN |
| D-3 | Sigma engine | PARTIAL | One YAML rule; only `contains`/`exact` selection; used only to bump importance score | `rules/sigma/engine.py` | Not a Sigma engine | Mark as partial | OPEN |
| D-4 | Network/C2 detection | MISSING | No rule for network connection / IDS alert; `NETWORK_TRAFFIC` never evaluated | `detection/rules.py` | Scenario 3 undetectable | Phase 13 | OPEN |
| D-5 | Insider-threat detection coverage | MISSING | Live replay of `datasets/insider_threat` (7-Zip staging of HR data, then a 15 MB upload to 203.0.113.50) produced **no detection and no case**: no rule covers file access, archive staging or data egress | `detection/rules.py` | A shipped dataset that the product cannot detect at all | Add data-staging/exfiltration rules (Phase 13 scenarios) or mark the dataset unsupported | OPEN |
| W-3 | Worker lazy imports | BROKEN | On the live worker, `from agents.orchestrator import …` inside the task body raised `ModuleNotFoundError: No module named 'agents'` in every forked child (backend packages are namespace packages; eager/in-process execution worked, so tests passed) | `workers/tasks/investigation_tasks.py` | Every worker investigation failed after 3 retries | Import at module scope (parent imports at startup, children inherit) + explicit `sys.path` in `workers/celery_app.py` | **FIXED (Phase 7)** |
| DB-2 | Cross-loop clients in workers | BROKEN | Agents used the module-level SQLAlchemy engine and the global Qdrant client, both bound to the loop that created them; the worker runs `asyncio.run` per task, so the second task failed ("attached to a different loop" / "bound to a different event loop") | `agents/orchestrator.py`, `memory/vector_repository.py` | Worker investigations fail from the second task onward | Session factory passed into the orchestrator (task uses its NullPool engine); Qdrant client created per event loop | **FIXED (Phase 7)** |
| C-1 | Correlation | PARTIAL | Matches `user_name` OR `hostname` within 24h of `updated_at` (wall clock), OPEN/ANALYZING only; no IP | `correlation/engine.py` `find_related_case` | Events arriving after review open duplicate cases; no network correlation | Add IP; define review-state merge policy | OPEN |
| C-2 | Investigation trigger | BROKEN | Every detection (new **or merged**) calls `asyncio.create_task(run_investigation)`; no lock. Reproduced: 2 concurrent investigations on case `09b762b7…` | `consumers/detection_consumer.py` `handle_event_stored` | Duplicate agent runs, racing status/report writes | Phase 5 lock; Phase 7 Celery | **FIXED (Phase 5)** — Redis per-case lock with TTL + heartbeat; concurrent attempts record a re-run request instead of starting a duplicate; verified live (sequential passes) |

## 5. Agents & LLM

| ID | Component | Status | Evidence | File / Symbol | Why it matters | Proposed fix | Restoration |
|---|---|---|---|---|---|---|---|
| L-1 | LLM service config | FAKE (config) | `LLMService(model="llama3.1", base_url="http://host.docker.internal:11434")` constructor defaults; `settings.OLLAMA_MODEL/OLLAMA_BASE_URL` never read | `services/llm_service.py` | Configuration silently ignored | Provider built from settings | **FIXED (Phase 2/8)** — provider abstraction (ollama/vllm/anthropic) built from settings; external providers require explicit opt-in |
| L-2 | LLM failure handling | PARTIAL | Any exception → `print` + return `""`; no retry/backoff; no schema validation; agents `json.loads` raw text | `services/llm_service.py` `generate` | Transient failures become degraded agents | Phase 8 | **FIXED (Phase 8)** — schema-validated generation with retries, corrective feedback, typed errors and bounded concurrency |
| L-3 | Agent pipeline | REAL | Live replay: Memory → Triage/Timeline/ThreatIntel (concurrent) → SOC Lead completed with real LLM output | `agents/orchestrator.py` | Core value | — | — |
| L-4 | Agent execution confidence | FAKE | Hardcoded per agent: Timeline 0.9, ThreatIntel 0.85, SOC Lead 0.95, Memory 1.0 | `agents/*.py` `finish_execution(confidence=…)` | UI displays invented per-agent confidence | Derive or null | **FIXED (Phase 9)** — per-agent confidence is the share of proposed findings that passed evidence validation; agents that propose nothing report NULL |
| L-5 | Degraded fallback content | PARTIAL | SOC Lead fallback emits 3 generic recommendations as report content; marked `degraded` in execution status only | `agents/report.py` | Fallback text can be mistaken for analysis | Typed degraded result, no invented recommendations | **FIXED (Phase 3)** — degraded SOC Lead yields `executive_summary=null`, no recommendations, report status `degraded` |
| L-6 | Triage guardrail | REAL | Prevents `LOW` when rule severity HIGH/CRITICAL (floors to MEDIUM) | `agents/triage.py` | Prompt-injection defense | Floor should be rule severity, not MEDIUM | **FIXED (Phase 3)** — floor is the deterministic rule severity (LLM cannot lower CRITICAL/HIGH at all) |
| L-7 | Prompt sandboxing | REAL | `<untrusted_security_evidence>` tags + escape (spec says `<EVIDENCE_BOUNDARY>`) | `core/utils.py` | — | Fix docs | — |
| T-1 | Tool calls | FAKE | Only "tool" is `memory_search`; `emit_step("tool_call_complete")` creates `AgentToolCall(duration_ms=content.get("duration_ms", 850.0))`; no duration ever supplied → 67/67 rows = 850 | `agents/base.py` `emit_step`, `agents/threat_intel.py` | Fabricated performance data in UI | Measured tool runner | **FIXED (Phase 2)** — `BaseAgent.run_tool` measures `perf_counter` duration, start/end, status, error; `emit_step` no longer fabricates tool calls |
| T-2 | Execution metrics | FAKE (by omission) | `llm_execution_time_ms`, `tool_execution_time_ms`, `confidence_explanation` never written; UI renders `null/1000` as `0.00s` | `models/investigation.py` `AgentExecution`; `InvestigationExplorer.tsx` | UI shows 0.00s as if measured | Measure or display "Not available" | **FIXED (Phase 2/9)** — LLM and tool time measured; `confidence_explanation` now carries the acceptance basis and counts |
| V-1 | `evidence_ids` | MISSING | `emit_step(evidence_ids=None)` everywhere; not stored in `AgentReasoningStep`; WS replay hardcodes `[]` | `agents/base.py`, `websocket/investigation_ws.py` | No finding is traceable to evidence | Finding contract with validated evidence IDs | **FIXED (Phase 3)** — `agent_findings` + `agent_finding_evidence` (FK to evidence_items); citations validated; `agent_reasoning_steps.evidence_ids` persisted and streamed |
| V-2 | `EvidenceItem.related_agent` | MISSING | Never set → Explorer "Evidence" tab always empty | `api/investigations.py` `get_investigation_execution` | Empty UI tab | Use finding→evidence links | **FIXED (Phase 3)** — execution evidence derived from that execution's findings |
| R-1 | Report persistence | MISSING | SOC Lead JSON only lives inside `agent_reasoning_steps.content`; UI scrapes `decision_made` step; PDF uses `case.description` | `agents/report.py`, `app/reports/page.tsx` | Two sources of truth that disagree | `investigation_reports` table; UI+PDF read it | **FIXED (Phase 3)** — `investigation_reports` (versioned, `is_current`); `/report`, `/reports`, `/findings`, `/export` and UI read it |
| M-1 | MITRE validation | BROKEN | `validate()` strips sub-technique (`T1059.001`→`T1059`); KB has ~12 entries | `security/mitre/knowledge_base.py` | Sub-techniques lost | Exact-ID lookup, parent fallback for name only | **FIXED (Phase 2)** — exact-ID validation; KB expanded to 31 entries; unknown sub-techniques recorded at parent with explicit reason |
| S-1 | Confidence score | FAKE | `ConfidenceEngine.calculate_score(0.8, 0.7, p_score, 0.6)` — 3 of 4 inputs constants; 68/81 cases = 0.75 | `agents/orchestrator.py`, `scoring/confidence.py` | Headline number is fiction | Phase 9 derived formula | **FIXED (Phase 9)** — six measured components with weights, values, details and contributions stored in `confidence_breakdown` |
| L-7b | Evidence truncation in prompts | BROKEN | `sanitize_evidence(max_length=2000)` truncated the serialized evidence list mid-item, silently dropping later evidence (and, after Phase 3, their IDs) from every agent prompt | `core/utils.py`, all agents | Agents analyzed a subset of evidence without knowing | Per-field clipping, max 40 items (earliest first) with explicit `omitted_item_count`, 20k block budget | **FIXED (Phase 3/8)** — per-field clipping plus explicit `num_ctx` so the model server no longer silently truncates long prompts |
| L-8 | Threat Intel degraded fallback | FAKE | On failure returned `historical_insight: "No prior matching incidents in verified investigation memory."` — a claim about a search that may not have run | `agents/threat_intel.py` | False negative presented as fact | `historical_insight=null`; statement only when memory search actually returned no results | **FIXED (Phase 3)** |
| L-9 | Local LLM capacity under concurrent agents | BROKEN | Live run 19:05: Triage, Timeline and Threat Intel all hit the 120 s timeout in both (duplicate) investigations — 6 concurrent `llama3.1` requests to one local Ollama with evidence-contract prompts | `agents/orchestrator.py`, `services/llm_service.py` | Analytic agents degrade under real load | Phase 5 (no duplicate runs) + Phase 8 (bounded LLM concurrency, context size, retries/backoff) | **FIXED (Phase 5/8)** — duplicate runs removed and LLM concurrency bounded (`LLM_MAX_CONCURRENCY=2`); all agents completed in the live runs after both changes |
| S-2 | ATT&CK technique confidence | FAKE | `AttackTechnique.confidence` hardcoded: 0.8 (detection), 0.9 (threat intel) | `detection/engine.py`, `agents/threat_intel.py` | Invented per-technique confidence | Phase 9 | **FIXED (Phase 9)** — 1.0 for deterministic rule matches, NULL for agent-proposed mappings (column made nullable) |

## 6. Memory

| ID | Component | Status | Evidence | File / Symbol | Why it matters | Proposed fix | Restoration |
|---|---|---|---|---|---|---|---|
| MEM-1 | IOC extraction | BROKEN | Filters `evidence_type in ('ip','domain','hash',...)`; detection emits `AUTHENTICATION_FAILURE`, `PROCESS_EXECUTION`, etc. → IOC sets always empty → identical `ioc_hash` for every case → `ioc_score=1.0` for every comparison | `agents/memory.py`, `agents/threat_intel.py`, `memory/knowledge_builder.py`, `api/investigations.py get_similar_investigations` | Every past case gets a false +0.15 similarity | Extract IOCs from linked events (IP, user, host, process, command); empty set → no IOC score | **FIXED (Phase 4)** — `memory/indicators.py` extracts IPs/domains/hashes/users/hosts/processes/commands from linked events; empty IOC set ⇒ `ioc_hash = None` (never a match) |
| MEM-2 | Indexing order | BROKEN | Qdrant upsert happens **before** Postgres insert; on FK failure the vector is orphaned | `memory/service.py` `index_knowledge` | Orphan vectors pollute retrieval | Postgres commit first, then Qdrant, mark indexed | **FIXED (Phase 4)** — PostgreSQL record committed first, then vector, then `vector_indexed_at`; retrieval only accepts hits matching the latest indexed record |
| MEM-3 | Indexing task failure semantics | BROKEN | `except Exception: print` → task reports SUCCESS; no retry | `workers/tasks/memory_tasks.py` | Failures invisible | Raise, `autoretry_for`, backoff | **FIXED (Phase 4)** — task raises, `autoretry_for` with exponential backoff (max 5), logs; unresolved cases refused |
| MEM-4 | Real memory content | BROKEN | 0 `investigation_memory` rows; 17 Qdrant points all from tests; 6 RESOLVED cases never indexed | DB/Qdrant | Memory Agent always returns "no matches" | Reindex resolved cases after fixes; purge orphans | **FIXED (Phase 4)** — 17 orphan vectors deleted, 6 resolved cases indexed, real report-sourced record verified live |
| MEM-5 | Qdrant URL | FAKE (config) | `memory_service = InvestigationMemoryService(QdrantRepository())` → hardcoded `http://qdrant:6333`; `settings.QDRANT_URL` ignored | `memory/service.py` | Config ignored | Use settings | **FIXED (Phase 1/4)** — settings-driven collection and URL |
| MEM-6 | Self-match | PARTIAL | Memory Agent does not exclude the current case | `agents/memory.py` | Reopened resolved cases match themselves | Exclude own ID | **FIXED (Phase 4)** — `exclude_investigation_id` in every caller; verified live (self-query returns 0 matches) |
| MEM-7 | `InvestigationMemory.investigation_id` lookup | PARTIAL | `scalar_one_or_none()` on all versions → raises `MultipleResultsFound` on 3rd index | `memory/service.py` | Reindex breaks after 2 versions | Filter `is_latest` | **FIXED (Phase 4)** — queries filter `is_latest`; partial unique index enforces one latest record per investigation |
| MEM-8 | Global singleton mutation | BROKEN | `index_resolved_investigation_task` replaced `memory_service.vector_repo` with a client bound to the task's short-lived event loop; any later in-process memory call failed with `Event loop is closed` (reproduced: ThreatIntel agent degraded in test run after indexing task) | `workers/tasks/memory_tasks.py` | Silent degradation of memory-backed agents in any process that also runs the task | Task-local `InvestigationMemoryService` sharing the embedding model | **FIXED (Phase 1)** — regression assertion in `test_celery_broker_dispatch_memory_indexing` |
| MEM-9 | LLM summarization at index time | FAKE | `KnowledgeBuilder` called the LLM when a case was resolved, inventing `attack_type`/`campaign`/`lessons_learned` (fallback text "Verified incident recorded in long-term memory."); unreviewed model output entered long-term memory, bypassing the human review gate | `memory/knowledge_builder.py` | Memory contents did not match what the analyst reviewed | Build knowledge from the persisted report (or evidence only, labelled `case_evidence`); no LLM at index time | **FIXED (Phase 4)** |
| MEM-10 | Semantic-only false matches | BROKEN | Measured: unrelated security texts score 0.24–0.39 total (semantic 0.49–0.78) because the embedding model gives any two security summaries a high baseline; these were shown as "Historical Intelligence Matches" | `memory/service.py` | Unrelated cases presented as historical precedent | Weighted score + `MEMORY_MIN_SIMILARITY = 0.45`; overlaps (technique/IOC/asset) carry the match | **FIXED (Phase 4)** |

## 7. WebSocket / Realtime

| ID | Component | Status | Evidence | File / Symbol | Why it matters | Proposed fix | Restoration |
|---|---|---|---|---|---|---|---|
| W-1 | WS manager | PARTIAL | In-process `ScopedConnectionManager`; JWT via query param; replays stored steps on connect | `websocket/investigation_ws.py` | Worker processes cannot broadcast | Phase 6 Redis pub/sub fan-out | **FIXED (Phase 6)** — events published to Redis pub/sub; each API process subscribes and fans out locally; `/health` reports the bridge |
| W-2 | WS URL in frontend | PARTIAL | Hardcoded `ws://localhost:8000` | `context/LiveInvestigationContext.tsx` | Breaks outside localhost | Derive from `NEXT_PUBLIC_API_URL` | OPEN |

## 8. Tests

| ID | Component | Status | Evidence | File / Symbol | Why it matters | Proposed fix | Restoration |
|---|---|---|---|---|---|---|---|
| X-1 | Documented pytest command | BROKEN | 7 `ModuleNotFoundError` at collection | no `pytest.ini`/`conftest.py` | CI/devs cannot run tests | `pytest.ini` with `pythonpath = .` | **FIXED (Phase 1)** |
| X-2 | Test isolation | BROKEN | Tests use `settings.DATABASE_URL` (dev DB); `test_celery_broker_dispatch_memory_indexing` sends real Celery task; `test_reopen_case_lifecycle` resolves without mocking `.delay` → worker FK failure; Qdrant test collections on dev Qdrant | `tests/test_memory_pipeline.py`, `tests/test_phase5_case_management.py` | Tests corrupt dev data | Test DB `yarox_test`, isolated Celery broker, test Qdrant prefix, Redis DB 15, guard assertion | **FIXED (Phase 1)** |
| X-3 | Mock-heavy tests | PARTIAL | Agent/evaluation tests patch `llm_service.generate`, use `AsyncMock` sessions | `evaluation/agent_eval.py`, several tests | Prove logic, not integration | Keep as unit tests; add real integration tests | OPEN |
| X-4 | Blocking sleep in async test | PARTIAL | `time.sleep(2)` inside async test | `tests/test_memory_pipeline.py` | Blocks loop | Replaced with `asyncio.sleep` + in-process test worker | **FIXED (Phase 1)** |
| X-5 | Alembic migrations | BROKEN | `alembic upgrade head` on an empty database fails: base revision `f070db4817a2` is empty (`pass`), `8532d6f9c999` is empty, `cba64ddf4a02` alters non-existent `investigation_cases`, `24d74fa147f3` reads legacy `agent_actions`. Real schema only exists because `api/main.py` runs `Base.metadata.create_all` at startup | `alembic/versions/*` | Fresh deployments cannot be built from migrations; schema changes are unmanaged | Squash into a baseline under ID `7a3e8b1d9c4f` (**blocked: requires owner approval to delete historical migration files**). Interim: fresh DBs built with `create_all` + `alembic stamp head`; new migrations are additive and tested from a frozen baseline | PARTIAL — `scripts/migrate.py` is now the only schema owner (empty DB: create_all+stamp; else upgrade); app startup no longer runs `create_all` and refuses an outdated schema. Squash of historical chain still needs owner approval |
| X-6 | Model / schema drift | BROKEN | Migrated dev schema has `ON DELETE SET NULL` on `investigation_cases.assigned_to_user_id`/`resolved_by_user_id`; models had no `ondelete`. Dev DB is also **missing** `ix_investigation_cases_assigned_to_user_id` and `ix_investigation_cases_resolved_by_user_id` that the model declares | `models/investigation.py` | Tests built from models diverge from production schema | Models aligned (`ondelete="SET NULL"`); missing indexes to be added by next migration | **FIXED (Phase 2)** — FK aligned (Phase 1); migration `b7c1e2d3f4a5` creates missing indexes (verified in dev `pg_indexes`) |
| X-7 | Historical dev-data contamination | BROKEN | Dev DB contains 27 users (3 seeded) and test-titled cases/Qdrant points from pre-isolation test runs | dev Postgres/Qdrant | Dev data is not trustworthy | Owner decision on cleanup; orphan vectors handled in Phase 4 | OPEN |

## 9. Frontend


| ID | Component | Status | Evidence | File / Symbol | Why it matters | Proposed fix | Restoration |
|---|---|---|---|---|---|---|---|
| F-1 | Embedded credentials | FAKE (security) | Auto-login with `analyst@yarox.local` / `YaroxAnalyst2026!` | `lib/api.ts` `getAuthToken` | Credential in client bundle; no real auth | Login page; token only from user login | OPEN |
| F-2 | Report recommended actions | FAKE | 6 hardcoded strings ("Disable compromised user account (jdoe)…", "Block 203.0.113.x…"), comment "demo data blended" | `app/reports/page.tsx` `recommendedActions` | Invented remediation shown as analysis | Render persisted report recommendations | **FIXED (Phase 3)** — reports page renders persisted recommendations with evidence refs; hardcoded list deleted |
| F-3 | Attack graph critical path | FAKE | `CRITICAL_LABELS = ["192.168.1.55","asmith","DB-SERVER-02","WmiPrvSE.exe"]` and label-specific layout nudges | `app/attack-graph/page.tsx` | Highlights attack path regardless of data | Backend graph; no invented criticality | OPEN |
| F-4 | Graph node tooltip | FAKE | Every node: "First seen: 2023-10-27 10:01:00 UTC", "Evidence Item" | `components/graph/CustomNodes.tsx` | Fabricated timestamps | Real first/last seen from backend | OPEN |
| F-5 | Dashboard agent cards | FAKE | `demoTasks` strings ("Reconstructing login sequence for jdoe", "Case #4A2F"); agents shown "active" whenever replay is playing; confidence fallback `87` | `app/page.tsx` `AGENTS`, `agentActive` | Agent activity invented | Derive from running executions | OPEN |
| F-6 | "N agents thinking" | FAKE | `activeAgentCount = isRunning ? 3 : 0` | `app/page.tsx` | Invented | Count running executions | OPEN |
| F-7 | "Live Gateway: Active" badge | FAKE | Static JSX | `app/page.tsx` | Invented status | Remove or use health | OPEN |
| F-8 | Infrastructure panel | FAKE (via H-1) | Reads hardcoded health | `app/page.tsx` | — | Real health | **FIXED (Phase 2)** — dashboard renders `components` with live status/detail |
| F-9 | Architecture page | FAKE | Static `avgDuration: "~3s"`, `lastRun: "Active"` | `app/architecture/page.tsx` | Invented runtime metrics | Mark as static diagram, remove metrics | OPEN |
| F-10 | Explorer metrics | FAKE (by omission) | Renders `null` LLM/tool timings as `0.00s` | `components/InvestigationExplorer.tsx` | — | "Not available" | OPEN |
| F-11 | Investigation summary/timeline | PARTIAL | Scrapes reasoning steps (first `completed` execution; with duplicate runs picks arbitrary one) | `app/investigations/[id]/page.tsx` | Nondeterministic display | Read persisted report | **FIXED (Phase 3)** — detail and reports pages read `/investigations/{id}/report` |
| F-12 | Timeline "critical" highlighting | PARTIAL | Keyword heuristic on action text | `app/investigations/[id]/page.tsx` | Presentation heuristic, not evidence | Label as heuristic or remove | **FIXED (Phase 3)** — keyword 'critical' highlighting removed from report timeline |
| F-13 | Events, evidence, investigations list pages | REAL | Read from API | `app/events`, `app/evidence`, `app/investigations` | — | — | — |
| F-14 | TypeScript errors | BROKEN | `tsc --noEmit`: `investigations/[id]/page.tsx` uses non-existent `evt.type`/`evt.content`; `lib/api.ts` assigns `string \| null` to `string` | frontend | Type safety hides real contract mismatches | Fix with Phase 14 contract cleanup | OPEN |

## 10. Repository Hygiene

| ID | Component | Status | Evidence | Why it matters | Proposed fix | Restoration |
|---|---|---|---|---|---|---|
| G-1 | Uncommitted work | PARTIAL | 30 modified files (+2784/-582), ~70 untracked incl. `core/auth.py`, `api/ingest.py`, `memory/*`, migrations, tests; HEAD commit `20cb693` imports untracked modules | Committed tree is not runnable; work at risk | Commit to restoration branch (media excluded) | **FIXED (Phase 1)** — branch `restoration/truthful-yarox`, commit `e0ed88e` |

---

## Restoration Log

Entries are appended per phase with evidence.

### Phase 1 — Test isolation + safety (2026-09-17)

**Changed**
- Branch `restoration/truthful-yarox`; pre-restoration work preserved in commit `e0ed88e` (videos `assets/url-shortner.mp4`, `media/YAROX PH2 DEMO.mov` and stray `test_ws.py`/`backend/yarox.db` intentionally left untracked, not deleted).
- `backend/pytest.ini`: `pythonpath = .`, `testpaths = tests`.
- `backend/conftest.py`: overrides env before settings load → `DATABASE_URL=…/yarox_test`, `REDIS_URL`/Celery broker/result backend → Redis DB 15, `QDRANT_COLLECTION=test_investigation_memory`; aborts if DB name lacks `_test`, Redis DB ≠ 15, or collection lacks `test_`; recreates test schema (`create_all` + `alembic stamp head`); purges `test_*` Qdrant collections and flushes Redis DB 15 at start/end; session-scoped event loop (production parity: one loop per process).
- `tests/support/celery.py`: in-process Celery worker bound to the isolated broker. Celery is **not** run eager: tasks call `asyncio.run`, which cannot run inside an async test's loop; the isolated broker plus explicit in-process worker exercises the real broker path instead.
- `tests/test_test_isolation.py`: proves settings/engine/Celery/Qdrant point at test infrastructure and that a committed write is absent from the development database (read-only check).
- `test_celery_broker_dispatch_memory_indexing` now uses the in-process test worker (previously dispatched to the development worker and wrote to development Postgres/Qdrant).
- `core/config.py`: `QDRANT_COLLECTION`; `memory/service.py` uses `settings.QDRANT_URL`/`QDRANT_COLLECTION` (MEM-5).
- `models/investigation.py`: FK `ondelete="SET NULL"` to match migrated schema (X-6).
- `workers/tasks/memory_tasks.py`: task-local memory service; global singleton no longer mutated (MEM-8).

**Tests run**
- `docker compose exec backend pytest -v tests/` → **73 passed** (71 pre-existing + 2 isolation tests), run 3 times consecutively.
- Guard: `TEST_DATABASE_URL=…/yarox pytest` → `Exit: Refusing to run tests against non-test database 'yarox'`.

**Verified isolation (before vs after two full runs)**
- Dev Postgres: cases 82, events 205, memory 0, users 27, audit 0, notes 0, executions 400 — identical.
- Dev Qdrant `investigation_memory`: 17 points — identical; collections `['investigation_memory','investigations']` — identical.
- Dev Celery worker `received` log count: 18 — identical (no test task reached it).
- Schema diff dev vs test: identical tables/columns/types/FK rules; column order differs; dev missing 2 indexes (X-6).

**Remaining / newly discovered**
- X-5 migrations cannot build a fresh DB; squash needs owner approval (file deletion was blocked).
- X-6 dev DB missing two indexes.
- X-7 dev data contaminated by historical test runs.
- Many tests remain mock-based unit tests (X-3); real integration tests arrive with later phases.

### Phase 2 — Remove fake system behavior (2026-09-17)

**Scope decision.** Per the mandated development order, Phase 2 covers health, tool/LLM timing, event integrity, MITRE identifiers and configuration truthfulness. Confidence scoring (S-1, L-4) is Phase 9; reports/evidence (R-1, V-1) are Phase 3; frontend fakes other than the health panel are Phase 14.

**Changed**
- `core/health.py` + `/health`: concurrent live probes with per-probe timeout — Postgres (`SELECT 1` + Alembic revision vs script head), Redis `PING`, Qdrant collection existence/point count, in-process event bus worker state, Ollama `/api/tags` + configured model installed, Celery `control.ping`, MinIO `/minio/health/live`. Required: postgres, redis, qdrant, event_bus. Overall `down` → HTTP 503; `degraded` → 200.
- `docker-compose.yml`: MinIO healthcheck `mc ready local`; `OLLAMA_MODEL` to backend; `OLLAMA_BASE_URL`/`OLLAMA_MODEL` to worker.
- `services/llm_service.py`: model/base URL from settings.
- `agents/base.py`: `run_tool()` measures real duration and records `started_at`, `completed_at`, `status`, `error_message`, input/output metadata; accumulates `tool_execution_time_ms`. `call_llm_with_timeout(execution=…)` accumulates measured `llm_execution_time_ms`. The fabricated `AgentToolCall(duration_ms=850)` path was deleted.
- `agents/memory.py`, `agents/threat_intel.py`: memory search runs through `run_tool` (Memory Agent's search was previously unrecorded).
- `core/integrity.py`, `models/event.py`, `consumers/db_writer.py`, `api/events.py`: SHA-256 event hashing (canonicalization documented in module docstring), hash at first storage, verification endpoint.
- `security/mitre/*`, `agents/threat_intel.py`: exact technique/sub-technique validation; prompt asks for most specific ID.
- Migration `b7c1e2d3f4a5` (events hash, tool call timing columns, missing dev indexes); `alembic/env.py` accepts explicit URL; `tests/support/baseline_schema.py` frozen schema at `7a3e8b1d9c4f`.
- Frontend dashboard infrastructure panel reads live `components`.

**Tests**
- New: `test_health.py` (5), `test_tool_call_measurement.py` (3), `test_event_integrity.py` (12), `test_mitre_techniques.py` (12 incl. parametrized), `test_migrations.py` (1).
- `docker compose exec backend pytest -v tests/` → **107 passed**.
- Migration test negative control (baseline without upgrade) reports 5 schema diffs → test is meaningful.

**Verified on the running system**
- `alembic upgrade head` on dev DB: `7a3e8b1d9c4f -> b7c1e2d3f4a5`; `ix_investigation_cases_assigned_to_user_id` / `_resolved_by_user_id` now present.
- `docker compose ps`: `yarox-minio … (healthy)` (was unhealthy since creation).
- `GET /health` (dev): `ok`; postgres at head `b7c1e2d3f4a5`, qdrant "17 points", llm "model 'llama3.1' installed", celery "1 worker(s)", minio live.
- MinIO stopped → `/health` overall `degraded`, `minio: down (ConnectError …)`; restarted.
- Live replay `credential_theft` @100x (18:51): `agent_tool_calls` durations 34.9 / 63.4 / 24.4 / 27.6 ms with measured timestamps and output metadata (previously all 850); `llm_execution_time_ms` 8.6–51.1 s per agent; 5 new events hashed, 205 legacy events NULL; `GET /events/19a94239…/integrity` → `verified: true`; legacy event → `verified: null`.
- Backend logs: no errors after restart.

**Remaining / newly discovered**
- Duplicate concurrent investigation reproduced again on this replay (C-2, Phase 5).
- Frontend TypeScript errors (F-14). Dashboard panel change is type-checked and served (HTTP 200) but not visually verified in a browser.
- `confidence_explanation` never populated (T-2 partial, Phase 9).

### Phase 3 — Evidence + report persistence (2026-09-17)

**Design**
- Contract (`schemas/findings.py`): finding = `finding_id, agent, finding, kind ∈ {observation, hypothesis}, confidence (agent-reported, optional), evidence_ids (≥1), reasoning_summary (≤500 chars, no chain-of-thought), mitre_techniques, timestamp`.
- Agents receive evidence with explicit `evidence_id` (`agents/evidence.py`). LLM output is untrusted: a finding, timeline entry, recommendation or MITRE mapping is persisted only if **every** cited ID belongs to the case; a fabricated citation rejects the whole entry. Rejections are recorded in `findings_recorded` / `reasoning_complete` steps.
- Trace chain: `agent_findings` → `agent_finding_evidence` (FK) → `evidence_items` → `events` (source, timestamp, `payload_sha256`). Exposed by `GET /investigations/{id}/findings` and inside `GET /investigations/{id}/report`.
- `investigation_reports`: versioned snapshot (`status` complete/partial/degraded, summary, finding IDs, cited recommendations, MITRE with `source` detection_rule/threat_intel_agent, timeline with `timeline_source` timeline_agent/evidence_chronology, evidence IDs, agent runs with errors). Case row locked `FOR UPDATE` during write. UI, API and PDF read only this record.
- Degraded paths produce no invented content: failed agents return `null`/empty with `status: degraded` and the error.
- Schema ownership: `scripts/migrate.py` runs before uvicorn in compose; `create_all` removed from app startup; startup raises if schema ≠ migration head.

**Tests**
- New: `test_evidence_contract.py` (9), `test_report_persistence.py` (3 integration: real event → db_writer → detection → orchestrator → report/API/PDF; versioning; degraded SOC Lead), `test_schema_bootstrap.py` (4), `tests/support/llm_double.py` (LLM test double that cites the evidence IDs found in the real prompt — proves IDs reach the model; does not test LLM quality).
- Updated to the stricter contract: evaluation harness mock outputs now cite evidence and assert an uncited recommendation is rejected; guardrail test now expects the rule floor (CRITICAL) instead of MEDIUM; orchestrator mock test patches report persistence.
- `docker compose exec backend pytest -v tests/` → **122 passed**.

**Verified on the running system (real Ollama `llama3.1`)**
- Incident discovered during rollout: uvicorn `--reload` restarted the backend on model edit and startup `create_all` created the new tables before the migration, breaking `alembic upgrade` and an in-flight investigation (`UndefinedColumnError evidence_ids`; orchestrator reset case to OPEN, nothing partially persisted). Resolved by removing `create_all` from startup, dropping the 3 empty accidentally-created tables (row counts verified 0 in the same transaction), and migrating via `scripts/migrate.py` (`b7c1e2d3f4a5 -> c2d3e4f5a6b7`).
- Backend log: `[migrate] database schema ready (upgraded)` → `Application startup complete`.
- Live replay `credential_theft` (19:05) → report `7eeb0d1f…` v1 for case `96cb4069…`: status **partial**; Triage/Timeline/Threat Intel **degraded (LLM request timed out)**, SOC Lead completed; `timeline_source=evidence_chronology`; 2 findings (0 rejected), 2 recommendations each citing a real evidence item.
- `GET /investigations/96cb4069…/report`: finding "Multiple failed login attempts detected for user jdoe." → evidence `67acd4d5` AUTHENTICATION_FAILURE → event `54b5da11` Windows Security 2023-10-27T10:00:05Z sha256 `ec5ffa0dc5ed…`; PowerShell finding → evidence `cf862718` → event `987f37ad` Sysmon 10:01:00Z sha256 `ed131b3c5b13…`.
- `GET /investigations/96cb4069…/export` with bearer token → HTTP 200 `application/pdf` 4334 bytes.
- Frontend: `tsc` shows only the 4 pre-existing errors (F-14); `/reports` and `/investigations/{id}` serve HTTP 200. Not visually verified in a browser.

**Remaining / newly discovered**
- L-9: agents time out under concurrent load on local Ollama (Phase 5/8).
- C-2: duplicate concurrent investigations still occur (Phase 5).
- Report `confidence_score` still comes from the hardcoded formula (S-1, Phase 9); S-2 technique confidence constants.
- Detection-rule MITRE entries carry no evidence link (`source: detection_rule`, `evidence_ids: []`) because `AttackTechnique` has no evidence relation.

### Phase 4 — Semantic memory (2026-09-18)

**Why memory was broken (root causes, verified)**
1. IOC extraction filtered evidence rows by type labels (`ip`, `domain`, `hash`) that the detection engine never produces (it writes `PROCESS_EXECUTION`, `AUTHENTICATION_FAILURE`, …), so every case had an empty IOC set, an identical `ioc_hash` and a false +0.15 IOC score against every other case.
2. Qdrant was written before PostgreSQL, so a failed transaction left orphan vectors; all 17 vectors in the dev collection were orphans from test runs.
3. The indexing task swallowed exceptions and reported success, so failures were invisible.
4. Knowledge was re-summarized by an LLM at index time, putting unreviewed content (invented attack types/campaigns) into memory.

**Changed**
- `memory/indicators.py`: indicators from linked events (normalized columns, metadata, raw payload) — IPs validated, hashes by regex, identities normalized (`DOMAIN\user` → user), processes basenamed.
- `memory/case_inputs.py`: one loader used by indexing *and* querying (Memory Agent, Threat Intel, `/similar`), so both sides are built identically. Was duplicated in 3 places, each with the same bug.
- `memory/knowledge_builder.py`: deterministic, no LLM. Source `investigation_report` (summary, recommendations, timeline, MITRE from the reviewed report) or `case_evidence` when a resolved case has no report, stated in the stored summary.
- `memory/service.py`: durable-first write ordering, pending-record resume, superseded-vector deletion, self-exclusion, and an explainable score `0.5*semantic + 0.2*mitre + 0.2*ioc + 0.1*asset` with shared techniques/IOCs/assets returned.
- `memory/maintenance.py` + `GET /memory/status`, `POST /memory/reconcile`, `POST /memory/reindex`: observable memory state and orphan cleanup.
- `workers/tasks/memory_tasks.py`: raises on failure, retries with backoff, refuses non-RESOLVED cases (human gate enforced in the worker, not only the API).
- Migration `d4e5f6a7b8c9`: `vector_indexed_at`, `knowledge_source`, `source_report_id`, partial unique index `uq_investigation_memory_latest`.

**Tests** (`tests/test_memory.py`, real Postgres + real Qdrant, no vector/embedding mocks)
- indicators from events, per-case `ioc_hash`, `None` for no indicators
- knowledge from report / from evidence-only, and that no LLM is called (`mock_llm.assert_not_called()`)
- index → retrieve with component scores; unrelated case filtered by threshold; self never matches
- vector failure leaves a pending record with no vector, retry resumes the same record (no second version)
- re-index supersedes version and deletes the old vector
- reconcile removes orphans and repairs pending records
- Celery task indexes a resolved case, refuses an OPEN case, and ends FAILURE when it cannot succeed
- `GET /memory/status` reports real state
- `tests/test_memory_schemas.py`: TimelineSection validation preserved from the removed `test_memory_pipeline.py`; obsolete LLM-knowledge tests replaced (`test_knowledge_builder_never_calls_an_llm`), `/similar` truthfulness test rewritten against the real database.
- `docker compose exec backend pytest -v tests/` → **129 passed**.

**Verified on the running system**
- `GET /memory/status` before: 6 resolved cases, 0 indexed, 17 Qdrant points, **17 orphans**.
- `POST /memory/reconcile` → `{"deleted_orphan_points": 17}`; `POST /memory/reindex` → 6 tasks, worker logged `Indexed case … (case_evidence)` ×6.
- `GET /memory/status` after: resolved 6, indexed 6, pending 0, points 6, orphans 0, missing 0.
- Real investigation resolved through the API → indexed as `investigation_report` v1 with indicators extracted from events (`ips: ["192.168.1.50"]`, `hosts: ["workstation-01"]`, `mitre: ["T1059","T1110"]`).
- Retrieval from the other real case of the same scenario: **1 match, total 0.9827** (semantic 0.9653, mitre 1.0, ioc 1.0, asset 1.0), shared techniques `["T1059","T1110"]`, shared assets `host:workstation-01`, `user:jdoe`. The 6 unrelated legacy memories were correctly excluded by the threshold.
- Self-query returns 0 matches.

**Remaining / newly discovered**
- The 6 pre-existing "resolved" cases in the dev database are themselves old test artifacts (X-7), so their memory records are `case_evidence` with no summary. Real dev data remains contaminated.
- Detection-rule MITRE entries still carry no evidence link, so memory inherits `evidence_ids: []` for them.
- Memory retrieval quality beyond this scenario is unmeasured; only one attack pattern has been verified end to end (Phase 13 covers the three scenarios).

### Phase 5 — Investigation concurrency, state and session safety (2026-09-18)

**Changed**
- `core/locks.py`: Redis lock (`SET NX PX` + unique token). TTL expires a crashed holder's lock; a heartbeat refreshes it while work runs; release is compare-and-delete so an expired holder cannot release someone else's lock. Plus a re-run flag so evidence arriving mid-investigation is not dropped.
- `agents/orchestrator.py`: `run_investigation` acquires the per-case lock, verifies the case is in an investigatable state, runs the DAG, then performs at most `INVESTIGATION_MAX_RERUNS` (2) sequential re-runs if attempts were made while it held the lock. Returns a typed outcome (`completed` / `skipped` / `failed`) instead of `None`, logs through `logging` instead of `print`, and broadcasts `INVESTIGATION_FAILED`.
- `core/case_state.py`: explicit transition table; `INVESTIGATABLE_STATES`; `validate_transition` used by the orchestrator and `PATCH /status` (409 on invalid). `POST /analyze` refuses closed cases.
- `services/investigation_runner.py`: background runs create and own their session; used by both `/analyze` and the detection consumer.

**Tests** (`tests/test_investigation_concurrency.py`, real Redis + real database)
- 3 concurrent runs of one case: exactly 1 executes, 2 are skipped, lock released afterwards
- different cases are not blocked by each other
- a re-run request made during a run is consumed by the holder
- a stale lock from a "crashed holder" expires and the case is reclaimed
- the heartbeat keeps a lock alive past its TTL, and a stale holder cannot release it
- valid/invalid transition matrix, every status has an explicit set, API returns 409 and writes no audit row
- closed cases are refused by both the API and the orchestrator
- `/analyze` runs with a session it created (not the request session)
- Full suite: **155 passed**.

**Verified on the running system**
- Live replay at 20:27:55 produced one case (`4f7c3c09`) with two strictly sequential passes: pass 1 20:27:55→20:29:24 (report v1, 7 findings), pass 2 started 20:29:24.9 (report v2, 8 findings, current). Previously the same replay produced two overlapping investigations.
- All five agents completed in both passes (no LLM timeouts) with 3 concurrent LLM calls instead of 6; timeline came from the Timeline Agent rather than the evidence-chronology fallback.

**Remaining / newly discovered**
- Live proof of lock contention comes from the sequential re-run behaviour and the Redis-backed tests; two simultaneous `/analyze` calls were not exercised against the live stack.
- Replay still re-ingests duplicate events (A-9), which is what triggers the re-run pass.

### Phase 6 — Cross-process event delivery (2026-09-18)

**Problem.** WebSocket connections live in the API process, so anything an agent broadcast from another process could never reach a browser. This had to be solved *before* moving investigations to Celery (Phase 7), otherwise live reasoning would silently disappear.

**Changed**
- `core/event_stream.py`: `publish_investigation_event()` publishes to the Redis channel `yarox:ws:investigations`; `InvestigationEventBridge` subscribes and delivers into the local connection manager. If Redis is unreachable the event is delivered to local connections instead (single-process deployments keep working) and the publish reports failure.
- `websocket/investigation_ws.py`: `broadcast()` now publishes (any process); `deliver_local()` performs the scoped socket writes. Case scoping is unchanged: detailed steps only to the case room, lifecycle events also to global subscribers.
- `api/main.py`: bridge started on startup, stopped on shutdown.
- `core/health.py`: new **required** component `ws_event_bridge` (running + subscribed), so a broken event path is visible instead of silent.

**Tests** (`tests/test_event_bridge.py`, real Redis)
- an event published from a separate thread with its own event loop and Redis connection (as a worker process does) reaches a connected client
- `broadcast()` goes through Redis (`published is True`), not the local fallback
- when Redis is unreachable the fallback delivers locally and reports `False`
- case scoping preserved across the bridge (case A detail only to A; `REPORT_READY` also to global)
- health probe reports up/down for the bridge
- `tests/test_security_phase4a.py` websocket scoping test now targets `deliver_local` (the delivery step); the publish path is covered above.
- Full suite: **160 passed**.

**Verified on the running system**
- `GET /health` → `ws_event_bridge: up, "subscribed to yarox:ws:investigations"`.
- A real `websockets` client connected to the running backend during an `apt29_simulation` replay received 6 live events (`AGENT_STARTED` Orchestrator, `AGENT_THINKING` for Memory, Triage, Timeline, Threat Intel, SOC Lead), each travelling agent → Redis → bridge → client.

**Remaining**
- Global subscribers receive lifecycle events only (by design); case-scoped detail requires a `case_id` subscription.
- Frontend still hardcodes `ws://localhost:8000` (W-2, Phase 14).

### Phase 7 — Investigations on Celery workers (2026-09-18)

**Changed**
- `workers/tasks/investigation_tasks.py`: `run_investigation_task` runs the orchestrator in a worker process with a fresh `create_async_engine(..., poolclass=NullPool)` inside the task's own event loop; `acks_late`, retries with exponential backoff, returns the orchestrator outcome.
- `agents/orchestrator.py`: accepts a `session_factory`; the task passes its NullPool factory so agents never use the API process's module-level engine.
- `memory/vector_repository.py`: one `AsyncQdrantClient` per event loop (clients bind their primitives to the loop that first uses them).
- `services/investigation_runner.py`: `dispatch_investigation()` queues the task and returns its id; `InvestigationDispatchError` on broker failure. `/analyze` returns the `task_id` (503 if the broker is unreachable), and the detection consumer dispatches instead of running agents in-process.
- `workers/celery_app.py`: explicit `sys.path` entry for the backend directory; both task modules included.
- `core/health.py`: `celery_worker` is now **required** ("investigations cannot run" when absent).

**Two real defects this phase exposed (both would break the deployed worker, neither visible in-process)**
1. Cross-loop clients (DB-2): the second task in a worker failed until the engine/Qdrant client became per-loop/per-task.
2. Lazy imports in the forked child (W-3): `ModuleNotFoundError: No module named 'agents'` on the live worker while all tests passed, because the tests' in-process worker inherits a working import context. Found only by running the real worker.

**Tests** (`tests/test_investigation_worker.py`)
- a real Celery worker consuming the real broker runs the full DAG and persists a report (all five agents completed)
- two consecutive tasks in the same worker both succeed (regression for the event-loop binding)
- `/analyze` queues a task and runs nothing in the API process; returns 503 when the broker is down
- detection consumer dispatches instead of executing
- worker imports do not depend on the working directory; the orchestrator import stays at module scope
- Full suite: **169 passed**.

**Verified on the running system**
- Worker registered `workers.tasks.investigation_tasks.run_investigation_task`; `/health` → `celery_worker: up`.
- Dispatched case `f6c81ca3…`: worker log `Worker starting investigation` → `Worker finished … {'status': 'completed', 'report_status': 'complete'}`, task `succeeded in 200.5s`; all 5 agents `completed`; report v1 `complete`, 10 findings, 2 recommendations; case → `WAITING_FOR_REVIEW`.
- A browser WebSocket client connected to the **API** process received 7 events produced by the **worker** process (`AGENT_STARTED`, 5 × `AGENT_THINKING`, `REPORT_READY`) — the Phase 6 bridge carrying real worker output.

**Remaining / newly discovered**
- D-5: the `insider_threat` dataset triggers no detection rule at all.
- Replay and the in-process event bus still die on API restart (E-1): a backend hot-reload during a replay silently dropped the remaining events.

### Phase 8 — LLM provider abstraction and output validation (2026-09-18)

**Changed**
- `services/llm/providers.py`: `LLMProvider` interface with `OllamaProvider`, `VLLMProvider` (OpenAI-compatible) and `AnthropicProvider`. All configuration (model, base URL, credentials, timeout) comes from settings. Per section 11 of the architecture spec, external providers are refused unless `LLM_ALLOW_EXTERNAL_PROVIDERS=true`, and the Anthropic provider additionally requires an API key. `availability()` separates "unreachable" from "model not installed".
- `services/llm/service.py`: `generate_structured(prompt, schema)` — bounded concurrency (semaphore), hard timeout, code-fence stripping, balanced-brace JSON extraction from surrounding prose, Pydantic validation, retries with exponential backoff **and the validation error fed back to the model**, and typed exhaustion errors (`LLMUnavailable` / `LLMInvalidOutput`). A caller never receives fabricated content.
- `schemas/agent_outputs.py`: per-agent output schemas (structure strict, types permissive); semantic validation (evidence citations, MITRE IDs) stays in `agents/evidence.py`.
- All four LLM agents now use validated generation; `services/llm_service.py` remains as the import path.
- `core/health.py`: the LLM probe builds the provider from current settings and reports provider/model/endpoint plus concurrency and attempt limits.
- Compose and `.env.example` carry the LLM settings; `LLM_MAX_CONCURRENCY=2` (a local model server serves few requests at a time — unbounded fan-out caused the L-9 timeouts).

**Tests** (`tests/test_llm_service.py`, 23)
- fence stripping and JSON extraction from prose, nested braces and braces inside strings
- invalid JSON retried with the reason in the next prompt; schema violation retried with the field-level error; success on a later attempt
- persistent invalid output raises `LLMInvalidOutput` after exactly 3 attempts (never returns content)
- transport failure retried then `LLMUnavailable`; timeout converted to a typed error
- concurrency never exceeds the configured limit
- provider selection: local default, vLLM from settings, unknown provider rejected, external provider requires both opt-in and credentials, and this deployment is local-only
- Full suite: **192 passed**.

**Verified on the running system (real Ollama)**
- `/health`: `provider 'ollama' model 'llama3.1' at http://host.docker.internal:11434 available; max 2 concurrent, 3 attempts`.
- Live replay `apt29_simulation`: all 5 agents completed in both passes (LLM time per agent 34-111 s); reports v2 and v3 `complete` with 9-11 findings and 2-3 recommendations, timeline from the agent.
- Worker log shows `LLM attempt 1/3 returned invalid JSON` followed by a successful retry — a real malformed model response that previously would have degraded the agent.
- Lock behaviour observed across worker processes: two workers logged `skipped: investigation already running for this case` while one ran.

**Remaining**
- Retry/validation behaviour on *other* models (only `llama3.1` exercised).
- vLLM and Anthropic providers are implemented and unit-tested but have not been run against a live endpoint.

### Phase 9 — Real confidence scoring (2026-09-18)

**Formula** (documented in `scoring/confidence.py`; weights sum to 1.0):

| Component | Weight | Derived from |
|---|---|---|
| rule_severity | 0.30 | severity of the deterministic detection that opened the case |
| agent_completion | 0.20 | agents that completed vs degraded |
| evidence_coverage | 0.20 | evidence items actually cited by findings / total evidence |
| corroboration | 0.15 | distinct source events (saturating at 3) and distinct telemetry sources (at 2) |
| memory_support | 0.10 | similarity of the closest verified historical case, 0 when none |
| evidence_integrity | 0.05 | evidence whose source event hash verifies (`core/integrity.py`) |

**Changed**
- `scoring/confidence.py`: pure, deterministic `calculate_confidence(ConfidenceInputs)` returning a score plus a component breakdown (value, weight, contribution, human-readable detail). The old signature took four floats, three of which callers hardcoded.
- `services/confidence_service.py`: collects inputs from persisted state (evidence rows, their source events and verified hashes, finding citations, agent outcomes, this run's memory result).
- `agents/orchestrator.py`: scores after the agents run, stores score and breakdown on the case (and thus in the report).
- Per-agent confidence: `acceptance_confidence()` = accepted / (accepted + rejected) findings, with `confidence_explanation` carrying the counts; agents that propose no findings (Memory Agent) store NULL instead of an invented number (previously 0.9 / 0.85 / 0.95 / 1.0).
- `AttackTechnique.confidence`: 1.0 for deterministic rule matches, NULL for agent-proposed mappings (migration `e5f6a7b8c9d0` makes the column nullable); previously constants 0.8 and 0.9.

**Tests** (`tests/test_confidence.py`, 15)
- weights sum to 1; best case = 1.0, empty case = 0.0; deterministic
- breakdown contributions sum exactly to the score, every component has a detail
- score varies across inputs (the old engine returned 0.75 for 68 of 81 cases)
- degraded agents reduce the score by exactly the expected share; uncited evidence lowers coverage; severity, memory and integrity components each move the score in the right direction
- per-agent acceptance confidence including the "proposed nothing → None" case
- integration against a real investigation: inputs collected from the database, breakdown stored on the case matches the report, score ≠ 0.75, triage confidence 0.5 (1 of 2 findings survived, the fabricated citation was rejected), Memory Agent confidence NULL
- Full suite: **207 passed**.

**Verified on the running system**
- Live replay produced case `de628c59` with confidence **0.78** and this stored breakdown: rule_severity 0.75 (HIGH) → 0.225, agent_completion 1.0 (4/4) → 0.2, evidence_coverage 0.5 (1/2 cited) → 0.1, corroboration 0.767 (2 events, 2 sources) → 0.115, memory_support 0.899 (real historical match) → 0.09, evidence_integrity 1.0 (2/2 hashes verified) → 0.05.
- Agent executions carried measured confidence with accepted/rejected counts; the Memory Agent stored NULL.
- The startup schema guard fired for real during this phase: after the migration file was added but before it was applied, the backend refused to start with "Database schema not ready … Run `python -m scripts.migrate`" instead of serving against a stale schema.

**Remaining**
- `evidence_coverage` currently shows 0.5 on live runs because agents cite the most relevant evidence rather than every item; that is a real signal, not a defect, but it means scores rarely approach 1.0.
