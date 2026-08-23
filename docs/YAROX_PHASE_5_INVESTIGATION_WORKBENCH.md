# YAROX Phase 5 — Investigation Workbench Design & Product Specification

**Document Status:** DESIGN SPECIFICATION / NOT IMPLEMENTED  
**Date:** August 23, 2026  
**Audited Baseline:** Phase 4C.1.1 Verified Core (`63/63` automated tests passing, `core_v1` benchmark score `98.75/100` PASS)  
**Target Delivery Phase:** Phase 5 — Investigation Workbench

---

## 1. Phase 5 Objective

The primary objective of **Phase 5 (Investigation Workbench)** is to transition YAROX from an autonomous investigation engine into a complete, interactive, end-to-end security analyst workbench. 

While Phases A through 4C.1.1 built and hardened the underlying autonomous multi-agent pipeline (Ingestion $\rightarrow$ Normalization $\rightarrow$ Detection $\rightarrow$ Swarm Orchestration $\rightarrow$ MITRE Mapping $\rightarrow$ Long-Term Vector Memory), the current analyst experience is predominantly read-only. Phase 5 equips SOC analysts with the tools to actively manage, review, annotate, collaborate on, override, audit, and resolve security cases directly within the YAROX console without leaving the platform.

---

## 2. Current YAROX State

Based on thorough, factual repository inspection, the current system state is:

1. **Backend Infrastructure:**
   - **FastAPI Core (`backend/`):** Fully asynchronous REST and WebSocket API (`:8000`).
   - **PostgreSQL Database:** Relational store containing `users`, `events`, `investigation_cases`, `evidence_items`, `agent_executions`, `agent_reasoning_steps`, `agent_tool_calls`, `attack_techniques`, `security_entities`, `security_relationships`, and `investigation_memory`.
   - **Redis (`:6379`):** Sliding-window rate limiter (120 req/min) and Celery task broker.
   - **Qdrant Vector Database (`:6333`):** Pinned `v1.8.2` server storing 384-dimensional dense vectors (`BAAI/bge-small-en-v1.5`) in `investigation_memory` collection.
   - **Celery Worker:** Asynchronous background task runner executing `index_resolved_investigation_task` with dedicated `NullPool` database sessions and fresh Qdrant clients.
   - **Local Inference (`host.docker.internal:11434`):** Local Ollama runtime serving `llama3.1`.

2. **Frontend Architecture:**
   - **Next.js (`frontend/`):** React 18, App Router, Tailwind CSS, `@tanstack/react-query`, Framer Motion, `@xyflow/react` running on `:3002`.
   - **Active Views:** `/` (Command Center), `/investigations` (Case Queue), `/investigations/[id]` (Investigation Detail), `/attack-graph` (Entity Graph), `/evidence` (Evidence Explorer & Events Table), `/reports` (Report Viewer & PDF Export), `/architecture` (Pipeline Diagram), `/events` (Raw Event Viewer).

3. **Verified Security & Data Controls:**
   - PBKDF2-HMAC-SHA256 password hashing + JWT HS256 authentication with RBAC (`ADMIN`, `ANALYST`, `VIEWER`).
   - Isolated machine-to-machine webhook ingestion (`POST /events/ingest`) requiring dedicated `X-API-Key`.
   - Fail-closed rate limiting on Redis outage (`HTTP 503`).
   - Strict XML prompt boundary isolation (`<untrusted_security_evidence>`) preventing LLM jailbreaks.
   - Deterministic severity floor guardrails in triage.
   - Human-gated memory indexing on analyst `RESOLVED` status.

---

## 3. Current Investigation Flow (Actual Implementation)

```
[Raw Event Payload]
       │
       ▼
[1] POST /events/ingest (backend/api/ingest.py:78)
       │ - Constant-time X-API-Key verification
       │ - Redis sliding-window rate limit (120 req/min)
       │ - 64 KB payload bound validation
       │
       ▼
[2] Event Normalization (backend/plugins/parsers/generic.py:10 & backend/core/taxonomy.py:46)
       │ - generic_parser.parse() normalizes timestamp to UTC ISO-8601
       │ - taxonomy_normalizer.normalize() assigns CanonicalEventType (AUTH_FAILURE, PROCESS_EXECUTION, etc.)
       │ - Raw unparsed type preserved in metadata_["raw_event_type"]
       │
       ▼
[3] Central Event Bus (backend/core/events.py:26)
       │ - event_bus.publish("EventNormalized", normalized_dict)
       │
       ▼
[4] Evidence Storage (backend/consumers/db_writer.py:7)
       │ - handle_event_normalized() inserts Event in PostgreSQL events table
       │ - event_bus.publish("EventStored", {"id": event.id})
       │
       ▼
[5] Detection Engine (backend/consumers/detection_consumer.py:9 & backend/detection/engine.py:33)
       │ - Evaluates rules: FailedLoginBruteForce, PrivilegeEscalation, SuspiciousProcessExecution, LateralMovement
       │
       ▼
[6] Contextual Correlation (backend/correlation/engine.py:15)
       │ - correlation_engine.find_related_case() queries 24-hour window for active cases matching user_name/hostname
       │ - If found: Escalates severity in-flight (HIGH -> CRITICAL), appends technique to title
       │ - If not found: Creates new InvestigationCase(status=OPEN, severity=rule_severity)
       │ - Persists EvidenceItem and AttackTechnique records
       │
       ▼
[7] Swarm Orchestration (backend/consumers/detection_consumer.py:22 & backend/agents/orchestrator.py:22)
       │ - Sets case.status = ANALYZING
       │ - Broadcasts WebSocket AGENT_STARTED
       │
       ▼
[8] Multi-Agent Swarm Execution:
       │ ├─► MemoryAgent (backend/agents/memory.py:17): Queries Qdrant for similar past cases -> MemoryContext
       │ ├─► TriageAgent (backend/agents/triage.py:16): Sandboxed LLM assessment -> Severity floor
       │ ├─► TimelineAgent (backend/agents/timeline.py:16): Sandboxed LLM chronological event sequence
       │ ├─► ThreatIntelAgent (backend/agents/threat_intel.py:20): MITRE KB validation -> AttackTechnique rows
       │ └─► ReportAgent (backend/agents/report.py:17): Drafts executive summary + 3 recommendations
       │ - ConfidenceEngine (backend/scoring/confidence.py:25): Computes weighted confidence score
       │ - Sets case.status = WAITING_FOR_REVIEW
       │ - Broadcasts WebSocket REPORT_READY
       │
       ▼
[9] Human Review Gate (backend/api/investigations.py:166)
       │ - Analyst reviews case in UI and triggers PATCH /investigations/{id}/status
       │ - If FALSE_POSITIVE: Status updated, archival aborted
       │ - If RESOLVED: Status updated, dispatches Celery archival task
       │
       ▼
[10] Long-Term Memory Archival (backend/workers/tasks/memory_tasks.py:9)
       │ - Celery worker receives task via Redis queue
       │ - KnowledgeBuilder.build() eagerly loads case relationships and structures KnowledgeObject
       │ - memory_service.index_knowledge(): Computes 384-d vector, upserts into Qdrant, stores in DB
```

---

## 4. Current Analyst Workflow

When an incident occurs today, an analyst interacts with the system through the following discrete steps:

1. **Discovery:** Analyst sees active cases in the Command Center (`/`) KPI cards or the Investigation Queue (`/investigations`).
2. **Case Selection:** Analyst clicks a case card to open the Investigation Explorer (`/investigations/[id]`).
3. **Orientation:** Analyst reads the AI Analyst Summary (drafted by `ReportAgent` / `SOC Lead`) and checks the Severity and Confidence badges.
4. **Investigation Review:**
   - Inspects the Attack Story Timeline (chronological cards with severity markers).
   - Inspects the Evidence Explorer (artifacts, type chips, timestamps, matched Sigma rules).
   - Inspects the MITRE ATT&CK card (technique IDs, names, tactics).
   - Inspects the Qdrant Memory Insight card (past similar case IDs and similarity scores).
   - Watches the AI Investigator right pane streaming live or replayed agent execution steps.
5. **Resolution Verdict:**
   - If valid attack: Analyst clicks **Resolve Incident** (`PATCH /investigations/{id}/status` $\rightarrow$ `RESOLVED`), triggering vector memory indexing.
   - If false alarm: Analyst clicks **False Positive** (`PATCH /investigations/{id}/status` $\rightarrow$ `FALSE_POSITIVE`).
6. **Reporting:** Analyst clicks **Export** to download a ReportLab-generated PDF report.

---

## 5. Verified Existing Capabilities

The following capabilities are fully implemented in code and verified across the automated test suite (63/63 tests passing):

| Capability | Backend Implementation | Database Model / Persistence | Frontend Component | Verification Status |
| :--- | :--- | :--- | :--- | :---: |
| **JWT Authentication & RBAC** | `core/auth.py`, `api/auth.py` | `models/user.py` (`User`, `UserRole`) | `lib/api.ts` (Axios Interceptors) | **INDEPENDENTLY VERIFIED** |
| **Live Ingestion Webhook** | `api/ingest.py` (`POST /events/ingest`) | `models/event.py` (`Event.raw_log`) | `app/page.tsx` (Live Badge) | **INDEPENDENTLY VERIFIED** |
| **Fail-Closed Rate Limiting** | `core/rate_limiter.py` | Redis sliding window | HTTP 429/503 Handlers | **INDEPENDENTLY VERIFIED** |
| **Event Normalization** | `plugins/parsers/generic.py`, `core/taxonomy.py` | `models/event.py` | `app/events/page.tsx` | **INDEPENDENTLY VERIFIED** |
| **Contextual Correlation** | `correlation/engine.py` | `models/investigation.py` | `app/attack-graph/page.tsx` | **INDEPENDENTLY VERIFIED** |
| **Multi-Agent Orchestrator** | `agents/orchestrator.py` | `models/investigation.py` (`AgentExecution`) | `app/investigations/[id]/page.tsx` | **INDEPENDENTLY VERIFIED** |
| **Prompt Sandboxing** | `core/utils.py` (`<untrusted_security_evidence>`) | Sandboxed prompts across all agents | Live Reasoning Feed | **INDEPENDENTLY VERIFIED** |
| **Room-Scoped WebSockets** | `websocket/investigation_ws.py` | In-memory `ScopedConnectionManager` | `context/LiveInvestigationContext.tsx`| **INDEPENDENTLY VERIFIED** |
| **Human Review Gate** | `api/investigations.py:166` | `investigation_cases.status` | Resolve / False Positive Buttons | **INDEPENDENTLY VERIFIED** |
| **Qdrant Vector Memory** | `memory/service.py`, `memory/vector_repository.py` | `models/investigation.py` (`InvestigationMemory`) + Qdrant `investigation_memory` | `components/investigation/MemoryInsights.tsx` | **INDEPENDENTLY VERIFIED** |
| **Celery Archival Dispatch**| `workers/tasks/memory_tasks.py` | Async task execution | Background Celery Task | **INDEPENDENTLY VERIFIED** |
| **PDF Report Generation** | `export/report_generator.py` | ReportLab PDF stream | Export Button in UI | **INDEPENDENTLY VERIFIED** |

---

## 6. Phase 5 Gap Analysis

The repository audit confirms that the following critical operational capabilities are currently **missing** from YAROX:

1. **Analyst Case Notes & Comments:** Analysts cannot attach notes, hypotheses, or external findings to an investigation.
2. **Case Assignment & Ownership:** Cases cannot be assigned to an analyst or team (`investigation_cases` has no `assigned_to_user_id`).
3. **Manual Severity Override:** Analysts cannot manually adjust case severity from the UI if the AI under- or over-estimates risk.
4. **Case Reopening:** Once resolved or marked false positive, cases cannot be reopened (`REOPENED` status does not exist).
5. **Resolution Attribution Audit:** Case status transitions do not record which specific user ID resolved or closed the case (`resolved_by_user_id` is missing).
6. **Immutable Audit Trail:** There is no dedicated audit log capturing analyst actions, edits, status updates, or assignment changes.
7. **Finding Verification & Analyst Overrides:** Analysts cannot approve, reject, or edit individual AI findings (e.g. remove a false MITRE technique or edit the summary text).
8. **Universal Search & Filtering:** No full-text search, IOC search (IP, domain, hash), or multi-attribute filtering exists in the frontend.
9. **Dynamic Remediation Actions:** The interactive checklist on `/reports` displays hardcoded string actions instead of dynamic recommendations produced by the ReportAgent.

---

## 7. Proposed Investigation Workbench Design

Phase 5 will transform `/investigations/[id]` into a unified **Investigation Workbench** organized around four functional pillars:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                INVESTIGATION WORKBENCH                                 │
├───────────────────────────────┬────────────────────────────────────────────────────────┤
│ [A] Case Header & Controls    │ Title, Severity (Editable), Status (Transitions),      │
│                               │ Assignee (Select), Confidence, SLA Timer, PDF Export   │
├───────────────────────────────┼───────────────────────────────┬────────────────────────┤
│ [B] Left Queue / Overview     │ [C] Central Tabbed Workspace  │ [D] Right Collaboration│
│                               │                               │     & Live Swarm       │
│ • Active Case Queue           │ 1. Overview & AI Findings     │ • Live Agent Reasoning │
│ • Priority Indicators         │ 2. Evidence Explorer (Filter) │ • Analyst Notes Feed   │
│ • Quick Filters               │ 3. Attack Story Timeline      │ • Case Audit Trail     │
│ • Assigned Cases Filter       │ 4. MITRE ATT&CK Matrix        │ • Tool Execution Logs  │
│                               │ 5. Historical Memory Matches  │                        │
│                               │ 6. Response & Remediation     │                        │
└───────────────────────────────┴───────────────────────────────┴────────────────────────┘
```

---

## 8. Case Lifecycle Specification

### Minimum Required Lifecycle State Machine

To support real SOC operations, Phase 5 will implement the following 6-state lifecycle:

```
   [ Detection Engine ]
            │
            ▼
         [ OPEN ] ◄────────────────────────────────────────┐
            │                                              │
            ▼ (Start Analysis)                             │ (Reopen Case)
      [ ANALYZING ]                                        │
            │                                              │
            ▼ (Agent Swarm Completes)                      │
   [ WAITING_FOR_REVIEW ]                                  │
            │                                              │
            ├──────────────────────┬───────────────────────┤
            ▼ (Analyst Resolves)   ▼ (Analyst Rejects)     │
       [ RESOLVED ]          [ FALSE_POSITIVE ]            │
            │                      │                       │
            └──────────────────────┴───────────────────────┘
```

### State Definitions & Permissions

| Status | Meaning | Permitted Transitions | Triggers / Side Effects |
| :--- | :--- | :--- | :--- |
| `OPEN` | New or unassigned incident ready for investigation. | `ANALYZING`, `RESOLVED`, `FALSE_POSITIVE` | Emits `CASE_UPDATED` WebSocket event. |
| `ANALYZING` | Multi-agent swarm is actively investigating evidence. | `WAITING_FOR_REVIEW`, `OPEN` | Runs agent execution pipeline in background. |
| `WAITING_FOR_REVIEW` | AI investigation completed. Awaits human analyst verdict. | `RESOLVED`, `FALSE_POSITIVE`, `ANALYZING` | Broadcasts `REPORT_READY`. Awaits human review. |
| `RESOLVED` | Analyst verified incident as true positive. Case closed. | `OPEN` (Reopened) | Dispatches Celery task to index into Qdrant & PostgreSQL memory archive. |
| `FALSE_POSITIVE` | Analyst rejected incident. Case closed. | `OPEN` (Reopened) | Aborts memory indexing. Logs false positive rationale. |

---

## 9. Evidence, Timeline, MITRE & Memory Presentation

### Evidence Presentation
- **Direct Finding Provenance:** Every AI finding will link directly to underlying `evidence_items` via `evidence_ids`.
- **Filtering & Search:** Analysts can filter evidence items by type (`IP`, `DOMAIN`, `HASH`, `USER`, `HOST`, `PROCESS`, `COMMAND`) and importance score ($\ge 0.8$).
- **Raw Log Drawer:** Clicking an evidence item opens a side drawer displaying the exact unparsed JSON from `events.raw_log`.

### Timeline Presentation
- **Structured Timeline Events:** Renders structured `TimelineEvent` records (`time`, `action`, `details`, `description`) with strict chronological ordering.
- **Severity Highlighting:** Critical actions (Credential Dumping, Privilege Escalation, Lateral Movement, Data Exfiltration) receive distinct visual badges.
- **Evidence Linking:** Clicking a timeline event highlights the corresponding evidence artifact in the Evidence Explorer.

### MITRE ATT&CK Matrix
- **Technique Card Verification:** Displays technique ID, tactic, technique name, and confidence score.
- **Analyst Override:** Analysts can toggle/remove unverified techniques before resolving the case.

### Historical Memory Presentation
- **Similarity Scoring Breakdown:** Renders dense semantic similarity, MITRE overlap score, and IOC overlap score.
- **Past Resolution Retrieval:** Displays the executive summary and immediate actions taken during previous similar investigations.
- **Direct Case Comparison:** Provides a one-click link to view the past investigation record.

---

## 10. Agent Activity and AI Findings

The workbench exposes **auditable agent actions and structured outputs**, strictly preserving prompt sandboxing without leaking internal chain-of-thought:

1. **Agent Execution Header:** Shows agent name, status (`completed`, `degraded`, `failed`), total execution time (ms), tool call count, and reasoning step count.
2. **Step Timeline:** Displays structured step types (`observation_started`, `tool_call_started`, `tool_call_complete`, `reasoning_complete`, `decision_made`).
3. **Tool Call Inspector:** Expandable view showing tool name (e.g. `memory_search`), input parameters, output summary, and duration (ms).
4. **Failure Transparency:** If an agent degrades or fails, the interface displays the fallback strategy used (e.g., "Ollama timeout: Fell back to deterministic rule severity floor").

---

## 11. Analyst Actions and Audit Trail

### Required Analyst Actions

| Action | HTTP Endpoint | DB Mutation | Audit Log Entry |
| :--- | :--- | :--- | :--- |
| **Add Note** | `POST /investigations/{id}/notes` | Insert `CaseNote` | `NOTE_ADDED` with note author and preview |
| **Assign Case** | `PATCH /investigations/{id}/assign` | Update `assigned_to_user_id` | `CASE_ASSIGNED` with previous/new assignee |
| **Override Severity** | `PATCH /investigations/{id}/severity` | Update `severity` | `SEVERITY_OVERRIDDEN` with previous/new severity & reason |
| **Resolve Case** | `PATCH /investigations/{id}/status` (`RESOLVED`) | Update `status`, `resolved_by_user_id`, `resolved_at` | `CASE_RESOLVED` (Triggers Celery memory archival) |
| **Mark False Positive** | `PATCH /investigations/{id}/status` (`FALSE_POSITIVE`) | Update `status`, `resolved_by_user_id`, `resolved_at` | `CASE_MARKED_FALSE_POSITIVE` with reason |
| **Reopen Case** | `PATCH /investigations/{id}/reopen` | Update `status` $\rightarrow$ `OPEN`, reset resolution fields | `CASE_REOPENED` with reopening justification |

### Immutable Audit Trail Model (`audit_logs`)
Every state mutation, note addition, severity change, and status transition will append an immutable row in the `audit_logs` table:
```sql
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID REFERENCES investigation_cases(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id),
    action VARCHAR(64) NOT NULL,
    details JSONB NOT NULL,
    timestamp TIMESTAMPTZ DEFAULT NOW()
);
```

---

## 12. Frontend Information Architecture

The redesigned `/investigations/[id]` page layout:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ YAROX > Investigations > [CASE-4A2F] Unauthorized PowerShell Execution                │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ [Severity: HIGH (Edit)] [Status: WAITING_FOR_REVIEW] [Confidence: 92%] [Assignee: jdoe]│
│ [Actions: Resolve Incident | False Positive | Start Re-Analysis | Export PDF]          │
├───────────────────────┬────────────────────────────────────────┬───────────────────────┤
│ CASE QUEUE            │ WORKSPACE TABS                         │ COLLABORATION & SWARM │
│ ───────────────────── │ ────────────────────────────────────── │ ───────────────────── │
│ 1. [CRITICAL] Lateral │ [Overview] [Evidence] [Timeline]       │ • Analyst Notes       │
│ 2. [HIGH] PowerShell  │ [MITRE] [Memory] [Remediation]         │   [Add Note Input...] │
│ 3. [MED] Failed Login │ ────────────────────────────────────── │   - 10:45 AM (asmith) │
│                       │ Tab Content:                           │     "Host isolated."  │
│ [Quick Filters]       │ • Structured Executive Summary         │ ───────────────────── │
│ [Search Cases...]     │ • Verified Attack Timeline             │ • Swarm Activity Feed │
│                       │ • Artifact Table with Sigma match      │   - Triage Analyst    │
│                       │ • MITRE Technique Matrix               │   - Timeline Analyst  │
│                       │ • Past Case Memory Matches             │   - Threat Intel      │
│                       │ • Actionable Remediation Checklist     │   - SOC Lead          │
└───────────────────────┴────────────────────────────────────────┴───────────────────────┘
```

---

## 13. Backend / API / Database Gap Matrix

| Proposed Feature | DB Model Required | API Endpoint Required | Schema / DTO Required | Frontend Component Required |
| :--- | :--- | :--- | :--- | :--- |
| **Analyst Notes** | `CaseNote` table (`id`, `case_id`, `user_id`, `content`, `created_at`) | `GET/POST /investigations/{id}/notes` | `CaseNoteCreate`, `CaseNoteResponse` | `AnalystNotesPanel.tsx` |
| **Case Assignment** | Add `assigned_to_user_id` to `investigation_cases` | `PATCH /investigations/{id}/assign` | `CaseAssignRequest` | `AssigneeSelector.tsx` |
| **Severity Override** | Existing `investigation_cases.severity` | `PATCH /investigations/{id}/severity` | `SeverityOverrideRequest` | `SeverityEditor.tsx` |
| **Resolution Tracking**| Add `resolved_by_user_id`, `resolved_at` to `investigation_cases` | Existing `PATCH /investigations/{id}/status` | Updated `StatusUpdateRequest` | `ResolutionModal.tsx` |
| **Case Reopening** | Handled via `status` transition | `POST /investigations/{id}/reopen` | `CaseReopenRequest` | `ReopenButton.tsx` |
| **Audit Trail** | `AuditLog` table (`id`, `case_id`, `user_id`, `action`, `details`, `timestamp`) | `GET /investigations/{id}/audit` | `AuditLogResponse` | `AuditTrailTab.tsx` |
| **Dynamic Remediation**| Existing `ReportAgent` recommendations output | Existing `/investigations/{id}` | Existing `MemoryContext` | Update `RemediationChecklist.tsx` |

---

## 14. Phase 5 Dependency Map

```
[Phase 4A: JWT / RBAC] ───────────────► Injects user_id into Notes, Assignment, and Audit Logs
[Phase 4B: Event Ingestion] ──────────► Feeds Evidence Explorer & Raw Log Drawer
[Phase 4C: Multi-Agent Swarm] ────────► Feeds Overview, Timeline, MITRE, and Report Tabs
[Phase 4C.1.1: Vector Memory] ────────► Feeds Memory Insights Tab & Celery Resolution Archival
```

---

## 15. Phase 5 Implementation Plan

Phase 5 will be implemented in four focused, incremental milestones:

### Milestone 5.1 — Database Models & Core Workbench APIs
1. Create Alembic migration adding `CaseNote` and `AuditLog` models, plus `assigned_to_user_id`, `resolved_by_user_id`, and `resolved_at` columns on `investigation_cases`.
2. Implement backend endpoints:
   - `GET/POST /investigations/{id}/notes`
   - `PATCH /investigations/{id}/assign`
   - `PATCH /investigations/{id}/severity`
   - `POST /investigations/{id}/reopen`
   - `GET /investigations/{id}/audit`
3. Add comprehensive automated unit and integration tests for all new endpoints.

### Milestone 5.2 — Workbench Frontend Information Architecture
1. Refactor `/investigations/[id]` into modular components (`CaseHeader`, `CaseQueue`, `WorkspaceTabs`, `CollaborationPanel`).
2. Implement tabbed workspace: `OverviewTab`, `EvidenceTab`, `TimelineTab`, `MitreTab`, `MemoryTab`, `RemediationTab`, `AuditTab`.
3. Connect real-time WebSocket updates for case notes, assignment, and status changes.

### Milestone 5.3 — Analyst Interaction & Collaboration Controls
1. Build `AnalystNotesPanel` with real-time optimistic updates.
2. Build `AssigneeSelector` and `SeverityEditor` dropdowns with audit logging.
3. Build `ResolutionModal` requiring resolution rationale and confirming vector memory archival.
4. Replace hardcoded checklist on `/reports` with dynamic recommendations from `ReportAgent`.

### Milestone 5.4 — End-to-End Verification & Regression Testing
1. Execute full automated test suite (verifying 100% pass rate across Phase 4A, 4B, 4C, and Phase 5 suites).
2. Execute `core_v1` benchmark verifying zero regression against frozen ground truth.
3. Document Phase 5 completion in `YAROX_ENGINEERING_LOG.md`.

---

## 16. Phase 5 Definition of Done

Phase 5 implementation will be complete and accepted only when:

1. [ ] **Case Collaboration:** An analyst can add a case note, assign a case to a user, and view notes in real time.
2. [ ] **Severity & Lifecycle Controls:** An analyst can override case severity, resolve a case with author attribution, mark false positive, and reopen a closed case.
3. [ ] **Immutable Audit Log:** Every status change, assignment, severity override, and note creation appends an immutable record to `audit_logs`.
4. [ ] **Evidence & Timeline Fidelity:** Evidence items link to raw logs in `events.raw_log`; structured timeline events render with accurate chronological ordering.
5. [ ] **Memory Archival Integrity:** Resolving a case triggers Celery archival to Qdrant vector store and PostgreSQL `investigation_memory`.
6. [ ] **Automated Test Suite:** 100% of existing tests (63/63) and all new Phase 5 tests pass cleanly.
7. [ ] **Zero Security Regressions:** Prompt injection resistance remains 100%; RBAC and rate limiting remain intact.

---

## 17. Risks & Unknowns

1. **Concurrent Analyst Editing:** If two analysts edit case metadata simultaneously, last-write-wins applies. (Acceptable for single-tenant local SOC console).
2. **Local LLM Latency:** Ollama inference times on consumer hardware vary (2s–10s per agent). All LLM calls have strict 120s timeouts and fallback defaults.

---

## 18. Explicitly Deferred Work (Out of Scope for Phase 5)

The following items are strictly deferred to future roadmap phases:

- Multi-tenancy / Organization row-level isolation (`tenant_id`).
- Distributed message streaming (Kafka / RabbitMQ).
- Outbound active SOAR response integrations (AWS Security Groups, CrowdStrike host isolation).
- Syslog / CloudTrail / Splunk streaming collectors.
- Kubernetes Helm packaging.
- `MemoryAgent` exception propagation refactor (cataloged deferred finding from Phase 4C.1.1).

---

## 19. Current YAROX Status Summary

- **IMPLEMENTED:** Ingestion webhook, rate limiting, event taxonomy, detection rules, contextual correlation, multi-agent swarm, prompt sandboxing, review gating, Qdrant vector memory, Celery background archival, PDF export, Next.js command center & investigation explorer.
- **INDEPENDENTLY VERIFIED:** Phase 4A Security, Phase 4B Ingestion, Phase 4C Evaluation Core, Phase 4C.1 Qdrant Infrastructure, Phase 4C.1.1 Memory Pipeline & Condition Closure (63/63 tests passing).
- **PARTIALLY IMPLEMENTED:** Investigation UI (present but read-only without notes or assignment), Suricata parser.
- **PLANNED (Phase 5):** Analyst notes, case assignment, severity override, case reopening, resolution attribution, immutable audit trail, tabbed workbench.
- **DEFERRED:** Multi-tenancy, Kafka streaming, SOAR containment, Syslog daemon, `MemoryAgent` error propagation refactoring.
- **UNKNOWN:** None. (All repository components, models, routes, and configs verified).

---

## 20. Implementation Readiness Verdict

### **READY FOR PHASE 5 IMPLEMENTATION**

**Justification:** The foundation is stable, hardened, and independently verified. All prerequisite systems (API authentication, database persistence, agent orchestration, vector memory, Celery background worker, and frontend explorer) are operating with a 100% test pass rate. The scope of Phase 5 is clearly bounded, realistic, and directly addresses the exact operational gaps required for a complete investigation workbench.
