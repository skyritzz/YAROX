# CLAUDE.md — YAROX Engineering & Operational Specification

> **Single Source of Truth (SSOT):** Consult [docs/YAROX_ARCHITECTURAL_RECONSTRUCTION.md](docs/YAROX_ARCHITECTURAL_RECONSTRUCTION.md) before making any architectural or structural modifications to this codebase.

---

## 1. Project Overview & Architecture

**YAROX** is an **Autonomous Multi-Agent Cybersecurity Investigation Platform** acting as an automated digital SOC team (Tier-1/Tier-2). It ingests security alerts/telemetry, correlates multi-stage events, runs specialized agents (Memory, Triage, Timeline, Threat Intel, SOC Lead), queries Qdrant vector memory, and produces courtroom-grade investigation reports.

* **Stack:**
  * **Backend:** FastAPI (Python 3.11), SQLAlchemy 2.0 Async (`asyncpg`), Alembic, Pydantic v2.
  * **Workers & Queues:** Celery, Redis 7.
  * **Databases:** PostgreSQL 15, Qdrant Vector DB (384-dim embeddings), MinIO S3 object storage.
  * **Frontend:** Next.js 15, React 19, Tailwind CSS, `@xyflow/react`, Recharts, Lucide.
  * **Inference:** Local LLM via Ollama / vLLM (`Llama-3.1-8B-Instruct` / `Llama-3.1-70B-Instruct`).

---

## 2. Essential Commands

### Infrastructure Management
```bash
# Start all 7 services in background
docker compose up -d

# Verify all containers are running & healthy
docker compose ps

# Inspect logs
docker compose logs -f backend
docker compose logs -f celery_worker
```

### Running Test Suites
```bash
# Run all automated test suites inside backend container
docker compose exec backend pytest -v tests/

# Run specific test suite (e.g. Memory pipeline or Case management)
docker compose exec backend pytest -v tests/test_memory_pipeline.py
docker compose exec backend pytest -v tests/test_phase5_case_management.py
```

### Health & Connectivity Verification
```bash
# Check backend health
curl -i http://localhost:8000/health

# Check frontend
curl -i http://localhost:3002
```

---

## 3. Engineering Rules for Claude Code

### Rule 1: Architectural Integrity & Minimal Refactoring
* Do **not** blindly rewrite working modules.
* Respect clean layer boundaries: `API -> Consumers -> Services/Agents -> Repositories -> Models`.
* Preserve all existing comments, docstrings, and verified test suites.

### Rule 2: Zero Fake Implementations
* **Never** introduce mock functions, hardcoded fallback dictionaries, or simulated sleep delays disguised as production code.
* If an external integration is unavailable, implement an explicit, typed fallback and log a warning.

### Rule 3: Asynchronous Database Safety
* Always use async SQLAlchemy (`AsyncSession`) with `selectinload` for relationships.
* In Celery workers, create fresh `create_async_engine` instances with `NullPool` inside the task loop to prevent asyncpg connection pool leaks across event loops.
* Never call synchronous database operations or trigger lazy-loading queries inside async contexts.

### Rule 4: Structured LLM Generation
* Every agent LLM call must enforce structured JSON output validated against a Pydantic schema.
* Implement exponential backoff retries (minimum 3 attempts) for model timeouts.
* Strip markdown code fences (````json ... ````) before deserializing.
* Never allow an LLM response to directly alter database state without schema validation and guardrail checks.

### Rule 5: Evidence & Forensic Chain of Custody
* Every agent finding, reasoning step, and recommendation must cite specific `evidence_ids`.
* Agents must strictly distinguish verified facts from working hypotheses.
* Raw telemetry payloads must be preserved in JSONB format with immutable timestamping and SHA-256 hashes.

### Rule 6: Security & Prompt Injection Defense
* Raw evidence passed into agent prompts must be sanitized and enclosed in `<EVIDENCE_BOUNDARY>` tags (`backend/core/utils.py`).
* Deterministic detection rules establish an unmodifiable severity floor; LLMs are strictly prohibited from downgrading verified high-severity alerts.
* Never hardcode production secrets, tokens, or private keys.

### Rule 7: Comprehensive Automated Verification
* Every new feature or bug fix must include automated pytest tests.
* Always verify changes by running the test suite inside the container environment.

---

## 4. Claude Code Priority Roadmap

1. **Step 1: Move Investigation Execution to Celery (CRITICAL):**
   * Currently, `backend/consumers/detection_consumer.py` launches investigations via `asyncio.create_task` inside FastAPI.
   * Migrate this to a Celery task: `workers.tasks.investigation_tasks.run_investigation_task`.
2. **Step 2: Harden LLM Service (CRITICAL):**
   * Refactor `backend/services/llm_service.py` to use Pydantic schema validation, retries with exponential backoff, and multi-provider abstraction (vLLM, Ollama, Anthropic).
3. **Step 3: Remove Hardcoded Confidence Weights (HIGH):**
   * Replace hardcoded floats in `backend/agents/orchestrator.py` with dynamic evidence-based calculations in `ConfidenceEngine`.
4. **Step 4: Durable Message Bus (HIGH):**
   * Migrate in-process `InMemoryEventBus` to Redis Streams so multi-container deployments can share events.
5. **Step 5: Expand Ingestion Connectors (HIGH):**
   * Implement connectors for Sysmon, Suricata EVE, and Splunk HEC using the Canonical Security Event schema.
