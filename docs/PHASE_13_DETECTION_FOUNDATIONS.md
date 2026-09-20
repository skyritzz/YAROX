# YAROX Phase 13 — Detection Foundations

**Status:** implemented and tested (foundations only — see "Explicitly out of scope" below; full Phase 13 scenario orchestration has not been started).

This phase addressed four confirmed gaps from `docs/YAROX_REALITY_AUDIT.md`
(D-1, D-3, D-4, D-5) as a prerequisite for Phase 13 scenario work, per the
governing instruction: "do not begin broad scenario orchestration until the
underlying detections work."

## 1. Audit — what was actually confirmed vs. assumed

Before writing any code, each gap was re-verified against the current
repository state rather than trusted from the audit's own (already slightly
stale, e.g. it predates the Suricata/Splunk connectors) description.

- **D-1 (first-match engine bug).** Confirmed real: `DetectionEngine.
  process_event` (`backend/detection/engine.py`, pre-Phase-13) contained
  `for rule in self.rules: if await rule.match(event): ... return case` —
  the `return` is inside the `for` loop, so the first matching rule ends
  evaluation for that event, silently skipping every rule listed after it in
  `self.rules`. Given `canonical_event_type` is a single value per event,
  most of the *original* 4 rules were mutually exclusive by construction, so
  the bug's blast radius was narrow before this phase — but two of the three
  *new* rules added here (`SuspiciousProcessExecution` and
  `DataStagingViaArchiveUtility`) both gate on `PROCESS_EXECUTION`, making
  real overlap newly reachable. Fixed (see §3).
- **D-3 (Sigma engine).** Confirmed as described: `rules/sigma/engine.py`
  supports only a flat AND of `contains`/`exact` selection criteria, one
  rule file exists, and it only adjusts an evidence importance score — it
  does not gate case creation. No concrete detection need in this phase
  required expanding it (the new rules are native Python, not Sigma YAML;
  see "How to add another connector"-equivalent reasoning in §2). Left
  untouched, per the instruction to improve Sigma only where it enables a
  concrete, tested detection.
- **D-4 (network/C2 detection).** Confirmed: no rule read
  `NETWORK_TRAFFIC` or `SYSTEM_ALERT` at all — both canonical types existed
  but had zero consumers, exactly as `docs/CANONICAL_EVENT_MODEL.md`'s
  Suricata connector section already documented ("no detection rule
  currently targets `SYSTEM_ALERT` or `NETWORK_TRAFFIC`").
- **D-5 (insider-threat detection).** Confirmed, and the audit's own cited
  evidence — `datasets/insider_threat/events.json` — was read directly
  (not re-described from memory) to ground the fix in the dataset's actual
  field shapes: a `Login Success`, two `File Access` records (one flagged
  `"reason": "Unusual access pattern"`), a `Process Creation` running
  `7z.exe` to archive two file-share paths together, and a `Network
  Connection` sending `bytes_sent: 15000000` to `203.0.113.50`. No existing
  rule's keyword list covered any of this.

## 2. Detection scope — what was decided, and what was deliberately excluded

**Governing constraint, taken literally throughout:** *"Do not claim
reliable C2 identification from generic network flows alone. Avoid
fabricated indicators or unsupported threat-intelligence claims."* This
system has no live threat-intel/IOC-reputation feed —
`agents/threat_intel.py` only searches YAROX's own prior-case memory
(Qdrant) and a static MITRE ATT&CK reference (`security/mitre/knowledge_base.py`),
never an external reputation service. Any rule claiming to "identify C2"
from an IP address or byte count alone would be fabricating a capability
this system doesn't have.

**What was built, and why each one is defensible without that capability:**

| Rule | Gates on | What it actually asserts | Why it's not a fabricated claim |
|---|---|---|---|
| `NetworkIntrusionAlert` | `canonical_event_type == SYSTEM_ALERT` | An external, purpose-built NIDS (Suricata) already matched a signature; this rule surfaces that match | The "detection" was performed by Suricata, not invented by YAROX — the rule quotes Suricata's own signature/category text verbatim |
| `DataStagingViaArchiveUtility` | `PROCESS_EXECUTION` + `process_name` in a small, explicit archive-utility set (7z/rar/zip/gzip/tar) | An archive/compression tool was invoked, with its exact command line | Does not assert intent or data sensitivity — explicitly hedged as "may indicate legitimate use or data staging," MEDIUM severity only |
| `LargeExternalDataTransfer` | `NETWORK_TRAFFIC` + byte count ≥ 10 MB + destination is not internal | A large outbound transfer occurred to a non-internal address | Purely structural (RFC 1918/loopback/link-local check via `ipaddress`, computed from the address itself) — explicitly hedged as "does not confirm exfiltration, C2, or malicious intent" |

**What was deliberately *not* built:** a beaconing/periodicity detector, a
"distinct destination fan-out" heuristic, or anything inferring malicious
intent from `NETWORK_TRAFFIC` flow data alone. The task instruction is
explicit that this class of inference is out of scope without real
threat-intel backing, and building it without validated real-world tuning
(false-positive rates, realistic thresholds) risks exactly the "fabricated
indicators" the instruction warns against. `LargeExternalDataTransfer` is a
volume heuristic only — it does not analyze timing, frequency, or protocol
behavior, and its description says so on every match.

## 3. What was implemented

### 3.1 Fix: `DetectionEngine.process_event` no longer stops at the first match (D-1)

`backend/detection/engine.py`: the per-match body (correlation lookup, case
create/update, Sigma evaluation, evidence dedup/creation, MITRE technique
dedup/creation, entity extraction, commits) was extracted into a new
`_record_match(db, event, rule)` method, unchanged in logic. `process_event`
now loops over **every** rule, calling `_record_match` for each match and
returning the *last* case touched — preserving the existing single-case
return contract every caller (`consumers/detection_consumer.py`,
`evaluation/runner.py`, 3 existing test files) already relies on, since a
single event has exactly one user/host and `correlation_engine` reliably
finds the same case for a second match on that same event.

A second, smaller defect was found while fixing this: the evidence-dedup
`artifact_val` fallback chain (`command_line` → `user_name`/`hostname`) had
no field for evidence types with no command line — two *different* Suricata
signatures on the same host would have collided on the same fallback
artifact (`hostname`) and the second would have been wrongly treated as a
duplicate. Fixed by extending the fallback to prefer `signature` and
`destination_ip`/`ip_address` before falling back to user/host.

### 3.2 New rules (D-4, D-5) — `backend/detection/rules.py`

`NetworkIntrusionAlert`, `DataStagingViaArchiveUtility`,
`LargeExternalDataTransfer` — see §2's table for what each asserts. Full
docstrings in the source explain the MITRE mapping choices (T1071/Command
and Control for IDS alerts — necessarily approximate, explained inline;
T1560/Archive Collected Data; T1048/Exfiltration Over Alternative Protocol)
and the severity policy (MEDIUM, never escalated by these rules alone;
`NetworkIntrusionAlert` reflects Suricata's *own* severity classification,
mapped LOW/MEDIUM/HIGH — never CRITICAL, never fabricated).

Registered in `DetectionEngine.__init__`'s `self.rules` list
(`backend/detection/engine.py`), bringing the total from 4 to 7.

### 3.3 Taxonomy fixes (found while validating the above)

`backend/core/taxonomy.py`, three purely additive `_TAXONOMY_MAP` entries:

1. **`"network connection"` → `NETWORK_TRAFFIC`.** The literal raw
   `event_type` string used by `datasets/insider_threat/events.json` (and
   plausibly other hand-authored/generic telemetry) had no mapping at all —
   it silently fell through to `UNKNOWN`, meaning no `NETWORK_TRAFFIC`-gated
   rule could ever see that dataset's own network event.
2. **`"system_alert"` → `SYSTEM_ALERT`, `"network_traffic"` →
   `NETWORK_TRAFFIC`** (self-referential, snake_case, matching the
   already-existing `"auth_failure"`/`"process_execution"` entries). **This
   was a real, confirmed defect found during this phase's own
   verification**, not a hypothetical: `schemas.canonical_event.
   CanonicalSecurityEvent._apply_taxonomy` rewrites a normalized event's
   `event_type` to the canonical value's own string at ingest time (e.g.
   `"Suricata Alert"` → `"SYSTEM_ALERT"`), and every detection rule
   re-normalizes `event.event_type` from the *stored* value, not the
   original raw string. Without a self-referential map entry, re-normalizing
   `"system_alert"` (the lowercased stored value) resolved to `UNKNOWN`, not
   back to `SYSTEM_ALERT` — meaning `NetworkIntrusionAlert` and
   `LargeExternalDataTransfer` passed every unit test built against
   freshly-constructed `CanonicalSecurityEvent` objects, but **silently
   never fired against a single real, previously-ingested-and-stored
   event**. Caught by `tests/test_suricata_connector.py`'s end-to-end test
   (updated in this phase to assert a real detection match) failing
   unexpectedly, root-caused, and fixed; `test_phase13_detection.py::
   test_canonical_types_survive_taxonomy_round_trip` is the permanent
   regression test for this exact class of bug.

### 3.4 A second real bug found during live/dataset verification: Python's `is_private`

`LargeExternalDataTransfer`'s internal-address check originally used
`ipaddress.IPv4Address.is_private`, which — confirmed by direct
interpretation, not assumed — also covers RFC 5737 documentation/TEST-NET
ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). The
pre-existing `datasets/insider_threat/events.json` fixture uses
`203.0.113.50` as its example external destination — the standard, correct
use of a TEST-NET address in documentation/example data — which the
original check incorrectly treated as "internal," permanently blinding the
rule to this exact scenario. Fixed with a narrower
`_is_internal_network_address()` helper that checks RFC 1918 ranges,
loopback, link-local and unspecified explicitly, rather than Python's
broader `is_private`. In real production telemetry this distinction is
close to moot (genuine traffic essentially never targets a TEST-NET range),
so the narrowing does not weaken the rule against real internal traffic.

## 4. Tests

New file `backend/tests/test_phase13_detection.py` (17 tests), no mocks of
the systems under test — every test stores a real `Event` row through a real
`AsyncSession` and runs the real `detection_engine.process_event` against
it (same pattern as `tests/test_report_persistence.py`'s
`_create_detected_case()` helper):

- **Taxonomy round-trip regression** (2 tests) — the permanent regression
  test for §3.3's bug, and a direct check that the dataset's own
  `"Network Connection"` string classifies correctly.
- **D-1** (1 test) — a single event that genuinely satisfies both
  `SuspiciousProcessExecution` and `DataStagingViaArchiveUtility`
  (`process_name: "7z.exe"`, command line deliberately containing `-enc` —
  not a realistic real-world command, constructed specifically to exercise
  the only reachable rule-overlap in the current rule set) produces **both**
  findings on the same case.
- **`NetworkIntrusionAlert`** (4 tests) — positive (real signature cited in
  evidence), negative (a plain `flow` record below the transfer threshold
  creates no case — proving this rule does *not* fire on generic flow data),
  malformed (`SYSTEM_ALERT` event with empty metadata does not crash, falls
  back to "Unspecified network intrusion signature"), duplicate (identical
  repeated signature does not create duplicate evidence).
- **`DataStagingViaArchiveUtility`** (3 tests) — positive (verbatim
  reproduction of the dataset's own 7z.exe command), negative (`notepad.exe`
  does not match), malformed (missing `process_name` does not crash).
- **`LargeExternalDataTransfer`** (6 tests) — positive (verbatim
  reproduction of the dataset's own 15 MB/203.0.113.50 event, asserting the
  exact "14.3 MB" figure and the required hedge language in the evidence
  text), private-IP negative, below-threshold negative, missing-byte-count
  negative (no crash), malformed-IP negative (no crash), and Suricata's own
  `bytes_toserver` field name (not just the dataset's `bytes_sent`).
- **Real dataset replay** (1 test) — loads the actual
  `datasets/insider_threat/events.json` via the real
  `replay.engine.ReplayEngine.load_dataset()` and confirms both of the
  dataset's own real behaviors now produce detections.

`tests/test_suricata_connector.py`'s existing end-to-end test was updated
(not left stale): it previously asserted, correctly at the time, that no
detection fires for a Suricata alert; it now asserts `NetworkIntrusionAlert`
fires, since that assumption is no longer true after this phase.

**Regression proof (not decorative):** `git stash push -- backend/detection/
engine.py backend/core/taxonomy.py backend/detection/rules.py` and
re-running `test_phase13_detection.py` reproduced 10 of 17 failures (the
other 7 are negative/no-match cases, correctly unaffected either way);
`git stash pop` restored all 17 passing.

**Full suite:** `docker compose exec backend pytest -q tests/` →
**324 passed** (307 baseline + 17 new), run twice consecutively, zero flakes.

## 5. Live verification (real running stack, not simulated)

`docker compose restart backend celery_worker` to load the new code, then:

- **D-4, via the real HTTP endpoint** (`POST /events/ingest/suricata`,
  real API-key auth, real rate limiter, real Redis Streams bus, real
  consumer): a Cobalt Strike Beaconing signature match produced a real
  `InvestigationCase` ("Application Layer Protocol", HIGH — matching
  Suricata's own severity 1) with a real `EvidenceItem` citing the exact
  signature and category text. This also correctly triggered the real
  Phase 7 Celery multi-agent investigation pipeline — all 5 agents (Memory,
  Triage, Forensic Timeline, Threat Intel, SOC Lead) ran against it and
  reached `completed` status using the real local Ollama LLM, not a mock.
- **D-5, directly against the real dev database** (real `AsyncSession`,
  real `detection_engine`, real `correlation_engine` — not via HTTP, to
  avoid triggering two more full Celery/LLM investigations for what the
  pytest suite above already covers with real-DB rigor): a `7z.exe`
  archiving event followed by an 18 MB transfer to `198.51.100.77`, same
  synthetic user/host, correctly **correlated into one case** — the case
  title progressed from `"Archive Collected Data"` to `"Archive Collected
  Data + Exfiltration Over Alternative Protocol"` exactly as the insider-
  threat dataset's real narrative (stage, then exfiltrate) would produce,
  with both evidence rows present and correctly worded.
- All verification rows (events, evidence, attack techniques, security
  relationships, agent executions and their reasoning/tool-call/finding
  rows, investigation reports, and the cases themselves) were deleted
  afterward, **after waiting for all in-flight agent executions to reach a
  terminal state** (confirmed via polling, not assumed) — consistent with
  the standing "do not purge dev data" constraint, since this was data
  created and removed entirely within this same verification step, not
  pre-existing data.

## 6. Known limitations

- **D-1's noise problem is not fixed, only its data-loss problem.**
  `SuspiciousProcessExecution`'s broad `cmd.exe`/`powershell` keyword match
  (flagged in the original audit text as "matches any `cmd.exe`/`powershell`
  command line") was not narrowed — out of scope for a first-match/data-loss
  fix, and narrowing detection indicators without real-world tuning data
  risks the same "fabricated precision" the task warns against elsewhere.
- **D-3 (Sigma engine) remains a minimal, single-rule, flat-AND matcher.**
  Deliberately untouched — no concrete detection in this phase required
  expanding it, and the instruction was explicit: improve Sigma only where
  it enables a concrete, tested detection.
- **D-4 is not "C2 detection."** `NetworkIntrusionAlert` only surfaces an
  *existing* IDS's own signature match. No rule in this codebase
  independently infers command-and-control behavior from raw network flow
  data — this is a deliberate scope boundary, not an oversight, per the
  explicit governing constraint. A genuine C2/beaconing heuristic (traffic
  periodicity, JA3/TLS fingerprinting, destination reputation) remains
  unbuilt and would need either real threat-intel integration or carefully
  validated behavioral analysis this session did not have the telemetry or
  time budget to build responsibly.
- **D-5's file-access half remains open.** The insider-threat dataset's two
  `File Access` events (including one already flagged `"Unusual access
  pattern"` by the fixture itself) produce no detection — building a
  "sensitive file / unusual access" baseline would require a definition of
  "sensitive" this system does not have without fabricating a classifier.
- **`LargeExternalDataTransfer`'s 10 MB threshold and internal-network
  definition are not empirically tuned** against any real traffic baseline
  — they are round, documented, defensible defaults, not the product of
  false-positive-rate analysis against real production data (which this
  system does not have access to).
- **No new Sigma rules, no changes to `rules/sigma/proc_creation_win_
  powershell_suspicious.yml`.**
- **Phase 13 scenario orchestration has not been started**, per the
  governing instruction ("do not begin broad scenario orchestration until
  the underlying detections work").

## 7. Completion criterion

D-1's first-match defect is fixed with a passing regression test confirmed
to fail without the fix. D-4 and D-5 each have a genuinely new, evidence-
based, explicitly-hedged detection rule, backed by unit, negative,
malformed-input, duplicate-event, and real-dataset-replay tests, and
verified live against the running stack including a real multi-agent
investigation run and a real multi-stage case correlation. D-3 was
correctly left alone. No rule in this phase claims C2 identification from
generic network flows, fabricates a threat-intelligence capability this
system does not have, or asserts confirmed malicious intent beyond what its
underlying evidence actually shows.
