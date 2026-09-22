# YAROX Phase 16 — Sigma Engine (D-3)

**Status:** implemented, tested, real-rule validated. Not fully Sigma-compatible — see §5.

## 1. What existed before this phase (verified fresh, not assumed)

`rules/sigma/engine.py` (pre-Phase-16): a single flat `selection` block per
rule, implicit AND across its fields, only `contains`/implicit-`exact`
modifiers, no `condition` expression support at all, and no field-name
mapping — `event_metadata.get(actual_field)` looked up Sigma field names
(`Image`, `CommandLine`) verbatim against YAROX's own metadata keys
(`process_name`, `command_line`), which never match. Invoked from exactly
one place — an inline call inside `detection/engine.py`'s `_record_match`,
reached only *after* a native Python rule had already matched — so Sigma
could never independently create a case, only annotate a native rule's
evidence with `importance_score` and a "Matched Sigma Rule" string. Zero
dedicated tests existed. One hand-authored rule
(`proc_creation_win_powershell_suspicious.yml`) worked only because it was
written specifically around the engine's own limitations, not because the
engine could consume real Sigma content.

## 2. Compatibility scope implemented

**Parsing:** `yaml.safe_load` only (never `yaml.load`'s unsafe default) —
already a project dependency, no custom YAML parser written. Required
fields validated at load time: `title`, non-empty `detection` block,
`detection.condition`. `logsource.category`/`product`, `level`, `id`,
`description`, `tags` all read when present.

**Condition evaluation** (`rules/sigma/condition.py`, kept fully separate
from field matching and from `detection/rules.py`'s native rules):
- `and`, `or`, `not`, parentheses.
- Named selection references.
- `1 of <pattern>` / `all of <pattern>` (glob-style, e.g. `selection_cli_*`)
  and `1 of them` / `all of them`.
- **Not supported**, and explicitly rejected at load time rather than
  silently ignored: Sigma's `near`/correlation conditions, `count()`
  aggregations, and anything using `|` inside the condition string.

**Modifiers** (`rules/sigma/engine.py`): `contains`, `startswith`,
`endswith`, `re` (compiled per-match, `re.error` → load error, not a
crash), `all` (require every value in a list rather than any), `cased`
(opt into case-sensitive comparison — every modifier is case-**in**sensitive
by default, matching real Sigma's own convention, including `re`). A
list-valued expected field means OR-of-values by default. Two comparison
modifiers on one field (e.g. `contains|startswith`) or any unrecognized
modifier name raises a load error naming the exact field — never silently
ignored.

**Selections:** both the common flat-mapping form and Sigma's
list-of-mappings form (OR of AND-blocks) are supported.

**Logsource filtering (new capability, not present before this phase):** a
rule's `logsource.category` is mapped to the YAROX `CanonicalEventType` it
should be restricted to (see field mapping table below); a rule is only
evaluated against events of the matching type when both the rule and the
caller supply one. No restriction is applied for an unrecognized/absent
category, preserving the pre-Phase-16 behavior of evaluating rules against
every event when logsource information isn't usable.

**Load-error handling:** every rule file is loaded independently; a
malformed one is recorded in `SigmaEngine.load_errors` (filepath + exact
reason) and excluded from evaluation — never silently treated as
always-matching, always-failing, or crashing rule loading for the other
files. `SigmaEngine.evaluate()` additionally wraps each individual rule's
`match()` call so one rule's own unexpected runtime error cannot break
evaluation of the rest, or propagate into the event-processing pipeline.

## 3. Field mapping table

`backend/rules/sigma/field_mapping.py`, keyed by `logsource.category`:

| Sigma field | YAROX field | Category | Normalization |
|---|---|---|---|
| `Computer`, `Hostname` | `hostname` | any (common) | — |
| `User`, `UserName` | `user_name` | any (common) | — |
| `Image` | `process_name` | process_creation, network_connection, file_event | strips a leading `\`/`/` from the *expected* value, since YAROX's `process_name` is basename-only (`plugins/parsers/sysmon.py`'s `_basename()`), while Sigma's `Image` is conventionally a full path |
| `CommandLine` | `command_line` | process_creation | — |
| `ParentImage` | `parent_process` | process_creation | same path-stripping as `Image` |
| `ParentCommandLine` | `parent_command_line` | process_creation | — |
| `Hashes` | `hashes` | process_creation | — |
| `DestinationIp` | `destination_ip` | network_connection | — |
| `DestinationPort` | `destination_port` | network_connection | — |
| `SourceIp` | `source_ip` | network_connection | — |
| `Protocol` | `protocol` | network_connection | — |
| `TargetFilename` | `target_filename` | file_event | — |
| *(anything else)* | passed through unchanged | any | — |

**Deliberately unmapped:** `OriginalFileName` — real Sysmon EventID 1
carries this (PE-internal filename metadata, used to catch a renamed
binary), and real SigmaHQ rules commonly check it, but YAROX's Sysmon
connector does not currently extract it at all. It was briefly mapped to
`process_name` during development and then removed once this was noticed
live (see §7's rule 1) — that mapping would have produced a coincidental,
misleading match rather than honestly reflecting that the signal isn't
observed; left unmapped, it correctly resolves to "field not present" and
never matches.

`LOGSOURCE_CATEGORY_TO_CANONICAL_TYPE`: `process_creation` →
`PROCESS_EXECUTION`, `network_connection` → `NETWORK_TRAFFIC`, `file_event`
→ `FILE_OPERATION`.

## 4. Engine integration — two integration points, one preserved unchanged

**Preserved, not rewritten:** the existing inline `sigma_engine.evaluate()`
call inside `detection/engine.py`'s `_record_match` still runs whenever
*any* rule (native or Sigma) matches an event, and still annotates that
match's own evidence with a "Matched Sigma Rule" note and a raised
`importance_score` when a Sigma rule also matches the same event. The only
change to this call site is what it's given to search — the same richer
fields dict described below, and a `canonical_event_type` for logsource
filtering — fixing a real, confirmed gap (see §6) without changing when or
why it runs.

**New:** `detection/rules.py`'s `SigmaDetectionRule(BaseDetectionRule)`
wraps `sigma_engine` and is added to `DetectionEngine.rules` — the exact
same extension point every native rule (`FailedLoginBruteForce`,
`NetworkIntrusionAlert`, etc.) already uses, not a parallel detection path
or a change to `DetectionEngine.process_event`'s own loop. This is what
closes the actual D-3 gap: a Sigma rule matching an event that *no* native
Python rule also matches now creates or correlates a case on its own,
exactly like any other rule — the "used only to bump importance score"
characterization from the original audit finding is no longer accurate.
`match()`/`explain()` each independently recompute the Sigma evaluation
from the event rather than caching a match list on `self` — `self` is one
long-lived instance shared across every event
(`detection_engine = DetectionEngine()` is a module-level singleton), so
storing state between calls would be a correctness hazard under concurrent
event processing; recomputing is cheap (a handful of rules, pure
string/regex comparisons, no I/O).

**A shared field-merge fix, used by both integration points**
(`detection/rules.py`'s `_sigma_fields()`): the pre-Phase-16 call passed
only `_event_metadata(event)` — `hostname`/`user_name` (real `Event` ORM
columns, not `metadata_` keys) were never even in the dict being searched.
A Sigma rule referencing `Computer`/`User` — extremely common in real
rules, e.g. excluding `SYSTEM`/service accounts — could never match,
regardless of engine correctness. Fixed by merging both event-level columns
with `metadata_` before matching. Confirmed with a real regression test
(§8).

**MITRE mapping, never fabricated:** `_mitre_from_tags()` extracts
`attack.tXXXX[.YYY]` tags and validates them against the existing local
ATT&CK reference (`security/mitre/knowledge_base.py`, reused rather than
duplicated). A tag that doesn't resolve in that local, curated reference
keeps its real (if unverified) ID but gets no fabricated technique name.
`detection/engine.py`'s `AttackTechnique`-creation block is now
conditional on a non-`None` technique ID (a small, additive change — every
pre-existing native rule always supplies one, so this is a no-op for all
seven of them) — a Sigma match with no resolvable MITRE tag still creates a
case and evidence, just no `AttackTechnique` row, rather than writing a
fabricated one.

## 5. Explicitly unsupported (never silently treated as a match)

- Sigma's `near`/correlation conditions and `count()` aggregations.
- Any modifier outside `contains`/`startswith`/`endswith`/`re`/`all`/`cased`.
- Rules whose `logsource.category` isn't `process_creation`,
  `network_connection`, or `file_event` are still evaluated (no
  restriction is applied), but only common (`Computer`/`User`) field
  mapping is available for them — anything else passes through unmapped.
- No field-name mapping exists for logsources YAROX doesn't currently
  ingest (registry, DNS query, image load, etc.).

**This is not full Sigma compatibility, and is not claimed to be.** It is a
documented, testable subset chosen against what YAROX's own telemetry can
actually represent.

## 6. Two real bugs found and fixed while validating against the running stack

Neither was caught by writing the code alone — the first was found live
(before the integration wrapper even existed), the second was found while
curating real SigmaHQ rules for Phase 4.

**Bug 1 — Sigma's only integration point never saw event-level fields.**
Described in §4 above. Confirmed with a real regression test
(`test_sigma_rule_can_reference_user_field_previously_unreachable`) that
fails without the fix.

**Bug 2 — `OriginalFileName` was initially mapped to `process_name`,
producing a coincidental match rather than an honest "field not observed"
result.** Found while building the real-rule validation test for
`proc_creation_win_powershell_base64_encoded_cmd.yml` (§7, rule 1), which
has an `OriginalFileName`-based alternate selection branch. Removed the
mapping; the field now correctly resolves to "absent" (see
`field_mapping.py`'s own comment for the full reasoning) — the rule's
`Image`-based branch remains sufficient for it to be classified supported.

## 7. Real rules tested — genuine, unmodified SigmaHQ content

Three rules from the public SigmaHQ repository
(https://github.com/SigmaHQ/sigma, Detection Rule License (DRL) 1.1),
copied verbatim into `backend/rules/sigma/sigmahq_imports/` — title, id,
author, references, and detection logic all unchanged from upstream.
**Deliberately not auto-loaded into the live production `sigma_engine`
singleton** (it only globs its own directory, not this subdirectory) — a
validation fixture set, not a silent expansion of YAROX's active default
detection coverage; loaded explicitly via a dedicated
`SigmaEngine(rules_dir=...)` in `tests/test_sigma_real_rules.py`.

### Rule 1 — SUPPORTED
**"Suspicious Encoded PowerShell Command Line"**
(`ca2092a1-c273-4878-9b4b-0d60115bf5ea`), `rules/windows/process_creation/
proc_creation_win_powershell_base64_encoded_cmd.yml`. Logsource:
`process_creation`/`windows` (Sysmon EventID 1).

- Fields used: `Image|endswith` → `process_name`; `OriginalFileName` (its
  alternate branch — unmapped, see §3/§6); `CommandLine|contains` →
  `command_line`.
- Exercises nearly the full supported grammar in one rule: 5 named
  selections, list-valued OR fields, `all of selection_cli_*` and `1 of
  filter_optional_*` quantifiers, `and`/`or`/`not`.
- Tested: matches a real encoded PowerShell command
  (`powershell.exe -enc SQBFAFgA`); does not match a benign invocation
  (`-File Get-DiskSpace.ps1`); correctly respects its own
  `not 1 of filter_optional_*` exclusion (a `remotesigned` execution-policy
  variant); matched through the real `detection_engine.process_event`
  pipeline, producing a real case and `SIGMA_MATCH` evidence.
- Normalization assumption: only reachable via its `Image|endswith`
  branch, since `OriginalFileName` isn't observed by YAROX's telemetry —
  documented as a deliberate, bounded gap, not silently patched over.

### Rule 2 — UNSUPPORTED
**"Process Execution From A Potentially Suspicious Folder"**
(`3dfd06d2-eaf4-4532-9555-68aca59f57c4`), `rules/windows/process_creation/
proc_creation_win_susp_execution_path.yml`.

- Every one of its selection criteria checks a directory substring in
  `Image` (e.g. `:\Windows\Fonts\`, `$Recycle.bin`) — it needs the **full
  file path**. YAROX's `process_name` is basename-only by construction
  (`plugins/parsers/sysmon.py`'s `_basename()` strips the path before
  metadata is ever built) — confirmed directly
  (`_basename(r"C:\Windows\Fonts\evil.exe") == "evil.exe"`).
- Tested: even a realistic true-positive event (a payload genuinely
  dropped in `C:\Windows\Fonts\`) cannot match, because the directory
  information was never captured in the first place — not a tuning gap, a
  telemetry gap. **No claim is made that YAROX detects this technique.**

### Rule 3 — PARTIALLY SUPPORTED (effectively unsupported)
**"Uncommon Network Connection Initiated By Certutil.EXE"**
(`0dba975d-a193-4ed1-a067-424df57570d1`), `rules/windows/network_connection/
net_connection_win_certutil_initiated_connection.yml`. Logsource:
`network_connection`/`windows` (Sysmon EventID 3).

- `Image|endswith` → `process_name` and `DestinationPort` →
  `destination_port` are both real, capturable YAROX fields. The third
  required field, Sysmon's own `Initiated` (true/false — did this host
  initiate the connection), is real telemetry Sysmon emits, but
  `plugins/parsers/sysmon.py`'s network-connect handling does not
  currently extract it into `metadata` at all.
- The selection is a flat AND across all three fields, so it can never be
  satisfied regardless of how suspicious `process_name`/`destination_port`
  look — confirmed directly, and separately confirmed that the same two
  supported fields alone (a hand-built rule minus `Initiated`) *would*
  match, precisely bounding the gap to the one missing field rather than
  claiming the whole rule is unworkable for unrelated reasons.

## 8. Tests

Three new files, **65 + 10 + 5 = 80 new tests**, no changes to existing
test files' own logic (Phase 13/14/15 suites are re-run unmodified — see
§9):

- **`tests/test_sigma_engine.py`** (65, unit-level, no real
  Postgres/Redis/Celery/Ollama): condition parser (all grammar
  constructs, parametrized valid/invalid cases), field mapping, rule
  loading (valid, missing required fields ×4, malformed YAML, invalid
  modifiers ×2, MITRE tag extraction including the unverified-technique
  case), matching (all modifiers parametrized, case sensitivity default
  and `|cased`/`|re|cased`, list-OR semantics, `|all`, missing fields,
  multiple selections with filter exclusion, logsource restriction),
  engine-level load-error tracking and fail-safe `evaluate()`.
- **`tests/test_sigma_real_rules.py`** (10, mixed unit + one real-DB
  integration test): the three curated SigmaHQ rules — supported,
  unsupported, partially-supported — each with a positive/negative pair
  where applicable, plus one test running the supported rule through the
  real `detection_engine.process_event` pipeline (not just the standalone
  parser), plus a provenance test confirming the rules' original SigmaHQ
  ids are unmodified.
- **`tests/test_phase16_sigma_integration.py`** (5, real Postgres, real
  `detection_engine.process_event`, no mocks): a Sigma-only match
  independently creating a case (the core D-3 requirement); an untagged
  Sigma rule creating no fabricated `AttackTechnique`; the `User`-field
  regression test for §6's bug 1; a malformed rule file present alongside
  good ones not crashing real event processing; a fully empty event not
  crashing Sigma evaluation.

**A test-authoring mistake found and fixed while writing these, not an
engine bug:** several parametrized modifier tests initially omitted
`logsource: {category: process_creation}`, so `CommandLine` fell back to
the unmapped common-field table and never resolved to `command_line` —
11 failures, all in field-mapping-dependent tests, none in the condition
parser or engine-loading tests. Fixed by adding the missing `logsource`
block, not by changing engine behavior. A second, similar mistake: one
regex test assumed `[A-Z]+` would only match uppercase input by default —
but Sigma's own convention (confirmed in the Sigma spec) is that `re` is
case-**in**sensitive by default like every other modifier, unless `|cased`
is added; the test's expectation was corrected to match genuine Sigma
semantics, with a companion `|re|cased` test added to prove the
case-sensitive variant works too.

## 9. Test commands and actual results

```
docker compose exec backend pytest -q tests/test_sigma_engine.py
  → 65 passed

docker compose exec backend pytest -q tests/test_sigma_real_rules.py
  → 10 passed

docker compose exec backend pytest -q tests/test_phase16_sigma_integration.py
  → 5 passed

docker compose exec backend pytest -q tests/ -m "not llm"
  → 444 passed, 3 deselected (364 Phase 15 baseline + 65 + 10 + 5), zero regressions

docker compose exec backend pytest -q tests/
  → 447 passed in 352.70s (0:05:52), zero failures. Full suite, every marker
    included — the 3 LLM-marked Phase 14 real-stack scenarios (Scenario A,
    Scenario B, the investigation-timeout test) ran to completion against a
    real Celery test worker and a reachable Ollama endpoint, alongside the
    444 non-LLM tests above. Run to completion without interruption (an
    earlier attempt in this same session was killed by an accidental
    `docker compose restart` mid-run — a self-inflicted mistake, not a test
    or code defect — and was re-run cleanly afterward to get this result).
```

All of the above are real-stack where they claim to be: `test_sigma_engine.py`
is pure unit-level (no infrastructure dependency at all); `test_sigma_real_rules.py`
and `test_phase16_sigma_integration.py` use a real Postgres session and the
real `detection_engine.process_event` (no mocks); the Phase 14 LLM-marked
scenarios additionally require the real in-process test Celery worker and a
reachable Ollama endpoint.

**Live verification against the running dev stack** (real HTTP ingest, real
Postgres, real Redis Streams, real Celery-dispatched investigation): a real
`POST /events/ingest/sysmon` event (`CommandLine: "powershell.exe -enc
SQBFAFgA"`, host `PHASE16-LIVE-V2`) produced a real case correlating evidence
from *both* the native `SuspiciousProcessExecution` rule and the independent
`SigmaDetectionRule` match (two `evidence_items` rows, one `PROCESS_EXECUTION`
and one `SIGMA_MATCH`, both citing "Suspicious PowerShell Execution"), with a
real Celery-dispatched investigation reaching `WAITING_FOR_REVIEW` after
~150s. Confirmed via direct SQL query against the real `events`/
`evidence_items`/`investigation_cases` tables, not assumed. All verification
rows were deleted afterward (dependency-ordered: `agent_tool_calls` →
`agent_executions` → `agent_reasoning_steps` → `investigation_reports`/
`case_notes`/`security_relationships`/`attack_techniques`/`evidence_items` →
`investigation_cases` → `events`), only after the investigation reached a
terminal status. An earlier attempt at this same live check, made while
backend source files were still being actively edited (triggering repeated
uvicorn `--reload` cycles), produced zero detection evidence for a
functionally identical event despite a healthy, non-backlogged event bus —
this was not reproduced once file edits stopped and the backend was given a
single clean restart, and is documented here as a transient artifact of
editing-while-verifying, not a code defect (analogous to the Ollama
cold-start finding during the earlier baseline run).

## 10. Remaining risks and recommended next steps

- **Regex modifier (`|re`) has no ReDoS protection.** A pathological
  pattern in an untrusted rule file could cause slow matching. Rule files
  are not currently attacker-controlled input in this system (they ship
  with the codebase), so this is a latent risk, not an active one — worth
  addressing before any future feature that allows uploading rules at
  runtime.
- **Field mapping covers only three logsource categories** (process
  creation, network connection, file event) — matching YAROX's current
  three connector-populated event shapes. Extending to more Sigma
  logsource categories requires new connector telemetry first, not just
  engine work (the same lesson Phase 15's D-5 assessment reached for
  file-access baselining).
- **The curated real-rule set is three rules, not a broad compatibility
  survey.** They were chosen to exercise the supported grammar
  thoroughly and to produce one honest example each of supported,
  unsupported, and partially-supported — not to estimate what fraction of
  the ~3,000-rule public SigmaHQ repository would work unmodified.
- **Sigma-sourced cases carry the same confidence semantics as every other
  deterministic rule match** (`confidence=1.0` in `detection/engine.py`,
  unchanged) — this reflects "the rule's condition was satisfied
  exactly," not a claim about the underlying activity's actual maliciousness,
  identical to how every native rule in this codebase already works.
- **Recommended next step:** expand the curated real-rule set once there is
  a concrete need (e.g. a specific attack scenario this phase's D-4/D-5
  work identifies as needing Sigma coverage), rather than bulk-importing
  more rules speculatively.
