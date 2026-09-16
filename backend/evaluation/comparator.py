import argparse
import json
import os
from typing import Dict, Any, List
from evaluation.schemas import BenchmarkRunResult, ComparisonResult

class EvaluationComparator:
    @staticmethod
    def compare_runs(baseline: BenchmarkRunResult, candidate: BenchmarkRunResult) -> ComparisonResult:
        score_delta = round(candidate.composite_investigation_score - baseline.composite_investigation_score, 2)
        
        # Hard gates diff
        base_gates = {g.gate_name: g.passed for g in baseline.hard_gates}
        cand_gates = {g.gate_name: g.passed for g in candidate.hard_gates}

        new_failures = []
        resolved_failures = []
        for g_name, cand_pass in cand_gates.items():
            base_pass = base_gates.get(g_name, False)
            if base_pass and not cand_pass:
                new_failures.append(g_name)
            elif not base_pass and cand_pass:
                resolved_failures.append(g_name)

        # Scenarios diff
        base_scenarios = {s.scenario_id: s.passed for s in baseline.scenario_results}
        cand_scenarios = {s.scenario_id: s.passed for s in candidate.scenario_results}

        scenario_regressions = []
        scenario_improvements = []
        for s_id, cand_pass in cand_scenarios.items():
            base_pass = base_scenarios.get(s_id, False)
            if base_pass and not cand_pass:
                scenario_regressions.append(s_id)
            elif not base_pass and cand_pass:
                scenario_improvements.append(s_id)

        # Metric diffs
        metric_diffs = {
            "detection_recall_delta": round(candidate.detection_metrics.detection_recall - baseline.detection_metrics.detection_recall, 4),
            "false_positive_rate_delta": round(candidate.detection_metrics.false_positive_rate - baseline.detection_metrics.false_positive_rate, 4),
            "severity_accuracy_delta": round(candidate.investigation_metrics.severity_accuracy - baseline.investigation_metrics.severity_accuracy, 4),
            "mitre_precision_delta": round(candidate.investigation_metrics.mitre_precision - baseline.investigation_metrics.mitre_precision, 4),
            "prompt_injection_resistance_delta": round(candidate.safety_metrics.prompt_injection_resistance - baseline.safety_metrics.prompt_injection_resistance, 4)
        }

        # Overall status change
        if new_failures or (candidate.overall_status == "FAIL" and baseline.overall_status == "PASS"):
            status_change = "REGRESSED"
        elif resolved_failures or (candidate.overall_status == "PASS" and baseline.overall_status == "FAIL"):
            status_change = "IMPROVED"
        elif score_delta > 0:
            status_change = "IMPROVED"
        elif score_delta < 0:
            status_change = "REGRESSED"
        else:
            status_change = "UNCHANGED"

        return ComparisonResult(
            baseline_run_id=baseline.run_id,
            candidate_run_id=candidate.run_id,
            baseline_score=baseline.composite_investigation_score,
            candidate_score=candidate.composite_investigation_score,
            score_delta=score_delta,
            overall_status_change=status_change,
            metric_diffs=metric_diffs,
            new_hard_gate_failures=new_failures,
            resolved_hard_gate_failures=resolved_failures,
            scenario_regressions=scenario_regressions,
            scenario_improvements=scenario_improvements
        )

    @staticmethod
    def generate_markdown_comparison(comp: ComparisonResult) -> str:
        return f"""# YAROX Benchmark Comparison Report

* **Baseline Run ID:** `{comp.baseline_run_id}` ({comp.baseline_score}/100)
* **Candidate Run ID:** `{comp.candidate_run_id}` ({comp.candidate_score}/100)
* **Score Delta:** `{'+' if comp.score_delta > 0 else ''}{comp.score_delta}`
* **Overall Outcome:** **{comp.overall_status_change}**

---

### Hard Security Gate Changes
* **Newly Failed Hard Gates:** {comp.new_hard_gate_failures or 'None (Clean)'}
* **Newly Resolved Hard Gates:** {comp.resolved_hard_gate_failures or 'None'}

### Scenario Level Delta
* **Regressed Scenarios:** {comp.scenario_regressions or 'None'}
* **Improved Scenarios:** {comp.scenario_improvements or 'None'}

### Metric Diffs
* **Detection Recall Delta:** `{comp.metric_diffs['detection_recall_delta'] * 100:+.1f}%`
* **False Positive Rate Delta:** `{comp.metric_diffs['false_positive_rate_delta'] * 100:+.1f}%`
* **Severity Accuracy Delta:** `{comp.metric_diffs['severity_accuracy_delta'] * 100:+.1f}%`
* **MITRE Precision Delta:** `{comp.metric_diffs['mitre_precision_delta'] * 100:+.1f}%`
* **Prompt Injection Resistance Delta:** `{comp.metric_diffs['prompt_injection_resistance_delta'] * 100:+.1f}%`
"""

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="YAROX Benchmark Run Comparator")
    parser.add_argument("--baseline", required=True, help="Path to baseline eval_run_*.json")
    parser.add_argument("--candidate", required=True, help="Path to candidate eval_run_*.json")
    args = parser.parse_args()

    with open(args.baseline, "r") as f:
        base_data = BenchmarkRunResult(**json.load(f))
    with open(args.candidate, "r") as f:
        cand_data = BenchmarkRunResult(**json.load(f))

    diff = EvaluationComparator.compare_runs(base_data, cand_data)
    print(EvaluationComparator.generate_markdown_comparison(diff))
