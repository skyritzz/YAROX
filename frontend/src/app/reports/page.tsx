"use client"

import { useQuery } from "@tanstack/react-query"
import { api, downloadReportPdf } from "@/lib/api"
import { useState } from "react"
import {
  FileText,
  Download,
  Shield,
  Target,
  CheckCircle2,
  Clock,
  AlertTriangle,
} from "lucide-react"
import { format } from "date-fns"
import { MemoryInsights } from "@/components/investigation/MemoryInsights"

/* ================================================================
   Severity helpers
   ================================================================ */
const severityConfig: Record<string, { color: string; bg: string }> = {
  CRITICAL: { color: "var(--severity-critical)", bg: "var(--severity-critical-bg)" },
  HIGH: { color: "var(--severity-high)", bg: "var(--severity-high-bg)" },
  MEDIUM: { color: "var(--severity-medium)", bg: "var(--severity-medium-bg)" },
  LOW: { color: "var(--severity-low)", bg: "var(--severity-low-bg)" },
  INFO: { color: "var(--severity-info)", bg: "var(--severity-info-bg)" },
}

const reportStatusLabel: Record<string, string> = {
  complete: "All agents completed",
  partial: "Partial: an upstream agent degraded",
  degraded: "Degraded: SOC Lead produced no validated report",
}

const card = {
  boxShadow: "var(--shadow-card)",
  border: "1px solid var(--border-default)",
}

function EvidenceRefs({ ids }: { ids: string[] }) {
  if (!ids?.length) return null
  return (
    <span className="text-[10px] font-mono text-[var(--text-secondary)]">
      evidence: {ids.map((id) => id.substring(0, 8)).join(", ")}
    </span>
  )
}

export default function ReportsPage() {
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [exportError, setExportError] = useState<string | null>(null)

  const { data: investigations, isLoading } = useQuery({
    queryKey: ["investigations"],
    queryFn: async () => {
      const { data } = await api.get("/investigations/")
      return data.sort(
        (a: any, b: any) =>
          new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime()
      )
    },
    refetchInterval: 5000,
  })

  // Case record (for evidence details)
  const { data: caseData } = useQuery({
    queryKey: ["investigation", selectedId],
    queryFn: async () => {
      const { data } = await api.get(`/investigations/${selectedId}`)
      return data
    },
    enabled: !!selectedId,
  })

  // Persisted report: the single source of truth for summary, findings, recommendations, timeline and MITRE
  const { data: report, isLoading: reportLoading } = useQuery({
    queryKey: ["investigationReport", selectedId],
    queryFn: async () => {
      try {
        const { data } = await api.get(`/investigations/${selectedId}/report`)
        return data
      } catch (err: any) {
        if (err?.response?.status === 404) return null
        throw err
      }
    },
    enabled: !!selectedId,
  })

  // Auto-select first case that has finished analysis
  if (!selectedId && investigations?.length > 0) {
    const completed = investigations.find(
      (i: any) =>
        i.status === "WAITING_FOR_REVIEW" ||
        i.status === "RESOLVED" ||
        i.status === "FALSE_POSITIVE"
    )
    setSelectedId((completed || investigations[0]).id)
  }

  const handleExport = async (caseId: string) => {
    setExportError(null)
    try {
      await downloadReportPdf(caseId)
    } catch (err: any) {
      setExportError(err?.response?.status === 404 ? "No report has been generated for this case." : "Export failed.")
    }
  }

  const evidenceById: Record<string, any> = {}
  for (const e of caseData?.evidence_items || []) evidenceById[e.id] = e

  const sev = severityConfig[report?.severity] || severityConfig.INFO

  if (isLoading) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <div className="flex items-center gap-3 text-[var(--text-secondary)]">
          <div className="w-5 h-5 border-2 border-[var(--accent-color)] border-t-transparent rounded-full animate-spin" />
          Loading reports...
        </div>
      </div>
    )
  }

  return (
    <div className="flex-1 flex h-full overflow-hidden">
      {/* Left: Case list */}
      <div
        className="w-[260px] shrink-0 bg-white flex flex-col h-full overflow-hidden"
        style={{ borderRight: "1px solid var(--border-default)" }}
      >
        <div className="px-4 pt-5 pb-3">
          <h2 className="text-sm font-semibold text-[var(--text-primary)]">Reports</h2>
          <p className="text-[10px] text-[var(--text-secondary)] mt-0.5">Select a case to view its report</p>
        </div>
        <div className="flex-1 overflow-y-auto px-3 pb-3 custom-scrollbar space-y-1">
          {investigations?.map((inv: any) => {
            const isActive = inv.id === selectedId
            const invSev = severityConfig[inv.severity] || severityConfig.INFO
            return (
              <button
                key={inv.id}
                onClick={() => setSelectedId(inv.id)}
                className={`w-full text-left rounded-xl p-3 transition-all duration-150 ${
                  isActive ? "bg-[var(--accent-light)]" : "hover:bg-[var(--muted)]"
                }`}
                style={{ borderLeft: isActive ? "3px solid var(--accent-color)" : "3px solid transparent" }}
              >
                <div className="flex items-center gap-2 mb-1">
                  <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: invSev.color }} />
                  <span className="text-xs font-medium text-[var(--text-primary)] truncate">{inv.title}</span>
                </div>
                <div className="pl-4 text-[10px] text-[var(--text-secondary)]">{inv.status.replace(/_/g, " ")}</div>
              </button>
            )
          })}
          {(!investigations || investigations.length === 0) && (
            <div className="text-xs text-[var(--text-secondary)] text-center py-8">No cases available.</div>
          )}
        </div>
      </div>

      {/* Right: Report view */}
      <div className="flex-1 overflow-y-auto custom-scrollbar">
        {selectedId && reportLoading && (
          <div className="py-16 text-center text-sm text-[var(--text-secondary)]">Loading report...</div>
        )}

        {selectedId && !reportLoading && report === null && (
          <div className="flex-1 flex flex-col items-center justify-center py-16">
            <FileText className="w-12 h-12 text-[var(--border-default)] mb-4" />
            <p className="text-sm text-[var(--text-secondary)]">No report has been generated for this case yet.</p>
          </div>
        )}

        {selectedId && report && (
          <div className="max-w-[900px] mx-auto px-8 py-8 space-y-8">
            {/* Header */}
            <div
              className="rounded-2xl p-6"
              style={{ ...card, background: `linear-gradient(135deg, ${sev.bg} 0%, white 100%)` }}
            >
              <div className="flex items-start justify-between mb-4">
                <div>
                  <div className="flex flex-wrap items-center gap-2 mb-2">
                    <span
                      className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider"
                      style={{ backgroundColor: sev.bg, color: sev.color }}
                    >
                      <AlertTriangle className="w-3 h-3" />
                      {report.severity}
                    </span>
                    <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold bg-[var(--muted)] text-[var(--text-secondary)]">
                      Confidence:{" "}
                      {report.confidence_score !== null && report.confidence_score !== undefined
                        ? `${(report.confidence_score * 100).toFixed(0)}%`
                        : "Not available"}
                    </span>
                    <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold bg-[var(--muted)] text-[var(--text-secondary)]">
                      v{report.version} · {reportStatusLabel[report.status] || report.status}
                    </span>
                  </div>
                  <h1 className="text-2xl font-bold text-[var(--text-primary)]">{report.title}</h1>
                  <p className="text-xs text-[var(--text-secondary)] mt-1">
                    Case {report.case_id.substring(0, 8)} · Report generated {format(new Date(report.generated_at), "PPpp")}
                  </p>
                </div>
                <button
                  onClick={() => handleExport(report.case_id)}
                  className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl text-sm font-semibold bg-[var(--accent-color)] text-white hover:bg-[var(--accent-hover)] transition-colors"
                >
                  <Download className="w-4 h-4" /> Export PDF
                </button>
              </div>
              {exportError && <div className="text-xs text-red-600 mb-2">{exportError}</div>}

              <div className="text-sm text-[var(--text-secondary)] leading-relaxed bg-white/60 rounded-xl p-4 mt-4">
                {report.executive_summary ||
                  "Not available: the SOC Lead did not produce a validated report. Manual review required."}
              </div>

              <div className="flex flex-wrap gap-2 mt-3">
                {report.agent_runs.map((run: any) => (
                  <span
                    key={run.agent}
                    title={run.error || ""}
                    className={`text-[10px] px-2 py-0.5 rounded-full ${
                      run.status === "completed" ? "bg-[var(--success-bg)] text-[var(--success)]" : "bg-red-50 text-red-600"
                    }`}
                  >
                    {run.agent}: {run.status}
                  </span>
                ))}
              </div>
            </div>

            {/* Memory Insights / Historical Comparison */}
            <MemoryInsights caseId={report.case_id} />

            {/* Findings */}
            <div className="bg-white rounded-2xl p-5" style={card}>
              <h2 className="text-sm font-semibold text-[var(--text-primary)] mb-4 flex items-center gap-2">
                <Shield className="w-4 h-4 text-[var(--accent-color)]" />
                Evidence-backed Findings ({report.findings.length})
              </h2>
              {report.findings.length === 0 ? (
                <p className="text-sm text-[var(--text-secondary)]">No evidence-backed findings were recorded.</p>
              ) : (
                <div className="space-y-3">
                  {report.findings.map((f: any) => (
                    <div key={f.finding_id} className="rounded-xl p-3 bg-[var(--muted)]">
                      <div className="flex items-center gap-2 mb-1 text-[10px] uppercase tracking-wider">
                        <span className="font-bold text-[var(--text-primary)]">{f.agent}</span>
                        <span
                          className={`px-1.5 py-0.5 rounded ${
                            f.kind === "observation" ? "bg-[var(--success-bg)] text-[var(--success)]" : "bg-[var(--severity-medium-bg)] text-[var(--severity-medium)]"
                          }`}
                        >
                          {f.kind}
                        </span>
                      </div>
                      <div className="text-sm text-[var(--text-primary)]">{f.finding}</div>
                      {f.reasoning_summary && (
                        <div className="text-xs text-[var(--text-secondary)] mt-1">{f.reasoning_summary}</div>
                      )}
                      <div className="mt-2 space-y-1">
                        {f.evidence.map((c: any) => (
                          <div key={c.evidence_id} className="text-[10px] font-mono text-[var(--text-secondary)] break-all">
                            {c.evidence_id.substring(0, 8)} · {c.evidence_type} · {c.event_source || c.source} ·{" "}
                            {c.event_timestamp || c.timestamp}
                            {c.event_payload_sha256 ? ` · sha256 ${c.event_payload_sha256.substring(0, 12)}…` : " · hash not recorded"}
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Timeline */}
            <div className="bg-white rounded-2xl p-5" style={card}>
              <h2 className="text-sm font-semibold text-[var(--text-primary)] mb-1 flex items-center gap-2">
                <Clock className="w-4 h-4 text-[var(--accent-color)]" />
                Attack Timeline
              </h2>
              <p className="text-[10px] text-[var(--text-secondary)] mb-4">
                Source:{" "}
                {report.timeline_source === "timeline_agent"
                  ? "Forensic Timeline Analyst (evidence-cited)"
                  : "Evidence chronology (timeline agent output unavailable)"}
              </p>
              <div className="relative pl-6 space-y-3">
                <div className="absolute left-[9px] top-1 bottom-1 w-px bg-[var(--border-default)]" />
                {report.timeline.map((t: any, idx: number) => (
                  <div key={idx} className="relative">
                    <div className="absolute -left-6 top-1 w-2 h-2 rounded-full bg-[var(--accent-light)] border border-[var(--accent-color)]" />
                    <div className="text-xs">
                      <span className="font-mono text-[var(--text-secondary)]">{t.time}</span>
                      <span className="mx-2 text-[var(--border-default)]">·</span>
                      <span className="font-medium text-[var(--text-primary)]">{t.action}</span>
                    </div>
                    {t.details && <div className="text-xs text-[var(--text-secondary)]">{t.details}</div>}
                    <EvidenceRefs ids={t.evidence_ids} />
                  </div>
                ))}
              </div>
            </div>

            {/* Recommended Actions */}
            <div className="bg-white rounded-2xl p-5" style={card}>
              <h2 className="text-sm font-semibold text-[var(--text-primary)] mb-4 flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-[var(--success)]" />
                Recommended Actions
              </h2>
              {report.recommendations.length === 0 ? (
                <p className="text-sm text-[var(--text-secondary)]">No evidence-backed recommendations were produced.</p>
              ) : (
                <div className="space-y-2">
                  {report.recommendations.map((r: any, idx: number) => (
                    <div key={idx} className="rounded-xl p-3 bg-[var(--muted)]">
                      <div className="text-sm text-[var(--text-primary)]">{r.action}</div>
                      {r.rationale && <div className="text-xs text-[var(--text-secondary)] mt-0.5">{r.rationale}</div>}
                      <EvidenceRefs ids={r.evidence_ids} />
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* MITRE techniques */}
            <div className="bg-white rounded-2xl p-5" style={card}>
              <h2 className="text-sm font-semibold text-[var(--text-primary)] mb-3 flex items-center gap-2">
                <Target className="w-4 h-4 text-[var(--severity-high)]" />
                MITRE ATT&CK Techniques
              </h2>
              {report.mitre_techniques.length === 0 ? (
                <p className="text-sm text-[var(--text-secondary)]">No MITRE mappings found.</p>
              ) : (
                <div className="flex flex-wrap gap-2">
                  {report.mitre_techniques.map((m: any) => (
                    <div
                      key={m.technique_id}
                      title={m.reason || ""}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs"
                      style={{
                        backgroundColor: "var(--severity-medium-bg)",
                        border: "1px solid var(--severity-medium-border)",
                        color: "var(--severity-medium)",
                      }}
                    >
                      <span className="font-bold">{m.technique_id}</span>
                      <span className="text-[var(--text-secondary)]">·</span>
                      <span className="text-[var(--text-primary)]">{m.technique_name}</span>
                      <span className="text-[10px] text-[var(--text-secondary)]">
                        ({m.source === "threat_intel_agent" ? "agent" : "rule"})
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Evidence considered by the report */}
            <div className="bg-white rounded-2xl p-5" style={card}>
              <h2 className="text-sm font-semibold text-[var(--text-primary)] mb-4">
                Evidence ({report.evidence_ids.length})
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {report.evidence_ids.map((id: string) => {
                  const e = evidenceById[id]
                  return (
                    <div key={id} className="rounded-xl p-3 bg-[var(--muted)]">
                      <div className="text-[10px] font-mono text-[var(--text-secondary)] mb-1">{id.substring(0, 8)}</div>
                      {e ? (
                        <>
                          <div className="text-[10px] font-bold uppercase tracking-wider text-[var(--accent-color)]">
                            {e.evidence_type}
                          </div>
                          <div className="font-mono text-[10px] text-[var(--text-primary)] bg-white p-2 rounded-lg break-all line-clamp-2 mt-1">
                            {e.artifact}
                          </div>
                        </>
                      ) : (
                        <div className="text-xs text-[var(--text-secondary)]">Not available</div>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          </div>
        )}

        {!selectedId && (
          <div className="flex-1 flex flex-col items-center justify-center py-16">
            <FileText className="w-12 h-12 text-[var(--border-default)] mb-4" />
            <p className="text-sm text-[var(--text-secondary)]">Select a case to view its report</p>
          </div>
        )}
      </div>
    </div>
  )
}
