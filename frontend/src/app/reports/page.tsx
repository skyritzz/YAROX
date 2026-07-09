"use client"

import { useQuery } from "@tanstack/react-query"
import { api } from "@/lib/api"
import { useState } from "react"
import { motion } from "framer-motion"
import {
  FileText,
  Download,
  Shield,
  Target,
  CheckCircle2,
  Clock,
  AlertTriangle,
  ChevronRight,
} from "lucide-react"
import { format } from "date-fns"

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

export default function ReportsPage() {
  const [selectedId, setSelectedId] = useState<string | null>(null)

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

  // Fetch selected investigation details
  const { data: reportData } = useQuery({
    queryKey: ["investigation", selectedId],
    queryFn: async () => {
      if (!selectedId) return null
      const { data } = await api.get(`/investigations/${selectedId}`)
      return data
    },
    enabled: !!selectedId,
  })

  // Auto-select first completed investigation
  if (
    !selectedId &&
    investigations?.length > 0
  ) {
    const completed = investigations.find(
      (i: any) =>
        i.status === "WAITING_FOR_REVIEW" ||
        i.status === "RESOLVED" ||
        i.status === "FALSE_POSITIVE"
    )
    if (completed) setSelectedId(completed.id)
    else if (investigations[0]) setSelectedId(investigations[0].id)
  }

  const handleExport = (id: string) => {
    window.open(`http://localhost:8000/investigations/${id}/export`, "_blank")
  }

  // Extract report content from selected case
  const socLeadAction = reportData?.agent_actions
    ?.filter((a: any) => a.agent_name === "SOC Lead")
    ?.sort(
      (a: any, b: any) =>
        new Date(a.created_at).getTime() - new Date(b.created_at).getTime()
    )
    ?.pop()

  const executiveSummary = socLeadAction?.output_data?.executive_summary
  const summaryText =
    typeof executiveSummary === "object"
      ? JSON.stringify(executiveSummary)
      : executiveSummary || null

  // Timeline
  const timelineAction = reportData?.agent_actions
    ?.filter((a: any) => a.agent_name === "Forensic Timeline Analyst")
    ?.sort(
      (a: any, b: any) =>
        new Date(a.created_at).getTime() - new Date(b.created_at).getTime()
    )
    ?.pop()
  let timelineEvents = timelineAction?.output_data?.timeline || []
  if (!Array.isArray(timelineEvents)) {
    if (timelineAction?.output_data?.result?.timeline)
      timelineEvents = timelineAction.output_data.result.timeline
    else timelineEvents = []
  }
  const uniqueTimeline: any[] = []
  const seenT = new Set()
  for (const t of timelineEvents) {
    const key = `${t.time}-${t.action}`.toLowerCase()
    if (!seenT.has(key)) {
      seenT.add(key)
      uniqueTimeline.push(t)
    }
  }

  // MITRE
  const uniqueMitre: any[] = []
  const seenM = new Set()
  for (const m of reportData?.mitre_techniques || []) {
    if (!seenM.has(m.technique_id)) {
      seenM.add(m.technique_id)
      uniqueMitre.push(m)
    }
  }

  // Evidence
  const uniqueEvidence: any[] = []
  const seenE = new Set()
  for (const e of reportData?.evidence_items || []) {
    const key = `${e.evidence_type}-${e.artifact}`
    if (!seenE.has(key)) {
      seenE.add(key)
      uniqueEvidence.push(e)
    }
  }

  // Recommended actions (demo data blended)
  const [checkedActions, setCheckedActions] = useState<Set<number>>(new Set())
  const recommendedActions = [
    "Disable compromised user account (jdoe) immediately",
    "Reset credentials for all accounts accessed from suspicious IP",
    "Audit all admin login activity in the last 72 hours",
    "Block external IP range 203.0.113.x at the perimeter firewall",
    "Escalate to Incident Response team for full forensic review",
    "Update detection rules for T1110 (Brute Force) variants",
  ]

  const toggleAction = (idx: number) => {
    setCheckedActions((prev) => {
      const next = new Set(prev)
      if (next.has(idx)) next.delete(idx)
      else next.add(idx)
      return next
    })
  }

  const sev = severityConfig[reportData?.severity] || severityConfig.INFO

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
      {/* Left: Report list */}
      <div
        className="w-[260px] shrink-0 bg-white flex flex-col h-full overflow-hidden"
        style={{ borderRight: "1px solid var(--border-default)" }}
      >
        <div className="px-4 pt-5 pb-3">
          <h2 className="text-sm font-semibold text-[var(--text-primary)]">
            Reports
          </h2>
          <p className="text-[10px] text-[var(--text-secondary)] mt-0.5">
            Select a case to view report
          </p>
        </div>
        <div className="flex-1 overflow-y-auto px-3 pb-3 custom-scrollbar space-y-1">
          {investigations?.map((inv: any) => {
            const isActive = inv.id === selectedId
            const invSev = severityConfig[inv.severity] || severityConfig.INFO
            const isComplete =
              inv.status === "WAITING_FOR_REVIEW" ||
              inv.status === "RESOLVED" ||
              inv.status === "FALSE_POSITIVE"
            return (
              <button
                key={inv.id}
                onClick={() => setSelectedId(inv.id)}
                className={`w-full text-left rounded-xl p-3 transition-all duration-150 ${
                  isActive
                    ? "bg-[var(--accent-light)]"
                    : "hover:bg-[var(--muted)]"
                }`}
                style={{
                  borderLeft: isActive
                    ? "3px solid var(--accent-color)"
                    : "3px solid transparent",
                }}
              >
                <div className="flex items-center gap-2 mb-1">
                  <span
                    className="w-2 h-2 rounded-full shrink-0"
                    style={{ backgroundColor: invSev.color }}
                  />
                  <span className="text-xs font-medium text-[var(--text-primary)] truncate">
                    {inv.title}
                  </span>
                </div>
                <div className="flex items-center gap-2 pl-4">
                  <span className="text-[10px] text-[var(--text-secondary)]">
                    {inv.status.replace(/_/g, " ")}
                  </span>
                  {isComplete && (
                    <CheckCircle2 className="w-3 h-3 text-[var(--success)]" />
                  )}
                </div>
              </button>
            )
          })}
          {(!investigations || investigations.length === 0) && (
            <div className="text-xs text-[var(--text-secondary)] text-center py-8">
              No cases available.
            </div>
          )}
        </div>
      </div>

      {/* Right: Report view */}
      <div className="flex-1 overflow-y-auto custom-scrollbar">
        {selectedId && reportData ? (
          <div className="max-w-[900px] mx-auto px-8 py-8 space-y-8">
            {/* Hero header */}
            <div
              className="rounded-2xl p-6"
              style={{
                background: `linear-gradient(135deg, ${sev.bg} 0%, white 100%)`,
                border: "1px solid var(--border-default)",
                boxShadow: "var(--shadow-card)",
              }}
            >
              <div className="flex items-start justify-between mb-4">
                <div>
                  <div className="flex items-center gap-2 mb-2">
                    <span
                      className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider"
                      style={{ backgroundColor: sev.bg, color: sev.color }}
                    >
                      <AlertTriangle className="w-3 h-3" />
                      {reportData.severity}
                    </span>
                    {reportData.confidence_score && (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-[var(--success-bg)] text-[var(--success)]">
                        Confidence: {(reportData.confidence_score * 100).toFixed(0)}%
                      </span>
                    )}
                  </div>
                  <h1 className="text-2xl font-bold text-[var(--text-primary)]">
                    {reportData.title}
                  </h1>
                  <p className="text-xs text-[var(--text-secondary)] mt-1">
                    Case {reportData.id?.substring(0, 8)} · Created{" "}
                    {format(new Date(reportData.created_at), "PPpp")}
                  </p>
                </div>
                <button
                  onClick={() => handleExport(reportData.id)}
                  className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl text-sm font-semibold bg-[var(--accent-color)] text-white hover:bg-[var(--accent-hover)] transition-colors"
                >
                  <Download className="w-4 h-4" /> Export PDF
                </button>
              </div>

              {/* Executive summary */}
              {summaryText && (
                <div className="text-sm text-[var(--text-secondary)] leading-relaxed bg-white/60 rounded-xl p-4 mt-4">
                  {summaryText}
                </div>
              )}
            </div>

            {/* Timeline (condensed) */}
            {uniqueTimeline.length > 0 && (
              <div
                className="bg-white rounded-2xl p-5"
                style={{
                  boxShadow: "var(--shadow-card)",
                  border: "1px solid var(--border-default)",
                }}
              >
                <h2 className="text-sm font-semibold text-[var(--text-primary)] mb-4 flex items-center gap-2">
                  <Clock className="w-4 h-4 text-[var(--accent-color)]" />
                  Attack Timeline
                </h2>
                <div className="relative pl-6 space-y-3">
                  <div className="absolute left-[9px] top-1 bottom-1 w-px bg-[var(--border-default)]" />
                  {uniqueTimeline.map((t: any, idx: number) => (
                    <div key={idx} className="relative">
                      <div className="absolute -left-6 top-1 w-2 h-2 rounded-full bg-[var(--accent-light)] border border-[var(--accent-color)]" />
                      <div className="text-xs">
                        <span className="font-mono text-[var(--text-secondary)]">
                          {typeof (t.time || t.timestamp) === "object"
                            ? JSON.stringify(t.time || t.timestamp)
                            : t.time || t.timestamp}
                        </span>
                        <span className="mx-2 text-[var(--border-default)]">·</span>
                        <span className="font-medium text-[var(--text-primary)]">
                          {typeof t.action === "object"
                            ? JSON.stringify(t.action)
                            : t.action}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Evidence card grid */}
            {uniqueEvidence.length > 0 && (
              <div
                className="bg-white rounded-2xl p-5"
                style={{
                  boxShadow: "var(--shadow-card)",
                  border: "1px solid var(--border-default)",
                }}
              >
                <h2 className="text-sm font-semibold text-[var(--text-primary)] mb-4 flex items-center gap-2">
                  <Shield className="w-4 h-4 text-[var(--accent-color)]" />
                  Evidence ({uniqueEvidence.length})
                </h2>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {uniqueEvidence.slice(0, 6).map((e: any, idx: number) => (
                    <div
                      key={idx}
                      className="rounded-xl p-3"
                      style={{
                        backgroundColor: "var(--muted)",
                        border: "1px solid var(--border-default)",
                      }}
                    >
                      <div className="flex items-center justify-between mb-2">
                        <span
                          className="text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded-full"
                          style={{
                            backgroundColor: "var(--accent-light)",
                            color: "var(--accent-color)",
                          }}
                        >
                          {e.evidence_type}
                        </span>
                        {e.importance_score && (
                          <span className="text-[10px] font-mono text-[var(--text-secondary)]">
                            {(e.importance_score * 100).toFixed(0)}% risk
                          </span>
                        )}
                      </div>
                      <div className="font-mono text-[10px] text-[var(--text-primary)] bg-white p-2 rounded-lg break-all line-clamp-2">
                        {e.artifact}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Recommended Actions */}
            <div
              className="bg-white rounded-2xl p-5"
              style={{
                boxShadow: "var(--shadow-card)",
                border: "1px solid var(--border-default)",
              }}
            >
              <h2 className="text-sm font-semibold text-[var(--text-primary)] mb-4 flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-[var(--success)]" />
                Recommended Actions
              </h2>
              <div className="space-y-2">
                {recommendedActions.map((action, idx) => (
                  <button
                    key={idx}
                    onClick={() => toggleAction(idx)}
                    className={`w-full flex items-start gap-3 rounded-xl p-3 text-left transition-all duration-150 ${
                      checkedActions.has(idx)
                        ? "bg-[var(--success-bg)]"
                        : "bg-[var(--muted)] hover:bg-[var(--border-default)]"
                    }`}
                  >
                    <div
                      className={`w-5 h-5 rounded-md border-2 flex items-center justify-center shrink-0 mt-0.5 transition-all duration-150 ${
                        checkedActions.has(idx)
                          ? "border-[var(--success)] bg-[var(--success)]"
                          : "border-[var(--border-default)]"
                      }`}
                    >
                      {checkedActions.has(idx) && (
                        <CheckCircle2 className="w-3 h-3 text-white" />
                      )}
                    </div>
                    <span
                      className={`text-sm ${
                        checkedActions.has(idx)
                          ? "text-[var(--success)] line-through"
                          : "text-[var(--text-primary)]"
                      }`}
                    >
                      {action}
                    </span>
                  </button>
                ))}
              </div>
            </div>

            {/* MITRE techniques as tag row */}
            {uniqueMitre.length > 0 && (
              <div
                className="bg-white rounded-2xl p-5"
                style={{
                  boxShadow: "var(--shadow-card)",
                  border: "1px solid var(--border-default)",
                }}
              >
                <h2 className="text-sm font-semibold text-[var(--text-primary)] mb-3 flex items-center gap-2">
                  <Target className="w-4 h-4 text-[var(--severity-high)]" />
                  MITRE ATT&CK Techniques
                </h2>
                <div className="flex flex-wrap gap-2">
                  {uniqueMitre.map((m: any, idx: number) => (
                    <div
                      key={idx}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs"
                      style={{
                        backgroundColor: "var(--severity-medium-bg)",
                        border: "1px solid var(--severity-medium-border)",
                        color: "var(--severity-medium)",
                      }}
                    >
                      <span className="font-bold">{m.technique_id}</span>
                      <span className="text-[var(--text-secondary)]">·</span>
                      <span className="text-[var(--text-primary)]">
                        {m.technique_name}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="flex-1 flex flex-col items-center justify-center py-16">
            <FileText className="w-12 h-12 text-[var(--border-default)] mb-4" />
            <p className="text-sm text-[var(--text-secondary)]">
              Select a case to view its report
            </p>
          </div>
        )}
      </div>
    </div>
  )
}
