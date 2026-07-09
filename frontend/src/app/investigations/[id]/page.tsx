"use client"

import { useQuery, useMutation } from "@tanstack/react-query"
import { api } from "@/lib/api"
import { useParams, useRouter } from "next/navigation"
import Link from "next/link"
import { useEffect, useState, useRef } from "react"
import { motion, AnimatePresence } from "framer-motion"
import {
  ShieldAlert,
  Download,
  Activity,
  Target,
  Clock,
  CheckCircle2,
  AlertCircle,
  BarChart3,
  Brain,
  ArrowLeft,
  Shield,
  Search,
} from "lucide-react"

/* ================================================================
   Severity + Status helpers
   ================================================================ */
const severityConfig: Record<string, { color: string; bg: string }> = {
  CRITICAL: { color: "var(--severity-critical)", bg: "var(--severity-critical-bg)" },
  HIGH: { color: "var(--severity-high)", bg: "var(--severity-high-bg)" },
  MEDIUM: { color: "var(--severity-medium)", bg: "var(--severity-medium-bg)" },
  LOW: { color: "var(--severity-low)", bg: "var(--severity-low-bg)" },
  INFO: { color: "var(--severity-info)", bg: "var(--severity-info-bg)" },
}

const agentAvatars: Record<string, { icon: any; color: string; bg: string }> = {
  "Triage Agent": { icon: Shield, color: "var(--agent-triage)", bg: "var(--agent-triage-bg)" },
  "Forensic Timeline Analyst": { icon: Clock, color: "var(--agent-timeline)", bg: "var(--agent-timeline-bg)" },
  "Threat Intel Analyst": { icon: Search, color: "var(--agent-threat-intel)", bg: "var(--agent-threat-intel-bg)" },
  "SOC Lead": { icon: Brain, color: "var(--agent-soc-lead)", bg: "var(--agent-soc-lead-bg)" },
}

const defaultAvatar = { icon: Shield, color: "var(--agent-triage)", bg: "var(--agent-triage-bg)" }

export default function InvestigationDetail() {
  const { id } = useParams()
  const router = useRouter()
  const [wsEvents, setWsEvents] = useState<any[]>([])
  const reasoningEndRef = useRef<HTMLDivElement>(null)

  const { data: caseData, isLoading, refetch } = useQuery({
    queryKey: ["investigation", id],
    queryFn: async () => {
      const { data } = await api.get(`/investigations/${id}`)
      return data
    },
    refetchInterval: (query) =>
      query.state.data?.status === "ANALYZING" ? 2000 : false,
  })

  // Fetch all investigations for the left queue
  const { data: allInvestigations } = useQuery({
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

  useEffect(() => {
    const ws = new WebSocket(`ws://localhost:8000/ws/investigations`)
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data)
      if (data.case_id === id) {
        setWsEvents((prev) => [...prev, data])
        if (data.event === "REPORT_READY") {
          refetch()
        }
      }
    }
    return () => ws.close()
  }, [id, refetch])

  // Auto-scroll reasoning panel
  useEffect(() => {
    reasoningEndRef.current?.scrollIntoView({ behavior: "smooth", block: "nearest", inline: "nearest" })
  }, [wsEvents, caseData?.agent_actions])

  const formatStatus = (s: string) => {
    if (!s) return ""
    const replaced = s.replace(/_/g, " ")
    return replaced.charAt(0).toUpperCase() + replaced.slice(1).toLowerCase()
  }

  const handleExport = async () => {
    window.open(`http://localhost:8000/investigations/${id}/export`, "_blank")
  }

  const updateStatusMutation = useMutation({
    mutationFn: async (newStatus: string) => {
      const { data } = await api.patch(`/investigations/${id}/status`, { status: newStatus })
      return data
    },
    onSuccess: () => {
      refetch()
    },
  })

  const startAnalysisMutation = useMutation({
    mutationFn: async () => {
      const { data } = await api.post(`/investigations/${id}/analyze`)
      return data
    },
    onSuccess: () => {
      refetch()
    },
  })

  if (isLoading) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <div className="flex items-center gap-3 text-[var(--text-secondary)]">
          <div className="w-5 h-5 border-2 border-[var(--accent-color)] border-t-transparent rounded-full animate-spin" />
          Loading investigation...
        </div>
      </div>
    )
  }

  // Gather timeline data
  const timelineActions = [...(caseData?.agent_actions || [])]
    .filter((a: any) => a.agent_name === "Forensic Timeline Analyst")
    .sort(
      (a: any, b: any) =>
        new Date(a.created_at).getTime() - new Date(b.created_at).getTime()
    )
  const timelineAction = timelineActions[timelineActions.length - 1]
  let timelineEvents = timelineAction?.output_data?.timeline || []
  if (!Array.isArray(timelineEvents)) {
    if (timelineAction?.output_data?.result?.timeline)
      timelineEvents = timelineAction.output_data.result.timeline
    else timelineEvents = []
  }
  // Deduplicate
  const uniqueTimelineEvents: any[] = []
  const seenT = new Set()
  for (const t of timelineEvents) {
    const key = `${t.time}-${t.action}-${t.details}`.toLowerCase()
    if (!seenT.has(key)) {
      seenT.add(key)
      uniqueTimelineEvents.push(t)
    }
  }

  // Gather agent reasoning (most recent run)
  const sortedActions = [...(caseData?.agent_actions || [])].sort(
    (a: any, b: any) =>
      new Date(a.created_at).getTime() - new Date(b.created_at).getTime()
  )
  let recentActions: any[] = []
  if (sortedActions.length > 0) {
    const lastTime = new Date(
      sortedActions[sortedActions.length - 1].created_at
    ).getTime()
    recentActions = sortedActions.filter(
      (a: any) => lastTime - new Date(a.created_at).getTime() < 300000
    )
  }

  // SOC Lead summary
  const socLeadActions = [...(caseData?.agent_actions || [])]
    .filter((a: any) => a.agent_name === "SOC Lead")
    .sort(
      (a: any, b: any) =>
        new Date(a.created_at).getTime() - new Date(b.created_at).getTime()
    )
  const summary =
    socLeadActions[socLeadActions.length - 1]?.output_data?.executive_summary
  const summaryText =
    typeof summary === "object"
      ? JSON.stringify(summary)
      : summary || "No AI analysis available."

  // MITRE techniques
  const uniqueMitre: any[] = []
  const seenMitre = new Set()
  for (const m of caseData?.mitre_techniques || []) {
    if (!seenMitre.has(m.technique_id)) {
      seenMitre.add(m.technique_id)
      uniqueMitre.push(m)
    }
  }

  // Threat intel insight
  const threatIntelActions = [...(caseData?.agent_actions || [])]
    .filter((a: any) => a.agent_name === "Threat Intel Analyst")
    .sort(
      (a: any, b: any) =>
        new Date(a.created_at).getTime() - new Date(b.created_at).getTime()
    )
  const historicalInsight =
    threatIntelActions[threatIntelActions.length - 1]?.output_data

  const sev = severityConfig[caseData?.severity] || severityConfig.INFO

  return (
    <div className="w-full h-[100vh] flex overflow-hidden bg-[#F9FAFB] p-6 gap-6">
      {/* ============================================================
          LEFT PANE — Incident Queue
          ============================================================ */}
      <div
        className="w-[300px] shrink-0 bg-white rounded-2xl flex flex-col h-full overflow-hidden"
        style={{
          boxShadow: "var(--shadow-card)",
          border: "1px solid var(--border-default)",
        }}
      >
        <div className="px-4 pt-5 pb-3">
          <button
            onClick={() => router.push("/investigations")}
            className="flex items-center gap-1.5 text-[var(--text-secondary)] hover:text-[var(--text-primary)] text-xs mb-3 transition-colors"
          >
            <ArrowLeft className="w-3.5 h-3.5" /> All Investigations
          </button>
          <h2 className="text-sm font-semibold text-[var(--text-primary)]">
            Case Queue
          </h2>
        </div>
        <div className="flex-1 overflow-y-auto px-3 pb-3 custom-scrollbar space-y-1">
          {allInvestigations?.map((inv: any, idx: number) => {
            const isActive = inv.id === id
            const invSev = severityConfig[inv.severity] || severityConfig.INFO
            return (
              <Link
                key={inv.id}
                href={`/investigations/${inv.id}`}
                className={`block rounded-xl p-3 transition-all duration-150 ${
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
                    className="w-5 h-5 rounded flex flex-shrink-0 items-center justify-center text-[10px] font-bold"
                    style={{ backgroundColor: invSev.bg, color: invSev.color, border: `1px solid ${invSev.color}30` }}
                  >
                    {idx + 1}
                  </span>
                  <span
                    className={`text-xs font-medium truncate ${
                      isActive
                        ? "text-[var(--accent-color)]"
                        : "text-[var(--text-primary)]"
                    }`}
                  >
                    {inv.title}
                  </span>
                </div>
                <div className="flex items-center justify-between pl-7">
                  <span className="text-[10px] text-[var(--text-secondary)]">
                    {formatStatus(inv.status)}
                  </span>
                  {inv.confidence_score && (
                    <span className="text-[10px] font-mono font-semibold text-[var(--text-secondary)]">
                      {(inv.confidence_score * 100).toFixed(0)}%
                    </span>
                  )}
                </div>
              </Link>
            )
          })}
        </div>
      </div>

      {/* ============================================================
          CENTER PANE — Attack Story Timeline
          ============================================================ */}
      <div className="flex-1 overflow-y-auto hide-scrollbar rounded-2xl">
        <div className="max-w-[800px] mx-auto space-y-6 pb-6">
          {/* Case Header */}
          <div className="flex items-start justify-between">
            <div>
              <h1 className="text-xl font-bold text-[var(--text-primary)] mb-2">
                {caseData?.title}
              </h1>
              <div className="flex flex-wrap items-center gap-2">
                {/* Severity */}
                <span
                  className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider"
                  style={{ backgroundColor: sev.bg, color: sev.color }}
                >
                  <AlertCircle className="w-3 h-3" />
                  {caseData?.severity}
                </span>
                {/* Status */}
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-[var(--accent-light)] text-[var(--accent-color)]">
                  {caseData?.status === "ANALYZING" && (
                    <span className="w-1.5 h-1.5 rounded-full bg-[var(--accent-color)] animate-dot-pulse" />
                  )}
                  {formatStatus(caseData?.status)}
                </span>
                {/* Confidence */}
                {caseData?.confidence_score && (
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-[var(--success-bg)] text-[var(--success)]">
                    <BarChart3 className="w-3 h-3" />
                    {(caseData.confidence_score * 100).toFixed(0)}%
                  </span>
                )}
                {/* Analysis time */}
                {caseData?.status !== "OPEN" &&
                  caseData?.status !== "ANALYZING" &&
                  caseData?.updated_at &&
                  caseData?.created_at && (
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono bg-[var(--muted)] text-[var(--text-secondary)]">
                      <Clock className="w-3 h-3" />
                      {(() => {
                        if (
                          caseData?.agent_actions &&
                          caseData.agent_actions.length > 0
                        ) {
                          const sorted = [...caseData.agent_actions].sort(
                            (a: any, b: any) =>
                              new Date(a.created_at).getTime() -
                              new Date(b.created_at).getTime()
                          )
                          const last = new Date(
                            sorted[sorted.length - 1].created_at
                          ).getTime()
                          const recent = sorted.filter(
                            (a: any) =>
                              last - new Date(a.created_at).getTime() < 300000
                          )
                          const first = new Date(
                            recent[0].created_at
                          ).getTime()
                          const duration =
                            Math.max((last - first) / 1000, 0) + 2.1
                          return duration.toFixed(1)
                        }
                        return (
                          (new Date(caseData.updated_at).getTime() -
                            new Date(caseData.created_at).getTime()) /
                          1000
                        ).toFixed(1)
                      })()}
                      s
                    </span>
                  )}
              </div>
            </div>
            <div className="flex items-center gap-2">
              {caseData?.status === "WAITING_FOR_REVIEW" && (
                <>
                  <button
                    onClick={() => updateStatusMutation.mutate("RESOLVED")}
                    disabled={updateStatusMutation.isPending}
                    className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium bg-[var(--success-bg)] text-[var(--success)] hover:opacity-80 transition-colors"
                  >
                    <CheckCircle2 className="w-3.5 h-3.5" /> Resolve Incident
                  </button>
                  <button
                    onClick={() => updateStatusMutation.mutate("FALSE_POSITIVE")}
                    disabled={updateStatusMutation.isPending}
                    className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium bg-[var(--muted)] text-[var(--text-secondary)] hover:bg-[#E5E7EB] transition-colors"
                  >
                    <ShieldAlert className="w-3.5 h-3.5" /> False Positive
                  </button>
                </>
              )}
              {caseData?.status === "ANALYZING" && (
                <button
                  onClick={() => updateStatusMutation.mutate("OPEN")}
                  disabled={updateStatusMutation.isPending}
                  className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium bg-[var(--muted)] text-[var(--text-secondary)] hover:bg-[#E5E7EB] transition-colors"
                >
                  <Activity className="w-3.5 h-3.5" /> Stop Analysis
                </button>
              )}
              {caseData?.status === "OPEN" && (
                <button
                  onClick={() => startAnalysisMutation.mutate()}
                  disabled={startAnalysisMutation.isPending}
                  className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium bg-[var(--accent-color)] text-white hover:opacity-90 transition-colors shadow-sm"
                >
                  <Activity className="w-3.5 h-3.5" /> Start Analysis
                </button>
              )}
              <button
                onClick={handleExport}
                className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium text-[var(--text-secondary)] hover:bg-[var(--muted)] border border-[var(--border-default)] transition-colors"
              >
                <Download className="w-3.5 h-3.5" /> Export
              </button>
            </div>
          </div>

          {/* AI Summary */}
          <div
            className="bg-white rounded-2xl p-5"
            style={{
              boxShadow: "var(--shadow-card)",
              border: "1px solid var(--border-default)",
            }}
          >
            <div className="flex items-center gap-2 mb-3">
              <div
                className="w-7 h-7 rounded-lg flex items-center justify-center"
                style={{ backgroundColor: "var(--agent-soc-lead-bg)" }}
              >
                <Brain
                  className="w-4 h-4"
                  style={{ color: "var(--agent-soc-lead)" }}
                />
              </div>
              <h3 className="text-sm font-semibold text-[var(--text-primary)]">
                AI Analyst Summary
              </h3>
            </div>
            {caseData?.status === "ANALYZING" ? (
              <div className="flex items-center gap-3 text-sm text-[var(--accent-color)] font-medium py-4">
                <div className="w-4 h-4 border-2 border-[var(--accent-color)] border-t-transparent rounded-full animate-spin" />
                AI Swarm is actively analyzing evidence...
              </div>
            ) : (
              <p className="text-sm text-[var(--text-secondary)] leading-relaxed">
                {summaryText}
              </p>
            )}
          </div>

          {/* Attack Timeline */}
          <div
            className="bg-white rounded-2xl p-5"
            style={{
              boxShadow: "var(--shadow-card)",
              border: "1px solid var(--border-default)",
            }}
          >
            <div className="flex items-center gap-2 mb-4">
              <Activity className="w-4 h-4 text-[var(--accent-color)]" />
              <h3 className="text-sm font-semibold text-[var(--text-primary)]">
                Attack Story Timeline
              </h3>
            </div>

            {uniqueTimelineEvents.length > 0 ? (
              <div className="relative pl-6">
                {/* Spine line */}
                <div className="absolute left-[9px] top-2 bottom-2 w-px bg-[var(--border-default)]" />
                <div className="space-y-4">
                  {uniqueTimelineEvents.map((t: any, idx: number) => {
                    // Determine if critical
                    const isCritical =
                      typeof t.action === "string" &&
                      (t.action.toLowerCase().includes("credential") ||
                        t.action.toLowerCase().includes("lateral") ||
                        t.action.toLowerCase().includes("exfil"))

                    return (
                      <motion.div
                        key={idx}
                        initial={{ opacity: 0, x: -12 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: idx * 0.05 }}
                        className="relative min-w-0 break-words"
                      >
                        {/* Dot on spine */}
                        <div
                          className={`absolute -left-6 top-1 w-[10px] h-[10px] rounded-full border-2 ${
                            isCritical
                              ? "border-[var(--severity-critical)] bg-[var(--severity-critical-bg)]"
                              : "border-[var(--border-default)] bg-white"
                          }`}
                          style={
                            isCritical
                              ? {
                                  boxShadow:
                                    "0 0 8px var(--severity-critical)",
                                }
                              : undefined
                          }
                        />

                        <div className="pb-1 min-w-0">
                          {/* Timestamp chip */}
                          <span className="inline-block text-[10px] font-mono text-[var(--text-secondary)] bg-[var(--muted)] px-1.5 py-0.5 rounded mb-1 break-all">
                            {typeof (t.time || t.timestamp) === "object"
                              ? JSON.stringify(t.time || t.timestamp)
                              : t.time || t.timestamp || "Unknown Time"}
                          </span>

                          {/* Event title */}
                          <div className="text-sm font-medium text-[var(--text-primary)] break-words">
                            {typeof t.action === "object"
                              ? JSON.stringify(t.action)
                              : t.action || "Unknown Action"}
                          </div>

                          {/* Details */}
                          <div className="text-xs text-[var(--text-secondary)] mt-0.5 leading-relaxed break-words whitespace-pre-wrap min-w-0">
                            {typeof (t.details || t.description) === "object"
                              ? JSON.stringify(t.details || t.description)
                              : t.details ||
                                t.description ||
                                "No details provided."}
                          </div>
                        </div>
                      </motion.div>
                    )
                  })}
                </div>
              </div>
            ) : (
              <div className="text-sm text-[var(--text-secondary)] py-8 text-center">
                No timeline events extracted yet.
              </div>
            )}
          </div>

          {/* Evidence Explorer */}
          <div
            className="bg-white rounded-2xl p-5"
            style={{
              boxShadow: "var(--shadow-card)",
              border: "1px solid var(--border-default)",
            }}
          >
            <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-4">
              Evidence Explorer
            </h3>
            <div className="space-y-3">
              {(() => {
                const uniqueEv: any[] = []
                const seenEv = new Set()
                for (const e of caseData?.evidence_items || []) {
                  const key = `${e.evidence_type}-${e.artifact}`
                  if (!seenEv.has(key)) {
                    seenEv.add(key)
                    uniqueEv.push(e)
                  }
                }
                return uniqueEv.map((e: any, idx: number) => (
                  <div
                    key={idx}
                    className="rounded-xl p-4 text-sm space-y-2"
                    style={{
                      backgroundColor: "var(--muted)",
                      border: "1px solid var(--border-default)",
                    }}
                  >
                    <div className="flex justify-between items-center">
                      <span
                        className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full"
                        style={{
                          backgroundColor: "var(--accent-light)",
                          color: "var(--accent-color)",
                        }}
                      >
                        {e.evidence_type}
                      </span>
                      <div className="flex items-center gap-3">
                        {e.importance_score && (
                          <div className="flex items-center gap-1.5">
                            <div className="w-12 h-1 bg-white rounded-full overflow-hidden">
                              <div
                                className="h-full rounded-full"
                                style={{
                                  width: `${e.importance_score * 100}%`,
                                  backgroundColor:
                                    e.importance_score > 0.9
                                      ? "var(--severity-critical)"
                                      : "var(--severity-medium)",
                                }}
                              />
                            </div>
                            <span className="text-[10px] font-mono text-[var(--text-secondary)]">
                              {(e.importance_score * 100).toFixed(0)}%
                            </span>
                          </div>
                        )}
                        <span className="text-[10px] font-mono text-[var(--text-secondary)]">
                          {new Date(e.timestamp)
                            .toISOString()
                            .split("T")
                            .join(" ")
                            .split(".")[0] + " UTC"}
                        </span>
                      </div>
                    </div>
                    <div className="font-mono text-xs text-[var(--text-primary)] bg-white p-2 rounded-lg break-all whitespace-pre-wrap">
                      {e.artifact}
                    </div>
                    {typeof e.reason === "string" &&
                    e.reason.includes("Matched Sigma Rule") ? (
                      <div className="space-y-1.5">
                        <div className="text-xs text-[var(--text-secondary)] italic break-words">
                          {e.reason.split("Matched Sigma Rule")[0].trim()}
                        </div>
                        <div
                          className="rounded-lg p-2 text-[10px] font-mono"
                          style={{
                            backgroundColor: "var(--accent-light)",
                            border: "1px solid var(--accent-color)",
                            color: "var(--accent-color)",
                          }}
                        >
                          <span className="font-bold uppercase tracking-wider block mb-0.5">
                            Matched Sigma Rule:
                          </span>
                          {e.reason.split("Matched Sigma Rule:")[1]?.trim()}
                        </div>
                      </div>
                    ) : (
                      <div className="text-xs text-[var(--text-secondary)] italic break-words">
                        {typeof e.reason === "object"
                          ? JSON.stringify(e.reason)
                          : e.reason}
                      </div>
                    )}
                  </div>
                ))
              })()}
            </div>
          </div>

          {/* MITRE ATT&CK */}
          <div
            className="bg-white rounded-2xl p-5"
            style={{
              boxShadow: "var(--shadow-card)",
              border: "1px solid var(--border-default)",
            }}
          >
            <div className="flex items-center gap-2 mb-4">
              <Target className="w-4 h-4 text-[var(--severity-high)]" />
              <h3 className="text-sm font-semibold text-[var(--text-primary)]">
                MITRE ATT&CK
              </h3>
            </div>

            {/* Qdrant Memory Insight */}
            {historicalInsight?.historical_insight &&
              historicalInsight.historical_insight !== "Failed to map." && (
                <div
                  className="rounded-xl p-3 mb-4"
                  style={{
                    backgroundColor: "var(--agent-soc-lead-bg)",
                    border: "1px solid var(--agent-soc-lead)",
                  }}
                >
                  <div className="text-[10px] font-bold text-[var(--agent-soc-lead)] uppercase tracking-wider mb-1 flex items-center gap-1">
                    <Brain className="w-3 h-3" /> Qdrant Memory Insight
                  </div>
                  <div className="text-sm text-[var(--text-primary)] italic mb-2">
                    {historicalInsight.historical_insight}
                  </div>
                  {historicalInsight.similar_case_ids?.length > 0 && (
                    <div className="flex flex-wrap gap-1.5 pt-2 border-t border-[var(--agent-soc-lead)]">
                      <span className="text-[10px] text-[var(--agent-soc-lead)] font-medium">
                        Related:
                      </span>
                      {historicalInsight.similar_case_ids.map((cid: string) => (
                        <Link
                          key={cid}
                          href={`/investigations/${cid}`}
                          className="text-[10px] px-1.5 py-0.5 rounded bg-white hover:bg-[var(--muted)] border border-[var(--border-default)] text-[var(--accent-color)] transition-colors truncate max-w-[100px]"
                        >
                          {cid.substring(0, 8)}
                        </Link>
                      ))}
                    </div>
                  )}
                </div>
              )}

            {/* Technique cards */}
            <div className="flex flex-wrap gap-2">
              {uniqueMitre.map((m: any, idx: number) => (
                <div
                  key={idx}
                  className="rounded-xl p-3 text-sm w-full min-w-0"
                  style={{
                    backgroundColor: "var(--muted)",
                    border: "1px solid var(--border-default)",
                  }}
                >
                  <div className="flex items-center gap-2 mb-1">
                    <span
                      className="text-xs font-bold px-1.5 py-0.5 rounded"
                      style={{
                        backgroundColor: "var(--severity-medium-bg)",
                        color: "var(--severity-medium)",
                      }}
                    >
                      {m.technique_id}
                    </span>
                    <span className="text-[10px] text-[var(--text-secondary)]">
                      {m.tactic}
                    </span>
                  </div>
                  <div className="text-xs font-medium text-[var(--text-primary)]">
                    {m.technique_name}
                  </div>
                  {m.reason && (
                    <div className="text-[10px] text-[var(--text-secondary)] italic mt-1 break-words">
                      {typeof m.reason === "object"
                        ? JSON.stringify(m.reason)
                        : m.reason}
                    </div>
                  )}
                </div>
              ))}
            </div>
            {uniqueMitre.length === 0 && (
              <div className="text-sm text-[var(--text-secondary)] text-center py-4">
                No MITRE techniques mapped yet.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ============================================================
          RIGHT PANE — AI Investigator Panel
          ============================================================ */}
      <div
        className="w-[340px] shrink-0 bg-white rounded-2xl flex flex-col h-full overflow-hidden"
        style={{
          boxShadow: "var(--shadow-card)",
          border: "1px solid var(--border-default)",
        }}
      >
        <div className="px-5 pt-5 pb-3 border-b border-[var(--border-default)]">
          <h2 className="text-sm font-semibold text-[var(--text-primary)] flex items-center gap-2">
            <Brain className="w-4 h-4 text-[var(--accent-color)]" />
            AI Investigator
          </h2>
          <p className="text-[10px] text-[var(--text-secondary)] mt-0.5">
            Live reasoning and handoffs
          </p>
        </div>
        <div className="flex-1 overflow-y-auto px-4 py-4 custom-scrollbar space-y-3">
          {/* Live WS events */}
          <AnimatePresence>
            {wsEvents.map((evt, idx) => {
              const avatar =
                agentAvatars[evt.agent] || defaultAvatar
              const AgentIcon = avatar.icon
              return (
                <motion.div
                  key={`ws-${idx}`}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.2 }}
                  className="flex items-start gap-2.5"
                >
                  <div
                    className="w-7 h-7 rounded-full flex items-center justify-center shrink-0 mt-0.5"
                    style={{ backgroundColor: avatar.bg }}
                  >
                    <AgentIcon
                      className="w-3.5 h-3.5"
                      style={{ color: avatar.color }}
                    />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="text-xs font-semibold text-[var(--text-primary)]">
                      {evt.agent}
                    </div>
                    <div className="text-xs text-[var(--text-secondary)] leading-relaxed mt-0.5">
                      {evt.thought ? (
                        <span className="italic">&ldquo;{evt.thought}&rdquo;</span>
                      ) : (
                        <span className="text-[var(--accent-color)] font-medium">
                          {evt.event}
                        </span>
                      )}
                    </div>
                  </div>
                </motion.div>
              )
            })}
          </AnimatePresence>

          {/* Persisted agent actions */}
          {recentActions.map((a: any, idx: number) => {
            const avatar =
              agentAvatars[a.agent_name] || defaultAvatar
            const AgentIcon = avatar.icon
            return (
              <motion.div
                key={`db-${idx}`}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: idx * 0.03 }}
                className="flex items-start gap-2.5"
              >
                <div
                  className="w-7 h-7 rounded-full flex items-center justify-center shrink-0 mt-0.5"
                  style={{ backgroundColor: avatar.bg }}
                >
                  <AgentIcon
                    className="w-3.5 h-3.5"
                    style={{ color: avatar.color }}
                  />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-semibold text-[var(--text-primary)]">
                      {a.agent_name}
                    </span>
                    <CheckCircle2 className="w-3 h-3 text-[var(--success)]" />
                  </div>
                  <div className="text-xs text-[var(--text-secondary)] italic leading-relaxed mt-0.5">
                    &ldquo;{a.thought}&rdquo;
                  </div>
                  {a.action_taken && (
                    <div className="text-[10px] font-mono text-[var(--accent-color)] mt-1">
                      → {a.action_taken}
                    </div>
                  )}
                </div>
              </motion.div>
            )
          })}

          {wsEvents.length === 0 && recentActions.length === 0 && (
            <div className="flex flex-col items-center justify-center h-full py-12 text-center">
              <Brain className="w-8 h-8 text-[var(--border-default)] mb-3" />
              <p className="text-xs text-[var(--text-secondary)]">
                Agent reasoning will appear here during analysis.
              </p>
            </div>
          )}

          <div ref={reasoningEndRef} />
        </div>
      </div>
    </div>
  )
}
