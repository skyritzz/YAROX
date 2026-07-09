"use client"

import { useQuery } from "@tanstack/react-query"
import { api } from "@/lib/api"
import { useState } from "react"
import { format } from "date-fns"
import { motion } from "framer-motion"
import { FolderOpen, List, Grid3x3, ChevronLeft, ChevronRight } from "lucide-react"

/* ================================================================
   Severity helpers
   ================================================================ */
const severityStyle: Record<string, { color: string; bg: string }> = {
  CRITICAL: { color: "var(--severity-critical)", bg: "var(--severity-critical-bg)" },
  HIGH: { color: "var(--severity-high)", bg: "var(--severity-high-bg)" },
  MEDIUM: { color: "var(--severity-medium)", bg: "var(--severity-medium-bg)" },
  LOW: { color: "var(--severity-low)", bg: "var(--severity-low-bg)" },
  INFO: { color: "var(--severity-info)", bg: "var(--severity-info-bg)" },
}

export default function EvidencePage() {
  const [activeTab, setActiveTab] = useState<"evidence" | "events">("evidence")
  const [page, setPage] = useState(0)
  const limit = 50

  // Fetch investigations for evidence items
  const { data: investigations } = useQuery({
    queryKey: ["investigations"],
    queryFn: async () => {
      const { data } = await api.get("/investigations/")
      return data
    },
    refetchInterval: 5000,
  })

  // Fetch raw events for the "All Events" tab
  const { data: events, isLoading: eventsLoading } = useQuery({
    queryKey: ["events", page],
    queryFn: async () => {
      const { data } = await api.get(`/events?limit=${limit}&offset=${page * limit}`)
      return data
    },
    refetchInterval: 2000,
  })

  // Aggregate all evidence items across investigations
  const allEvidence = investigations?.flatMap((inv: any) =>
    (inv.evidence_items || []).map((e: any) => ({
      ...e,
      investigation_title: inv.title,
      investigation_id: inv.id,
      investigation_severity: inv.severity,
    }))
  ) || []

  // Deduplicate by evidence type to prevent similar items (like multiple PowerShell executions) from cluttering the view
  const uniqueEvidence: any[] = []
  const seen = new Set()
  for (const e of allEvidence) {
    const key = e.evidence_type
    if (!seen.has(key)) {
      seen.add(key)
      uniqueEvidence.push(e)
    }
  }

  const getSeverityStyle = (severity: string) => {
    return severityStyle[severity?.toUpperCase()] || severityStyle.INFO
  }

  return (
    <div className="flex-1 overflow-y-auto">
      <div className="max-w-[1400px] mx-auto px-8 py-8 space-y-6">
        {/* Header */}
        <div>
          <h1 className="text-[24px] font-bold tracking-tight text-[var(--text-primary)] leading-[32px]">
            Evidence
          </h1>
          <p className="text-sm text-[var(--text-secondary)] mt-1">
            Collected artifacts and raw event telemetry
          </p>
        </div>

        {/* Tabs */}
        <div className="flex items-center gap-1 bg-[var(--muted)] rounded-xl p-1 w-fit">
          <button
            onClick={() => setActiveTab("evidence")}
            className={`px-4 py-2 text-sm font-medium rounded-lg transition-all duration-150 ${
              activeTab === "evidence"
                ? "bg-white text-[var(--text-primary)] shadow-sm"
                : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
            }`}
          >
            <span className="flex items-center gap-1.5">
              <Grid3x3 className="w-4 h-4" />
              Key Evidence
              {uniqueEvidence.length > 0 && (
                <span className="text-[10px] bg-[var(--accent-light)] text-[var(--accent-color)] px-1.5 py-0.5 rounded-full font-semibold">
                  {uniqueEvidence.length}
                </span>
              )}
            </span>
          </button>
          <button
            onClick={() => setActiveTab("events")}
            className={`px-4 py-2 text-sm font-medium rounded-lg transition-all duration-150 ${
              activeTab === "events"
                ? "bg-white text-[var(--text-primary)] shadow-sm"
                : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
            }`}
          >
            <span className="flex items-center gap-1.5">
              <List className="w-4 h-4" />
              All Events
            </span>
          </button>
        </div>

        {/* Key Evidence Tab */}
        {activeTab === "evidence" && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {uniqueEvidence.length > 0 ? (
              uniqueEvidence.map((e: any, idx: number) => (
                <motion.div
                  key={idx}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: idx * 0.03 }}
                  className="bg-white rounded-2xl p-5 space-y-3"
                  style={{
                    boxShadow: "var(--shadow-card)",
                    border: "1px solid var(--border-default)",
                  }}
                >
                  {/* Header row */}
                  <div className="flex items-center justify-between">
                    <span
                      className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full"
                      style={{
                        backgroundColor: "var(--accent-light)",
                        color: "var(--accent-color)",
                      }}
                    >
                      {e.evidence_type}
                    </span>
                    <div className="flex items-center gap-2">
                      {e.importance_score && (
                        <div className="flex items-center gap-1.5">
                          <div className="w-10 h-1 bg-[var(--muted)] rounded-full overflow-hidden">
                            <div
                              className="h-full rounded-full"
                              style={{
                                width: `${e.importance_score * 100}%`,
                                backgroundColor:
                                  e.importance_score > 0.9
                                    ? "var(--severity-critical)"
                                    : e.importance_score > 0.7
                                    ? "var(--severity-high)"
                                    : "var(--severity-medium)",
                              }}
                            />
                          </div>
                          <span className="text-[10px] font-mono text-[var(--text-secondary)]">
                            {(e.importance_score * 100).toFixed(0)}%
                          </span>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Artifact preview */}
                  <div className="font-mono text-xs text-[var(--text-primary)] bg-[var(--muted)] p-3 rounded-xl break-all whitespace-pre-wrap leading-relaxed">
                    {e.artifact}
                  </div>

                  {/* Reason */}
                  {e.reason && (
                    <div className="text-xs text-[var(--text-secondary)] italic leading-relaxed break-words whitespace-pre-wrap min-w-0">
                      {typeof e.reason === "object"
                        ? JSON.stringify(e.reason)
                        : e.reason}
                    </div>
                  )}

                  {/* Footer */}
                  <div className="flex items-center justify-between pt-2 border-t border-[var(--border-default)]">
                    <a
                      href={`/investigations/${e.investigation_id}`}
                      className="text-[10px] font-medium text-[var(--accent-color)] hover:underline"
                    >
                      {e.investigation_title}
                    </a>
                    <span className="text-[10px] font-mono text-[var(--text-secondary)]">
                      {e.timestamp
                        ? format(new Date(e.timestamp), "yyyy-MM-dd HH:mm:ss")
                        : "—"}
                    </span>
                  </div>
                </motion.div>
              ))
            ) : (
              <div className="col-span-2 text-center py-16">
                <FolderOpen className="w-10 h-10 text-[var(--border-default)] mx-auto mb-3" />
                <p className="text-sm text-[var(--text-secondary)]">
                  No evidence collected yet.
                </p>
                <p className="text-xs text-[var(--text-secondary)] mt-1">
                  Evidence will appear here as AI agents analyze investigations.
                </p>
              </div>
            )}
          </div>
        )}

        {/* All Events Tab */}
        {activeTab === "events" && (
          <div
            className="bg-white rounded-2xl overflow-hidden"
            style={{
              boxShadow: "var(--shadow-card)",
              border: "1px solid var(--border-default)",
            }}
          >
            {/* Pagination */}
            <div className="px-5 py-3 flex items-center justify-between border-b border-[var(--border-default)]">
              <span className="text-xs text-[var(--text-secondary)]">
                Page {page + 1} · {limit} per page
              </span>
              <div className="flex gap-1.5">
                <button
                  disabled={page === 0}
                  onClick={() => setPage((p) => Math.max(0, p - 1))}
                  className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-medium text-[var(--text-secondary)] hover:bg-[var(--muted)] disabled:opacity-40 transition-colors border border-[var(--border-default)]"
                >
                  <ChevronLeft className="w-3.5 h-3.5" /> Previous
                </button>
                <button
                  onClick={() => setPage((p) => p + 1)}
                  className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-medium text-[var(--text-secondary)] hover:bg-[var(--muted)] transition-colors border border-[var(--border-default)]"
                >
                  Next <ChevronRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            {/* Table */}
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-[var(--border-default)]">
                    <th className="text-left text-[10px] font-medium text-[var(--text-secondary)] uppercase tracking-wider px-5 py-3">
                      Time
                    </th>
                    <th className="text-left text-[10px] font-medium text-[var(--text-secondary)] uppercase tracking-wider px-5 py-3">
                      Severity
                    </th>
                    <th className="text-left text-[10px] font-medium text-[var(--text-secondary)] uppercase tracking-wider px-5 py-3">
                      Event Type
                    </th>
                    <th className="text-left text-[10px] font-medium text-[var(--text-secondary)] uppercase tracking-wider px-5 py-3">
                      Host
                    </th>
                    <th className="text-left text-[10px] font-medium text-[var(--text-secondary)] uppercase tracking-wider px-5 py-3">
                      User
                    </th>
                    <th className="text-left text-[10px] font-medium text-[var(--text-secondary)] uppercase tracking-wider px-5 py-3">
                      Source
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {eventsLoading ? (
                    <tr>
                      <td colSpan={6} className="text-center py-12 text-sm text-[var(--text-secondary)]">
                        Loading events...
                      </td>
                    </tr>
                  ) : events?.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="text-center py-12 text-sm text-[var(--text-secondary)]">
                        No events found.
                      </td>
                    </tr>
                  ) : (
                    events?.map((event: any) => {
                      const sev = getSeverityStyle(event.severity)
                      return (
                        <tr
                          key={event.id}
                          className="border-b border-[var(--border-default)] hover:bg-[#F9FAFB] transition-colors"
                        >
                          <td className="px-5 py-3 font-mono text-xs text-[var(--text-secondary)]">
                            {format(new Date(event.timestamp), "yyyy-MM-dd HH:mm:ss")}
                          </td>
                          <td className="px-5 py-3">
                            <span
                              className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider"
                              style={{ backgroundColor: sev.bg, color: sev.color }}
                            >
                              {event.severity}
                            </span>
                          </td>
                          <td className="px-5 py-3 text-sm font-medium text-[var(--text-primary)]">
                            {event.event_type}
                          </td>
                          <td className="px-5 py-3 text-sm text-[var(--text-secondary)]">
                            {event.hostname}
                          </td>
                          <td className="px-5 py-3 text-sm text-[var(--text-secondary)]">
                            {event.user_name}
                          </td>
                          <td className="px-5 py-3 text-xs text-[var(--text-secondary)]">
                            {event.source}
                          </td>
                        </tr>
                      )
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
