"use client"

import { useQuery } from "@tanstack/react-query"
import { api } from "@/lib/api"
import { useRouter } from "next/navigation"
import { motion } from "framer-motion"
import { ShieldAlert, AlertTriangle, Database, ChevronRight, TrendingUp } from "lucide-react"
import { useEffect, useState } from "react"

/* ================================================================
   Animated counter
   ================================================================ */
function AnimatedCounter({ value }: { value: number }) {
  const [display, setDisplay] = useState(0)
  useEffect(() => {
    const duration = 600
    const start = performance.now()
    const from = display
    const step = (now: number) => {
      const progress = Math.min((now - start) / duration, 1)
      setDisplay(Math.round(from + (value - from) * progress))
      if (progress < 1) requestAnimationFrame(step)
    }
    requestAnimationFrame(step)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value])
  return <span>{display}</span>
}

/* ================================================================
   Severity helpers
   ================================================================ */
const severityConfig: Record<string, { color: string; bg: string; border: string }> = {
  CRITICAL: { color: "var(--severity-critical)", bg: "var(--severity-critical-bg)", border: "var(--severity-critical-border)" },
  HIGH: { color: "var(--severity-high)", bg: "var(--severity-high-bg)", border: "var(--severity-high-border)" },
  MEDIUM: { color: "var(--severity-medium)", bg: "var(--severity-medium-bg)", border: "var(--severity-medium-border)" },
  LOW: { color: "var(--severity-low)", bg: "var(--severity-low-bg)", border: "var(--severity-low-border)" },
  INFO: { color: "var(--severity-info)", bg: "var(--severity-info-bg)", border: "var(--severity-info-border)" },
}

const statusConfig: Record<string, { color: string; bg: string }> = {
  ANALYZING: { color: "var(--accent-color)", bg: "var(--accent-light)" },
  OPEN: { color: "var(--severity-medium)", bg: "var(--severity-medium-bg)" },
  WAITING_FOR_REVIEW: { color: "var(--severity-high)", bg: "var(--severity-high-bg)" },
  RESOLVED: { color: "var(--success)", bg: "var(--success-bg)" },
  FALSE_POSITIVE: { color: "var(--severity-info)", bg: "var(--severity-info-bg)" },
}

export default function InvestigationsPage() {
  const router = useRouter()
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

  if (isLoading) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <div className="flex items-center gap-3 text-[var(--text-secondary)]">
          <div className="w-5 h-5 border-2 border-[var(--accent-color)] border-t-transparent rounded-full animate-spin" />
          Loading investigations...
        </div>
      </div>
    )
  }

  const activeCases =
    investigations?.filter(
      (i: any) => i.status === "ANALYZING" || i.status === "OPEN"
    ).length || 0
  const criticalCases =
    investigations?.filter((i: any) => i.severity === "CRITICAL").length || 0
  const totalCases = investigations?.length || 0

  return (
    <div className="flex-1 overflow-y-auto">
      <div className="max-w-[1400px] mx-auto px-8 py-8 space-y-6">
        {/* Header */}
        <div>
          <h1 className="text-[24px] font-bold tracking-tight text-[var(--text-primary)] leading-[32px]">
            Investigations
          </h1>
          <p className="text-sm text-[var(--text-secondary)] mt-1">
            Active security cases and AI investigation status
          </p>
        </div>

        {/* KPI Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[
            {
              label: "Active",
              value: activeCases,
              icon: ShieldAlert,
              color: "var(--accent-color)",
              bg: "var(--accent-light)",
            },
            {
              label: "Critical",
              value: criticalCases,
              icon: AlertTriangle,
              color: "var(--severity-critical)",
              bg: "var(--severity-critical-bg)",
            },
            {
              label: "Total Cases",
              value: totalCases,
              icon: Database,
              color: "var(--agent-triage)",
              bg: "var(--agent-triage-bg)",
            },
          ].map((kpi) => (
            <div
              key={kpi.label}
              className="bg-white rounded-2xl p-5 flex items-center justify-between"
              style={{
                boxShadow: "var(--shadow-card)",
                border: "1px solid var(--border-default)",
              }}
            >
              <div>
                <div className="text-xs font-medium text-[var(--text-secondary)] uppercase tracking-wider mb-1">
                  {kpi.label}
                </div>
                <div className="text-3xl font-bold font-mono text-[var(--text-primary)] animate-count-up">
                  <AnimatedCounter value={kpi.value} />
                </div>
              </div>
              <div
                className="w-11 h-11 rounded-xl flex items-center justify-center"
                style={{ backgroundColor: kpi.bg }}
              >
                <kpi.icon className="w-5 h-5" style={{ color: kpi.color }} />
              </div>
            </div>
          ))}
        </div>

        {/* Investigation Table */}
        <div
          className="bg-white rounded-2xl overflow-hidden"
          style={{
            boxShadow: "var(--shadow-card)",
            border: "1px solid var(--border-default)",
          }}
        >
          <div className="px-5 pt-5 pb-3">
            <h2 className="text-sm font-semibold text-[var(--text-primary)]">
              All Investigations
            </h2>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-[var(--border-default)]">
                  <th className="text-left text-xs font-medium text-[var(--text-secondary)] uppercase tracking-wider px-5 py-3">
                    Case
                  </th>
                  <th className="text-left text-xs font-medium text-[var(--text-secondary)] uppercase tracking-wider px-5 py-3">
                    Created
                  </th>
                  <th className="text-left text-xs font-medium text-[var(--text-secondary)] uppercase tracking-wider px-5 py-3">
                    Severity
                  </th>
                  <th className="text-left text-xs font-medium text-[var(--text-secondary)] uppercase tracking-wider px-5 py-3">
                    Status
                  </th>
                  <th className="text-left text-xs font-medium text-[var(--text-secondary)] uppercase tracking-wider px-5 py-3">
                    Confidence
                  </th>
                  <th className="px-5 py-3" />
                </tr>
              </thead>
              <tbody>
                {investigations?.map((inv: any, idx: number) => {
                  const sev = severityConfig[inv.severity] || severityConfig.INFO
                  const status = statusConfig[inv.status] || statusConfig.OPEN
                  const confidence = inv.confidence_score
                    ? Math.round(inv.confidence_score * 100)
                    : null

                  return (
                    <motion.tr
                      key={inv.id}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ delay: idx * 0.03 }}
                      onClick={() => router.push(`/investigations/${inv.id}`)}
                      className="border-b border-[var(--border-default)] hover:bg-[#F9FAFB] cursor-pointer group transition-colors"
                      style={{
                        borderLeft: `4px solid ${sev.color}`,
                      }}
                    >
                      <td className="px-5 py-4">
                        <div className="text-sm font-medium text-[var(--text-primary)]">
                          {inv.title}
                        </div>
                        <div className="text-xs text-[var(--text-secondary)] font-mono mt-0.5">
                          {inv.id.substring(0, 8)}
                        </div>
                      </td>
                      <td className="px-5 py-4 text-sm text-[var(--text-secondary)] whitespace-nowrap">
                        {new Date(inv.created_at).toLocaleString()}
                      </td>
                      <td className="px-5 py-4">
                        <span
                          className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-bold uppercase tracking-wider"
                          style={{
                            backgroundColor: sev.bg,
                            color: sev.color,
                          }}
                        >
                          {inv.severity}
                        </span>
                      </td>
                      <td className="px-5 py-4">
                        <span
                          className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-bold uppercase tracking-wider"
                          style={{
                            backgroundColor: status.bg,
                            color: status.color,
                          }}
                        >
                          {inv.status === "ANALYZING" && (
                            <span
                              className="w-1.5 h-1.5 rounded-full animate-dot-pulse"
                              style={{ backgroundColor: status.color }}
                            />
                          )}
                          {inv.status.replace(/_/g, " ")}
                        </span>
                      </td>
                      <td className="px-5 py-4">
                        {confidence !== null ? (
                          <div className="flex items-center gap-2 min-w-[100px]">
                            <div className="flex-1 h-1.5 bg-[var(--muted)] rounded-full overflow-hidden">
                              <div
                                className="h-full rounded-full transition-all duration-500"
                                style={{
                                  width: `${confidence}%`,
                                  backgroundColor: "var(--accent-color)",
                                }}
                              />
                            </div>
                            <span className="text-xs font-mono font-semibold text-[var(--text-primary)] w-8 text-right">
                              {confidence}%
                            </span>
                          </div>
                        ) : (
                          <span className="text-xs text-[var(--text-secondary)]">—</span>
                        )}
                      </td>
                      <td className="px-5 py-4">
                        <span className="text-xs font-medium text-[var(--accent-color)] opacity-0 group-hover:opacity-100 transition-opacity flex items-center gap-0.5">
                          View <ChevronRight className="w-3 h-3" />
                        </span>
                      </td>
                    </motion.tr>
                  )
                })}
              </tbody>
            </table>
          </div>

          {(!investigations || investigations.length === 0) && (
            <div className="text-center py-16 text-[var(--text-secondary)]">
              <Database className="w-8 h-8 mx-auto mb-3 opacity-30" />
              <p className="text-sm">No investigations found.</p>
              <p className="text-xs mt-1">
                Start a simulation from the Command Center to begin.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
