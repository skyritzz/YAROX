"use client"

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { api } from "@/lib/api"
import { useState, useEffect, useRef } from "react"
import { motion, AnimatePresence } from "framer-motion"
import {
  Shield,
  Search,
  Clock,
  FileText,
  Brain,
  Activity,
  Play,
  Pause,
  RotateCcw,
  ChevronRight,
  Zap,
} from "lucide-react"
import { format } from "date-fns"

/* ================================================================
   Agent demo data — task strings are static/demo, 
   confidence and status blend from real API data
   ================================================================ */
const AGENTS = [
  {
    id: "triage",
    name: "Triage Agent",
    dbName: "Triage Analyst",
    icon: Shield,
    color: "var(--agent-triage)",
    bg: "var(--agent-triage-bg)",
    demoTasks: {
      active: "Classifying incoming security event",
      idle: "Standing by for new events",
    },
    statusLabel: { active: "Investigating", idle: "Idle" },
  },
  {
    id: "timeline",
    name: "Timeline Analyst",
    dbName: "Forensic Timeline Analyst",
    icon: Clock,
    color: "var(--agent-timeline)",
    bg: "var(--agent-timeline-bg)",
    demoTasks: {
      active: "Reconstructing login sequence for jdoe",
      idle: "Awaiting evidence",
    },
    statusLabel: { active: "Building timeline", idle: "Idle" },
  },
  {
    id: "threat-intel",
    name: "Threat Intel Agent",
    dbName: "Threat Intel Analyst",
    icon: Search,
    color: "var(--agent-threat-intel)",
    bg: "var(--agent-threat-intel-bg)",
    demoTasks: {
      active: "Correlating with MITRE ATT&CK T1110",
      idle: "Waiting for triage output",
    },
    statusLabel: { active: "Mapping ATT&CK", idle: "Idle" },
  },
  {
    id: "soc-lead",
    name: "SOC Lead Agent",
    dbName: "SOC Lead",
    icon: Brain,
    color: "var(--agent-soc-lead)",
    bg: "var(--agent-soc-lead-bg)",
    demoTasks: {
      active: "Drafting executive summary for Case #4A2F",
      idle: "All reports finalized",
    },
    statusLabel: { active: "Drafting report", idle: "Idle" },
  },
]

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

/* ================================================================
   Animated number component
   ================================================================ */
function AnimatedNumber({ value }: { value: number }) {
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
   Main Command Center
   ================================================================ */
export default function CommandCenter() {
  const queryClient = useQueryClient()
  const activityEndRef = useRef<HTMLDivElement>(null)

  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ["dashboardStats"],
    queryFn: async () => {
      const { data } = await api.get("/dashboard/stats")
      return data
    },
    refetchInterval: 2000,
  })

  const { data: investigations } = useQuery({
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

  const { data: health } = useQuery({
    queryKey: ["systemHealth"],
    queryFn: async () => {
      const { data } = await api.get("/health")
      return data
    },
    refetchInterval: 10000,
  })

  // Replay status for embedded controls
  const { data: statusList } = useQuery({
    queryKey: ["replayStatus"],
    queryFn: async () => {
      const { data } = await api.get("/replay/status")
      return data
    },
    refetchInterval: 2000,
  })

  const currentSession = statusList?.[0]
  const isPlaying = currentSession?.status === "PLAYING"

  const [scenario, setScenario] = useState("credential_theft")
  const [speed, setSpeed] = useState("1.0")

  const startReplay = useMutation({
    mutationFn: async () => {
      const { data } = await api.post("/replay/start", {
        scenario_name: scenario,
        speed_multiplier: parseFloat(speed),
      })
      return data
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["replayStatus"] }),
  })

  const pauseReplay = useMutation({
    mutationFn: async () => {
      if (currentSession?.id) await api.post(`/replay/${currentSession.id}/pause`)
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["replayStatus"] }),
  })

  const resetReplay = useMutation({
    mutationFn: async () => {
      if (currentSession?.id) await api.post(`/replay/${currentSession.id}/reset`)
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["replayStatus"] }),
  })

  // Auto-scroll activity feed
  useEffect(() => {
    activityEndRef.current?.scrollIntoView({ behavior: "smooth" })
  }, [stats?.recent_activity])

  if (statsLoading) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <div className="flex items-center gap-3 text-[var(--text-secondary)]">
          <div className="w-5 h-5 border-2 border-[var(--accent-color)] border-t-transparent rounded-full animate-spin" />
          Initializing Command Center...
        </div>
      </div>
    )
  }

  const isRunning = stats?.replay_status === "PLAYING"
  const hasEvents = stats?.total_events > 0
  const activeCases = investigations?.filter(
    (i: any) => i.status === "ANALYZING" || i.status === "OPEN"
  ).length || 0
  const criticalCases = investigations?.filter(
    (i: any) => i.severity === "CRITICAL"
  ).length || 0

  // Determine which agents are "active" based on real replay status
  const activeAgentCount: number = isRunning ? 3 : 0

  return (
    <div className="flex-1 overflow-y-auto">
      <div className="max-w-[1400px] mx-auto px-8 py-8 space-y-8">
        {/* ============================================================
            HEADER
            ============================================================ */}
        <div>
          <h1 className="text-[32px] font-bold tracking-tight text-[var(--text-primary)] leading-[40px]">
            YAROX Command Center
          </h1>
          <div className="flex items-center gap-2 mt-2 text-sm text-[var(--text-secondary)]">
            <span
              className={`inline-block w-2 h-2 rounded-full ${
                isRunning ? "bg-[var(--success)] animate-dot-pulse" : "bg-[var(--border-default)]"
              }`}
            />
            <span>
              {activeCases} active investigation{activeCases !== 1 ? "s" : ""}
              {" · "}
              {activeAgentCount > 0
                ? `${activeAgentCount} agent${activeAgentCount !== 1 ? "s" : ""} thinking`
                : "All agents idle"}
              {stats?.recent_activity?.length > 0 &&
                ` · Last event ${(() => {
                  const last = stats.recent_activity[0]?.timestamp
                  if (!last) return "—"
                  const diff = Math.round(
                    (Date.now() - new Date(last).getTime()) / 1000
                  )
                  return diff < 60 ? `${diff}s ago` : `${Math.round(diff / 60)}m ago`
                })()}`}
            </span>
          </div>
        </div>

        {/* ============================================================
            REPLAY CONTROL BAR (folded from /timeline)
            ============================================================ */}
        <div
          className="bg-white rounded-2xl p-4 flex items-center gap-4 flex-wrap"
          style={{ boxShadow: "var(--shadow-card)", border: "1px solid var(--border-default)" }}
        >
          <div className="flex items-center gap-2">
            <button
              onClick={() =>
                isPlaying ? pauseReplay.mutate() : startReplay.mutate()
              }
              disabled={startReplay.isPending || pauseReplay.isPending}
              className={`inline-flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold transition-all duration-150 ${
                isPlaying
                  ? "bg-red-50 text-red-600 hover:bg-red-100"
                  : "bg-[var(--accent-color)] text-white hover:bg-[var(--accent-hover)]"
              } disabled:opacity-50`}
            >
              {isPlaying ? (
                <>
                  <Pause className="w-4 h-4" /> Pause
                </>
              ) : (
                <>
                  <Play className="w-4 h-4" /> Start Simulation
                </>
              )}
            </button>
            <button
              onClick={() => resetReplay.mutate()}
              disabled={resetReplay.isPending || !currentSession}
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl text-sm font-medium text-[var(--text-secondary)] hover:bg-[var(--muted)] transition-colors disabled:opacity-50"
            >
              <RotateCcw className="w-4 h-4" /> Reset
            </button>
          </div>

          <div className="h-6 w-px bg-[var(--border-default)]" />

          <div className="flex items-center gap-4 text-sm">
            <div className="flex items-center gap-2">
              <span className="text-[var(--text-secondary)]">Scenario:</span>
              <select
                value={scenario}
                onChange={(e) => setScenario(e.target.value)}
                disabled={isPlaying}
                className="bg-transparent border border-[var(--border-default)] rounded-lg px-2 py-1 text-[var(--text-primary)] font-medium focus:outline-none focus:border-[var(--accent-color)] disabled:opacity-50"
              >
                <option value="credential_theft">Credential Theft</option>
                <option value="insider_threat">Insider Threat</option>
                <option value="apt_blackout">APT Blackout</option>
                <option value="apt29_simulation">APT29 Simulation</option>
              </select>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-[var(--text-secondary)]">Speed:</span>
              <select
                value={speed}
                onChange={(e) => setSpeed(e.target.value)}
                disabled={isPlaying}
                className="bg-transparent border border-[var(--border-default)] rounded-lg px-2 py-1 font-mono font-semibold text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent-color)] disabled:opacity-50"
              >
                <option value="0.5">0.5×</option>
                <option value="1.0">1.0×</option>
                <option value="2.0">2.0×</option>
                <option value="5.0">5.0×</option>
                <option value="10.0">10.0×</option>
              </select>
            </div>
            <div>
              <span className="text-[var(--text-secondary)]">Progress: </span>
              <span className="font-mono font-semibold text-[var(--text-primary)]">
                {stats?.progress_percent || 0}%
              </span>
            </div>
          </div>

          {/* Progress bar */}
          <div className="flex-1 min-w-[120px]">
            <div className="h-1.5 bg-[var(--muted)] rounded-full overflow-hidden">
              <div
                className="h-full rounded-full transition-all duration-500"
                style={{
                  width: `${stats?.progress_percent || 0}%`,
                  backgroundColor: isRunning ? "var(--accent-color)" : "var(--border-default)",
                }}
              />
            </div>
          </div>

          {isRunning && (
            <div className="flex items-center gap-1.5 text-xs font-medium text-[var(--success)]">
              <Zap className="w-3.5 h-3.5" />
              {stats?.events_per_sec || 0} events/s
            </div>
          )}
        </div>

        {/* ============================================================
            AI SECURITY TEAM — 4 Agent Cards
            ============================================================ */}
        <div>
          <h2 className="text-lg font-semibold text-[var(--text-primary)] mb-4">
            AI Security Team
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {AGENTS.map((agent, idx) => {
              // First 3 agents active when replay running, SOC Lead active when cases exist
              const agentActive =
                isRunning && (idx < 3 || (investigations?.length || 0) > 0)
              const confidence =
                stats?.average_confidence ??
                (agentActive ? 87 : 0)

              return (
                <motion.div
                  key={agent.id}
                  className={`bg-white rounded-2xl p-5 transition-all duration-200 cursor-default ${
                    agentActive ? "animate-agent-pulse" : ""
                  }`}
                  style={{
                    boxShadow: "var(--shadow-card)",
                    border: "1px solid var(--border-default)",
                  }}
                  whileHover={{ y: -2, boxShadow: "var(--shadow-card-hover)" }}
                >
                  {/* Icon + Name */}
                  <div className="flex items-center gap-3 mb-4">
                    <div
                      className="w-10 h-10 rounded-xl flex items-center justify-center"
                      style={{ backgroundColor: agent.bg }}
                    >
                      <agent.icon
                        className="w-5 h-5"
                        style={{ color: agent.color }}
                      />
                    </div>
                    <div className="min-w-0">
                      <div className="text-sm font-semibold text-[var(--text-primary)] truncate">
                        {agent.name}
                      </div>
                      <div className="text-xs text-[var(--text-secondary)] truncate">
                        {agentActive
                          ? agent.demoTasks.active
                          : agent.demoTasks.idle}
                      </div>
                    </div>
                  </div>

                  {/* Confidence bar */}
                  <div className="mb-3">
                    <div className="flex justify-between text-xs mb-1">
                      <span className="text-[var(--text-secondary)]">
                        Confidence
                      </span>
                      <span className="font-mono font-semibold text-[var(--text-primary)]">
                        <AnimatedNumber value={agentActive ? confidence : 0} />%
                      </span>
                    </div>
                    <div className="h-1.5 bg-[var(--muted)] rounded-full overflow-hidden">
                      <motion.div
                        className="h-full rounded-full"
                        style={{ backgroundColor: agent.color }}
                        initial={{ width: 0 }}
                        animate={{
                          width: `${agentActive ? confidence : 0}%`,
                        }}
                        transition={{ duration: 0.8, ease: "easeOut" }}
                      />
                    </div>
                  </div>

                  {/* Status pill */}
                  <div
                    className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium"
                    style={{
                      backgroundColor: agentActive ? agent.bg : "var(--muted)",
                      color: agentActive
                        ? agent.color
                        : "var(--text-secondary)",
                    }}
                  >
                    {agentActive && (
                      <span
                        className="w-1.5 h-1.5 rounded-full animate-dot-pulse"
                        style={{ backgroundColor: agent.color }}
                      />
                    )}
                    {agentActive
                      ? agent.statusLabel.active
                      : agent.statusLabel.idle}
                  </div>
                </motion.div>
              )
            })}
          </div>
        </div>

        {/* ============================================================
            BOTTOM 2-COLUMN: Incident Feed + Activity Stream
            ============================================================ */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* LEFT — Mini Incident Feed */}
          <div
            className="bg-white rounded-2xl overflow-hidden"
            style={{
              boxShadow: "var(--shadow-card)",
              border: "1px solid var(--border-default)",
            }}
          >
            <div className="px-5 pt-5 pb-3 flex items-center justify-between">
              <h3 className="text-sm font-semibold text-[var(--text-primary)]">
                Recent Detections
              </h3>
              <a
                href="/investigations"
                className="text-xs font-medium text-[var(--accent-color)] hover:underline flex items-center gap-0.5"
              >
                View all <ChevronRight className="w-3 h-3" />
              </a>
            </div>
            <div className="px-5 pb-5 space-y-2">
              {investigations?.slice(0, 5).map((inv: any, idx: number) => {
                const sev = severityConfig[inv.severity] || severityConfig.INFO
                return (
                  <motion.a
                    key={inv.id}
                    href={`/investigations/${inv.id}`}
                    initial={{ opacity: 0, x: -12 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: idx * 0.05 }}
                    className="block rounded-xl p-3 hover:bg-[var(--muted)] transition-colors group"
                    style={{ borderLeft: `3px solid ${sev.color}` }}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-sm font-medium text-[var(--text-primary)] group-hover:text-[var(--accent-color)] transition-colors truncate">
                        {inv.title}
                      </span>
                      <span
                        className="text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded"
                        style={{
                          backgroundColor: sev.bg,
                          color: sev.color,
                        }}
                      >
                        {inv.severity}
                      </span>
                    </div>
                    <div className="flex items-center gap-3 text-xs text-[var(--text-secondary)]">
                      <span>{inv.status.replace(/_/g, " ")}</span>
                      {inv.confidence_score && (
                        <span className="font-mono">
                          {(inv.confidence_score * 100).toFixed(0)}%
                        </span>
                      )}
                    </div>
                  </motion.a>
                )
              })}
              {(!investigations || investigations.length === 0) && (
                <div className="text-sm text-[var(--text-secondary)] py-8 text-center">
                  No investigations yet. Start a simulation to begin.
                </div>
              )}
            </div>
          </div>

          {/* RIGHT — Real-time Activity Stream (chat-log style) */}
          <div
            className="bg-white rounded-2xl overflow-hidden flex flex-col"
            style={{
              boxShadow: "var(--shadow-card)",
              border: "1px solid var(--border-default)",
              maxHeight: 420,
            }}
          >
            <div className="px-5 pt-5 pb-3">
              <h3 className="text-sm font-semibold text-[var(--text-primary)]">
                Live Activity
              </h3>
            </div>
            <div className="flex-1 overflow-y-auto px-5 pb-5 custom-scrollbar space-y-3">
              {stats?.recent_activity?.length > 0 ? (
                <AnimatePresence>
                  {stats.recent_activity
                    .slice()
                    .reverse()
                    .map((activity: any, idx: number) => {
                      let agentMatch = AGENTS[0]
                      if (activity.agent_name) {
                        agentMatch = AGENTS.find(a => a.dbName === activity.agent_name) || AGENTS[0]
                      } else if (activity.message.includes("Replay")) {
                        agentMatch = { ...AGENTS[0], name: "System", icon: Activity, color: "var(--text-secondary)", bg: "var(--muted)" }
                      }
                      return (
                        <motion.div
                          key={`${activity.timestamp}-${idx}`}
                          initial={{ opacity: 0, y: 8 }}
                          animate={{ opacity: 1, y: 0 }}
                          transition={{ delay: idx * 0.03 }}
                          className="flex items-start gap-3"
                        >
                          <div
                            className="w-7 h-7 rounded-full flex items-center justify-center shrink-0 mt-0.5"
                            style={{ backgroundColor: agentMatch.bg }}
                          >
                            <agentMatch.icon
                              className="w-3.5 h-3.5"
                              style={{ color: agentMatch.color }}
                            />
                          </div>
                          <div className="min-w-0">
                            <div className="flex items-baseline gap-2">
                              <span className="text-xs font-semibold text-[var(--text-primary)]">
                                {agentMatch.name}
                              </span>
                              <span className="text-[10px] text-[var(--text-secondary)] font-mono">
                                {format(
                                  new Date(activity.timestamp),
                                  "HH:mm:ss"
                                )}
                              </span>
                            </div>
                            <p className="text-sm text-[var(--text-secondary)] leading-snug">
                              {activity.message}
                            </p>
                          </div>
                        </motion.div>
                      )
                    })}
                </AnimatePresence>
              ) : (
                <div className="flex flex-col items-center justify-center h-full py-12 text-center">
                  <Activity className="w-8 h-8 text-[var(--border-default)] mb-3" />
                  <p className="text-sm text-[var(--text-secondary)]">
                    Waiting for activity...
                  </p>
                  <p className="text-xs text-[var(--text-secondary)] mt-1">
                    Start a simulation to see live agent events.
                  </p>
                </div>
              )}
              <div ref={activityEndRef} />
            </div>
          </div>
        </div>

        {/* ============================================================
            INFRASTRUCTURE STATUS
            ============================================================ */}
        {health?.infrastructure && (
          <div
            className="bg-white rounded-2xl p-5"
            style={{
              boxShadow: "var(--shadow-card)",
              border: "1px solid var(--border-default)",
            }}
          >
            <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-3">
              Infrastructure
            </h3>
            <div className="flex flex-wrap gap-2">
              {Object.entries(health.infrastructure).map(
                ([key, value]: [string, any]) => {
                  const isHealthy =
                    value === "Healthy" || value === "Active"
                  return (
                    <div
                      key={key}
                      className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-medium"
                      style={{
                        backgroundColor: isHealthy
                          ? "var(--success-bg)"
                          : "var(--severity-critical-bg)",
                        color: isHealthy
                          ? "var(--success)"
                          : "var(--severity-critical)",
                      }}
                    >
                      <span
                        className={`w-1.5 h-1.5 rounded-full ${
                          isHealthy ? "animate-dot-pulse" : ""
                        }`}
                        style={{
                          backgroundColor: isHealthy
                            ? "var(--success)"
                            : "var(--severity-critical)",
                        }}
                      />
                      {key}
                    </div>
                  )
                }
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
