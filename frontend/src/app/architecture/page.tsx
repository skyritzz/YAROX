"use client"

import React from "react"
import {
  ReactFlow,
  Controls,
  Background,
  useNodesState,
  useEdgesState,
  MarkerType,
  Edge,
} from "@xyflow/react"
import "@xyflow/react/dist/style.css"
import { Shield, Clock, Search, Brain, FileText, Zap } from "lucide-react"

/* ================================================================
   Pipeline stage data
   ================================================================ */
const stages = [
  {
    id: "event",
    label: "Security Event",
    icon: "⚡",
    description: "Incoming telemetry",
    avgDuration: "< 1s",
    lastRun: "Active",
    color: "var(--text-secondary)",
    bg: "var(--muted)",
  },
  {
    id: "triage",
    label: "Triage Agent",
    icon: "🛡️",
    description: "Classifies & prioritizes",
    avgDuration: "~2s",
    lastRun: "Active",
    color: "var(--agent-triage)",
    bg: "var(--agent-triage-bg)",
  },
  {
    id: "timeline",
    label: "Timeline Analyst",
    icon: "🕐",
    description: "Reconstructs sequence",
    avgDuration: "~3s",
    lastRun: "Active",
    color: "var(--agent-timeline)",
    bg: "var(--agent-timeline-bg)",
  },
  {
    id: "threat-intel",
    label: "Threat Intel Agent",
    icon: "🔍",
    description: "MITRE mapping & context",
    avgDuration: "~4s",
    lastRun: "Active",
    color: "var(--agent-threat-intel)",
    bg: "var(--agent-threat-intel-bg)",
  },
  {
    id: "soc-lead",
    label: "SOC Lead Agent",
    icon: "🧠",
    description: "Synthesizes & decides",
    avgDuration: "~3s",
    lastRun: "Active",
    color: "var(--agent-soc-lead)",
    bg: "var(--agent-soc-lead-bg)",
  },
  {
    id: "report",
    label: "Final Report",
    icon: "📄",
    description: "Structured deliverable",
    avgDuration: "~1s",
    lastRun: "Complete",
    color: "var(--success)",
    bg: "var(--success-bg)",
  },
]

/* ================================================================
   Build React Flow nodes from stages
   ================================================================ */
const CARD_W = 200
const CARD_H = 120
const GAP = 60

const initialNodes: any[] = stages.map((stage, idx) => ({
  id: stage.id,
  position: { x: idx * (CARD_W + GAP) + 40, y: 80 },
  data: {
    label: (
      <div
        className="rounded-2xl p-4 w-[200px] text-left transition-shadow duration-200 hover:shadow-lg"
        style={{
          background: "white",
          boxShadow: "var(--shadow-card)",
          border: `1px solid var(--border-default)`,
        }}
      >
        <div className="flex items-center gap-2 mb-2">
          <div
            className="w-8 h-8 rounded-xl flex items-center justify-center text-sm"
            style={{ backgroundColor: stage.bg }}
          >
            {stage.icon}
          </div>
          <div className="text-xs font-bold text-[var(--text-primary)] leading-tight">
            {stage.label}
          </div>
        </div>
        <div className="text-[10px] text-[var(--text-secondary)] mb-2">
          {stage.description}
        </div>
        <div className="flex items-center justify-between">
          <span className="text-[10px] font-mono text-[var(--text-secondary)]">
            {stage.avgDuration}
          </span>
          <span
            className="text-[10px] font-semibold px-1.5 py-0.5 rounded-full"
            style={{
              backgroundColor: stage.bg,
              color: stage.color,
            }}
          >
            {stage.lastRun}
          </span>
        </div>
      </div>
    ),
  },
  style: {
    background: "transparent",
    border: "none",
    padding: 0,
    width: CARD_W,
  },
  draggable: true,
  selectable: false,
}))

// Add a "parallel" label between timeline and threat-intel
initialNodes.push({
  id: "parallel-label",
  position: {
    x: 2 * (CARD_W + GAP) + 40 + CARD_W / 2 + GAP / 2,
    y: 30,
  },
  data: {
    label: (
      <div className="text-[10px] font-medium text-[var(--text-secondary)] bg-[var(--muted)] px-2 py-0.5 rounded-full border border-[var(--border-default)]">
        parallel execution
      </div>
    ),
  },
  style: {
    background: "transparent",
    border: "none",
    padding: 0,
  },
  draggable: false,
  selectable: false,
})

const initialEdges: Edge[] = [
  {
    id: "e-event-triage",
    source: "event",
    target: "triage",
    animated: true,
    style: { stroke: "#4F46E5", strokeWidth: 2 },
    markerEnd: { type: MarkerType.ArrowClosed, color: "#4F46E5" },
  },
  {
    id: "e-triage-timeline",
    source: "triage",
    target: "timeline",
    animated: true,
    style: { stroke: "#4F46E5", strokeWidth: 2 },
    markerEnd: { type: MarkerType.ArrowClosed, color: "#4F46E5" },
  },
  {
    id: "e-triage-threat",
    source: "triage",
    target: "threat-intel",
    animated: true,
    style: { stroke: "#4F46E5", strokeWidth: 2 },
    markerEnd: { type: MarkerType.ArrowClosed, color: "#4F46E5" },
  },
  {
    id: "e-timeline-soc",
    source: "timeline",
    target: "soc-lead",
    animated: true,
    style: { stroke: "#4F46E5", strokeWidth: 2 },
    markerEnd: { type: MarkerType.ArrowClosed, color: "#4F46E5" },
  },
  {
    id: "e-threat-soc",
    source: "threat-intel",
    target: "soc-lead",
    animated: true,
    style: { stroke: "#4F46E5", strokeWidth: 2 },
    markerEnd: { type: MarkerType.ArrowClosed, color: "#4F46E5" },
  },
  {
    id: "e-soc-report",
    source: "soc-lead",
    target: "report",
    animated: true,
    style: { stroke: "#16A34A", strokeWidth: 2 },
    markerEnd: { type: MarkerType.ArrowClosed, color: "#16A34A" },
  },
]

export default function AgentWorkflowPage() {
  const [nodes, , onNodesChange] = useNodesState(initialNodes)
  const [edges, , onEdgesChange] = useEdgesState(initialEdges)

  return (
    <div className="flex-1 flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="px-8 pt-8 pb-4">
        <h1 className="text-[24px] font-bold tracking-tight text-[var(--text-primary)] leading-[32px]">
          Agent Workflow
        </h1>
        <p className="text-sm text-[var(--text-secondary)] mt-1">
          AI investigation pipeline — event intake through final report
        </p>
      </div>

      {/* Pipeline legend */}
      <div className="px-8 pb-4 flex items-center gap-4 text-xs">
        <div className="flex items-center gap-1.5">
          <div className="w-6 h-0.5 bg-[var(--accent-color)] rounded-full" />
          <span className="text-[var(--text-secondary)]">Active flow</span>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-6 h-0.5 bg-[var(--success)] rounded-full" />
          <span className="text-[var(--text-secondary)]">Completed</span>
        </div>
        <div className="flex items-center gap-1.5 ml-auto">
          <span className="text-[var(--text-secondary)]">
            Avg total pipeline: ~13s
          </span>
        </div>
      </div>

      {/* Flow canvas */}
      <div
        className="flex-1 mx-8 mb-8 rounded-2xl overflow-hidden"
        style={{
          boxShadow: "var(--shadow-card)",
          border: "1px solid var(--border-default)",
          backgroundColor: "var(--background)",
        }}
      >
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          fitView
          fitViewOptions={{ padding: 0.3 }}
          minZoom={0.3}
          maxZoom={1.5}
          panOnDrag
          zoomOnScroll
        >
          <Background color="#D0D5DD" gap={24} size={1.5} />
          <Controls />
        </ReactFlow>
      </div>
    </div>
  )
}
