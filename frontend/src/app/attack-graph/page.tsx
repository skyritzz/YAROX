"use client"

import { useQuery } from "@tanstack/react-query"
import { api } from "@/lib/api"
import {
  ReactFlow,
  Controls,
  Background,
  useNodesState,
  useEdgesState,
  MarkerType,
  MiniMap,
} from "@xyflow/react"
import "@xyflow/react/dist/style.css"
import { useMemo, useState } from "react"
import dagre from "dagre"
import { UserNode, HostNode, ProcessNode, IPNode } from "@/components/graph/CustomNodes"

const nodeTypes = {
  USER: UserNode,
  HOST: HostNode,
  PROCESS: ProcessNode,
  IP: IPNode,
}

export default function AttackGraphPage() {
  const { data: graphData, isLoading } = useQuery({
    queryKey: ["entity_graph"],
    queryFn: async () => {
      const { data } = await api.get("/investigations/graph/entities")
      return data
    },
  })

  const [nodes, setNodes, onNodesChange] = useNodesState([] as any[])
  const [edges, setEdges, onEdgesChange] = useEdgesState([] as any[])
  const [showMinimap, setShowMinimap] = useState(true)

  useMemo(() => {
    if (!graphData) return
    const newNodes: any[] = []
    const newEdges: any[] = []

    // Dagre auto-layout - compact spacing to fit viewport
    const dagreGraph = new dagre.graphlib.Graph()
    dagreGraph.setDefaultEdgeLabel(() => ({}))
    dagreGraph.setGraph({ rankdir: "TB", nodesep: 60, ranksep: 100, align: "DL" })

    graphData.nodes.forEach((n: any) => {
      dagreGraph.setNode(n.id, { width: 250, height: 100 })
    })

    graphData.edges.forEach((e: any) => {
      dagreGraph.setEdge(e.source, e.target)
    })

    dagre.layout(dagreGraph)

    // The backend's entity graph (GET /investigations/graph/entities) does not carry
    // any severity, criticality or "attack path" signal today (see docs/YAROX_REALITY_AUDIT.md
    // A-5) — it is the full set of entities and relationships across all cases. Every
    // node and edge is therefore rendered identically rather than inventing a highlighted
    // "critical path" from demo data labels.
    graphData.nodes.forEach((n: any) => {
      const nodeWithPosition = dagreGraph.node(n.id)
      newNodes.push({
        id: n.id,
        type: n.type,
        position: { x: nodeWithPosition.x - 125, y: nodeWithPosition.y - 50 },
        data: { label: n.label, type: n.type },
      })
    })

    graphData.edges.forEach((e: any) => {
      newEdges.push({
        id: e.id,
        source: e.source,
        target: e.target,
        label: e.label,
        style: {
          stroke: "var(--border-default)",
          strokeWidth: 1.5,
          opacity: 0.8,
        },
        labelStyle: {
          fill: "var(--text-secondary)",
          fontSize: 12,
          fontWeight: 700,
          letterSpacing: "0.02em",
        },
        labelBgStyle: {
          fill: "rgba(255,255,255,0.95)",
          stroke: "var(--border-default)",
          strokeWidth: 1,
        },
        labelBgBorderRadius: 16,
        labelBgPadding: [16, 8] as [number, number],
        markerEnd: { type: MarkerType.ArrowClosed, color: "var(--border-default)" },
      })
    })

    setNodes(newNodes)
    setEdges(newEdges)
  }, [graphData, setNodes, setEdges])

  if (isLoading) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <div className="flex items-center gap-3 text-[var(--text-secondary)]">
          <div className="w-5 h-5 border-2 border-[var(--accent-color)] border-t-transparent rounded-full animate-spin" />
          Loading attack graph...
        </div>
      </div>
    )
  }

  if (!graphData || graphData.nodes.length === 0) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center text-center px-8">
        <h1 className="text-[24px] font-bold tracking-tight text-[var(--text-primary)] mb-2">
          Attack Graph
        </h1>
        <p className="text-sm text-[var(--text-secondary)]">
          Not available — no entity relationships have been extracted from investigations yet.
        </p>
      </div>
    )
  }

  return (
    <div className="flex-1 flex h-full overflow-hidden relative" style={{
      background: "radial-gradient(circle at center, var(--background) 0%, #f1f3f7 100%)"
    }}>
      {/* Header overlaid */}
      <div className="absolute top-8 left-8 z-10 pointer-events-none">
        <h1 className="text-[24px] font-bold tracking-tight text-[var(--text-primary)] leading-[32px] drop-shadow-sm">
          Attack Graph
        </h1>
        <p className="text-sm text-[var(--text-secondary)] mt-1 drop-shadow-sm font-medium">
          Entity relationships across all investigations
        </p>
      </div>

      {/* Graph */}
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        fitView
        fitViewOptions={{ padding: 0.3 }}
        minZoom={0.1}
        className="w-full h-full"
      >
        <Background color="#D0D5DD" gap={24} size={1.5} />
        
        {/* Customized Controls (floating pill) */}
        <Controls 
          className="bg-white/80 backdrop-blur-md rounded-full shadow-lg border border-[var(--border-default)] !flex !flex-row !p-1 !bottom-8 !left-1/2 !-translate-x-1/2 !top-auto !m-0"
          showInteractive={false}
        />
        
        {/* Toggle Button for Minimap */}
        <div className="absolute bottom-8 right-8 z-50 flex flex-col items-end gap-3 pointer-events-auto">
          <button 
            onClick={() => setShowMinimap(!showMinimap)}
            className="bg-white/90 backdrop-blur-md shadow-md px-4 py-2 rounded-full text-xs font-bold text-[var(--text-secondary)] hover:text-black border border-[var(--border-default)] transition-colors"
          >
            {showMinimap ? "Hide Map" : "Show Map"}
          </button>
        </div>

        {/* Customized MiniMap */}
        {showMinimap && (
          <MiniMap
            className="!bg-white/60 !backdrop-blur-md !border-none !rounded-2xl !shadow-xl !m-8 !mb-20"
            maskColor="rgba(255, 255, 255, 0.4)"
            nodeBorderRadius={4}
            nodeStrokeWidth={0}
            nodeColor="#94a3b8"
          />
        )}
      </ReactFlow>
    </div>
  )
}
