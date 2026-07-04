"use client"

import { useQuery } from "@tanstack/react-query"
import { api } from "@/lib/api"
import { ReactFlow, Controls, Background, useNodesState, useEdgesState, MarkerType, MiniMap } from "@xyflow/react"
import '@xyflow/react/dist/style.css'
import { useMemo } from "react"
import { Card, CardContent } from "@/components/ui/card"
import dagre from 'dagre'
import { UserNode, HostNode, ProcessNode, IPNode } from '@/components/graph/CustomNodes'

const nodeTypes = {
  USER: UserNode,
  HOST: HostNode,
  PROCESS: ProcessNode,
  IP: IPNode
};

export default function AttackGraphPage() {
  const { data: graphData, isLoading } = useQuery({
    queryKey: ['entity_graph'],
    queryFn: async () => {
      const { data } = await api.get('/investigations/graph/entities')
      return data
    }
  })

  const [nodes, setNodes, onNodesChange] = useNodesState([])
  const [edges, setEdges, onEdgesChange] = useEdgesState([])

  useMemo(() => {
    if (!graphData) return
    const newNodes: any[] = []
    const newEdges: any[] = []
    
    // Initialize Dagre Graph for Auto-Layout
    const dagreGraph = new dagre.graphlib.Graph();
    dagreGraph.setDefaultEdgeLabel(() => ({}));
    dagreGraph.setGraph({ rankdir: 'TB', nodesep: 150, ranksep: 200, align: 'DL' });
    
    // Add nodes to layout engine
    graphData.nodes.forEach((n: any) => {
      dagreGraph.setNode(n.id, { width: 250, height: 100 });
    });
    
    // Add edges to layout engine
    graphData.edges.forEach((e: any) => {
      dagreGraph.setEdge(e.source, e.target);
    });
    
    // Calculate Layout
    dagre.layout(dagreGraph);

    // Apply layout to ReactFlow Nodes
    graphData.nodes.forEach((n: any) => {
      const nodeWithPosition = dagreGraph.node(n.id);
      newNodes.push({
        id: n.id,
        type: n.type,
        position: { x: nodeWithPosition.x - 125, y: nodeWithPosition.y - 50 },
        data: { label: n.label }
      });
    })

    // Apply premium styling to edges
    graphData.edges.forEach((e: any) => {
      newEdges.push({
        id: e.id,
        source: e.source,
        target: e.target,
        animated: true,
        label: e.label,
        style: { stroke: '#10b981', strokeWidth: 2, opacity: 0.8 }, // emerald green animated
        labelStyle: { fill: '#d4d4d8', fontSize: 11, fontWeight: 700, letterSpacing: '0.05em' },
        labelBgStyle: { fill: '#18181b', stroke: '#27272a', strokeWidth: 1 },
        labelBgBorderRadius: 6,
        labelBgPadding: [8, 4],
        markerEnd: { type: MarkerType.ArrowClosed, color: '#10b981' }
      })
    })

    setNodes(newNodes)
    setEdges(newEdges)
  }, [graphData, setNodes, setEdges])

  if (isLoading) return <div className="p-8">Loading attack graph...</div>

  return (
    <div className="flex-1 p-8 bg-zinc-950 text-zinc-100 flex flex-col h-full overflow-hidden">
      <h1 className="text-3xl font-bold tracking-tight mb-2">Global Attack Graph</h1>
      <p className="text-zinc-400 mb-6">Visualizing security investigations and their relationships in a directed threat hierarchy.</p>
      
      <Card className="flex-1 bg-zinc-900 border-zinc-800 overflow-hidden min-h-[600px] shadow-2xl">
        <CardContent className="p-0 h-full w-full">
          <ReactFlow 
            nodes={nodes} 
            edges={edges} 
            nodeTypes={nodeTypes}
            onNodesChange={onNodesChange} 
            onEdgesChange={onEdgesChange}
            fitView
            fitViewOptions={{ padding: 0.2 }}
            minZoom={0.1}
          >
            <Background color="#3f3f46" gap={24} size={2} />
            <Controls className="bg-zinc-800 text-zinc-300 border-zinc-700 shadow-xl" />
            <MiniMap 
              className="bg-zinc-900 border border-zinc-800 rounded-lg shadow-xl"
              maskColor="rgba(0, 0, 0, 0.7)"
              nodeColor={(n: any) => {
                if (n.type === 'USER') return '#1e3a8a';
                if (n.type === 'HOST') return '#064e3b';
                if (n.type === 'PROCESS') return '#7f1d1d';
                return '#701a75';
              }}
            />
          </ReactFlow>
        </CardContent>
      </Card>
    </div>
  )
}
