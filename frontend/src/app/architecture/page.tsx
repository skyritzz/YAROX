"use client"

import React, { useCallback } from 'react';
import {
  ReactFlow,
  MiniMap,
  Controls,
  Background,
  useNodesState,
  useEdgesState,
  addEdge,
  Connection,
  Edge,
  BackgroundVariant,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';

const initialNodes = [
  // Phase 1 Core Pipeline
  { id: 'replay', position: { x: 50, y: 50 }, data: { label: 'Replay Engine' }, style: { background: '#18181b', color: '#f4f4f5', border: '1px solid #3f3f46', borderRadius: '8px', padding: '10px' } },
  { id: 'bus', position: { x: 250, y: 50 }, data: { label: 'InMemory Event Bus' }, style: { background: '#18181b', color: '#f4f4f5', border: '1px solid #3b82f6', borderRadius: '8px', padding: '10px' } },
  { id: 'normalization', position: { x: 450, y: 50 }, data: { label: 'Normalization (Parsers)' }, style: { background: '#18181b', color: '#f4f4f5', border: '1px solid #3f3f46', borderRadius: '8px', padding: '10px' } },
  { id: 'storage', position: { x: 650, y: 50 }, data: { label: 'Evidence Store (PostgreSQL)' }, style: { background: '#18181b', color: '#f4f4f5', border: '1px solid #10b981', borderRadius: '8px', padding: '10px' } },
  { id: 'dashboard', position: { x: 850, y: 50 }, data: { label: 'Investigation Dashboard' }, style: { background: '#18181b', color: '#f4f4f5', border: '1px solid #8b5cf6', borderRadius: '8px', padding: '10px' } },
  
  // Phase 2 AI Agents
  { id: 'phase2_label', position: { x: 50, y: 150 }, data: { label: 'Phase 2: Multi-Agent System' }, style: { background: 'transparent', color: '#a1a1aa', border: 'none', fontSize: '12px', fontWeight: 'bold' }, type: 'default', draggable: false, selectable: false },
  { id: 'planner', position: { x: 250, y: 200 }, data: { label: 'Planner Agent' }, style: { background: '#18181b', color: '#f4f4f5', border: '1px dashed #f59e0b', borderRadius: '8px', padding: '10px' } },
  { id: 'detection', position: { x: 450, y: 200 }, data: { label: 'Detection Agent' }, style: { background: '#18181b', color: '#f4f4f5', border: '1px dashed #f59e0b', borderRadius: '8px', padding: '10px' } },
  { id: 'threat_intel', position: { x: 650, y: 200 }, data: { label: 'Threat Intel Plugin' }, style: { background: '#18181b', color: '#f4f4f5', border: '1px dashed #ef4444', borderRadius: '8px', padding: '10px' } },
  { id: 'report', position: { x: 850, y: 200 }, data: { label: 'Automated Report' }, style: { background: '#18181b', color: '#f4f4f5', border: '1px dashed #10b981', borderRadius: '8px', padding: '10px' } },
];

const initialEdges = [
  // Core Pipeline
  { id: 'e1-2', source: 'replay', target: 'bus', animated: true, style: { stroke: '#a1a1aa' } },
  { id: 'e2-3', source: 'bus', target: 'normalization', animated: true, style: { stroke: '#a1a1aa' } },
  { id: 'e3-4', source: 'normalization', target: 'storage', animated: true, style: { stroke: '#a1a1aa' } },
  { id: 'e4-5', source: 'storage', target: 'dashboard', animated: false, style: { stroke: '#a1a1aa' } },
  
  // AI Pipeline
  { id: 'e2-p1', source: 'bus', target: 'planner', animated: true, style: { stroke: '#f59e0b', strokeDasharray: '5 5' } },
  { id: 'ep1-d1', source: 'planner', target: 'detection', animated: true, style: { stroke: '#f59e0b', strokeDasharray: '5 5' } },
  { id: 'ed1-t1', source: 'detection', target: 'threat_intel', animated: true, style: { stroke: '#f59e0b', strokeDasharray: '5 5' } },
  { id: 'et1-r1', source: 'threat_intel', target: 'report', animated: true, style: { stroke: '#f59e0b', strokeDasharray: '5 5' } },
  { id: 'ed1-4', source: 'detection', target: 'storage', animated: false, style: { stroke: '#a1a1aa', strokeDasharray: '5 5' } },
];

export default function ArchitecturePage() {
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  const onConnect = useCallback(
    (params: Connection | Edge) => setEdges((eds) => addEdge(params, eds)),
    [setEdges],
  );

  return (
    <div className="flex-1 p-8 overflow-hidden bg-zinc-950 flex flex-col h-full">
      <div className="mb-6 shrink-0">
        <h1 className="text-3xl font-bold tracking-tight text-zinc-100">System Architecture</h1>
        <p className="text-zinc-400 mt-1">Interactive data pipeline and agent orchestration layout.</p>
      </div>
      
      <div className="flex-1 border border-zinc-800 rounded-lg overflow-hidden bg-zinc-900/50">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onConnect={onConnect}
          fitView
          className="dark"
        >
          <Controls className="bg-zinc-900 border-zinc-800 fill-zinc-400" />
          <MiniMap 
            nodeColor={(node) => {
              if (node.id === 'storage' || node.id === 'report') return '#10b981';
              if (node.id === 'dashboard') return '#8b5cf6';
              if (node.id === 'bus') return '#3b82f6';
              if (node.id === 'threat_intel') return '#ef4444';
              if (node.id.includes('phase2')) return 'transparent';
              return '#3f3f46';
            }}
            maskColor="rgba(24, 24, 27, 0.7)"
            className="bg-zinc-950 border border-zinc-800"
          />
          <Background variant={BackgroundVariant.Dots} gap={12} size={1} color="#3f3f46" />
        </ReactFlow>
      </div>
    </div>
  );
}
