import { Handle, Position, BaseEdge, getBezierPath, EdgeProps, EdgeLabelRenderer } from "@xyflow/react"
import { User, Monitor, Terminal, Globe, Clock, FileText, ExternalLink } from "lucide-react"
import * as Tooltip from '@radix-ui/react-tooltip'

interface NodeData {
  label: string
  isCritical?: boolean
  type?: string
}

const NodeWrapper = ({
  children,
  iconBg,
  borderColor,
  isCritical,
  data
}: {
  children: React.ReactNode
  iconBg: string
  borderColor: string
  isCritical?: boolean
  data?: NodeData
}) => (
  <div className="group relative">
    <Tooltip.Provider delayDuration={200}>
      <Tooltip.Root>
        <Tooltip.Trigger asChild>
          {/* Node Body */}
          <div
            className="px-5 py-4 rounded-2xl bg-white flex flex-col gap-4 min-w-[220px] transition-all duration-200 hover:-translate-y-1 relative cursor-default"
            style={{
              boxShadow: isCritical 
                ? `0 0 20px -2px ${borderColor}, var(--shadow-card)`
                : "var(--shadow-card)",
              border: isCritical ? `2px solid ${borderColor}` : `1px solid var(--border-default)`,
            }}
          >
            <Handle
              type="target"
              position={Position.Top}
              className="w-2 h-2 !bg-[var(--border-default)] !border-white transition-colors group-hover:!bg-[var(--accent-color)]"
            />
            {children}
            <Handle
              type="source"
              position={Position.Bottom}
              className="w-2 h-2 !bg-[var(--border-default)] !border-white transition-colors group-hover:!bg-[var(--accent-color)]"
            />
          </div>
        </Tooltip.Trigger>

        <Tooltip.Portal>
          <Tooltip.Content
            sideOffset={12}
            collisionPadding={20}
            className="w-64 bg-white/95 backdrop-blur-md rounded-xl p-4 shadow-xl border border-[var(--border-default)] z-50 animate-in fade-in-0 zoom-in-95 data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=closed]:zoom-out-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2"
          >
            <div className="flex items-center gap-2 mb-2">
              <Clock className="w-3.5 h-3.5 text-[var(--text-secondary)]" />
              <span className="text-[10px] text-[var(--text-secondary)] font-mono">First seen: 2023-10-27 10:01:00 UTC</span>
            </div>
            <div className="flex items-center gap-2 mb-3">
              <FileText className="w-3.5 h-3.5 text-[var(--text-secondary)]" />
              <span className="text-xs text-[var(--text-primary)] font-medium">3 Evidence Items</span>
            </div>
            <a href="/investigations" className="inline-flex items-center gap-1.5 text-xs text-[var(--accent-color)] hover:underline font-medium">
              View Investigation <ExternalLink className="w-3 h-3" />
            </a>
            <Tooltip.Arrow className="fill-white drop-shadow-sm" width={14} height={7} />
          </Tooltip.Content>
        </Tooltip.Portal>
      </Tooltip.Root>
    </Tooltip.Provider>
  </div>
)

export const WiderArcEdge = (props: EdgeProps) => {
  const { sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, markerEnd, style, label, labelStyle, labelBgStyle, labelBgPadding, labelBgBorderRadius } = props;
  
  // High curvature generates a much wider arc so it naturally dodges obstacles in the middle column
  const [edgePath, labelX, labelY] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
    curvature: 0.8,
  });

  return (
    <>
      <BaseEdge path={edgePath} markerEnd={markerEnd} style={style} />
      {label && (
        <EdgeLabelRenderer>
          <div
            className="nodrag nopan"
            style={{
              position: 'absolute',
              transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)`,
              pointerEvents: 'all',
              background: 'rgba(255,255,255,0.95)',
              padding: '2px 8px',
              borderRadius: '16px',
              border: `1px solid ${style?.stroke || 'var(--border-default)'}`,
              fontSize: '10px',
              fontWeight: 700,
              color: style?.stroke === 'var(--severity-critical)' ? 'var(--severity-critical)' : 'var(--text-secondary)',
              letterSpacing: '0.02em',
            }}
          >
            {label}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
}

export const UserNode = ({ data }: { data: NodeData }) => (
  <NodeWrapper iconBg="var(--agent-triage-bg)" borderColor="var(--agent-triage)" isCritical={data.isCritical} data={data}>
    <div className={`flex items-center gap-3 border-b pb-3 ${data.isCritical ? 'border-[var(--agent-triage)]/20' : 'border-[var(--border-default)]'}`}>
      <div
        className="w-9 h-9 rounded-xl flex items-center justify-center shadow-sm"
        style={{ backgroundColor: "var(--agent-triage-bg)" }}
      >
        <User className="w-4.5 h-4.5" style={{ color: "var(--agent-triage)" }} />
      </div>
      <span
        className="text-[11px] font-bold tracking-wider uppercase"
        style={{ color: "var(--agent-triage)" }}
      >
        USER
      </span>
    </div>
    <div className="text-[13px] font-medium text-[var(--text-primary)] font-mono truncate" title={data.label}>
      {data.label}
    </div>
  </NodeWrapper>
)

export const HostNode = ({ data }: { data: NodeData }) => (
  <NodeWrapper iconBg="var(--agent-timeline-bg)" borderColor="var(--agent-timeline)" isCritical={data.isCritical} data={data}>
    <div className={`flex items-center gap-3 border-b pb-3 ${data.isCritical ? 'border-[var(--agent-timeline)]/20' : 'border-[var(--border-default)]'}`}>
      <div
        className="w-9 h-9 rounded-xl flex items-center justify-center shadow-sm"
        style={{ backgroundColor: "var(--agent-timeline-bg)" }}
      >
        <Monitor className="w-4.5 h-4.5" style={{ color: "var(--agent-timeline)" }} />
      </div>
      <span
        className="text-[11px] font-bold tracking-wider uppercase"
        style={{ color: "var(--agent-timeline)" }}
      >
        HOST
      </span>
    </div>
    <div className="text-[13px] font-medium text-[var(--text-primary)] font-mono truncate" title={data.label}>
      {data.label}
    </div>
  </NodeWrapper>
)

export const ProcessNode = ({ data }: { data: NodeData }) => (
  <NodeWrapper iconBg="var(--severity-critical-bg)" borderColor="var(--severity-critical)" isCritical={data.isCritical} data={data}>
    <div className={`flex items-center gap-3 border-b pb-3 ${data.isCritical ? 'border-[var(--severity-critical)]/20' : 'border-[var(--border-default)]'}`}>
      <div
        className="w-9 h-9 rounded-xl flex items-center justify-center shadow-sm"
        style={{ backgroundColor: "var(--severity-critical-bg)" }}
      >
        <Terminal className="w-4.5 h-4.5" style={{ color: "var(--severity-critical)" }} />
      </div>
      <span
        className="text-[11px] font-bold tracking-wider uppercase"
        style={{ color: "var(--severity-critical)" }}
      >
        PROCESS
      </span>
    </div>
    <div className="text-[13px] font-medium text-[var(--text-primary)] font-mono truncate" title={data.label}>
      {data.label}
    </div>
  </NodeWrapper>
)

export const IPNode = ({ data }: { data: NodeData }) => (
  <NodeWrapper iconBg="var(--agent-soc-lead-bg)" borderColor="var(--agent-soc-lead)" isCritical={data.isCritical} data={data}>
    <div className={`flex items-center gap-3 border-b pb-3 ${data.isCritical ? 'border-[var(--agent-soc-lead)]/20' : 'border-[var(--border-default)]'}`}>
      <div
        className="w-9 h-9 rounded-xl flex items-center justify-center shadow-sm"
        style={{ backgroundColor: "var(--agent-soc-lead-bg)" }}
      >
        <Globe className="w-4.5 h-4.5" style={{ color: "var(--agent-soc-lead)" }} />
      </div>
      <span
        className="text-[11px] font-bold tracking-wider uppercase"
        style={{ color: "var(--agent-soc-lead)" }}
      >
        IP ADDRESS
      </span>
    </div>
    <div className="text-[13px] font-medium text-[var(--text-primary)] font-mono truncate" title={data.label}>
      {data.label}
    </div>
  </NodeWrapper>
)
