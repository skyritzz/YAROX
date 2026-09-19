import { Handle, Position } from "@xyflow/react"
import { User, Monitor, Terminal, Globe } from "lucide-react"

interface NodeData {
  label: string
  type?: string
}

// The backend entity graph (GET /investigations/graph/entities) returns only id, label
// and type for each entity — no first-seen timestamp, memory-match or criticality data.
// Earlier versions of this component showed a fabricated "First seen" timestamp and a
// fabricated memory-match badge on every node; neither was ever backed by a real prop
// from the API, so both have been removed rather than displayed as if real.
const NodeWrapper = ({
  children,
  borderColor,
}: {
  children: React.ReactNode
  iconBg: string
  borderColor: string
  data?: NodeData
}) => (
  <div className="group relative">
    <div
      className="px-5 py-4 rounded-2xl bg-white flex flex-col gap-4 min-w-[220px] transition-all duration-200 hover:-translate-y-1 relative cursor-default"
      style={{
        boxShadow: "var(--shadow-card)",
        border: `1px solid var(--border-default)`,
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
  </div>
)

export const UserNode = ({ data }: { data: NodeData }) => (
  <NodeWrapper iconBg="var(--agent-triage-bg)" borderColor="var(--agent-triage)" data={data}>
    <div className="flex items-center gap-3 border-b pb-3 border-[var(--border-default)]">
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
  <NodeWrapper iconBg="var(--agent-timeline-bg)" borderColor="var(--agent-timeline)" data={data}>
    <div className="flex items-center gap-3 border-b pb-3 border-[var(--border-default)]">
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
  <NodeWrapper iconBg="var(--severity-critical-bg)" borderColor="var(--severity-critical)" data={data}>
    <div className="flex items-center gap-3 border-b pb-3 border-[var(--border-default)]">
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
  <NodeWrapper iconBg="var(--agent-soc-lead-bg)" borderColor="var(--agent-soc-lead)" data={data}>
    <div className="flex items-center gap-3 border-b pb-3 border-[var(--border-default)]">
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
