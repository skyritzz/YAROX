import { Handle, Position } from '@xyflow/react';
import { User, Monitor, Terminal, Globe } from 'lucide-react';

const NodeWrapper = ({ children, className, borderClass }: any) => (
  <div className={`px-4 py-3 rounded-xl border bg-zinc-950/80 backdrop-blur-md shadow-lg flex flex-col gap-3 min-w-[220px] ${borderClass} ${className}`}>
    <Handle type="target" position={Position.Top} className="w-2 h-2 !bg-zinc-500 !border-zinc-800" />
    {children}
    <Handle type="source" position={Position.Bottom} className="w-2 h-2 !bg-zinc-500 !border-zinc-800" />
  </div>
);

export const UserNode = ({ data }: any) => (
  <NodeWrapper borderClass="border-blue-900/60 shadow-[0_0_15px_rgba(30,58,138,0.25)]">
    <div className="flex items-center gap-2 border-b border-blue-900/30 pb-2">
      <div className="bg-blue-950/50 p-1.5 rounded-md border border-blue-900/30">
        <User className="w-4 h-4 text-blue-400" />
      </div>
      <span className="text-xs font-bold text-blue-400 tracking-wider">USER</span>
    </div>
    <div className="text-zinc-200 font-mono text-sm truncate" title={data.label}>{data.label}</div>
  </NodeWrapper>
);

export const HostNode = ({ data }: any) => (
  <NodeWrapper borderClass="border-emerald-900/60 shadow-[0_0_15px_rgba(6,78,59,0.25)]">
    <div className="flex items-center gap-2 border-b border-emerald-900/30 pb-2">
      <div className="bg-emerald-950/50 p-1.5 rounded-md border border-emerald-900/30">
        <Monitor className="w-4 h-4 text-emerald-400" />
      </div>
      <span className="text-xs font-bold text-emerald-400 tracking-wider">HOST</span>
    </div>
    <div className="text-zinc-200 font-mono text-sm truncate" title={data.label}>{data.label}</div>
  </NodeWrapper>
);

export const ProcessNode = ({ data }: any) => (
  <NodeWrapper borderClass="border-red-900/60 shadow-[0_0_15px_rgba(153,27,27,0.25)]">
    <div className="flex items-center gap-2 border-b border-red-900/30 pb-2">
      <div className="bg-red-950/50 p-1.5 rounded-md border border-red-900/30">
        <Terminal className="w-4 h-4 text-red-400" />
      </div>
      <span className="text-xs font-bold text-red-400 tracking-wider">PROCESS</span>
    </div>
    <div className="text-zinc-200 font-mono text-sm truncate" title={data.label}>{data.label}</div>
  </NodeWrapper>
);

export const IPNode = ({ data }: any) => (
  <NodeWrapper borderClass="border-fuchsia-900/60 shadow-[0_0_15px_rgba(112,26,117,0.25)]">
    <div className="flex items-center gap-2 border-b border-fuchsia-900/30 pb-2">
      <div className="bg-fuchsia-950/50 p-1.5 rounded-md border border-fuchsia-900/30">
        <Globe className="w-4 h-4 text-fuchsia-400" />
      </div>
      <span className="text-xs font-bold text-fuchsia-400 tracking-wider">IP ADDRESS</span>
    </div>
    <div className="text-zinc-200 font-mono text-sm truncate" title={data.label}>{data.label}</div>
  </NodeWrapper>
);
