import Link from "next/link";
import { LayoutDashboard, List, Activity, Settings, Info, Network, GitMerge, FileText } from "lucide-react";

export default function Sidebar() {
  return (
    <div className="w-72 border-r border-zinc-800 bg-zinc-950 flex flex-col h-screen p-4">
      <div className="mb-10 px-4 mt-4">
        <h1 className="text-3xl font-bold tracking-tight text-white mb-2">YAROX</h1>
        <p className="text-xs text-zinc-400 leading-relaxed font-medium">Autonomous Investigation<br/>Platform</p>
      </div>

      <nav className="flex-1 space-y-2">
        <Link href="/" className="flex items-center gap-3 px-4 py-2 text-sm font-medium rounded-md hover:bg-zinc-800 text-zinc-300 hover:text-white transition-colors">
          <LayoutDashboard className="w-4 h-4" />
          Dashboard
        </Link>
        <Link href="/events" className="flex items-center gap-3 px-4 py-2 text-sm font-medium rounded-md hover:bg-zinc-800 text-zinc-300 hover:text-white transition-colors">
          <List className="w-4 h-4" />
          Raw Events
        </Link>
        <Link href="/investigations" className="flex items-center gap-3 px-4 py-2 text-sm font-medium rounded-md hover:bg-zinc-800 text-zinc-300 hover:text-white transition-colors">
          <FileText className="w-4 h-4 text-emerald-400" />
          AI Case Inbox
        </Link>
        <Link href="/attack-graph" className="flex items-center gap-3 px-4 py-2 text-sm font-medium rounded-md hover:bg-zinc-800 text-zinc-300 hover:text-white transition-colors">
          <GitMerge className="w-4 h-4 text-amber-400" />
          Attack Graph
        </Link>
        <Link href="/timeline" className="flex items-center gap-3 px-4 py-2 text-sm font-medium rounded-md hover:bg-zinc-800 text-zinc-300 hover:text-white transition-colors">
          <Activity className="w-4 h-4" />
          Simulation Controls
        </Link>
        <Link href="/architecture" className="flex items-center gap-3 px-4 py-2 text-sm font-medium rounded-md hover:bg-zinc-800 text-zinc-300 hover:text-white transition-colors">
          <Network className="w-4 h-4 text-purple-400" />
          Agent Workflow
        </Link>
      </nav>

      <div className="mt-auto space-y-2 pt-4 border-t border-zinc-800">
        <Link href="/settings" className="flex items-center gap-3 px-4 py-2 text-sm font-medium rounded-md hover:bg-zinc-800 text-zinc-400 hover:text-white transition-colors">
          <Settings className="w-4 h-4" />
          Settings
        </Link>
        <Link href="/about" className="flex items-center gap-3 px-4 py-2 text-sm font-medium rounded-md hover:bg-zinc-800 text-zinc-400 hover:text-white transition-colors">
          <Info className="w-4 h-4" />
          About
        </Link>
      </div>
    </div>
  );
}
