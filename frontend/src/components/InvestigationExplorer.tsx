"use client"

import React, { useState } from "react"
import { useQuery } from "@tanstack/react-query"
import { api } from "@/lib/api"
import { motion, AnimatePresence } from "framer-motion"
import { useInvestigation } from "@/context/InvestigationContext"
import { useLiveEvents } from "@/context/LiveInvestigationContext"
import ReactMarkdown from "react-markdown"
import remarkGfm from "remark-gfm"
import { 
    X, Activity, Brain, Clock, Shield, Search, CheckCircle2, 
    AlertCircle, FileText, Database, Target, Copy 
} from "lucide-react"

export function InvestigationExplorer() {
    const { caseId, selectedExecutionId, setSelectedExecutionId } = useInvestigation()
    const liveEvents = useLiveEvents()
    const [activeTab, setActiveTab] = useState<"summary" | "evidence" | "reasoning" | "timeline" | "tools" | "metrics">("summary")

    const { data: explData, isLoading } = useQuery({
        queryKey: ["explainability", caseId, selectedExecutionId],
        queryFn: async () => {
            if (!selectedExecutionId) return null;
            const { data } = await api.get(`/investigations/${caseId}/executions/${selectedExecutionId}`)
            return data
        },
        enabled: !!selectedExecutionId,
        refetchInterval: (query) => query.state.data?.execution?.status === "running" ? 2000 : false
    })

    if (!selectedExecutionId) return null;

    const tabs = [
        { id: "summary", label: "Summary" },
        { id: "evidence", label: "Evidence" },
        { id: "reasoning", label: "Reasoning" },
        { id: "timeline", label: "Timeline" },
        { id: "tools", label: "Tools" },
        { id: "metrics", label: "Metrics" },
    ] as const;

    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text)
    }

    const formatTime = (ts: string) => {
        if (!ts) return "";
        try {
            const d = new Date(ts);
            if (isNaN(d.getTime())) return ts;
            const pad = (n: number, w=2) => n.toString().padStart(w, '0');
            const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
            const dateStr = `${months[d.getMonth()]} ${pad(d.getDate())}, ${d.getFullYear()}`;
            const timeStr = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
            return `${dateStr} - ${timeStr}`;
        } catch (e) {
            return ts;
        }
    };

    const renderJsonUI = (data: any, depth = 0): React.ReactNode => {
        if (data === null) return "null";
        if (Array.isArray(data)) {
            return (
                <div className={`space-y-2 ${depth > 0 ? 'mt-1' : ''}`}>
                    {data.map((item, idx) => (
                        <div key={idx} className="bg-white/5 p-2.5 rounded border border-white/10 min-w-0">
                            {renderJsonUI(item, depth + 1)}
                        </div>
                    ))}
                </div>
            )
        } else if (typeof data === 'object') {
            return (
                <div className={`space-y-2 ${depth > 0 ? 'mt-1' : ''}`}>
                    {Object.entries(data).map(([k, v]) => (
                        <div key={k} className="flex flex-col sm:flex-row sm:items-start gap-1 sm:gap-4 min-w-0">
                            <span className="text-gray-500 font-mono text-[10px] uppercase tracking-wider shrink-0 sm:w-24 mt-0.5">{k.replace(/_/g, " ")}:</span>
                            <div className="text-gray-300 font-mono text-xs break-all whitespace-pre-wrap flex-1 min-w-0">
                                {typeof v === 'object' ? renderJsonUI(v, depth + 1) : String(v)}
                            </div>
                        </div>
                    ))}
                </div>
            )
        }
        return String(data)
    }

    const renderPayload = (payload: any) => {
        if (typeof payload === 'string') {
            return <ReactMarkdown remarkPlugins={[remarkGfm]}>{payload}</ReactMarkdown>;
        }
        if (typeof payload === 'object' && payload !== null) {
            const { text, executive_summary, mitre_mapping, ...rest } = payload;
            const mainText = text || executive_summary || '';
            const hasRest = Object.keys(rest).length > 0 || mitre_mapping;
            
            return (
                <div className="space-y-3">
                    {mainText && (
                        <ReactMarkdown remarkPlugins={[remarkGfm]}>
                            {mainText}
                        </ReactMarkdown>
                    )}
                    {hasRest && (
                        <div className="grid grid-cols-1 gap-2 mt-2">
                            {mitre_mapping && (
                                <div className="bg-black/40 p-3 rounded border border-white/5">
                                    <div className="text-[10px] text-gray-500 font-mono mb-2 uppercase tracking-wider">MITRE MAPPING</div>
                                    {renderJsonUI(mitre_mapping)}
                                </div>
                            )}
                            {Object.entries(rest).map(([k, v]) => (
                                <div key={k} className="bg-black/40 p-3 rounded border border-white/5 min-w-0">
                                    <div className="text-[10px] text-gray-500 font-mono mb-2 uppercase tracking-wider">{k.replace(/_/g, " ")}</div>
                                    {typeof v === 'object' ? renderJsonUI(v) : (
                                        <div className="text-xs break-all whitespace-pre-wrap text-gray-300 font-mono min-w-0">
                                            {String(v)}
                                        </div>
                                    )}
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            )
        }
        return <span>{String(payload)}</span>;
    };

    return (
        <AnimatePresence>
            <motion.div
                initial={{ x: "100%", opacity: 0 }}
                animate={{ x: 0, opacity: 1 }}
                exit={{ x: "100%", opacity: 0 }}
                transition={{ type: "spring", damping: 25, stiffness: 200 }}
                className="fixed top-0 right-0 w-[600px] h-screen bg-[#111827]/95 backdrop-blur-xl border-l border-white/10 z-50 flex flex-col text-white shadow-2xl"
                style={{ boxShadow: "-10px 0 30px rgba(0,0,0,0.5)" }}
            >
                {/* Header */}
                <div className="flex items-center justify-between p-6 border-b border-white/10 shrink-0">
                    <div>
                        <h2 className="text-xl font-bold flex items-center gap-2">
                            <Brain className="w-5 h-5 text-purple-400" />
                            Investigation Explorer
                        </h2>
                        {explData && (
                            <div className="flex items-center gap-3 mt-2 text-sm text-gray-400">
                                <span>{explData.execution.agent_name}</span>
                                <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${
                                    explData.execution.status === "running" ? "bg-blue-500/20 text-blue-400" : "bg-green-500/20 text-green-400"
                                }`}>
                                    {explData.execution.status}
                                </span>
                            </div>
                        )}
                    </div>
                    <button onClick={() => setSelectedExecutionId(null)} className="p-2 hover:bg-white/10 rounded-full transition-colors text-gray-400">
                        <X className="w-5 h-5" />
                    </button>
                </div>

                {/* Tabs */}
                <div className="flex px-6 border-b border-white/10 shrink-0 overflow-x-auto hide-scrollbar">
                    {tabs.map(t => (
                        <button
                            key={t.id}
                            onClick={() => setActiveTab(t.id)}
                            className={`px-4 py-3 text-sm font-medium whitespace-nowrap border-b-2 transition-colors ${
                                activeTab === t.id ? "border-purple-500 text-purple-400" : "border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-600"
                            }`}
                        >
                            {t.label}
                        </button>
                    ))}
                </div>

                {/* Content */}
                <div className="flex-1 overflow-y-auto p-6 custom-scrollbar">
                    {isLoading ? (
                        <div className="flex items-center justify-center h-full text-gray-400">
                            <div className="w-6 h-6 border-2 border-purple-500 border-t-transparent rounded-full animate-spin mr-3" />
                            Loading execution data...
                        </div>
                    ) : !explData ? (
                        <div className="text-center text-gray-400 mt-10">No data found.</div>
                    ) : (
                        <div className="space-y-6">
                            {activeTab === "summary" && (
                                <div className="space-y-6">
                                    <div className="grid grid-cols-2 gap-4">
                                        <div className="bg-white/5 p-4 rounded-xl border border-white/10">
                                            <div className="text-xs text-gray-400 mb-1">Total Duration</div>
                                            <div className="text-xl font-mono">{(explData.metrics.total_execution_time_ms / 1000).toFixed(1)}s</div>
                                        </div>
                                        <div className="bg-white/5 p-4 rounded-xl border border-white/10">
                                            <div className="text-xs text-gray-400 mb-1">Confidence</div>
                                            <div className="text-xl font-bold text-green-400">{(explData.execution.confidence * 100).toFixed(0)}%</div>
                                        </div>
                                        <div className="bg-white/5 p-4 rounded-xl border border-white/10">
                                            <div className="text-xs text-gray-400 mb-1">Tool Calls</div>
                                            <div className="text-xl font-mono">{explData.metrics.tool_call_count}</div>
                                        </div>
                                        <div className="bg-white/5 p-4 rounded-xl border border-white/10">
                                            <div className="text-xs text-gray-400 mb-1">Evidence Discovered</div>
                                            <div className="text-xl font-mono">{explData.evidence.length}</div>
                                        </div>
                                    </div>
                                    
                                    {explData.decision && (
                                        <div className="bg-green-500/10 border border-green-500/30 p-5 rounded-xl">
                                            <div className="flex justify-between items-center mb-3">
                                                <h3 className="text-sm font-bold text-green-400 uppercase tracking-wider">Final Decision</h3>
                                                <button onClick={() => copyToClipboard(JSON.stringify(explData.decision, null, 2))} className="text-gray-400 hover:text-white"><Copy className="w-4 h-4"/></button>
                                            </div>
                                            <div className="prose prose-invert prose-sm max-w-none">
                                                {renderPayload(explData.decision)}
                                            </div>
                                        </div>
                                    )}

                                    {explData.execution.confidence_explanation && (
                                        <div className="bg-white/5 border border-white/10 p-5 rounded-xl">
                                            <h3 className="text-sm font-bold text-gray-300 uppercase tracking-wider mb-3">Confidence Breakdown</h3>
                                            <div className="space-y-3 text-sm">
                                                <div>
                                                    <span className="text-green-400 font-bold mb-1 block">✓ Strong Signals</span>
                                                    <ul className="list-disc pl-5 text-gray-400">
                                                        {explData.execution.confidence_explanation.strong_signals?.map((s: string, i: number) => <li key={i}>{s}</li>) || <li>None</li>}
                                                    </ul>
                                                </div>
                                                <div>
                                                    <span className="text-red-400 font-bold mb-1 block">✗ Weak Signals</span>
                                                    <ul className="list-disc pl-5 text-gray-400">
                                                        {explData.execution.confidence_explanation.weak_signals?.map((s: string, i: number) => <li key={i}>{s}</li>) || <li>None</li>}
                                                    </ul>
                                                </div>
                                            </div>
                                        </div>
                                    )}
                                </div>
                            )}

                            {activeTab === "evidence" && (
                                <div className="space-y-4">
                                    {explData.evidence.map((ev: any) => (
                                        <div key={ev.id} className="bg-white/5 border border-white/10 p-4 rounded-xl">
                                            <div className="flex justify-between items-start mb-2">
                                                <span className="text-xs font-bold px-2 py-0.5 rounded bg-blue-500/20 text-blue-400 uppercase">{ev.evidence_type}</span>
                                                <span className="text-[10px] text-gray-500 font-mono">{formatTime(ev.timestamp)}</span>
                                            </div>
                                            <div className="text-sm text-gray-300 font-mono bg-black/30 p-2 rounded mb-3 break-all">{ev.artifact}</div>
                                            <div className="flex gap-2">
                                                <button className="text-[10px] uppercase font-bold text-purple-400 bg-purple-400/10 hover:bg-purple-400/20 px-2 py-1 rounded transition-colors">Jump to Timeline</button>
                                                <button className="text-[10px] uppercase font-bold text-orange-400 bg-orange-400/10 hover:bg-orange-400/20 px-2 py-1 rounded transition-colors">Jump to Graph</button>
                                            </div>
                                        </div>
                                    ))}
                                    {explData.evidence.length === 0 && <div className="text-gray-500 text-center py-10">No evidence recorded by this agent.</div>}
                                </div>
                            )}

                            {activeTab === "reasoning" && (
                                <div className="space-y-4">
                                    {explData.timeline.filter((t: any) => t.step_type.includes("reasoning")).map((t: any, i: number) => (
                                        <div key={i} className="bg-purple-500/10 border border-purple-500/30 p-5 rounded-xl">
                                            <div className="prose prose-invert prose-sm max-w-none">
                                                {renderPayload(t.payload)}
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            )}

                            {activeTab === "timeline" && (
                                <div className="relative pl-6">
                                    <div className="absolute left-[11px] top-2 bottom-2 w-px bg-white/10" />
                                    <div className="space-y-6">
                                        {explData.timeline.map((t: any, idx: number) => {
                                            const colors: Record<string, string> = {
                                                observation: "bg-blue-500 border-blue-400",
                                                tool_call: "bg-orange-500 border-orange-400",
                                                reasoning: "bg-purple-500 border-purple-400",
                                                decision: "bg-green-500 border-green-400",
                                                failed: "bg-red-500 border-red-400",
                                            }
                                            const defaultColor = "bg-gray-500 border-gray-400"
                                            const dotColor = Object.entries(colors).find(([k]) => t.step_type.includes(k))?.[1] || defaultColor

                                            return (
                                                <div key={idx} className="relative">
                                                    <div className={`absolute -left-[29px] top-1.5 w-3 h-3 rounded-full border-2 ${dotColor}`} />
                                                    <div className="text-xs text-gray-500 font-mono mb-1">{formatTime(t.timestamp)}</div>
                                                    <div className="text-sm font-bold text-gray-200 uppercase tracking-wider mb-1">{t.step_type.replace(/_/g, " ")}</div>
                                                    <div className="text-sm text-gray-400 bg-white/5 p-3 rounded-xl border border-white/5 break-all whitespace-pre-wrap">
                                                        {renderPayload(t.payload)}
                                                    </div>
                                                </div>
                                            )
                                        })}
                                    </div>
                                </div>
                            )}

                            {activeTab === "tools" && (
                                <div className="space-y-4">
                                    {explData.tool_calls.map((tool: any, i: number) => (
                                        <div key={i} className="bg-white/5 border border-white/10 rounded-xl overflow-hidden">
                                            <div className="bg-black/20 p-3 flex justify-between items-center border-b border-white/10">
                                                <div className="font-bold text-orange-400 font-mono text-sm">{tool.tool_name}</div>
                                                <div className="flex gap-3 text-xs font-mono">
                                                    <span className={tool.status === "Failed" ? "text-red-400" : "text-green-400"}>{tool.status || "Completed"}</span>
                                                    <span className="text-gray-500">{tool.duration_ms?.toFixed(0)}ms</span>
                                                </div>
                                            </div>
                                            <div className="p-4 space-y-4">
                                                <div>
                                                    <div className="text-[10px] uppercase text-gray-500 font-bold mb-2 flex items-center gap-1.5">
                                                        <svg className="w-3 h-3 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 5l7 7-7 7M5 5l7 7-7 7" /></svg>
                                                        Execution Input
                                                    </div>
                                                    <div className="bg-black/30 rounded-lg p-3 border border-white/5">
                                                        {typeof tool.input === 'object' && tool.input !== null ? (
                                                            <div className="space-y-2">
                                                                {Object.entries(tool.input).map(([k, v]) => (
                                                                    <div key={k} className="flex flex-col sm:flex-row sm:items-start gap-1 sm:gap-3">
                                                                        <span className="text-[11px] text-blue-400/80 font-mono pt-0.5 shrink-0">{k}:</span>
                                                                        {typeof v === 'object' && v !== null && Object.keys(v).length > 0 ? (
                                                                            <pre className="text-xs text-gray-300 font-mono bg-black/40 p-2 rounded border border-white/5 overflow-x-auto w-full">{JSON.stringify(v, null, 2)}</pre>
                                                                        ) : (
                                                                            <span className="text-xs text-gray-200 font-mono bg-white/5 px-2 py-0.5 rounded border border-white/5 break-all">
                                                                                {typeof v === 'object' ? '{}' : String(v)}
                                                                            </span>
                                                                        )}
                                                                    </div>
                                                                ))}
                                                            </div>
                                                        ) : (
                                                            <span className="text-xs text-gray-300 font-mono">{String(tool.input)}</span>
                                                        )}
                                                    </div>
                                                </div>
                                                <div>
                                                    <div className="text-[10px] uppercase text-gray-500 font-bold mb-2 flex items-center gap-1.5">
                                                        <svg className="w-3 h-3 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" /></svg>
                                                        Execution Output
                                                    </div>
                                                    <div className="bg-black/30 rounded-lg p-3 border border-white/5 max-h-60 overflow-y-auto">
                                                        {typeof tool.output === 'object' && tool.output !== null ? (
                                                            <div className="space-y-2">
                                                                {Object.entries(tool.output).map(([k, v]) => (
                                                                    <div key={k} className="flex flex-col sm:flex-row sm:items-start gap-1 sm:gap-3">
                                                                        <span className="text-[11px] text-emerald-400/80 font-mono pt-0.5 shrink-0">{k}:</span>
                                                                        {typeof v === 'object' && v !== null && Object.keys(v).length > 0 ? (
                                                                            <pre className="text-xs text-gray-300 font-mono bg-black/40 p-2 rounded border border-white/5 overflow-x-auto w-full">{JSON.stringify(v, null, 2)}</pre>
                                                                        ) : (
                                                                            <span className="text-xs text-gray-200 font-mono bg-white/5 px-2 py-0.5 rounded border border-white/5 break-all">
                                                                                {typeof v === 'object' ? '{}' : String(v)}
                                                                            </span>
                                                                        )}
                                                                    </div>
                                                                ))}
                                                            </div>
                                                        ) : (
                                                            <span className="text-xs text-gray-300 font-mono">{String(tool.output)}</span>
                                                        )}
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    ))}
                                    {explData.tool_calls.length === 0 && <div className="text-gray-500 text-center py-10">No tools were called by this agent.</div>}
                                </div>
                            )}

                            {activeTab === "metrics" && (
                                <div className="space-y-4">
                                    <div className="bg-white/5 p-5 rounded-xl border border-white/10 grid grid-cols-2 gap-4">
                                        <div>
                                            <div className="text-xs text-gray-500">LLM Generation Time</div>
                                            <div className="text-lg font-mono text-gray-200">{(explData.metrics.llm_execution_time_ms / 1000).toFixed(2)}s</div>
                                        </div>
                                        <div>
                                            <div className="text-xs text-gray-500">Tool Execution Time</div>
                                            <div className="text-lg font-mono text-gray-200">{(explData.metrics.tool_execution_time_ms / 1000).toFixed(2)}s</div>
                                        </div>
                                    </div>
                                </div>
                            )}
                        </div>
                    )}
                </div>
            </motion.div>
        </AnimatePresence>
    )
}
