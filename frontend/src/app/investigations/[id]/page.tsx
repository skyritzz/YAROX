"use client"

import { useQuery } from "@tanstack/react-query"
import { api } from "@/lib/api"
import { useParams, useRouter } from "next/navigation"
import Link from "next/link"
import { useEffect, useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { ShieldAlert, Download, Activity, Target, Clock, CheckCircle2, AlertCircle, BarChart3, Brain, ArrowLeft } from "lucide-react"

export default function InvestigationDetail() {
  const { id } = useParams()
  const router = useRouter()
  const [wsEvents, setWsEvents] = useState<any[]>([])

  const { data: caseData, isLoading, refetch } = useQuery({
    queryKey: ['investigation', id],
    queryFn: async () => {
      const { data } = await api.get(`/investigations/${id}`)
      return data
    },
    refetchInterval: (query) => query.state.data?.status === 'ANALYZING' ? 2000 : false
  })

  useEffect(() => {
    const ws = new WebSocket(`ws://localhost:8000/ws/investigations`)
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data)
      if (data.case_id === id) {
        setWsEvents(prev => [...prev, data])
        if (data.event === 'REPORT_READY') {
          refetch()
        }
      }
    }
    return () => ws.close()
  }, [id, refetch])

  const handleExport = async () => {
    window.open(`http://localhost:8000/investigations/${id}/export`, '_blank')
  }

  if (isLoading) return <div className="p-8">Loading investigation details...</div>

  return (
    <div className="flex-1 p-8 overflow-y-auto bg-zinc-950 text-zinc-100 space-y-6">
      <div className="flex justify-between items-start">
        <div>
          <button 
            onClick={() => router.push('/investigations')}
            className="flex items-center gap-1.5 text-zinc-400 hover:text-zinc-200 text-sm mb-4 transition-colors"
          >
            <ArrowLeft className="w-4 h-4" /> Back to Inbox
          </button>
          <h1 className="text-3xl font-bold tracking-tight mb-4 text-zinc-100">Case: {caseData?.title}</h1>
          <div className="flex flex-wrap items-center gap-3 text-sm">
            
            {/* Severity Badge */}
            <div className={`flex items-center gap-1.5 px-3 py-1 rounded-full border shadow-sm ${
              caseData?.severity === 'CRITICAL' ? 'bg-red-950/40 border-red-900/50 text-red-500' : 
              caseData?.severity === 'HIGH' ? 'bg-orange-950/40 border-orange-900/50 text-orange-500' :
              caseData?.severity === 'MEDIUM' ? 'bg-amber-950/40 border-amber-900/50 text-amber-500' :
              'bg-zinc-900/50 border-zinc-800 text-zinc-400'
            }`}>
              <AlertCircle className="w-3.5 h-3.5" />
              <span className="font-bold tracking-wider text-[11px] uppercase">{caseData?.severity}</span>
            </div>

            {/* Status Badge */}
            <div className="flex items-center gap-1.5 px-3 py-1 rounded-full bg-blue-950/30 border border-blue-900/40 text-blue-400 shadow-sm">
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span className="font-bold tracking-wider text-[11px] uppercase">
                {caseData?.status.replace(/_/g, ' ')}
              </span>
            </div>

            {/* Confidence Badge with Explainability */}
            {caseData?.confidence_score && (
              <div className="relative group">
                <div className="flex items-center gap-1.5 px-3 py-1 rounded-full bg-emerald-950/30 border border-emerald-900/40 text-emerald-400 shadow-sm cursor-help">
                  <BarChart3 className="w-3.5 h-3.5" />
                  <span className="font-bold tracking-wider text-[11px] uppercase">
                    Confidence: {(caseData.confidence_score * 100).toFixed(0)}%
                  </span>
                </div>
                {/* Explainability Popover */}
                {caseData.confidence_breakdown && (
                  <div className="absolute top-full left-0 mt-2 w-64 bg-zinc-900 border border-zinc-700 rounded-lg shadow-2xl opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 z-50 p-3">
                    <div className="text-[10px] font-bold text-zinc-500 mb-2 uppercase tracking-wider">Why AI Decided This</div>
                    <div className="space-y-2">
                      {caseData.confidence_breakdown.map((item: any, i: number) => (
                        <div key={i} className="flex justify-between items-center text-xs">
                          <span className="text-zinc-300">{item.label}</span>
                          <span className="font-mono text-emerald-400 font-bold">+{item.score}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Analysis Time Badge */}
            {caseData?.status !== 'OPEN' && caseData?.status !== 'ANALYZING' && caseData?.updated_at && caseData?.created_at && (
              <div className="flex items-center gap-1.5 px-3 py-1 rounded-full bg-zinc-900/60 border border-zinc-800 text-zinc-400 shadow-sm">
                <Clock className="w-3.5 h-3.5" />
                <span className="font-mono text-xs mt-0.5">
                  {(() => {
                    if (caseData?.agent_actions && caseData.agent_actions.length > 0) {
                      const sorted = [...caseData.agent_actions].sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());
                      const last = new Date(sorted[sorted.length - 1].created_at).getTime();
                      // Only consider actions in the most recent run (within 5 minutes of the last action)
                      const recent = sorted.filter(a => last - new Date(a.created_at).getTime() < 300000);
                      const first = new Date(recent[0].created_at).getTime();
                      const duration = Math.max((last - first) / 1000, 0) + 2.1; 
                      return duration.toFixed(1);
                    }
                    return ((new Date(caseData.updated_at).getTime() - new Date(caseData.created_at).getTime()) / 1000).toFixed(1);
                  })()}s
                </span>
              </div>
            )}
          </div>
        </div>
        <button 
          onClick={handleExport}
          className="flex items-center gap-2 bg-zinc-800 hover:bg-zinc-700 px-4 py-2 rounded text-sm transition-colors"
        >
          <Download className="w-4 h-4" />
          Export PDF
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
          <Card className="bg-zinc-900 border-zinc-800">
            <CardHeader>
              <CardTitle className="text-emerald-500 flex items-center gap-2">
                <ShieldAlert className="w-5 h-5" /> AI Analyst Summary
              </CardTitle>
            </CardHeader>
            <CardContent className="text-zinc-300 leading-relaxed min-h-[100px]">
              {caseData?.status === 'ANALYZING' ? (
                <div className="flex items-center gap-3 animate-pulse text-emerald-500 font-medium h-full pt-4">
                  <div className="w-5 h-5 border-2 border-emerald-500 border-t-transparent rounded-full animate-spin" />
                  AI Swarm is actively analyzing evidence...
                </div>
              ) : (
                (() => {
                  const socLeadActions = [...(caseData?.agent_actions || [])]
                    .filter((a: any) => a.agent_name === 'SOC Lead')
                    .sort((a: any, b: any) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());
                  const summary = socLeadActions.pop()?.output_data?.executive_summary;
                  return typeof summary === 'object' ? JSON.stringify(summary) : (summary || "No AI analysis available.");
                })()
              )}
            </CardContent>
          </Card>

          <Card className="bg-zinc-900 border-zinc-800">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Activity className="w-5 h-5" /> Attack Timeline
              </CardTitle>
            </CardHeader>
            <CardContent>
               <div className="space-y-4 relative before:absolute before:inset-0 before:ml-[5.5rem] before:-translate-x-px md:before:mx-auto md:before:translate-x-0 before:h-full before:w-0.5 before:bg-gradient-to-b before:from-transparent before:via-zinc-800 before:to-transparent">
                 {(() => {
                    const timelineActions = [...(caseData?.agent_actions || [])]
                      .filter((a: any) => a.agent_name === 'Forensic Timeline Analyst')
                      .sort((a: any, b: any) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());
                    const action = timelineActions.pop();
                    let tEvents = action?.output_data?.timeline || [];
                    if (!Array.isArray(tEvents)) {
                        // Attempt to extract if it's nested
                        if (action?.output_data?.result?.timeline) tEvents = action.output_data.result.timeline;
                        else tEvents = [];
                    }
                    if (tEvents.length === 0) {
                        return <div className="text-zinc-500 italic p-4 text-center">No timeline events extracted.</div>
                    }
                    
                    const uniqueTEvents: any[] = [];
                    const seenT = new Set();
                    for (const t of tEvents) {
                        const key = `${t.time}-${t.action}-${t.details}`.toLowerCase();
                        if (!seenT.has(key)) {
                            seenT.add(key);
                            uniqueTEvents.push(t);
                        }
                    }
                    
                    return uniqueTEvents.map((t: any, idx: number) => (
                      <div key={idx} className="relative flex items-center justify-between md:justify-normal md:odd:flex-row-reverse group is-active">
                         <div className="flex items-center justify-center w-6 h-6 rounded-full border border-zinc-700 bg-zinc-900 group-hover:border-emerald-500 shrink-0 md:order-1 md:group-odd:-translate-x-1/2 md:group-even:translate-x-1/2 shadow transition-colors z-10" />
                         <div className="w-[calc(100%-2.5rem)] md:w-[calc(50%-1.5rem)] bg-zinc-950 p-3 rounded border border-zinc-800">
                           <div className="font-mono text-xs text-zinc-500 mb-1">
                             {typeof (t.time || t.timestamp) === 'object' ? JSON.stringify(t.time || t.timestamp) : (t.time || t.timestamp || "Unknown Time")}
                           </div>
                           <div className="font-medium text-emerald-400 text-sm mb-1 break-words">
                             {typeof t.action === 'object' ? JSON.stringify(t.action) : (t.action || "Unknown Action")}
                           </div>
                           <div className="text-zinc-400 text-sm break-words whitespace-pre-wrap overflow-hidden">
                             {typeof (t.details || t.description) === 'object' ? JSON.stringify(t.details || t.description) : (t.details || t.description || "No details provided.")}
                           </div>
                         </div>
                      </div>
                    ))
                 })()}
               </div>
            </CardContent>
          </Card>
          
          <Card className="bg-zinc-900 border-zinc-800">
            <CardHeader>
              <CardTitle>Evidence Explorer</CardTitle>
            </CardHeader>
            <CardContent>
               <div className="space-y-3 overflow-hidden">
                 {(() => {
                    const uniqueEv: any[] = [];
                    const seenEv = new Set();
                    for (const e of caseData?.evidence_items || []) {
                        const key = `${e.evidence_type}-${e.artifact}`;
                        if (!seenEv.has(key)) {
                            seenEv.add(key);
                            uniqueEv.push(e);
                        }
                    }
                    return uniqueEv.map((e: any, idx: number) => (
                      <div key={idx} className="bg-zinc-950 p-4 rounded border border-zinc-800 text-sm flex flex-col gap-2 overflow-hidden">
                         <div className="flex justify-between items-center border-b border-zinc-800 pb-2">
                            <span className="text-emerald-500 font-bold tracking-wider text-xs">{e.evidence_type}</span>
                            <div className="flex items-center gap-3">
                               {e.importance_score && (
                                  <span className={`px-2 py-0.5 rounded text-xs font-bold ${e.importance_score > 0.9 ? 'bg-red-950/50 text-red-400 border border-red-900/50' : 'bg-amber-950/50 text-amber-400 border border-amber-900/50'}`}>
                                    Risk: {(e.importance_score * 100).toFixed(0)}%
                                  </span>
                               )}
                               <span className="font-mono text-xs text-zinc-500" title="Historical Event Time (UTC)">
                                 {new Date(e.timestamp).toISOString().split('T').join(' ').split('.')[0] + ' UTC'}
                               </span>
                            </div>
                         </div>
                         <div className="text-zinc-300 font-mono text-xs bg-zinc-900 p-2 rounded break-all whitespace-pre-wrap overflow-hidden">{e.artifact}</div>
                         
                         {typeof e.reason === 'string' && e.reason.includes('Matched Sigma Rule') ? (
                           <div className="text-zinc-400 text-xs mt-1 space-y-2">
                             <div className="italic break-all whitespace-pre-wrap">{e.reason.split('Matched Sigma Rule')[0].trim()}</div>
                             <div className="bg-indigo-950/30 border border-indigo-900/50 rounded p-2 text-indigo-300 font-mono text-[10px]">
                               <span className="text-indigo-400 font-bold uppercase tracking-wider mb-1 block">Matched Sigma Rule:</span>
                               {e.reason.split('Matched Sigma Rule:')[1].trim()}
                             </div>
                           </div>
                         ) : (
                           <div className="text-zinc-500 text-xs italic mt-1 break-all whitespace-pre-wrap">
                             {typeof e.reason === 'object' ? JSON.stringify(e.reason) : e.reason}
                           </div>
                         )}
                      </div>
                    ))
                 })()}
               </div>
            </CardContent>
          </Card>
        </div>

        <div className="space-y-6">
          <Card className="bg-zinc-900 border-zinc-800">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Target className="w-5 h-5" /> MITRE ATT&CK
              </CardTitle>
            </CardHeader>
            <CardContent>
               <div className="space-y-3">
                 {(() => {
                    const threatIntelActions = [...(caseData?.agent_actions || [])]
                      .filter((a: any) => a.agent_name === 'Threat Intel Analyst')
                      .sort((a: any, b: any) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());
                    const historicalInsight = threatIntelActions.pop()?.output_data;
                    if (historicalInsight?.historical_insight && historicalInsight.historical_insight !== "Failed to map.") {
                      return (
                        <div className="bg-indigo-950/30 border border-indigo-900/50 p-3 rounded mb-2">
                           <div className="text-indigo-400 font-bold text-[11px] uppercase tracking-wider mb-1 flex items-center gap-1.5">
                             <Brain className="w-3.5 h-3.5" /> Qdrant Memory Insight
                           </div>
                           <div className="text-indigo-200 text-sm italic break-words mb-2">{historicalInsight.historical_insight}</div>
                           {historicalInsight.similar_case_ids && historicalInsight.similar_case_ids.length > 0 && (
                             <div className="flex flex-wrap gap-2 mt-2 pt-2 border-t border-indigo-900/30">
                               <span className="text-xs text-indigo-400 font-medium">Related Cases:</span>
                               {historicalInsight.similar_case_ids.map((cid: string) => (
                                 <Link key={cid} href={`/investigations/${cid}`} className="text-[10px] bg-indigo-900/40 hover:bg-indigo-800/60 border border-indigo-800 text-indigo-300 px-2 py-0.5 rounded transition-colors truncate max-w-[120px]">
                                   {cid}
                                 </Link>
                               ))}
                             </div>
                           )}
                        </div>
                      );
                    }
                    return null;
                 })()}
                 {(() => {
                    const uniqueMitre: any[] = [];
                    const seenMitre = new Set();
                    for (const m of caseData?.mitre_techniques || []) {
                        if (!seenMitre.has(m.technique_id)) {
                            seenMitre.add(m.technique_id);
                            uniqueMitre.push(m);
                        }
                    }
                    return uniqueMitre.map((m: any, idx: number) => (
                      <div key={idx} className="bg-zinc-950 p-3 rounded border border-zinc-800">
                         <div className="flex justify-between items-center mb-1">
                            <span className="font-bold text-amber-500 text-sm">{m.technique_id}</span>
                            <span className="text-xs text-zinc-500">{m.tactic}</span>
                         </div>
                         <div className="text-zinc-300 text-sm font-medium mb-1">{m.technique_name}</div>
                         {m.reason && <div className="text-zinc-500 text-xs italic break-all whitespace-pre-wrap">{typeof m.reason === 'object' ? JSON.stringify(m.reason) : m.reason}</div>}
                      </div>
                    ))
                 })()}
               </div>
            </CardContent>
          </Card>

          <Card className="bg-zinc-900 border-zinc-800">
            <CardHeader>
              <CardTitle>Agent Reasoning Panel</CardTitle>
            </CardHeader>
            <CardContent>
                <div className="space-y-4 max-h-[600px] overflow-y-auto pr-2 custom-scrollbar">
                 {wsEvents.map((evt, idx) => (
                    <div key={idx} className="text-sm border-l-2 border-emerald-500 pl-3 py-1">
                       <div className="font-bold text-zinc-400 flex items-center gap-2">🤖 {evt.agent}</div>
                       <div className="text-zinc-300">
                         {evt.thought ? 
                           <span className="italic">{evt.thought}</span> : 
                           <span className="animate-pulse">{evt.event}</span>
                         }
                       </div>
                    </div>
                 ))}
                 {(() => {
                    const sortedActions = [...(caseData?.agent_actions || [])].sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());
                    if (sortedActions.length === 0) return null;
                    const lastTime = new Date(sortedActions[sortedActions.length - 1].created_at).getTime();
                    const recentActions = sortedActions.filter(a => lastTime - new Date(a.created_at).getTime() < 300000);
                    
                    return recentActions.map((a: any, idx: number) => (
                      <div key={`db-${idx}`} className="text-sm border-l-2 border-zinc-700 pl-3 py-2 bg-zinc-950/50 rounded-r">
                         <div className="font-bold text-zinc-500 mb-1 flex items-center gap-2">✓ {a.agent_name}</div>
                         <div className="text-zinc-400 italic">"{a.thought}"</div>
                         {a.action_taken && <div className="text-emerald-500/80 text-xs mt-1 font-mono">Action: {a.action_taken}</div>}
                      </div>
                    ));
                 })()}
               </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}
