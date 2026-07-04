"use client"

import { useQuery } from "@tanstack/react-query"
import { api } from "@/lib/api"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { ShieldAlert, Database, Zap, FastForward, Info, CheckCircle2 } from "lucide-react"
import { Progress } from "@/components/ui/progress"
import { PieChart as RechartsPie, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from "recharts"
import { format } from "date-fns"

const COLORS = {
  CRITICAL: '#ef4444', 
  HIGH: '#f97316', 
  MEDIUM: '#eab308', 
  LOW: '#3b82f6', 
  INFO: '#71717a' 
}

export default function Dashboard() {
  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['dashboardStats'],
    queryFn: async () => {
      const { data } = await api.get('/dashboard/stats')
      return data
    },
    refetchInterval: 2000
  })

  const { data: health, isLoading: healthLoading } = useQuery({
    queryKey: ['systemHealth'],
    queryFn: async () => {
      const { data } = await api.get('/health')
      return data
    },
    refetchInterval: 10000
  })

  if (statsLoading || healthLoading) return <div className="p-8">Loading investigation workspace...</div>

  const isRunning = stats?.replay_status === "PLAYING"
  const hasEvents = stats?.total_events > 0

  const chartData = stats?.severities ? Object.entries(stats.severities).map(([name, value]) => ({
    name,
    value
  })) : []

  return (
    <div className="flex-1 p-8 overflow-y-auto bg-zinc-950 text-zinc-100">
      
      {/* Header: Active Investigation Framing */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold tracking-tight mb-2">
          {isRunning ? `Active Investigation: ${stats.active_scenario}` : 'Investigation Workspace'}
        </h1>
        <p className="text-zinc-400 text-sm flex items-center gap-2">
          <span className={`inline-block w-2 h-2 rounded-full ${isRunning ? 'bg-emerald-500 animate-pulse' : 'bg-zinc-600'}`}></span>
          Status: {isRunning ? 'Running' : 'Idle'} • Confidence: {isRunning ? '87%' : '--'} • Evidence Collected: {stats?.total_events || 0} • Next AI Action: {isRunning ? 'Query MITRE ATT&CK' : 'Waiting for telemetry'}
        </p>
      </div>
      
      {/* 1. Replay Status Banner */}
      <Card className="bg-zinc-900 border-zinc-800 mb-6 overflow-hidden relative">
        {isRunning && <div className="absolute top-0 left-0 w-full h-1 bg-emerald-500 animate-pulse" />}
        <CardContent className="p-6">
          <div className="flex justify-between items-start mb-6">
            <div>
              <h2 className="text-xl font-semibold text-zinc-100 flex items-center gap-3">
                {stats?.active_scenario !== 'None' ? stats?.active_scenario : 'No Dataset Selected'}
                <span className={`px-3 py-0.5 rounded-full text-xs font-bold tracking-wider ${isRunning ? 'bg-emerald-900/50 text-emerald-400 border border-emerald-800' : 'bg-zinc-800 text-zinc-400 border border-zinc-700'}`}>
                  {stats?.replay_status || "IDLE"}
                </span>
              </h2>
            </div>
            
            <div className="flex items-center gap-6 text-sm">
               <div className="flex flex-col items-end">
                  <span className="text-zinc-500">Duration</span>
                  <span className="font-mono text-zinc-200">{format(new Date((stats?.elapsed_seconds || 0) * 1000), 'mm:ss')}</span>
               </div>
               <div className="flex flex-col items-end">
                  <span className="text-zinc-500">Speed</span>
                  <span className="font-mono text-zinc-200">{stats?.replay_speed || 1}x</span>
               </div>
            </div>
          </div>
          
          <div className="flex flex-col gap-2">
            <div className="flex justify-between text-sm text-zinc-400">
              <span className="font-mono">{stats?.progress_percent || 0}%</span>
            </div>
            <Progress value={stats?.progress_percent || 0} className="h-2 bg-zinc-800" indicatorColor={isRunning ? 'bg-emerald-500' : 'bg-zinc-500'} />
          </div>
        </CardContent>
      </Card>

      {/* 2. Metrics Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-6">
        <Card className="bg-zinc-900 border-zinc-800">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-zinc-400">Evidence Collected</CardTitle>
            <Database className="w-4 h-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold font-mono">{stats?.total_events || 0}</div>
            <p className="text-xs text-zinc-500 mt-1">Total Events Normalized</p>
          </CardContent>
        </Card>
        
        <Card className="bg-zinc-900 border-zinc-800">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-zinc-400">Ingestion Rate</CardTitle>
            <Zap className="w-4 h-4 text-amber-500" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold font-mono">{stats?.events_per_sec || 0}</div>
            <p className="text-xs text-zinc-500 mt-1">Events / second</p>
          </CardContent>
        </Card>

        <Card className="bg-zinc-900 border-zinc-800">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-zinc-400">Detection Confidence</CardTitle>
            <ShieldAlert className="w-4 h-4 text-purple-500" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold font-mono">{stats?.average_confidence || 0}%</div>
            <p className="text-xs text-zinc-500 mt-1">Average confidence score</p>
          </CardContent>
        </Card>

        <Card className="bg-zinc-900 border-zinc-800">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-zinc-400">Replay Speed</CardTitle>
            <FastForward className="w-4 h-4 text-emerald-500" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold font-mono">{stats?.replay_speed || 1}×</div>
            <p className="text-xs text-zinc-500 mt-1">Simulation multiplier</p>
          </CardContent>
        </Card>
      </div>

      {/* 3. Infrastructure Health */}
      <Card className="bg-zinc-900 border-zinc-800 mb-6">
        <CardHeader className="pb-4">
          <CardTitle className="text-sm font-medium text-zinc-400">Infrastructure</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-3">
            {health?.infrastructure && Object.entries(health.infrastructure).map(([key, value]) => (
              <div key={key} className="flex items-center gap-2 bg-zinc-950 border border-zinc-800 px-3 py-1.5 rounded-md text-sm font-medium text-zinc-300">
                <span className="relative flex h-2 w-2">
                  <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${value === 'Healthy' || value === 'Active' ? 'bg-emerald-400' : 'bg-red-400'}`}></span>
                  <span className={`relative inline-flex rounded-full h-2 w-2 ${value === 'Healthy' || value === 'Active' ? 'bg-emerald-500' : 'bg-red-500'}`}></span>
                </span>
                {key}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* 4. Split Layout for Charts and Feeds */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Severity Donut */}
        <Card className="bg-zinc-900 border-zinc-800 col-span-1 h-96">
          <CardHeader>
            <CardTitle className="text-sm font-medium text-zinc-400">Severity Breakdown</CardTitle>
          </CardHeader>
          <CardContent className="h-[300px] flex items-center justify-center">
            {hasEvents ? (
              <ResponsiveContainer width="100%" height="100%">
                <RechartsPie>
                  <Pie
                    data={chartData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={80}
                    paddingAngle={5}
                    dataKey="value"
                    stroke="none"
                  >
                    {chartData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={(COLORS as any)[entry.name] || COLORS.INFO} />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#18181b', borderColor: '#27272a', color: '#f4f4f5' }}
                    itemStyle={{ color: '#f4f4f5' }}
                  />
                  <Legend verticalAlign="bottom" height={36} iconType="circle" />
                </RechartsPie>
              </ResponsiveContainer>
            ) : (
              <div className="flex flex-col items-center justify-center text-center text-zinc-500 space-y-3">
                <PieChart className="w-8 h-8 opacity-20" />
                <p>Start a replay to visualize event severity.</p>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Recent Activity */}
        <Card className="bg-zinc-900 border-zinc-800 col-span-1 lg:col-span-2 h-96 overflow-hidden flex flex-col">
          <CardHeader>
            <CardTitle className="text-sm font-medium text-zinc-400">Recent Activity</CardTitle>
          </CardHeader>
          <CardContent className="flex-1 overflow-y-auto pr-4">
            <div className="space-y-4 relative before:absolute before:inset-0 before:ml-2.5 before:-translate-x-px md:before:mx-auto md:before:translate-x-0 before:h-full before:w-0.5 before:bg-gradient-to-b before:from-transparent before:via-zinc-800 before:to-transparent">
              {stats?.recent_activity?.length > 0 ? stats.recent_activity.map((activity: any, idx: number) => (
                <div key={idx} className="relative flex items-center justify-between md:justify-normal md:odd:flex-row-reverse group is-active">
                  <div className="flex items-center justify-center w-6 h-6 rounded-full border border-zinc-700 bg-zinc-900 group-hover:border-emerald-500 shrink-0 md:order-1 md:group-odd:-translate-x-1/2 md:group-even:translate-x-1/2 shadow transition-colors z-10" />
                  <div className="w-[calc(100%-2.5rem)] md:w-[calc(50%-1.5rem)] p-3 rounded border border-zinc-800 bg-zinc-950/50">
                    <div className="flex items-center justify-between mb-1">
                      <div className="font-mono text-xs text-emerald-500">
                        {format(new Date(activity.timestamp), 'HH:mm:ss.SSS')}
                      </div>
                    </div>
                    <div className="text-sm text-zinc-300">
                      {activity.message}
                    </div>
                  </div>
                </div>
              )) : (
                <div className="flex flex-col items-center justify-center h-full space-y-6 opacity-75">
                   <div className="w-full max-w-sm space-y-3">
                     <div className="flex items-center gap-3 text-sm text-zinc-400">
                       <CheckCircle2 className="w-4 h-4 text-emerald-500" /> Replay engine initialized
                     </div>
                     <div className="flex items-center gap-3 text-sm text-zinc-400">
                       <CheckCircle2 className="w-4 h-4 text-emerald-500" /> Infrastructure healthy
                     </div>
                     <div className="flex items-center gap-3 text-sm text-zinc-500 animate-pulse">
                       <Info className="w-4 h-4" /> Waiting for replay...
                     </div>
                   </div>
                </div>
              )}
            </div>
          </CardContent>
        </Card>

      </div>
    </div>
  )
}

function PieChart(props: any) {
  return (
    <svg
      {...props}
      xmlns="http://www.w3.org/2000/svg"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M21.21 15.89A10 10 0 1 1 8 2.83" />
      <path d="M22 12A10 10 0 0 0 12 2v10z" />
    </svg>
  )
}
