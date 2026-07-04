"use client"

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { api } from "@/lib/api"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Play, Pause, RotateCcw, FastForward } from "lucide-react"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { useState } from "react"

export default function TimelinePage() {
  const queryClient = useQueryClient()
  const [scenario, setScenario] = useState("credential_theft")
  const [speed, setSpeed] = useState("1.0")

  const { data: statusList } = useQuery({
    queryKey: ['replayStatus'],
    queryFn: async () => {
      const { data } = await api.get('/replay/status')
      return data
    },
    refetchInterval: 2000
  })

  const currentSession = statusList?.[0]

  const startReplay = useMutation({
    mutationFn: async () => {
      const { data } = await api.post('/replay/start', {
        scenario_name: scenario,
        speed_multiplier: parseFloat(speed)
      })
      return data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['replayStatus'] })
    }
  })

  const pauseReplay = useMutation({
    mutationFn: async () => {
      if (currentSession?.id) {
        await api.post(`/replay/${currentSession.id}/pause`)
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['replayStatus'] })
    }
  })

  const resetReplay = useMutation({
    mutationFn: async () => {
      if (currentSession?.id) {
        await api.post(`/replay/${currentSession.id}/reset`)
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['replayStatus'] })
    }
  })

  const isPlaying = currentSession?.status === "PLAYING"

  return (
    <div className="flex-1 p-8 overflow-y-auto">
      <h1 className="text-3xl font-bold mb-8">Timeline & Replay</h1>
      
      <Card className="bg-zinc-900 border-zinc-800 max-w-3xl mb-8">
        <CardHeader>
          <CardTitle>Replay Controls</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col gap-6">
            <div className="flex gap-4 items-center">
              <div className="flex-1">
                <label className="text-sm font-medium text-zinc-400 mb-1 block">Scenario</label>
                <Select value={scenario} onValueChange={setScenario} disabled={isPlaying}>
                  <SelectTrigger className="bg-zinc-950 border-zinc-800">
                    <SelectValue placeholder="Select scenario" />
                  </SelectTrigger>
                  <SelectContent className="bg-zinc-900 border-zinc-800 text-zinc-100">
                    <SelectItem value="credential_theft">Credential Theft (Demo)</SelectItem>
                    <SelectItem value="apt29_simulation">APT29 Simulation (Advanced)</SelectItem>
                    <SelectItem value="ransomware" disabled>Ransomware (Future)</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="w-32">
                <label className="text-sm font-medium text-zinc-400 mb-1 block">Speed</label>
                <Select value={speed} onValueChange={setSpeed} disabled={isPlaying}>
                  <SelectTrigger className="bg-zinc-950 border-zinc-800">
                    <SelectValue placeholder="Speed" />
                  </SelectTrigger>
                  <SelectContent className="bg-zinc-900 border-zinc-800 text-zinc-100">
                    <SelectItem value="1.0">1x</SelectItem>
                    <SelectItem value="5.0">5x</SelectItem>
                    <SelectItem value="10.0">10x</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="flex items-center gap-4 p-4 bg-zinc-950 rounded-lg border border-zinc-800">
              <Button 
                variant={isPlaying ? "destructive" : "default"}
                size="lg"
                className={!isPlaying ? "bg-emerald-600 hover:bg-emerald-700 text-white" : ""}
                onClick={() => isPlaying ? pauseReplay.mutate() : startReplay.mutate()}
                disabled={startReplay.isPending || pauseReplay.isPending}
              >
                {isPlaying ? <Pause className="w-5 h-5 mr-2" /> : <Play className="w-5 h-5 mr-2" />}
                {isPlaying ? "Pause Simulation" : "Start Simulation"}
              </Button>
              
              <Button 
                variant="outline" 
                size="lg"
                className="border-zinc-700 hover:bg-zinc-800"
                onClick={() => resetReplay.mutate()}
                disabled={resetReplay.isPending || !currentSession}
              >
                <RotateCcw className="w-5 h-5 mr-2" />
                Reset
              </Button>

              <div className="ml-auto text-right">
                <div className="text-sm text-zinc-400">Current Status</div>
                <div className="font-mono font-bold text-lg text-emerald-500">
                  {currentSession?.status || "IDLE"}
                </div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
      
      <div className="max-w-3xl">
        <h2 className="text-xl font-semibold mb-4 text-zinc-300">Session History</h2>
        <div className="space-y-4 border-l-2 border-zinc-800 ml-4 pl-4">
          {statusList?.map((session: any) => (
            <div key={session.id} className="relative">
              <div className="absolute w-3 h-3 bg-zinc-800 rounded-full -left-[23px] top-1.5 border-2 border-zinc-950" />
              <div className="bg-zinc-900/50 border border-zinc-800/50 p-4 rounded-lg">
                <div className="flex justify-between mb-2">
                  <span className="font-medium text-zinc-200">{session.scenario_name}</span>
                  <span className="text-xs text-zinc-500 font-mono">
                    {new Date(session.created_at).toLocaleString()}
                  </span>
                </div>
                <div className="flex gap-4 text-sm text-zinc-400">
                  <span>Status: <span className="text-zinc-300">{session.status}</span></span>
                  <span>Speed: <span className="text-zinc-300">{session.speed_multiplier}x</span></span>
                </div>
              </div>
            </div>
          ))}
          {(!statusList || statusList.length === 0) && (
            <div className="text-sm text-zinc-500 italic">No replay sessions found.</div>
          )}
        </div>
      </div>
    </div>
  )
}
