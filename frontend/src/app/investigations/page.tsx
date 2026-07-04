"use client"

import { useQuery } from "@tanstack/react-query"
import { api } from "@/lib/api"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { ShieldAlert, AlertTriangle, Database } from "lucide-react"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useRouter } from "next/navigation"

export default function InvestigationsPage() {
  const router = useRouter()
  const { data: investigations, isLoading } = useQuery({
    queryKey: ['investigations'],
    queryFn: async () => {
      const { data } = await api.get('/investigations/')
      return data.sort((a: any, b: any) => new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime())
    },
    refetchInterval: 5000
  })

  if (isLoading) return <div className="p-8">Loading investigations...</div>

  const activeCases = investigations?.filter((i: any) => i.status === 'ANALYZING' || i.status === 'OPEN').length || 0
  const criticalCases = investigations?.filter((i: any) => i.severity === 'CRITICAL').length || 0

  return (
    <div className="flex-1 p-8 overflow-y-auto bg-zinc-950 text-zinc-100">
      <h1 className="text-3xl font-bold tracking-tight mb-6">SOC Case Management</h1>
      
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <Card className="bg-zinc-900 border-zinc-800">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-zinc-400">Active Investigations</CardTitle>
            <ShieldAlert className="w-4 h-4 text-emerald-500" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold font-mono">{activeCases}</div>
          </CardContent>
        </Card>
        
        <Card className="bg-zinc-900 border-zinc-800">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-zinc-400">Critical Cases</CardTitle>
            <AlertTriangle className="w-4 h-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold font-mono text-red-500">{criticalCases}</div>
          </CardContent>
        </Card>
        
        <Card className="bg-zinc-900 border-zinc-800">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-zinc-400">Total Cases</CardTitle>
            <Database className="w-4 h-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold font-mono">{investigations?.length || 0}</div>
          </CardContent>
        </Card>
      </div>

      <Card className="bg-zinc-900 border-zinc-800">
        <CardHeader>
          <CardTitle>Recent Investigations</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow className="border-zinc-800">
                <TableHead className="text-zinc-400">Case ID</TableHead>
                <TableHead className="text-zinc-400">Created At</TableHead>
                <TableHead className="text-zinc-400">Title</TableHead>
                <TableHead className="text-zinc-400">Severity</TableHead>
                <TableHead className="text-zinc-400">Status</TableHead>
                <TableHead className="text-zinc-400 text-right">Confidence</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {investigations?.map((inv: any) => (
                <TableRow 
                  key={inv.id} 
                  className="border-zinc-800 hover:bg-zinc-800/50 cursor-pointer"
                  onClick={() => router.push(`/investigations/${inv.id}`)}
                >
                  <TableCell className="font-mono text-xs text-zinc-500">{inv.id.substring(0, 8)}</TableCell>
                  <TableCell className="text-zinc-400 text-sm whitespace-nowrap">{new Date(inv.created_at).toLocaleString()}</TableCell>
                  <TableCell className="font-medium text-zinc-200">{inv.title}</TableCell>
                  <TableCell>
                    <span className={`px-2 py-1 rounded text-xs ${inv.severity === 'CRITICAL' ? 'bg-red-900/30 text-red-500' : 'bg-zinc-800 text-zinc-400'}`}>
                      {inv.severity}
                    </span>
                  </TableCell>
                  <TableCell>
                    <span className={`px-2 py-1 rounded text-xs font-medium ${
                      inv.status === 'WAITING_FOR_REVIEW' ? 'bg-amber-900/30 text-amber-500' : 
                      inv.status === 'ANALYZING' ? 'bg-blue-900/30 text-blue-400' : 
                      'bg-zinc-800 text-zinc-400'
                    }`}>
                      {inv.status}
                    </span>
                  </TableCell>
                  <TableCell className="text-right">
                    {inv.confidence_score ? `${(inv.confidence_score * 100).toFixed(0)}%` : '--'}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  )
}
