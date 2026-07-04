"use client"

import { useQuery } from "@tanstack/react-query"
import { api } from "@/lib/api"
import { useState } from "react"
import { format } from "date-fns"
import { Badge } from "@/components/ui/badge"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"

export default function EventsPage() {
  const [page, setPage] = useState(0)
  const limit = 50

  const { data: events, isLoading } = useQuery({
    queryKey: ['events', page],
    queryFn: async () => {
      const { data } = await api.get(`/events?limit=${limit}&offset=${page * limit}`)
      return data
    },
    refetchInterval: 2000
  })

  const getSeverityColor = (severity: string) => {
    switch (severity.toUpperCase()) {
      case 'CRITICAL': return 'bg-red-900 text-red-100'
      case 'HIGH': return 'bg-orange-900 text-orange-100'
      case 'MEDIUM': return 'bg-yellow-900 text-yellow-100'
      case 'LOW': return 'bg-blue-900 text-blue-100'
      default: return 'bg-zinc-800 text-zinc-300'
    }
  }

  return (
    <div className="flex-1 p-8 flex flex-col h-full overflow-hidden">
      <div className="flex justify-between items-center mb-6 shrink-0">
        <h1 className="text-3xl font-bold">Event Viewer</h1>
        <div className="flex gap-2">
          <button 
            disabled={page === 0}
            onClick={() => setPage(p => Math.max(0, p - 1))}
            className="px-4 py-2 bg-zinc-800 rounded hover:bg-zinc-700 disabled:opacity-50 text-sm"
          >
            Previous
          </button>
          <button 
            onClick={() => setPage(p => p + 1)}
            className="px-4 py-2 bg-zinc-800 rounded hover:bg-zinc-700 text-sm"
          >
            Next
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-auto border border-zinc-800 rounded-md bg-zinc-900/50">
        <Table>
          <TableHeader className="sticky top-0 bg-zinc-950 z-10 shadow-sm">
            <TableRow className="border-zinc-800 hover:bg-transparent">
              <TableHead className="w-[180px]">Time</TableHead>
              <TableHead>Severity</TableHead>
              <TableHead>Event Type</TableHead>
              <TableHead>Host</TableHead>
              <TableHead>User</TableHead>
              <TableHead>Source</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={6} className="text-center h-24">Loading events...</TableCell>
              </TableRow>
            ) : events?.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="text-center h-24">No events found.</TableCell>
              </TableRow>
            ) : (
              events?.map((event: any) => (
                <TableRow key={event.id} className="border-zinc-800/50 hover:bg-zinc-800/50 cursor-pointer">
                  <TableCell className="font-mono text-xs text-zinc-400">
                    {format(new Date(event.timestamp), 'yyyy-MM-dd HH:mm:ss')}
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className={`border-0 ${getSeverityColor(event.severity)}`}>
                      {event.severity}
                    </Badge>
                  </TableCell>
                  <TableCell className="font-medium text-sm">{event.event_type}</TableCell>
                  <TableCell className="text-sm text-zinc-300">{event.hostname}</TableCell>
                  <TableCell className="text-sm text-zinc-300">{event.user_name}</TableCell>
                  <TableCell className="text-xs text-zinc-500">{event.source}</TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  )
}
