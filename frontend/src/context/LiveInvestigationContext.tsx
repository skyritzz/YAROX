"use client"
import React, { createContext, useContext, useEffect, useState, ReactNode } from "react"
import { getAuthToken } from "@/lib/api"

export interface InvestigationEvent {
    event_id: string;
    investigation_id: string;
    execution_id: string;
    timestamp: string;
    agent_name: string;
    event_type: string;
    step_type: string;
    payload: any;
    confidence?: number;
    evidence_ids?: string[];
    tool_call_id?: string;
}

interface LiveContextType {
    wsEvents: InvestigationEvent[];
}

const LiveContext = createContext<LiveContextType | undefined>(undefined);

export const LiveInvestigationProvider = ({ caseId, children }: { caseId: string, children: ReactNode }) => {
    const [wsEvents, setWsEvents] = useState<InvestigationEvent[]>([])

    useEffect(() => {
        if (!caseId) return;
        let ws: WebSocket | null = null;
        let isCancelled = false;

        async function initWs() {
            const token = await getAuthToken();
            if (isCancelled) return;
            
            const tokenParam = token ? `&token=${encodeURIComponent(token)}` : '';
            ws = new WebSocket(`ws://localhost:8000/ws/investigations?case_id=${caseId}${tokenParam}`);
            
            ws.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data)
                    if (data.investigation_id === caseId || data.case_id === caseId) {
                        setWsEvents((prev) => [...prev, data])
                    }
                } catch (err) {}
            }
        }

        initWs();

        return () => {
            isCancelled = true;
            if (ws) ws.close();
        }
    }, [caseId])

    return (
        <LiveContext.Provider value={{ wsEvents }}>
            {children}
        </LiveContext.Provider>
    )
}

export const useLiveEvents = () => {
    const ctx = useContext(LiveContext)
    if (!ctx) throw new Error("useLiveEvents must be used within LiveInvestigationProvider")
    return ctx.wsEvents;
}
