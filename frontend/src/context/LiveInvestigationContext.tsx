"use client"
import React, { createContext, useContext, useEffect, useState, ReactNode } from "react"

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

        // The browser sends the httpOnly session cookie automatically on the WebSocket
        // handshake (see backend/websocket/investigation_ws.py); no token is read from
        // or passed through JavaScript.
        const ws = new WebSocket(`ws://localhost:8000/ws/investigations?case_id=${caseId}`);

        ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data)
                if (data.investigation_id === caseId || data.case_id === caseId) {
                    setWsEvents((prev) => [...prev, data])
                }
            } catch (err) {}
        }

        return () => {
            ws.close();
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
