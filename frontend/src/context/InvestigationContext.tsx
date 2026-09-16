"use client"
import React, { createContext, useContext, useState, ReactNode } from "react"
import { useQuery } from "@tanstack/react-query"
import { api } from "@/lib/api"

interface InvestigationContextType {
    caseId: string;
    caseData: any;
    isLoading: boolean;
    refetch: () => void;
    selectedExecutionId: string | null;
    setSelectedExecutionId: (id: string | null) => void;
}

const InvContext = createContext<InvestigationContextType | undefined>(undefined);

export const InvestigationProvider = ({ caseId, children }: { caseId: string, children: ReactNode }) => {
    const [selectedExecutionId, setSelectedExecutionId] = useState<string | null>(null)

    const { data: caseData, isLoading, refetch } = useQuery({
        queryKey: ["investigation", caseId],
        queryFn: async () => {
            const { data } = await api.get(`/investigations/${caseId}`)
            return data
        },
        refetchInterval: (query) =>
            query.state.data?.status === "ANALYZING" ? 2000 : false,
    })

    return (
        <InvContext.Provider value={{
            caseId,
            caseData,
            isLoading,
            refetch,
            selectedExecutionId,
            setSelectedExecutionId
        }}>
            {children}
        </InvContext.Provider>
    )
}

export const useInvestigation = () => {
    const ctx = useContext(InvContext)
    if (!ctx) throw new Error("useInvestigation must be used within InvestigationProvider")
    return ctx;
}
