"use client"

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useState } from 'react'
import { AuthProvider, useAuth } from '@/context/AuthContext'
import { LoginScreen } from '@/components/LoginScreen'

function AuthGate({ children }: { children: React.ReactNode }) {
  const { user, isLoading } = useAuth()

  if (isLoading) {
    return (
      <div className="min-h-screen w-full flex items-center justify-center bg-[#F9FAFB]">
        <div className="w-5 h-5 border-2 border-[var(--accent-color)] border-t-transparent rounded-full animate-spin" />
      </div>
    )
  }

  if (!user) {
    return <LoginScreen />
  }

  return <>{children}</>
}

export default function Providers({ children }: { children: React.ReactNode }) {
  const [queryClient] = useState(() => new QueryClient())

  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <AuthGate>{children}</AuthGate>
      </AuthProvider>
    </QueryClientProvider>
  )
}
