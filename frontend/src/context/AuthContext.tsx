"use client"
import React, { createContext, useContext, useEffect, useState, ReactNode, useCallback } from "react"
import { api } from "@/lib/api"

export interface CurrentUser {
  id: string
  email: string
  full_name?: string | null
  role: "ADMIN" | "ANALYST" | "VIEWER"
}

interface AuthContextType {
  user: CurrentUser | null
  isLoading: boolean
  error: string | null
  login: (email: string, password: string) => Promise<boolean>
  logout: () => Promise<void>
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export const AuthProvider = ({ children }: { children: ReactNode }) => {
  const [user, setUser] = useState<CurrentUser | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const refresh = useCallback(async () => {
    try {
      const { data } = await api.get("/auth/me")
      setUser(data)
    } catch {
      setUser(null)
    } finally {
      setIsLoading(false)
    }
  }, [])

  useEffect(() => {
    refresh()
  }, [refresh])

  const login = async (email: string, password: string) => {
    setError(null)
    try {
      const { data } = await api.post("/auth/login", { email, password })
      setUser({ id: data.user_id, email: data.email, full_name: data.full_name, role: data.role })
      return true
    } catch (err: any) {
      setError(err?.response?.data?.detail || "Login failed. Check your credentials.")
      return false
    }
  }

  const logout = async () => {
    try {
      await api.post("/auth/logout")
    } finally {
      setUser(null)
    }
  }

  return (
    <AuthContext.Provider value={{ user, isLoading, error, login, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = () => {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error("useAuth must be used within AuthProvider")
  return ctx
}
