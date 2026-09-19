"use client"
import React, { useState } from "react"
import { Shield } from "lucide-react"
import { useAuth } from "@/context/AuthContext"

export function LoginScreen() {
  const { login, error } = useAuth()
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [submitting, setSubmitting] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setSubmitting(true)
    await login(email, password)
    setSubmitting(false)
  }

  return (
    <div className="min-h-screen w-full flex items-center justify-center bg-[#F9FAFB]">
      <div className="w-full max-w-sm bg-white rounded-2xl p-8" style={{ boxShadow: "var(--shadow-card)", border: "1px solid var(--border-default)" }}>
        <div className="flex items-center gap-2 mb-6">
          <div className="w-9 h-9 rounded-xl flex items-center justify-center bg-[var(--accent-light)]">
            <Shield className="w-5 h-5 text-[var(--accent-color)]" />
          </div>
          <div>
            <div className="text-sm font-bold text-[var(--text-primary)]">YAROX</div>
            <div className="text-[11px] text-[var(--text-secondary)]">Sign in to continue</div>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-[var(--text-secondary)] mb-1">Email</label>
            <input
              type="email"
              required
              autoComplete="username"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-3 py-2 rounded-xl border border-[var(--border-default)] text-sm focus:outline-none focus:border-[var(--accent-color)]"
              placeholder="you@company.com"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-[var(--text-secondary)] mb-1">Password</label>
            <input
              type="password"
              required
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-3 py-2 rounded-xl border border-[var(--border-default)] text-sm focus:outline-none focus:border-[var(--accent-color)]"
              placeholder="••••••••"
            />
          </div>

          {error && <div className="text-xs text-red-600 bg-red-50 rounded-lg px-3 py-2">{error}</div>}

          <button
            type="submit"
            disabled={submitting}
            className="w-full py-2.5 rounded-xl text-sm font-semibold bg-[var(--accent-color)] text-white hover:bg-[var(--accent-hover)] transition-colors disabled:opacity-50"
          >
            {submitting ? "Signing in..." : "Sign in"}
          </button>
        </form>
      </div>
    </div>
  )
}
