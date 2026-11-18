import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { useStore, type AuthSession } from '../lib/store'
import { motion } from 'framer-motion'
import { Shield } from 'lucide-react'

export function Login() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [totpCode, setTotpCode] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const setSession = useStore((s) => s.setSession)
  const navigate = useNavigate()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, totp_code: totpCode || undefined }),
      })
      if (!res.ok) {
        const body = await res.json().catch(() => ({ error: 'Login failed' }))
        throw new Error(body.error)
      }
      const data: AuthSession = await res.json()
      setSession(data)
      navigate(data.force_password_change ? '/change-password' : '/')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-[var(--vz-bg-primary)] noise-overlay grid-bg">
      <motion.div
        initial={{ opacity: 0, scale: 0.97 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.3 }}
        className="glass glow-red w-full max-w-sm rounded-3xl p-8"
      >
        {/* Logo */}
        <div className="mb-8 flex flex-col items-center gap-3">
          <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-[var(--vz-accent-vibrant)]/10">
            <Shield size={28} className="text-[var(--vz-accent-vibrant)] logo-custom" />
          </div>
          <h1 className="gradient-text text-xl font-bold tracking-tight">Heimdallr</h1>
          <p className="text-xs text-[var(--vz-text-muted)]">DNS Server Console</p>
        </div>

        <form onSubmit={handleSubmit} className="flex flex-col gap-3">
          <input
            type="text"
            placeholder="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            className="w-full rounded-xl border border-[var(--vz-border-color)]/40 bg-[var(--vz-bg-primary)] px-4 py-3 text-sm text-[var(--vz-text-secondary)] placeholder:text-[var(--vz-text-muted)]/40 outline-none transition-all focus:border-[var(--vz-accent-vibrant)]/50 focus:shadow-[0_0_15px_rgba(255,45,45,0.1)]"
          />
          <input
            type="password"
            placeholder="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            className="w-full rounded-xl border border-[var(--vz-border-color)]/40 bg-[var(--vz-bg-primary)] px-4 py-3 text-sm text-[var(--vz-text-secondary)] placeholder:text-[var(--vz-text-muted)]/40 outline-none transition-all focus:border-[var(--vz-accent-vibrant)]/50 focus:shadow-[0_0_15px_rgba(255,45,45,0.1)]"
          />
          <input
            type="text"
            placeholder="totp code (optional)"
            value={totpCode}
            onChange={(e) => setTotpCode(e.target.value)}
            className="w-full rounded-xl border border-[var(--vz-border-color)]/40 bg-[var(--vz-bg-primary)] px-4 py-3 text-sm text-[var(--vz-text-secondary)] placeholder:text-[var(--vz-text-muted)]/40 outline-none transition-all focus:border-[var(--vz-accent-vibrant)]/50 focus:shadow-[0_0_15px_rgba(255,45,45,0.1)]"
          />

          {error && (
            <motion.p
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="rounded-xl bg-[var(--vz-accent-vibrant)]/10 px-3 py-2 text-xs text-[var(--vz-accent-vibrant)]"
            >
              {error}
            </motion.p>
          )}

          <button
            type="submit"
            disabled={loading}
            className="relative mt-1 overflow-hidden rounded-xl bg-[var(--vz-accent-vibrant)] px-4 py-3 text-sm font-bold text-white transition-all hover:bg-[var(--vz-accent-vibrant)]/80 disabled:opacity-50"
          >
            <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/10 to-transparent -translate-x-full hover:animate-shimmer pointer-events-none" />
            <span className="relative z-10">{loading ? 'Signing in...' : 'Sign in'}</span>
          </button>
        </form>

        <p className="mt-6 text-center text-[10px] text-[var(--vz-text-muted)]">
          Don't have an account?{' '}
          <Link
            to="/register"
            className="text-[var(--vz-accent-vibrant)] transition-colors hover:text-[var(--vz-accent-vibrant)]/80"
          >
            Register
          </Link>
        </p>
      </motion.div>
    </div>
  )
}
