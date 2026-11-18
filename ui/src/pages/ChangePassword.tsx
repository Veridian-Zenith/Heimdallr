import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useStore } from '../lib/store'
import { motion } from 'framer-motion'
import { KeyRound } from 'lucide-react'

export function ChangePassword() {
  const [currentPassword, setCurrentPassword] = useState('')
  const [newUsername, setNewUsername] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const session = useStore((s) => s.session)
  const setSession = useStore((s) => s.setSession)
  const navigate = useNavigate()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      const res = await fetch('/api/auth/change-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session?.token ?? ''}`,
        },
        body: JSON.stringify({
          current_password: currentPassword,
          new_username: newUsername || undefined,
          new_password: newPassword,
        }),
      })
      if (!res.ok) {
        const body = await res.json().catch(() => ({ error: 'Failed' }))
        throw new Error(body.error)
      }
      if (session) {
        setSession({ ...session, force_password_change: false })
      }
      navigate('/')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-[var(--vz-bg-primary)] noise-overlay grid-bg">
      <motion.div
        initial={{ opacity: 0, scale: 0.97 }}
        animate={{ opacity: 1, scale: 1 }}
        className="glass glow-red w-full max-w-sm rounded-3xl p-8"
      >
        <div className="mb-8 flex flex-col items-center gap-3">
          <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-[var(--vz-accent-vibrant)]/10">
            <KeyRound size={28} className="text-[var(--vz-accent-vibrant)] logo-custom" />
          </div>
          <h1 className="gradient-text text-xl font-bold tracking-tight">Change Password</h1>
          <p className="text-center text-xs text-[var(--vz-text-muted)]">
            You must change your default credentials before continuing.
          </p>
        </div>

        <form onSubmit={handleSubmit} className="flex flex-col gap-3">
          <input
            type="password"
            placeholder="current password"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
            required
            className="w-full rounded-xl border border-[var(--vz-border-color)]/40 bg-[var(--vz-bg-primary)] px-4 py-3 text-sm text-[var(--vz-text-secondary)] placeholder:text-[var(--vz-text-muted)]/40 outline-none transition-all focus:border-[var(--vz-accent-vibrant)]/50 focus:shadow-[0_0_15px_rgba(255,45,45,0.1)]"
          />
          <input
            type="text"
            placeholder="new username (optional)"
            value={newUsername}
            onChange={(e) => setNewUsername(e.target.value)}
            className="w-full rounded-xl border border-[var(--vz-border-color)]/40 bg-[var(--vz-bg-primary)] px-4 py-3 text-sm text-[var(--vz-text-secondary)] placeholder:text-[var(--vz-text-muted)]/40 outline-none transition-all focus:border-[var(--vz-accent-vibrant)]/50"
          />
          <input
            type="password"
            placeholder="new password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            required
            className="w-full rounded-xl border border-[var(--vz-border-color)]/40 bg-[var(--vz-bg-primary)] px-4 py-3 text-sm text-[var(--vz-text-secondary)] placeholder:text-[var(--vz-text-muted)]/40 outline-none transition-all focus:border-[var(--vz-accent-vibrant)]/50"
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
            disabled={loading || !currentPassword || !newPassword}
            className="mt-1 rounded-xl bg-[var(--vz-accent-vibrant)] px-4 py-3 text-sm font-bold text-white transition-all hover:bg-[var(--vz-accent-vibrant)]/80 disabled:opacity-50"
          >
            {loading ? 'Saving...' : 'Change Password'}
          </button>
        </form>
      </motion.div>
    </div>
  )
}
