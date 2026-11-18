import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { Shield, Copy, Check } from 'lucide-react'
import type { ChallengeResponse } from '../lib/store'

type Step = 'challenge' | 'verify' | 'register'

export function Register() {
  const [step, setStep] = useState<Step>('challenge')
  const [challenge, setChallenge] = useState<ChallengeResponse | null>(null)
  const [answer, setAnswer] = useState('')
  const [verificationToken, setVerificationToken] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [copied, setCopied] = useState(false)
  const navigate = useNavigate()

  const fetchChallenge = async () => {
    setLoading(true)
    setError('')
    try {
      const res = await fetch('/api/auth/challenge')
      const data: ChallengeResponse = await res.json()
      setChallenge(data)
      setStep('verify')
    } catch {
      setError('Failed to generate challenge')
    } finally {
      setLoading(false)
    }
  }

  const submitAnswer = async () => {
    setLoading(true)
    setError('')
    try {
      const res = await fetch('/api/auth/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ challenge_id: challenge!.challenge_id, answer: answer.trim() }),
      })
      if (!res.ok) {
        const body = await res.json().catch(() => ({ error: 'Verification failed' }))
        throw new Error(body.error)
      }
      const data = await res.json()
      setVerificationToken(data.verification_token)
      setStep('register')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Verification failed')
    } finally {
      setLoading(false)
    }
  }

  const doRegister = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          verification_token: verificationToken,
          username,
          password,
        }),
      })
      if (!res.ok) {
        const body = await res.json().catch(() => ({ error: 'Registration failed' }))
        throw new Error(body.error)
      }
      navigate('/login')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Registration failed')
    } finally {
      setLoading(false)
    }
  }

  const copyCommand = () => {
    if (challenge) {
      navigator.clipboard.writeText(challenge.command)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-[var(--vz-bg-primary)] noise-overlay grid-bg">
      <motion.div
        initial={{ opacity: 0, scale: 0.97 }}
        animate={{ opacity: 1, scale: 1 }}
        className="glass glow-red w-full max-w-md rounded-3xl p-8"
      >
        <div className="mb-8 flex flex-col items-center gap-3">
          <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-[var(--vz-accent-vibrant)]/10">
            <Shield size={28} className="text-[var(--vz-accent-vibrant)] logo-custom" />
          </div>
          <h1 className="gradient-text text-xl font-bold tracking-tight">Create Account</h1>
          <p className="text-center text-xs text-[var(--vz-text-muted)]">
            {step === 'challenge' && 'Human verification required to prevent automated sign-ups'}
            {step === 'verify' && 'Run the command below and paste the first 16 hex characters'}
            {step === 'register' && 'Choose your credentials'}
          </p>
        </div>

        {step === 'challenge' && (
          <div className="flex flex-col gap-4">
            <button
              onClick={fetchChallenge}
              disabled={loading}
              className="relative overflow-hidden rounded-xl bg-[var(--vz-accent-vibrant)] px-4 py-3 text-sm font-bold text-white transition-all hover:bg-[var(--vz-accent-vibrant)]/80 disabled:opacity-50"
            >
              {loading ? 'Generating...' : 'Start Verification'}
            </button>
          </div>
        )}

        {step === 'verify' && challenge && (
          <div className="flex flex-col gap-4">
            <div className="rounded-xl bg-[var(--vz-bg-primary)] border border-[var(--vz-border-color)]/30 p-4">
              <p className="mb-2 text-[10px] uppercase tracking-widest text-[var(--vz-text-muted)]">
                Run this command
              </p>
              <div className="flex items-center gap-2">
                <code className="flex-1 overflow-x-auto text-xs text-[var(--vz-accent-vibrant)]">
                  {challenge.command}
                </code>
                <button
                  onClick={copyCommand}
                  className="shrink-0 rounded-lg p-1.5 text-[var(--vz-text-muted)] hover:text-[var(--vz-accent-vibrant)]"
                >
                  {copied ? <Check size={12} /> : <Copy size={12} />}
                </button>
              </div>
            </div>
            <input
              type="text"
              placeholder="paste first 16 hex characters"
              value={answer}
              onChange={(e) => setAnswer(e.target.value)}
              className="w-full rounded-xl border border-[var(--vz-border-color)]/40 bg-[var(--vz-bg-primary)] px-4 py-3 font-mono text-sm text-[var(--vz-text-secondary)] placeholder:text-[var(--vz-text-muted)]/40 outline-none transition-all focus:border-[var(--vz-accent-vibrant)]/50 focus:shadow-[0_0_15px_rgba(255,45,45,0.1)]"
            />
            {error && (
              <p className="rounded-xl bg-[var(--vz-accent-vibrant)]/10 px-3 py-2 text-xs text-[var(--vz-accent-vibrant)]">
                {error}
              </p>
            )}
            <button
              onClick={submitAnswer}
              disabled={loading || answer.length < 16}
              className="rounded-xl bg-[var(--vz-accent-vibrant)] px-4 py-3 text-sm font-bold text-white transition-all hover:bg-[var(--vz-accent-vibrant)]/80 disabled:opacity-50"
            >
              {loading ? 'Verifying...' : 'Verify'}
            </button>
          </div>
        )}

        {step === 'register' && (
          <form onSubmit={doRegister} className="flex flex-col gap-3">
            <input
              type="text"
              placeholder="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              className="w-full rounded-xl border border-[var(--vz-border-color)]/40 bg-[var(--vz-bg-primary)] px-4 py-3 text-sm text-[var(--vz-text-secondary)] placeholder:text-[var(--vz-text-muted)]/40 outline-none transition-all focus:border-[var(--vz-accent-vibrant)]/50"
            />
            <input
              type="password"
              placeholder="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="w-full rounded-xl border border-[var(--vz-border-color)]/40 bg-[var(--vz-bg-primary)] px-4 py-3 text-sm text-[var(--vz-text-secondary)] placeholder:text-[var(--vz-text-muted)]/40 outline-none transition-all focus:border-[var(--vz-accent-vibrant)]/50"
            />
            {error && (
              <p className="rounded-xl bg-[var(--vz-accent-vibrant)]/10 px-3 py-2 text-xs text-[var(--vz-accent-vibrant)]">
                {error}
              </p>
            )}
            <button
              type="submit"
              disabled={loading}
              className="rounded-xl bg-[var(--vz-accent-vibrant)] px-4 py-3 text-sm font-bold text-white transition-all hover:bg-[var(--vz-accent-vibrant)]/80 disabled:opacity-50"
            >
              {loading ? 'Creating...' : 'Create Account'}
            </button>
          </form>
        )}

        <p className="mt-6 text-center text-[10px] text-[var(--vz-text-muted)]">
          Already have an account?{' '}
          <Link
            to="/login"
            className="text-[var(--vz-accent-vibrant)] transition-colors hover:text-[var(--vz-accent-vibrant)]/80"
          >
            Sign in
          </Link>
        </p>
      </motion.div>
    </div>
  )
}
