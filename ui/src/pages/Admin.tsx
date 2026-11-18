import { useState, useEffect } from 'react'
import { useStore } from '../lib/store'
import { UserPlus, KeyRound, Shield } from 'lucide-react'

export function Admin() {
  const session = useStore((s) => s.session)
  const [users, setUsers] = useState<any[]>([])
  const [tokens, setTokens] = useState<any[]>([])
  const [newUser, setNewUser] = useState('')

  const headers = session?.token ? { Authorization: `Bearer ${session.token}` } : undefined

  const refresh = async () => {
    try {
      const [uRes, tRes] = await Promise.all([
        fetch('/api/admin/users', { headers }),
        fetch('/api/admin/tokens', { headers }),
      ])
      if (uRes.ok) { const d = await uRes.json(); setUsers(d.users || []) }
      if (tRes.ok) { const d = await tRes.json(); setTokens(d.tokens || []) }
    } catch (e) { console.error('admin refresh', e) }
  }

  useEffect(() => { refresh() }, [])

  const createUser = async () => {
    if (!newUser.trim()) return
    await fetch('/api/admin/users', {
      method: 'POST',
      headers: { ...headers, 'Content-Type': 'application/json' } as any,
      body: JSON.stringify({ username: newUser.trim(), password: 'changeme', roles: ['dns_reader'] }),
    })
    setNewUser('')
    refresh()
  }

  return (
    <div className="flex flex-col gap-6">
      <h1 className="gradient-text text-2xl font-bold tracking-tight">Administration</h1>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="glass card-glow rounded-2xl p-5">
          <h2 className="mb-3 text-[10px] font-bold uppercase tracking-widest text-[var(--vz-text-muted)] flex items-center gap-2">
            <UserPlus size={14} /> Users
          </h2>
          <div className="flex gap-2 mb-3">
            <input
              value={newUser}
              onChange={(e) => setNewUser(e.target.value)}
              placeholder="New username"
              className="flex-1 rounded-xl border border-[var(--vz-border-color)]/40 bg-[var(--vz-bg-primary)] px-3 py-2 text-xs outline-none focus:border-[var(--vz-accent-vibrant)]/50"
              onKeyDown={(e) => e.key === 'Enter' && createUser()}
            />
            <button onClick={createUser} className="rounded-xl bg-[var(--vz-accent-vibrant)] px-3 py-2 text-xs font-bold text-white hover:bg-[var(--vz-accent-vibrant)]/80">Add</button>
          </div>
          <div className="flex flex-col gap-1">
            {users.map((u: any) => (
              <div key={u.name} className="flex items-center justify-between rounded-xl px-3 py-2 text-xs hover:bg-[var(--vz-surface-glass)]">
                <div className="flex items-center gap-2">
                  <Shield size={12} className="text-[var(--vz-accent-vibrant)]" />
                  <span className="font-medium text-[var(--vz-text-secondary)]">{u.name}</span>
                </div>
                <span className="text-[var(--vz-text-muted)]">{u.roles?.join(', ') || 'dns_reader'} {u.totp_enabled ? '(2FA)' : ''}</span>
              </div>
            ))}
            {users.length === 0 && <span className="text-xs text-[var(--vz-text-muted)]">No users</span>}
          </div>
        </div>

        <div className="glass card-glow rounded-2xl p-5">
          <h2 className="mb-3 text-[10px] font-bold uppercase tracking-widest text-[var(--vz-text-muted)] flex items-center gap-2">
            <KeyRound size={14} /> API Tokens
          </h2>
          <div className="flex flex-col gap-1">
            {tokens.map((t: any) => (
              <div key={t.name} className="flex items-center justify-between rounded-xl px-3 py-2 text-xs hover:bg-[var(--vz-surface-glass)]">
                <span className="font-medium text-[var(--vz-text-secondary)]">{t.name}</span>
                <span className="text-[var(--vz-text-muted)]">{t.roles?.join(', ') || 'dns_reader'}</span>
              </div>
            ))}
            {tokens.length === 0 && <span className="text-xs text-[var(--vz-text-muted)]">No tokens</span>}
          </div>
        </div>
      </div>
    </div>
  )
}
