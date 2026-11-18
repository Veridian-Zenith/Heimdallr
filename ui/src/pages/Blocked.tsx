import { useState, useEffect } from 'react'
import { useStore } from '../lib/store'
import { Shield, ShieldCheck, Plus, Trash2 } from 'lucide-react'

export function Blocked() {
  const session = useStore((s) => s.session)
  const [status, setStatus] = useState<any>(null)
  const [blockedDomain, setBlockedDomain] = useState('')
  const [allowedDomain, setAllowedDomain] = useState('')
  const [manualBlocked, setManualBlocked] = useState<string[]>([])
  const [manualAllowed, setManualAllowed] = useState<string[]>([])

  const headers = session?.token ? { Authorization: `Bearer ${session.token}` } : undefined

  const refresh = async () => {
    try {
      const [sRes, bRes, aRes] = await Promise.all([
        fetch('/api/blocking/status', { headers }),
        fetch('/api/blocking/blocked', { headers }),
        fetch('/api/blocking/allowed', { headers }),
      ])
      if (sRes.ok) setStatus(await sRes.json())
      if (bRes.ok) setManualBlocked(await bRes.json())
      if (aRes.ok) setManualAllowed(await aRes.json())
    } catch (e) { console.error('blocking refresh', e) }
  }

  useEffect(() => { refresh() }, [])

  const addBlocked = async () => {
    if (!blockedDomain.trim()) return
    await fetch('/api/blocking/blocked/add', {
      method: 'POST', headers: { ...headers, 'Content-Type': 'application/json' } as any,
      body: JSON.stringify({ domain: blockedDomain.trim() }),
    })
    setBlockedDomain('')
    refresh()
  }

  const addAllowed = async () => {
    if (!allowedDomain.trim()) return
    await fetch('/api/blocking/allowed/add', {
      method: 'POST', headers: { ...headers, 'Content-Type': 'application/json' } as any,
      body: JSON.stringify({ domain: allowedDomain.trim() }),
    })
    setAllowedDomain('')
    refresh()
  }

  const removeBlocked = async (d: string) => {
    await fetch('/api/blocking/blocked/remove', {
      method: 'POST', headers: { ...headers, 'Content-Type': 'application/json' } as any,
      body: JSON.stringify({ domain: d }),
    })
    refresh()
  }

  const removeAllowed = async (d: string) => {
    await fetch('/api/blocking/allowed/remove', {
      method: 'POST', headers: { ...headers, 'Content-Type': 'application/json' } as any,
      body: JSON.stringify({ domain: d }),
    })
    refresh()
  }

  return (
    <div className="flex flex-col gap-6">
      <h1 className="gradient-text text-2xl font-bold tracking-tight">Blocking</h1>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="glass card-glow rounded-2xl p-5 lg:col-span-2">
          <h2 className="mb-4 text-[10px] font-bold uppercase tracking-widest text-[var(--vz-text-muted)] flex items-center gap-2">
            <Shield size={14} /> Blocked Domains
          </h2>
          <div className="flex gap-2 mb-3">
            <input
              value={blockedDomain}
              onChange={(e) => setBlockedDomain(e.target.value)}
              placeholder="example.com"
              className="flex-1 rounded-xl border border-[var(--vz-border-color)]/40 bg-[var(--vz-bg-primary)] px-3 py-2 text-xs outline-none focus:border-[var(--vz-accent-vibrant)]/50"
              onKeyDown={(e) => e.key === 'Enter' && addBlocked()}
            />
            <button onClick={addBlocked} className="rounded-xl bg-[var(--vz-accent-vibrant)] px-3 py-2 text-xs font-bold text-white hover:bg-[var(--vz-accent-vibrant)]/80"><Plus size={14} /></button>
          </div>
          <div className="flex flex-wrap gap-2 max-h-48 overflow-y-auto scrollbar-hide">
            {manualBlocked.map((d) => (
              <span key={d} className="inline-flex items-center gap-1 rounded-lg bg-[var(--vz-accent-vibrant)]/10 px-2.5 py-1 text-xs text-[var(--vz-text-secondary)]">
                {d}
                <button onClick={() => removeBlocked(d)} className="text-[var(--vz-accent-vibrant)] hover:text-red-400"><Trash2 size={10} /></button>
              </span>
            ))}
            {manualBlocked.length === 0 && <span className="text-xs text-[var(--vz-text-muted)]">No manually blocked domains</span>}
          </div>
        </div>

        <div className="glass card-glow rounded-2xl p-5">
          <h2 className="mb-4 text-[10px] font-bold uppercase tracking-widest text-[var(--vz-text-muted)] flex items-center gap-2">
            <ShieldCheck size={14} /> Allowed Domains
          </h2>
          <div className="flex gap-2 mb-3">
            <input
              value={allowedDomain}
              onChange={(e) => setAllowedDomain(e.target.value)}
              placeholder="example.com"
              className="flex-1 rounded-xl border border-[var(--vz-border-color)]/40 bg-[var(--vz-bg-primary)] px-3 py-2 text-xs outline-none focus:border-[var(--vz-accent-vibrant)]/50"
              onKeyDown={(e) => e.key === 'Enter' && addAllowed()}
            />
            <button onClick={addAllowed} className="rounded-xl bg-[var(--vz-accent-vibrant)]/10 px-3 py-2 text-xs font-bold text-[var(--vz-accent-vibrant)] hover:bg-[var(--vz-accent-vibrant)]/20"><Plus size={14} /></button>
          </div>
          <div className="flex flex-wrap gap-2 max-h-48 overflow-y-auto scrollbar-hide">
            {manualAllowed.map((d) => (
              <span key={d} className="inline-flex items-center gap-1 rounded-lg bg-[var(--vz-accent-vibrant)]/10 px-2.5 py-1 text-xs text-[var(--vz-text-secondary)]">
                {d}
                <button onClick={() => removeAllowed(d)} className="text-[var(--vz-accent-vibrant)] hover:text-red-400"><Trash2 size={10} /></button>
              </span>
            ))}
            {manualAllowed.length === 0 && <span className="text-xs text-[var(--vz-text-muted)]">No manually allowed domains</span>}
          </div>
        </div>
      </div>

      <div className="glass card-glow rounded-2xl p-5">
        <h2 className="mb-3 text-[10px] font-bold uppercase tracking-widest text-[var(--vz-text-muted)]">Blocking Status</h2>
        <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
          {[
            ['Blocking Enabled', status?.enabled ? 'Yes' : 'No'],
            ['CNAME Cloaking', status?.cname_cloaking ? 'Yes' : 'No'],
            ['DNS Rebinding', status?.rebinding ? 'Yes' : 'No'],
            ['Blocklist Entries', String(status?.blocklist_entries ?? 0)],
          ].map(([label, value]) => (
            <div key={label} className="rounded-xl bg-[var(--vz-bg-primary)]/60 px-4 py-3">
              <div className="text-[10px] text-[var(--vz-text-muted)] mb-1">{label}</div>
              <div className="text-lg font-bold text-[var(--vz-text-secondary)]">{value}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
