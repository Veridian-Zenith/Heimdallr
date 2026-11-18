import { useState } from 'react'
import { useStore } from '../lib/store'
import { motion } from 'framer-motion'
import { Search } from 'lucide-react'

export function DNSClient() {
  const session = useStore((s) => s.session)
  const [name, setName] = useState('')
  const [server, setServer] = useState('1.1.1.1')
  const [rtype, setRtype] = useState('A')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<any>(null)

  const lookup = async () => {
    setLoading(true)
    setResult(null)
    try {
      const res = await fetch('/api/dns/lookup', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(session?.token ? { Authorization: `Bearer ${session.token}` } : {}),
        },
        body: JSON.stringify({ server, name, rtype }),
      })
      if (res.ok) setResult(await res.json())
      else setResult({ error: await res.text() })
    } catch (e) {
      setResult({ error: String(e) })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <h1 className="gradient-text text-2xl font-bold tracking-tight">DNS Client</h1>
      <div className="glass card-glow rounded-2xl p-5">
        <div className="flex flex-wrap gap-2 mb-4">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Query name (e.g. example.com)"
            className="flex-1 min-w-[240px] rounded-xl border border-[var(--vz-border-color)]/40 bg-[var(--vz-bg-primary)] px-4 py-2.5 text-sm text-[var(--vz-text-secondary)] placeholder:text-[var(--vz-text-muted)]/40 outline-none focus:border-[var(--vz-accent-vibrant)]/50"
          />
          <input
            value={server}
            onChange={(e) => setServer(e.target.value)}
            placeholder="Server (e.g. 1.1.1.1)"
            className="w-48 rounded-xl border border-[var(--vz-border-color)]/40 bg-[var(--vz-bg-primary)] px-4 py-2.5 text-sm text-[var(--vz-text-secondary)] placeholder:text-[var(--vz-text-muted)]/40 outline-none focus:border-[var(--vz-accent-vibrant)]/50"
          />
          <select
            value={rtype}
            onChange={(e) => setRtype(e.target.value)}
            className="rounded-xl border border-[var(--vz-border-color)]/40 bg-[var(--vz-bg-primary)] px-4 py-2.5 text-sm text-[var(--vz-text-secondary)] outline-none focus:border-[var(--vz-accent-vibrant)]/50"
          >
            {['A','AAAA','CNAME','MX','NS','SOA','TXT','SRV','PTR','HTTPS'].map(t => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
          <button
            onClick={lookup}
            disabled={loading || !name.trim()}
            className="rounded-xl bg-[var(--vz-accent-vibrant)] px-5 py-2.5 text-sm font-bold text-white transition-all hover:bg-[var(--vz-accent-vibrant)]/80 disabled:opacity-50 flex items-center gap-2"
          >
            <Search size={16} /> Lookup
          </button>
        </div>
        {loading && <div className="text-xs text-[var(--vz-text-muted)]">Querying...</div>}
        {result && (
          <motion.div initial={{ opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }} className="mt-3 rounded-xl bg-[var(--vz-bg-primary)]/40 p-4 text-xs text-[var(--vz-text-secondary)]">
            <div className="font-bold mb-2">{result.name} — {result.status}</div>
            <div className="text-[var(--vz-text-muted)] mb-2">Latency: {result.latency_ms ?? 0}ms</div>
            {result.error ? (
              <div className="text-[var(--vz-accent-vibrant)]">{result.error}</div>
            ) : (
              <div className="flex flex-col gap-1">
                {result.answers?.map((a: any, i: number) => (
                  <div key={i} className="font-mono text-[10px] leading-relaxed">
                    <span className="text-[var(--vz-accent-vibrant)]">{a.rtype}</span>
                    <span className="text-[var(--vz-text-muted)] mx-1">|</span>
                    <span>{a.data}</span>
                    <span className="text-[var(--vz-text-muted)] ml-2">TTL: {a.ttl}</span>
                  </div>
                ))}
                {!result.answers?.length && <span className="text-[var(--vz-text-muted)]">No records</span>}
              </div>
            )}
          </motion.div>
        )}
      </div>
    </div>
  )
}
