import { useEffect, useState } from 'react'
import { useStore } from '../lib/store'
import { motion } from 'framer-motion'
import { Database, Trash2, RefreshCcw } from 'lucide-react'

export function Cache() {
  const session = useStore((s) => s.session)
  const [stats, setStats] = useState({ entries: 0, max_size: 50000, hits: 0, misses: 0 })
  const [loading, setLoading] = useState(false)

  const fetchStats = async () => {
    setLoading(true)
    try {
      const res = await fetch('/api/cache/stats', {
        headers: session?.token ? { Authorization: `Bearer ${session.token}` } : {},
      })
      if (res.ok) setStats(await res.json())
    } catch (e) {
      console.error('cache stats', e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchStats() }, [])

  const flush = async () => {
    if (!confirm('Flush entire cache?')) return
    await fetch('/api/cache/flush', {
      method: 'POST',
      headers: session?.token ? {
        Authorization: `Bearer ${session.token}`,
        'Content-Type': 'application/json',
      } : {},
    })
    fetchStats()
  }

  return (
    <div className="flex flex-col gap-6">
      <h1 className="gradient-text text-2xl font-bold tracking-tight">Cache</h1>
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {[
          ['Entries', stats.entries.toString(), 'database' as const],
          ['Hits', stats.hits.toString(), 'refresh' as const],
          ['Misses', stats.misses.toString(), 'trash' as const],
        ].map(([label, value, iconName]) => (
          <motion.div
            key={label}
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            className="glass card-glow rounded-2xl p-5"
          >
            <div className="flex items-center gap-3 mb-2">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-[var(--vz-accent-vibrant)]/10">
                {iconName === 'database' && <Database size={20} className="text-[var(--vz-accent-vibrant)]" />}
                {iconName === 'refresh' && <RefreshCcw size={20} className="text-[var(--vz-accent-vibrant)]" />}
                {iconName === 'trash' && <Trash2 size={20} className="text-[var(--vz-accent-vibrant)]" />}
              </div>
              <span className="text-[10px] font-bold uppercase tracking-widest text-[var(--vz-text-muted)]">{label}</span>
            </div>
            <div className="text-3xl font-bold text-[var(--vz-text-secondary)]">{value}</div>
          </motion.div>
        ))}
      </div>
      <div className="glass card-glow rounded-2xl p-5 flex items-center justify-between">
        <div>
          <h3 className="text-sm font-bold text-[var(--vz-text-secondary)]">Cache Capacity</h3>
          <p className="text-xs text-[var(--vz-text-muted)]">{stats.entries} / {stats.max_size} entries used</p>
        </div>
        <button
          onClick={flush}
          disabled={loading}
          className="rounded-xl bg-[var(--vz-accent-vibrant)]/10 px-4 py-2 text-sm font-bold text-[var(--vz-accent-vibrant)] hover:bg-[var(--vz-accent-vibrant)]/20 transition-all"
        >
          Flush Cache
        </button>
      </div>
    </div>
  )
}
