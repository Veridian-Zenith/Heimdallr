import { useEffect } from 'react'
import { useStore } from '../lib/store'
import { motion } from 'framer-motion'
import {
  Server,
  Globe,
  Shield,
  HardDrive,
  Activity,
  Clock,
  Wifi,
  Database,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'

const card = (i: number) => ({
  initial: { opacity: 0, y: 8 },
  animate: { opacity: 1, y: 0 },
  transition: { delay: i * 0.06, duration: 0.3, ease: 'easeOut' as const },
})

function StatCard({
  icon: Icon,
  label,
  value,
  accent,
  index,
}: {
  icon: LucideIcon
  label: string
  value: string | number
  accent?: boolean
  index: number
}) {
  return (
    <motion.div
      {...card(index)}
      className="glass card-glow group rounded-2xl p-5"
    >
      <div className="mb-3 flex items-center gap-3">
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-[var(--vz-accent-vibrant)]/8">
          <Icon
            size={18}
            className={accent ? 'text-[var(--vz-accent-vibrant)]' : 'text-[var(--vz-text-muted)]'}
          />
        </div>
        <span className="text-[10px] font-bold uppercase tracking-widest text-[var(--vz-text-muted)]">
          {label}
        </span>
      </div>
      <p
        className="text-2xl font-bold tracking-tight"
        style={{ color: accent ? 'var(--vz-accent-vibrant)' : 'var(--vz-text-secondary)' }}
      >
        {value}
      </p>
    </motion.div>
  )
}

function InfoRow({ label, value }: { label: string; value: string | number | undefined }) {
  return (
    <div className="flex items-center justify-between py-2 border-b border-[var(--vz-border-color)]/30 last:border-0">
      <span className="text-xs text-[var(--vz-text-muted)]">{label}</span>
      <span className="text-xs font-medium text-[var(--vz-text-secondary)]">{value ?? '...'}</span>
    </div>
  )
}

export function Dashboard() {
  const info = useStore((s) => s.serverInfo)
  const zones = useStore((s) => s.zones)
  const filterStats = useStore((s) => s.filterStats)
  const fetchServerInfo = useStore((s) => s.fetchServerInfo)
  const fetchZones = useStore((s) => s.fetchZones)
  const fetchFilterStats = useStore((s) => s.fetchFilterStats)

  useEffect(() => {
    fetchServerInfo()
    fetchZones()
    fetchFilterStats()
  }, [fetchServerInfo, fetchZones, fetchFilterStats])

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="gradient-text text-2xl font-bold tracking-tight">
          Dashboard
        </h1>
        <div className="flex items-center gap-2 text-[10px] text-[var(--vz-text-muted)]">
          <span className="h-1.5 w-1.5 rounded-full bg-[var(--vz-accent-vibrant)] animate-pulse-glow" />
          LIVE
        </div>
      </div>

      {/* Stats grid */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard icon={Server} label="Version" value={info?.version ?? '...'} accent index={0} />
        <StatCard icon={Globe} label="Zones" value={zones.length} index={1} />
        <StatCard icon={Shield} label="DNSSEC" value={info?.dnssec_validation ? 'Active' : 'Off'} accent={info?.dnssec_validation} index={2} />
        <StatCard icon={HardDrive} label="Cache" value={info?.cache_size ? `${(info.cache_size / 1000).toFixed(0)}K` : '...'} index={3} />
      </div>

      {/* Second row */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard icon={Activity} label="Blocklist" value={filterStats?.blocklist_entries ?? 0} index={4} />
        <StatCard icon={Database} label="Regex Rules" value={filterStats?.regex_patterns ?? 0} index={5} />
        <StatCard icon={Wifi} label="Listeners" value={info?.dns_listen?.length ?? 0} index={6} />
        <StatCard icon={Clock} label="Log Level" value={info?.log_level ?? '...'} index={7} />
      </div>

      {/* Info panels */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <motion.div {...card(8)} className="glass card-glow rounded-2xl p-5">
          <h2 className="mb-4 gradient-text text-sm font-bold uppercase tracking-widest">
            Server
          </h2>
          <div className="flex flex-col">
            <InfoRow label="Hostname" value={info?.hostname} />
            <InfoRow label="DNS Listen" value={info?.dns_listen?.join(', ')} />
            <InfoRow label="API Listen" value={info?.api_listen} />
            <InfoRow label="Version" value={info?.version} />
          </div>
        </motion.div>

        <motion.div {...card(9)} className="glass card-glow rounded-2xl p-5">
          <h2 className="mb-4 gradient-text text-sm font-bold uppercase tracking-widest">
            Filtering
          </h2>
          <div className="flex flex-col">
            <InfoRow label="Blocklist Entries" value={filterStats?.blocklist_entries} />
            <InfoRow label="Regex Patterns" value={filterStats?.regex_patterns} />
            <InfoRow
              label="CNAME Cloaking"
              value={filterStats?.cname_cloaking ? 'Enabled' : 'Disabled'}
            />
            <InfoRow
              label="Rebinding Protection"
              value={filterStats?.rebinding ? 'Enabled' : 'Disabled'}
            />
          </div>
        </motion.div>
      </div>
    </div>
  )
}
