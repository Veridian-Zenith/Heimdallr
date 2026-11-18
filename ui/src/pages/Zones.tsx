import { useEffect } from 'react'
import { useStore } from '../lib/store'
import { motion } from 'framer-motion'
import { Globe, ChevronRight } from 'lucide-react'

export function Zones() {
  const zones = useStore((s) => s.zones)
  const fetchZones = useStore((s) => s.fetchZones)
  const selectedZone = useStore((s) => s.selectedZone)
  const setSelectedZone = useStore((s) => s.setSelectedZone)
  const zoneRecords = useStore((s) => s.zoneRecords)
  const fetchZoneRecords = useStore((s) => s.fetchZoneRecords)

  useEffect(() => { fetchZones() }, [fetchZones])
  useEffect(() => { if (selectedZone) fetchZoneRecords(selectedZone) }, [selectedZone, fetchZoneRecords])

  return (
    <div className="flex flex-col gap-6">
      <h1 className="gradient-text text-2xl font-bold tracking-tight">Zones</h1>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {/* Zone list */}
        <div className="glass card-glow rounded-2xl p-4 lg:col-span-1">
          <h2 className="mb-3 text-[10px] font-bold uppercase tracking-widest text-[var(--vz-text-muted)]">
            {zones.length} zone{zones.length !== 1 ? 's' : ''}
          </h2>
          <div className="flex flex-col gap-1 scrollbar-hide max-h-[60vh] overflow-y-auto">
            {zones.map((zone, i) => (
              <motion.button
                key={zone.name}
                initial={{ opacity: 0, x: -4 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.03 }}
                onClick={() => setSelectedZone(zone.name)}
                className={`group flex items-center gap-2 rounded-xl px-3 py-2.5 text-left text-sm transition-all ${
                  selectedZone === zone.name
                    ? 'sidebar-active bg-[var(--vz-surface-glass)] text-[var(--vz-accent-vibrant)]'
                    : 'text-[var(--vz-text-muted)] hover:bg-[var(--vz-surface-glass)] hover:text-[var(--vz-text-secondary)]'
                }`}
              >
                <Globe size={14} className="shrink-0" />
                <span className="flex-1 truncate font-mono text-xs">{zone.name}</span>
                <ChevronRight size={12} className="text-[var(--vz-text-muted)]/40 group-hover:text-[var(--vz-accent-vibrant)]/50" />
              </motion.button>
            ))}
            {zones.length === 0 && (
              <p className="text-xs text-[var(--vz-text-muted)]">No zones loaded</p>
            )}
          </div>
        </div>

        {/* Records */}
        <div className="glass card-glow rounded-2xl p-4 lg:col-span-2">
          <h2 className="mb-3 text-[10px] font-bold uppercase tracking-widest text-[var(--vz-text-muted)]">
            {selectedZone ? `Records — ${selectedZone}` : 'Select a zone'}
          </h2>
          {zoneRecords.length > 0 ? (
            <div className="overflow-x-auto scrollbar-hide max-h-[60vh]">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[var(--vz-border-color)]/40 text-left">
                    <th className="pb-2 text-[10px] font-bold uppercase tracking-widest text-[var(--vz-text-muted)]">Name</th>
                    <th className="pb-2 text-[10px] font-bold uppercase tracking-widest text-[var(--vz-text-muted)]">Type</th>
                    <th className="pb-2 text-[10px] font-bold uppercase tracking-widest text-[var(--vz-text-muted)]">TTL</th>
                    <th className="pb-2 text-[10px] font-bold uppercase tracking-widest text-[var(--vz-text-muted)]">Data</th>
                  </tr>
                </thead>
                <tbody>
                  {zoneRecords.map((rec, i) => (
                    <motion.tr
                      key={i}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ delay: i * 0.02 }}
                      className="border-b border-[var(--vz-border-color)]/20 hover:bg-[var(--vz-surface-glass)]"
                    >
                      <td className="py-2 pr-4 font-mono text-xs text-[var(--vz-text-secondary)]">{rec.name}</td>
                      <td className="py-2 pr-4">
                        <span className="rounded-lg bg-[var(--vz-accent-vibrant)]/8 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-[var(--vz-accent-vibrant)]">
                          {rec.rtype}
                        </span>
                      </td>
                      <td className="py-2 pr-4 font-mono text-xs text-[var(--vz-text-muted)]">{rec.ttl}</td>
                      <td className="py-2 font-mono text-xs text-[var(--vz-text-muted)]">{rec.rdata}</td>
                    </motion.tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-xs text-[var(--vz-text-muted)]">
              {selectedZone ? 'No records found' : 'Click a zone to view records'}
            </p>
          )}
        </div>
      </div>
    </div>
  )
}
