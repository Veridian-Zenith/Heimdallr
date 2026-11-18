import { motion } from 'framer-motion'
import { ScrollText } from 'lucide-react'

export function Logs() {
  return (
    <div className="flex flex-col gap-6">
      <h1 className="gradient-text text-2xl font-bold tracking-tight">Logs</h1>
      <motion.div
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        className="glass card-glow rounded-2xl p-5"
      >
        <div className="flex items-center gap-3 text-xs text-[var(--vz-text-muted)]">
          <ScrollText size={16} className="text-[var(--vz-accent-vibrant)]/50" />
          <span>Query log viewer — coming soon</span>
        </div>
      </motion.div>
    </div>
  )
}
