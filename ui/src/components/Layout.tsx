import { Outlet, useNavigate, useLocation } from 'react-router-dom'
import { useStore } from '../lib/store'
import { motion } from 'framer-motion'
import {
  LayoutDashboard,
  Globe,
  Settings,
  ScrollText,
  Database,
  Shield,
  Cpu,
  Search,
  LogOut,
  Menu,
  X,
} from 'lucide-react'
import { useState } from 'react'
import { cn } from '../lib/utils'

const navItems = [
  { path: '/', label: 'Dashboard', icon: LayoutDashboard },
  { path: '/zones', label: 'Zones', icon: Globe },
  { path: '/cache', label: 'Cache', icon: Database },
  { path: '/blocked', label: 'Blocked', icon: Shield },
  { path: '/dns', label: 'DNS Client', icon: Search },
  { path: '/settings', label: 'Settings', icon: Settings },
  { path: '/admin', label: 'Admin', icon: Cpu },
  { path: '/logs', label: 'Logs', icon: ScrollText },
]

export function Layout() {
  const [collapsed, setCollapsed] = useState(false)
  const navigate = useNavigate()
  const location = useLocation()
  const session = useStore((s) => s.session)
  const logout = useStore((s) => s.logout)

  return (
    <div className="flex h-screen bg-[var(--vz-bg-primary)] text-[var(--vz-text-secondary)] noise-overlay grid-bg">
      {/* Sidebar */}
      <aside
        className={cn(
          'relative flex flex-col border-r border-[var(--vz-border-color)] bg-[var(--vz-bg-secondary)]/80 backdrop-blur-xl transition-all duration-300',
          collapsed ? 'w-16' : 'w-56',
        )}
      >
        {/* Logo */}
        <div className="flex h-14 items-center gap-3 border-b border-[var(--vz-border-color)] px-4">
          <Shield
            size={22}
            className="shrink-0 text-[var(--vz-accent-vibrant)] logo-custom"
          />
          {!collapsed && (
            <span className="gradient-text text-lg font-bold tracking-tight">
              Heimdallr
            </span>
          )}
          <button
            onClick={() => setCollapsed(!collapsed)}
            className="ml-auto rounded-lg p-1.5 text-[var(--vz-text-muted)] transition-colors hover:bg-[var(--vz-surface-glass)] hover:text-[var(--vz-accent-vibrant)]"
          >
            {collapsed ? <Menu size={16} /> : <X size={16} />}
          </button>
        </div>

        {/* Nav */}
        <nav className="flex-1 py-3">
          {navItems.map((item) => {
            const active = location.pathname === item.path
            return (
              <button
                key={item.path}
                onClick={() => navigate(item.path)}
                className={cn(
                  'group relative flex w-full items-center gap-3 px-4 py-2.5 text-sm transition-all',
                  active
                    ? 'sidebar-active bg-[var(--vz-surface-glass)] text-[var(--vz-accent-vibrant)]'
                    : 'text-[var(--vz-text-muted)] hover:bg-[var(--vz-surface-glass)] hover:text-[var(--vz-text-secondary)]',
                )}
              >
                <item.icon size={18} className="shrink-0" />
                {!collapsed && <span>{item.label}</span>}
              </button>
            )
          })}
        </nav>

        {/* User */}
        {session && (
          <div className="border-t border-[var(--vz-border-color)] p-3">
            {!collapsed && (
              <div className="mb-2 flex items-center justify-between px-1">
                <span className="text-xs text-[var(--vz-text-muted)]">
                  {session.user}
                </span>
                <button
                  onClick={() => {
                    logout()
                    navigate('/login')
                  }}
                  className="rounded-lg p-1 text-[var(--vz-text-muted)] transition-colors hover:text-[var(--vz-accent-vibrant)]"
                  title="Sign out"
                >
                  <LogOut size={14} />
                </button>
              </div>
            )}
            {collapsed && (
              <button
                onClick={() => {
                  logout()
                  navigate('/login')
                }}
                className="flex w-full justify-center rounded-lg p-1.5 text-[var(--vz-text-muted)] transition-colors hover:text-[var(--vz-accent-vibrant)]"
                title="Sign out"
              >
                <LogOut size={16} />
              </button>
            )}
          </div>
        )}
      </aside>

      {/* Main */}
      <main className="flex-1 overflow-y-auto p-6">
        <motion.div
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.25, ease: 'easeOut' }}
        >
          <Outlet />
        </motion.div>
      </main>
    </div>
  )
}
