import { Routes, Route, Navigate } from 'react-router-dom'
import { useStore } from './lib/store'
import { Layout } from './components/Layout'
import { Login } from './pages/Login'
import { Register } from './pages/Register'
import { ChangePassword } from './pages/ChangePassword'
import { Dashboard } from './pages/Dashboard'
import { Zones } from './pages/Zones'
import { Settings } from './pages/Settings'
import { Logs } from './pages/Logs'
import { Cache } from './pages/Cache'
import { Blocked } from './pages/Blocked'
import { Admin } from './pages/Admin'
import { DNSClient } from './pages/DNSClient'

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const session = useStore((s) => s.session)
  if (!session) return <Navigate to="/login" replace />
  if (session.force_password_change) return <Navigate to="/change-password" replace />
  return <>{children}</>
}

export default function App() {
  const session = useStore((s) => s.session)

  return (
    <Routes>
      <Route
        path="/login"
        element={session && !session.force_password_change ? <Navigate to="/" replace /> : <Login />}
      />
      <Route path="/register" element={<Register />} />
      <Route
        path="/change-password"
        element={
          session ? <ChangePassword /> : <Navigate to="/login" replace />
        }
      />
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <Layout />
          </ProtectedRoute>
        }
      >
        <Route index element={<Dashboard />} />
        <Route path="zones" element={<Zones />} />
        <Route path="settings" element={<Settings />} />
        <Route path="logs" element={<Logs />} />
        <Route path="cache" element={<Cache />} />
        <Route path="blocked" element={<Blocked />} />
        <Route path="dns" element={<DNSClient />} />
        <Route path="admin" element={<Admin />} />
      </Route>
    </Routes>
  )
}
