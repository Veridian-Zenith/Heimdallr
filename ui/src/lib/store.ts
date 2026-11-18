import { create } from 'zustand'

// ── API types ───────────────────────────────────────────────────────────────

export interface ServerInfo {
  version: string
  hostname: string
  dns_listen: string[]
  api_listen: string
  zones_loaded: number
  dnssec_validation: boolean
  cache_size: number
  log_level: string
}

export interface ZoneSummary {
  name: string
  kind: string
  file: string | null
  primaries: string[]
}

export interface RecordSummary {
  name: string
  rtype: string
  ttl: number
  rdata: string
}

export interface FilterStats {
  cname_cloaking: boolean
  rebinding: boolean
  blocklist_entries: number
  regex_patterns: number
}

export interface AuthSession {
  token: string
  user: string
  roles: string[]
  expires: number
  force_password_change: boolean
}

export interface ChallengeResponse {
  challenge_id: string
  command: string
  description: string
}

export interface VerifyHumanResponse {
  verification_token: string
  expires: number
}

// ── Store ───────────────────────────────────────────────────────────────────

interface HeimdallrState {
  session: AuthSession | null
  setSession: (s: AuthSession) => void
  logout: () => void

  serverInfo: ServerInfo | null
  fetchServerInfo: () => Promise<void>

  zones: ZoneSummary[]
  fetchZones: () => Promise<void>

  filterStats: FilterStats | null
  fetchFilterStats: () => Promise<void>

  selectedZone: string | null
  setSelectedZone: (name: string | null) => void
  zoneRecords: RecordSummary[]
  fetchZoneRecords: (zone: string) => Promise<void>
}

function authHeaders(session: AuthSession | null): Record<string, string> {
  if (!session) return {}
  return { Authorization: `Bearer ${session.token}` }
}

async function api<T>(path: string, session: AuthSession | null, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...authHeaders(session),
      ...init?.headers,
    },
  })
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }))
    throw new Error(body.error || res.statusText)
  }
  return res.json()
}

function loadSession(): AuthSession | null {
  try {
    const raw = localStorage.getItem('heimdallr-session')
    if (!raw) return null
    const s: AuthSession = JSON.parse(raw)
    if (s.expires * 1000 < Date.now()) {
      localStorage.removeItem('heimdallr-session')
      return null
    }
    return s
  } catch {
    localStorage.removeItem('heimdallr-session')
    return null
  }
}

export const useStore = create<HeimdallrState>((set, _get) => ({
  session: loadSession(),
  setSession: (s) => {
    localStorage.setItem('heimdallr-session', JSON.stringify(s))
    set({ session: s })
  },
  logout: () => {
    localStorage.removeItem('heimdallr-session')
    set({ session: null, serverInfo: null, zones: [], filterStats: null, zoneRecords: [] })
  },

  serverInfo: null,
  fetchServerInfo: async () => {
    const session = _get().session
    const info = await api<ServerInfo>('/api/info', session)
    set({ serverInfo: info })
  },

  zones: [],
  fetchZones: async () => {
    const session = _get().session
    const data = await api<{ zones: ZoneSummary[] }>('/api/zones', session)
    set({ zones: data.zones })
  },

  filterStats: null,
  fetchFilterStats: async () => {
    const session = _get().session
    const stats = await api<FilterStats>('/api/filter/stats', session)
    set({ filterStats: stats })
  },

  selectedZone: null,
  setSelectedZone: (name) => set({ selectedZone: name, zoneRecords: [] }),
  zoneRecords: [],
  fetchZoneRecords: async (zone) => {
    const session = _get().session
    const data = await api<{ records: RecordSummary[] }>(
      `/api/zones/${encodeURIComponent(zone)}/records`,
      session,
    )
    set({ zoneRecords: data.records })
  },
}))
