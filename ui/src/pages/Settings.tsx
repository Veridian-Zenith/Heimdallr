import { useState, useEffect } from 'react'
import { useStore } from '../lib/store'

export function Settings() {
  const session = useStore((s) => s.session)
  const [tab, setTab] = useState('general')
  const [msg, setMsg] = useState('')
  const [saving, setSaving] = useState(false)
  const [form, setForm] = useState<Record<string, any>>({})

  const headers = session?.token ? { Authorization: `Bearer ${session.token}` } : undefined

  useEffect(() => {
    (async () => {
      try {
        const res = await fetch('/api/settings', { headers })
        if (res.ok) {
          const cfg = await res.json()
          setForm({
            // General
            host: cfg.host || '', hostadmin: cfg.hostadmin || '', zones_dir: cfg.zones_dir || '',
            listen: cfg.listen?.join(', ') || '', listen_tls: cfg.listen_tls?.join(', ') || '', listen_quic: cfg.listen_quic?.join(', ') || '', listen_https: cfg.listen_https?.join(', ') || '',
            // Resolver
            forwarders: cfg.resolver?.forwarders?.join(', ') || '', forward_protocol: cfg.resolver?.forward_protocol || 'udp',
            qname_min: cfg.resolver?.qname_minimization?.enable || false, qname_mode: cfg.resolver?.qname_minimization?.mode || 'strict',
            qname_max_iter: cfg.resolver?.qname_minimization?.max_iterations || 7, qname_random: cfg.resolver?.qname_randomization || false,
            ecs: cfg.resolver?.ecs || false, concurrency: cfg.resolver?.concurrency || 2, timeout: cfg.resolver?.timeout_ms || 2000,
            // Cache
            cache_size: cfg.cache?.size || 50000, serve_stale: cfg.cache?.serve_stale ?? true, prefetch: cfg.cache?.prefetch || 2,
            persistent: cfg.cache?.persistent || '', persistent_max_age: cfg.cache?.persistent_max_age_days || 7,
            // DNSSEC
            dnssec_validation: cfg.dnssec?.validation ?? true, dnssec_signing: cfg.dnssec?.signing || false,
            dnssec_provider: cfg.dnssec?.provider || 'ring', keys_dir: cfg.dnssec_keys?.keys_dir || '/var/lib/heimdallr/keys',
            trust_anchor: cfg.dnssec_keys?.trust_anchor || '',
            // Filter / Blocking
            cname_cloaking: cfg.filter?.cname_cloaking ?? true, rebinding: cfg.filter?.rebinding ?? true,
            cname_limit: cfg.filter?.cname_chain_limit || 8, sinkhole_v4: cfg.filter?.sinkhole_v4 || '0.0.0.0',
            sinkhole_v6: cfg.filter?.sinkhole_v6 || '::', blocklists_raw: cfg.filter?.blocklists?.join(', ') || '',
            allowlists_raw: cfg.filter?.allowlists?.join(', ') || '', regex_raw: cfg.filter?.regex_blocklist?.join(', ') || '',
            // Proxy
            proxy_enable: cfg.proxy?.enable || false, proxy_protocol: cfg.proxy?.protocol || 'v2', proxy_allow: cfg.proxy?.allow?.join(', ') || '',
            // API
            api_listen: cfg.api?.listen || '127.0.0.1:5380', api_tls_cert: cfg.api?.tls_cert || '', api_tls_key: cfg.api?.tls_key || '',
            // Auth
            auth_enabled: cfg.auth?.enabled || false, auth_totp: cfg.auth?.totp || false, auth_oidc: cfg.auth?.oidc || false,
            token_secret: cfg.auth?.token_secret || '',
            // TLS / Certificates
            tls_cert: cfg.tls?.cert || '', tls_key: cfg.tls?.key || '', tls_letsencrypt_dir: cfg.tls?.letsencrypt_dir || '/etc/letsencrypt/live',
            tls_self_signed: cfg.tls?.self_signed || false,
            // Log
            log_level: cfg.log?.level || 'info', log_format: cfg.log?.format || 'text', query_log_url: cfg.log?.query_log || '',
            // Metrics
            metrics_enable: cfg.metrics?.enable ?? true, metrics_endpoint: cfg.metrics?.endpoint || '/metrics', metrics_format: cfg.metrics?.format || 'openmetrics',
            // DNS64
            dns64_prefix: cfg.dns64?.prefix || '', dns64_always: cfg.dns64?.always_synthesize || false,
            // Cluster
            cluster_enable: cfg.cluster?.enable || false, cluster_peers: cfg.cluster?.peers?.join(', ') || '',
            // DHCP
            dhcp_enable: cfg.dhcp?.enable || false, dhcp_ranges: JSON.stringify(cfg.dhcp?.ranges || []),
          })
        }
      } catch (e) { console.error('settings load', e) }
    })()
  }, [])

  const saveAll = async () => {
    setSaving(true); setMsg('')
    try {
      const body: any = { ...form }
      // Build full config object from form fields
      const payload = {
        host: body.host,
        hostadmin: body.hostadmin || undefined,
        zones_dir: body.zones_dir,
        listen: body.listen ? body.listen.split(',').map((s: string) => s.trim()).filter(Boolean) : undefined,
        listen_tls: body.listen_tls ? body.listen_tls.split(',').map((s: string) => s.trim()).filter(Boolean) : undefined,
        listen_quic: body.listen_tls ? body.listen_tls.split(',').map((s: string) => s.trim()).filter(Boolean) : undefined,
        listen_https: body.listen_https ? body.listen_https.split(',').map((s: string) => s.trim()).filter(Boolean) : undefined,
        tls: {
          cert: body.tls_cert || undefined,
          key: body.tls_key || undefined,
          letsencrypt_dir: body.tls_letsencrypt_dir,
          self_signed: body.tls_self_signed,
        },
        dnssec_keys: {
          keys_dir: body.keys_dir,
          trust_anchor: body.trust_anchor || undefined,
        },
        resolver: {
          forwarders: body.forwarders_raw ? body.forwarders_raw.split(',').map((s: string) => s.trim()).filter(Boolean) : (body.forwarders ? [body.forwarders] : undefined),
          forward_protocol: body.forward_protocol,
          qname_minimization: { enable: !!body.qname_min, mode: body.qname_mode || 'strict', max_iterations: Number(body.qname_max_iter) || 7 },
          qname_randomization: !!body.qname_random,
          ecs: !!body.ecs,
          concurrency: Number(body.concurrency) || 2,
          timeout_ms: Number(body.timeout) || 2000,
        },
        cache: {
          size: Number(body.cache_size) || 50000,
          serve_stale: !!body.serve_stale,
          prefetch: Number(body.prefetch) || 2,
          persistent: body.persistent || undefined,
          persistent_max_age_days: Number(body.persistent_max_age) || 7,
        },
        dnssec: {
          validation: !!body.dnssec_validation,
          signing: !!body.dnssec_signing,
          provider: 'ring',
        },
        filter: {
          blocklists: body.blocklists_raw ? body.blocklists_raw.split(',').map((s: string) => s.trim()).filter(Boolean) : (body.blocklists ? [body.blocklists] : undefined),
          allowlists: body.allowlists_raw ? body.allowlists_raw.split(',').map((s: string) => s.trim()).filter(Boolean) : (body.allowlists ? [body.allowlists] : undefined),
          regex_blocklist: body.regex_raw ? body.regex_raw.split(',').map((s: string) => s.trim()).filter(Boolean) : (body.regex ? [body.regex] : undefined),
          cname_cloaking: !!body.cname_cloaking,
          rebinding: !!body.rebinding,
          cname_chain_limit: Number(body.cname_limit) || 8,
          sinkhole_v4: body.sinkhole_v4,
          sinkhole_v6: body.sinkhole_v6,
        },
        proxy: {
          enable: !!body.proxy_enable,
          protocol: body.proxy_protocol,
          allow: body.proxy_allow ? body.proxy_allow.split(',').map((s: string) => s.trim()).filter(Boolean) : undefined,
        },
        api: {
          listen: body.api_listen,
          tls_cert: body.api_tls_cert || undefined,
          tls_key: body.api_tls_key || undefined,
        },
        auth: {
          enabled: !!body.auth_enabled,
          totp: !!body.auth_totp,
          oidc: !!body.auth_oidc,
        },
        log: {
          level: body.log_level,
          format: body.log_format,
          query_log: body.query_log_url || undefined,
        },
        metrics: {
          enable: !!body.metrics_enable,
          endpoint: body.metrics_endpoint,
          format: body.metrics_format,
        },
        dns64: {
          prefix: body.dns64_prefix || undefined,
          always_synthesize: !!body.dns64_always,
        },
        cluster: {
          enable: !!body.cluster_enable,
          peers: body.cluster_peers ? body.cluster_peers.split(',').map((s: string) => s.trim()).filter(Boolean) : undefined,
        },
        dhcp: {
          enable: !!body.dhcp_enable,
        },
      }
      const res = await fetch('/api/settings', {
        method: 'PUT',
        headers: { ...headers, 'Content-Type': 'application/json' } as any,
        body: JSON.stringify(payload),
      })
      if (!res.ok) { setMsg('Save failed') } else { setMsg('Saved successfully'); setTimeout(() => setMsg(''), 3000) }
    } catch (e) { setMsg('Error') }
    finally { setSaving(false) }
  }

  const tabs = [
    { id: 'general', label: 'General' },
    { id: 'resolver', label: 'Resolver' },
    { id: 'cache', label: 'Cache' },
    { id: 'dnssec', label: 'DNSSEC' },
    { id: 'filter', label: 'Blocking' },
    { id: 'proxy', label: 'Proxy' },
    { id: 'dns64', label: 'DNS64' },
    { id: 'metrics', label: 'Metrics' },
    { id: 'log', label: 'Log' },
    { id: 'tls', label: 'TLS' },
    { id: 'auth', label: 'Auth' },
    { id: 'api', label: 'API' },
    { id: 'cluster', label: 'Cluster' },
    { id: 'dhcp', label: 'DHCP' },
  ]

  return (
    <div className="flex flex-col gap-4">
      <h1 className="gradient-text text-2xl font-bold tracking-tight">Settings</h1>
      <p className="text-xs text-[var(--vz-text-muted)]">Every config value is editable below. All sections save to <code>/etc/heimdallr/config.toml</code>.</p>

      <div className="flex flex-wrap gap-1">
        {tabs.map((t) => (
                      <button key={t.id} onClick={() => { setTab(t.id); window.scrollTo({ top: 0, behavior: 'smooth' }) }} className={`rounded-md px-2.5 py-1 text-[10px] font-bold uppercase tracking-wide transition-all ${tab === t.id ? 'bg-[var(--vz-accent-vibrant)] text-white' : 'text-[var(--vz-text-muted)] hover:bg-[var(--vz-surface-glass)] hover:text-[var(--vz-text-secondary)]'}`}>{t.label}</button>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* GENERAL */}
        <Section title="General" id="general">
          <Field label="Host" keyName="host" form={form} setForm={setForm} />
          <Field label="Host Admin (email)" keyName="hostadmin" form={form} setForm={setForm} />
          <Field label="Zones Dir" keyName="zones_dir" form={form} setForm={setForm} />
          <Field label="DNS Listen" keyName="listen" form={form} setForm={setForm} />
          <Field label="TLS Listen" keyName="listen_tls" form={form} setForm={setForm} />
          <Field label="QUIC Listen" keyName="listen_tls" form={form} setForm={setForm} />
          <Field label="HTTPS Listen" keyName="listen_https" form={form} setForm={setForm} />
        </Section>

        {/* RESOLVER */}
        <Section title="Resolver" id="resolver">
          <Field label="Forwarders (comma list)" keyName="forwarders_raw" form={form} setForm={setForm} />
          <SelectField label="Forward Protocol" keyName="forward_protocol" form={form} setForm={setForm} options={['udp','tcp','dot','doh','doq']} />
          <Checkbox label="QNAME Minimization" keyName="qname_min" form={form} setForm={setForm} />
          <SelectField label="QNAME Mode" keyName="qname_mode" form={form} setForm={setForm} options={['incremental','aggressive','strict']} />
          <Field label="QNAME Max Iterations" keyName="qname_max_iter" form={form} setForm={setForm} type="number" />
          <Checkbox label="Case Randomization" keyName="qname_random" form={form} setForm={setForm} />
          <Checkbox label="ECS" keyName="ecs" form={form} setForm={setForm} />
          <Field label="Concurrency" keyName="concurrency" form={form} setForm={setForm} type="number" />
          <Field label="Timeout (ms)" keyName="timeout" form={form} setForm={setForm} type="number" />
        </Section>

        {/* CACHE */}
        <Section title="Cache" id="cache">
          <Field label="Max Entries" keyName="cache_size" form={form} setForm={setForm} type="number" />
          <Checkbox label="Serve Stale" keyName="serve_stale" form={form} setForm={setForm} />
          <Field label="Prefetch Threshold" keyName="prefetch" form={form} setForm={setForm} type="number" />
          <Field label="Persistent File Path" keyName="persistent" form={form} setForm={setForm} />
          <Field label="Persistent Max Age (days)" keyName="persistent_max_age" form={form} setForm={setForm} type="number" />
        </Section>

        {/* DNSSEC */}
        <Section title="DNSSEC" id="dnssec">
          <Checkbox label="Validation" keyName="dnssec_validation" form={form} setForm={setForm} />
          <Checkbox label="Signing" keyName="dnssec_signing" form={form} setForm={setForm} />
          <Field label="Keys Dir" keyName="keys_dir" form={form} setForm={setForm} />
          <Field label="Trust Anchor File" keyName="trust_anchor" form={form} setForm={setForm} />
        </Section>

        {/* FILTER / BLOCKING */}
        <Section title="Blocking" id="filter">
          <Checkbox label="CNAME Cloaking" keyName="cname_cloaking" form={form} setForm={setForm} />
          <Checkbox label="Rebinding Protection" keyName="rebinding" form={form} setForm={setForm} />
          <Field label="CNAME Chain Limit" keyName="cname_limit" form={form} setForm={setForm} type="number" />
          <Field label="Sinkhole IPv4" keyName="sinkhole_v4" form={form} setForm={setForm} />
          <Field label="Sinkhole IPv6" keyName="sinkhole_v6" form={form} setForm={setForm} />
          <Field label="Blocklists (comma URLs/paths)" keyName="blocklists_raw" form={form} setForm={setForm} />
          <Field label="Allowlists (comma URLs/paths)" keyName="allowlists_raw" form={form} setForm={setForm} />
          <Field label="Regex Patterns (comma)" keyName="regex_raw" form={form} setForm={setForm} />
        </Section>

        {/* PROXY */}
        <Section title="Proxy" id="proxy">
          <Checkbox label="Enable" keyName="proxy_enable" form={form} setForm={setForm} />
          <SelectField label="Protocol" keyName="proxy_protocol" form={form} setForm={setForm} options={['v1','v2']} />
          <Field label="Allowed Proxies (comma)" keyName="proxy_allow" form={form} setForm={setForm} />
        </Section>

        {/* API */}
        <Section title="API" id="api">
          <Field label="Listen Address" keyName="api_listen" form={form} setForm={setForm} />
          <Field label="TLS Cert Path" keyName="api_tls_cert" form={form} setForm={setForm} />
          <Field label="TLS Key Path" keyName="api_tls_key" form={form} setForm={setForm} />
        </Section>

        {/* TLS */}
        <Section title="TLS" id="tls">
          <Field label="Cert Path" keyName="tls_cert" form={form} setForm={setForm} />
          <Field label="Key Path" keyName="tls_key" form={form} setForm={setForm} />
          <Field label="Let's Encrypt Dir" keyName="tls_letsencrypt_dir" form={form} setForm={setForm} />
          <Checkbox label="Self-Signed Fallback" keyName="tls_self_signed" form={form} setForm={setForm} />
        </Section>

        {/* AUTH */}
        <Section title="Auth" id="auth">
          <Checkbox label="Enabled" keyName="auth_enabled" form={form} setForm={setForm} />
          <Checkbox label="TOTP Enabled" keyName="auth_totp" form={form} setForm={setForm} />
          <Checkbox label="OIDC Enabled" keyName="auth_oidc" form={form} setForm={setForm} />
          <Field label="Token Secret" keyName="token_secret" form={form} setForm={setForm} />
        </Section>

        {/* LOG */}
        <Section title="Log" id="log">
          <SelectField label="Level" keyName="log_level" form={form} setForm={setForm} options={['trace','debug','info','warn','error']} />
          <SelectField label="Format" keyName="log_format" form={form} setForm={setForm} options={['text','json']} />
          <Field label="Query Log DB URL" keyName="query_log_url" form={form} setForm={setForm} />
        </Section>

        {/* METRICS */}
        <Section title="Metrics" id="metrics">
          <Checkbox label="Enable" keyName="metrics_enable" form={form} setForm={setForm} />
          <Field label="Endpoint Path" keyName="metrics_endpoint" form={form} setForm={setForm} />
          <SelectField label="Format" keyName="metrics_format" form={form} setForm={setForm} options={['openmetrics']} />
        </Section>

        {/* CLUSTER */}
        <Section title="Cluster" id="cluster">
          <Checkbox label="Enable" keyName="cluster_enable" form={form} setForm={setForm} />
          <Field label="Peers (comma)" keyName="cluster_peers" form={form} setForm={setForm} />
        </Section>

        {/* DHCP */}
        <Section title="DHCP" id="dhcp">
          <Checkbox label="Enable" keyName="dhcp_enable" form={form} setForm={setForm} />
        </Section>
      </div>

      <button
        onClick={saveAll}
        disabled={saving}
        className="rounded-xl bg-[var(--vz-accent-vibrant)] px-6 py-3 text-sm font-bold text-white transition-all hover:bg-[var(--vz-accent-vibrant)]/80 disabled:opacity-50 shadow-[0_0_20px_rgba(255,45,45,0.15)]"
      >
        {saving ? 'Saving all settings...' : 'Save All Settings'}
      </button>
      {msg && <span className="text-xs text-[var(--vz-text-muted)]">{msg}</span>}

      <div className="glass rounded-2xl p-4 text-xs text-[var(--vz-text-muted)]">
        <strong className="text-[var(--vz-text-secondary)]">Note:</strong> Settings update the runtime config and persist to <code>/etc/heimdallr/config.toml</code>. Some changes (listen addresses, zone reloads) require server restart.
      </div>
    </div>
  )
}

// Helper components for Settings
function Section({ title, id, children }: { title: string; id: string; children: React.ReactNode }) {
  return (
    <div id={id} className="border border-[var(--vz-border-color)]/30 rounded-2xl bg-[var(--vz-bg-secondary)]/40 p-4">
      <h3 className="text-[10px] font-bold uppercase tracking-widest text-[var(--vz-text-muted)] mb-3 border-b border-[var(--vz-border-color)]/20 pb-2">{title}</h3>
      <div className="flex flex-col gap-3">{children}</div>
    </div>
  )
}

function Field({ label, keyName, form, setForm, type = 'text' }: { label: string; keyName: string; form: any; setForm: (f: any) => void; type?: string }) {
  return (
    <label className="flex flex-col gap-1 text-xs">
      <span className="text-[var(--vz-text-muted)]">{label}</span>
      <input
        type={type}
        value={(form as any)[keyName] ?? ''}
        onChange={(e) => setForm({ ...form, [keyName]: type === 'number' ? Number(e.target.value) || 0 : e.target.value })}
        className="rounded-lg border border-[var(--vz-border-color)]/40 bg-[var(--vz-bg-primary)] px-3 py-2 text-xs text-[var(--vz-text-secondary)] outline-none focus:border-[var(--vz-accent-vibrant)]/50 transition-all"
      />
    </label>
  )
}

function SelectField({ label, keyName, form, setForm, options }: { label: string; keyName: string; form: any; setForm: (f: any) => void; options: string[] }) {
  return (
    <label className="flex flex-col gap-1 text-xs">
      <span className="text-[var(--vz-text-muted)]">{label}</span>
      <select
        value={(form as any)[keyName] ?? ''}
        onChange={(e) => setForm({ ...form, [keyName]: e.target.value })}
        className="rounded-lg border border-[var(--vz-border-color)]/40 bg-[var(--vz-bg-primary)] px-3 py-2 text-xs text-[var(--vz-text-secondary)] outline-none focus:border-[var(--vz-accent-vibrant)]/50 transition-all"
      >
        {options.map((o) => <option key={o} value={o}>{o}</option>)}
      </select>
    </label>
  )
}

function Checkbox({ label, keyName, form, setForm }: { label: string; keyName: string; form: any; setForm: (f: any) => void }) {
  return (
    <label className="flex items-center gap-2 text-xs text-[var(--vz-text-secondary)] cursor-pointer select-none">
      <input type="checkbox" checked={!!(form as any)[keyName]} onChange={(e) => setForm({ ...form, [keyName]: e.target.checked })} className="h-4 w-4 rounded border-[var(--vz-border-color)] bg-[var(--vz-bg-primary)] accent-[var(--vz-accent-vibrant)]" />
      <span>{label}</span>
    </label>
  )
}
