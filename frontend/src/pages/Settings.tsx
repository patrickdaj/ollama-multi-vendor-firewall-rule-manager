import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { RefreshCw, Database, Server, Activity, CheckCircle2, XCircle, KeyRound, Save } from 'lucide-react'
import { api, type SystemSetting } from '@/lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'

const SETTING_LABELS: Record<string, string> = {
  default_username: 'Default Username',
  default_password: 'Default Password',
  default_verify_ssl: 'Verify SSL by default',
  default_port_paloalto: 'PAN-OS default port',
  default_port_fortinet: 'FortiGate default port',
  default_port_cisco_asa: 'Cisco ASA default port',
  default_port_cisco_ftd: 'Cisco FTD default port',
}

const DEFAULT_PORTS: Record<string, number> = {
  default_port_paloalto: 443,
  default_port_fortinet: 443,
  default_port_cisco_asa: 443,
  default_port_cisco_ftd: 443,
}

function SettingRow({ setting, onChange }: {
  setting: SystemSetting
  onChange: (key: string, value: string | number | boolean | null) => void
}) {
  const label = SETTING_LABELS[setting.key] ?? setting.key
  const isPassword = setting.key === 'default_password'
  const isBoolean = setting.key === 'default_verify_ssl'
  const isPort = setting.key.startsWith('default_port_')
  const [localValue, setLocalValue] = useState<string>(
    setting.value == null ? '' : String(setting.value)
  )
  const [dirty, setDirty] = useState(false)

  const handle = (v: string) => { setLocalValue(v); setDirty(true) }

  const save = () => {
    if (isBoolean) return  // handled by toggle
    if (isPort) {
      const n = parseInt(localValue, 10)
      onChange(setting.key, isNaN(n) ? null : n)
    } else {
      onChange(setting.key, localValue || null)
    }
    setDirty(false)
  }

  if (isBoolean) {
    const checked = setting.value === true
    return (
      <div className="flex items-center justify-between py-2">
        <label className="text-sm">{label}</label>
        <button
          onClick={() => onChange(setting.key, !checked)}
          className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${checked ? 'bg-primary' : 'bg-muted'}`}
        >
          <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${checked ? 'translate-x-4' : 'translate-x-1'}`} />
        </button>
      </div>
    )
  }

  return (
    <div className="flex items-center justify-between gap-3 py-1.5">
      <label className="text-sm text-muted-foreground w-48 flex-shrink-0">{label}</label>
      <div className="flex-1 flex gap-2">
        <Input
          type={isPassword ? 'password' : isPort ? 'number' : 'text'}
          value={localValue}
          onChange={e => handle(e.target.value)}
          placeholder={isPort ? String(DEFAULT_PORTS[setting.key] ?? 443) : isPassword ? '(unchanged)' : '—'}
          className="h-8 text-xs"
          onKeyDown={e => e.key === 'Enter' && save()}
        />
        {dirty && (
          <Button size="sm" className="h-8 px-3" onClick={save}>
            <Save className="h-3 w-3" />
          </Button>
        )}
      </div>
    </div>
  )
}

function DefaultCredentials() {
  const qc = useQueryClient()
  const { data: settings = [], isLoading } = useQuery({
    queryKey: ['system-settings'],
    queryFn: api.settings.list,
  })

  const upsert = useMutation({
    mutationFn: ({ key, value }: { key: string; value: string | number | boolean | null }) =>
      api.settings.upsert(key, value),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['system-settings'] }),
  })

  if (isLoading) return <div className="text-muted-foreground text-sm">Loading…</div>

  const credSettings = settings.filter(s =>
    ['default_username', 'default_password', 'default_verify_ssl'].includes(s.key)
  )
  const portSettings = settings.filter(s => s.key.startsWith('default_port_'))

  return (
    <div className="space-y-4">
      <div className="space-y-1">
        <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Credentials</h4>
        {credSettings.map(s => (
          <SettingRow
            key={s.key}
            setting={s}
            onChange={(key, value) => upsert.mutate({ key, value })}
          />
        ))}
      </div>
      <div className="space-y-1">
        <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Default Ports</h4>
        {portSettings.map(s => (
          <SettingRow
            key={s.key}
            setting={s}
            onChange={(key, value) => upsert.mutate({ key, value })}
          />
        ))}
      </div>
      <p className="text-xs text-muted-foreground pt-1">
        These values pre-fill the device registration form. Each device can override them individually.
        Passwords are stored encrypted.
      </p>
    </div>
  )
}

export function Settings() {
  const qc = useQueryClient()
  const { data: health } = useQuery({
    queryKey: ['health'],
    queryFn: api.health,
    refetchInterval: 30000,
  })
  const { data: ragStatus } = useQuery({
    queryKey: ['rag-status'],
    queryFn: api.rag.status,
    refetchInterval: 30000,
  })
  const { data: devices = [] } = useQuery({
    queryKey: ['devices'],
    queryFn: api.devices.list,
  })

  const reindexAll = useMutation({
    mutationFn: async () => {
      for (const d of devices) {
        await api.devices.reindex(d.name)
      }
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rag-status'] }),
  })

  const ok = health?.status === 'ok'

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Settings</h1>
        <p className="text-muted-foreground text-sm mt-1">System status and configuration</p>
      </div>

      {/* Default credentials */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <KeyRound className="h-4 w-4" />
            Default Device Credentials
          </CardTitle>
        </CardHeader>
        <CardContent>
          <DefaultCredentials />
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Server className="h-4 w-4" />
              API Status
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Status</span>
              <div className="flex items-center gap-1.5">
                {ok
                  ? <CheckCircle2 className="h-4 w-4 text-green-500" />
                  : <XCircle className="h-4 w-4 text-red-500" />}
                <span className="text-sm">{health?.status ?? 'checking…'}</span>
              </div>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Environment</span>
              <Badge variant="outline">{health?.env ?? '—'}</Badge>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Registered devices</span>
              <span className="text-sm">{devices.length}</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Database className="h-4 w-4" />
              RAG Index (ChromaDB)
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Documents</span>
              <span className="text-sm font-medium">
                {ragStatus?.document_count.toLocaleString() ?? '—'}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Collection</span>
              <span className="text-xs font-mono text-muted-foreground">
                {ragStatus?.collection ?? '—'}
              </span>
            </div>
            <Button
              size="sm"
              variant="outline"
              className="w-full"
              onClick={() => reindexAll.mutate()}
              disabled={reindexAll.isPending || devices.length === 0}
            >
              {reindexAll.isPending ? (
                <><RefreshCw className="h-3.5 w-3.5 animate-spin mr-1.5" />Reindexing…</>
              ) : (
                <><Activity className="h-3.5 w-3.5 mr-1.5" />Reindex All Devices</>
              )}
            </Button>
            {reindexAll.isError && (
              <p className="text-xs text-destructive">{String(reindexAll.error)}</p>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">About</CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground space-y-1">
          <p>Ignis — multi-vendor firewall policy management with local LLM.</p>
          <p className="text-xs">No cloud · No telemetry · All data stays local.</p>
        </CardContent>
      </Card>
    </div>
  )
}
