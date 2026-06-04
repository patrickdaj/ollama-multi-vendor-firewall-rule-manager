import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Plus, RefreshCw, Server, ChevronRight, Check,
  Download, Layers, Wifi,
} from 'lucide-react'
import { api, type Device, type DeviceCreate, type Group, type SystemSetting } from '@/lib/api'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Select } from '@/components/ui/select'
import { Dialog } from '@/components/ui/dialog'
import { VENDOR_LABELS, fmtRelative, cn } from '@/lib/utils'

const VENDORS = ['paloalto', 'cisco_asa', 'cisco_ftd', 'fortinet']

// ── Pipeline stage ────────────────────────────────────────────────────────────

type Stage = 'registered' | 'discovered' | 'grouped' | 'managed'

function deviceStage(d: Device): Stage {
  const synced = !!d.last_synced_at && d.snapshot_count > 0
  const grouped = !!d.device_group_id
  if (synced && grouped) return 'managed'
  if (grouped) return 'grouped'
  if (synced) return 'discovered'
  return 'registered'
}

const STAGE_META: Record<Stage, { label: string; color: string; hint: string }> = {
  registered: { label: 'Registered',  color: 'bg-muted-foreground/40', hint: 'Run a sync to pull its policy' },
  discovered: { label: 'Discovered',  color: 'bg-yellow-500',          hint: 'Assign it to an Intent group' },
  grouped:    { label: 'Grouped',     color: 'bg-blue-500',            hint: 'Sync the device to complete setup' },
  managed:    { label: 'Managed',     color: 'bg-green-500',           hint: 'Fully in the fold' },
}

// ── Device form ───────────────────────────────────────────────────────────────

function DeviceForm({ initial, onSubmit, onClose, loading }: {
  initial?: Partial<DeviceCreate>
  onSubmit: (data: DeviceCreate) => void
  onClose: () => void
  loading?: boolean
}) {
  const [form, setForm] = useState<DeviceCreate>({
    name: initial?.name ?? '',
    vendor: initial?.vendor ?? 'paloalto',
    host: initial?.host ?? '',
    port: initial?.port,
    verify_ssl: initial?.verify_ssl ?? true,
    username: '',
    password: '',
    api_key: '',
    notes: initial?.notes ?? '',
  })

  const set = (k: keyof DeviceCreate) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) =>
    setForm(f => ({ ...f, [k]: e.target.value }))

  return (
    <form onSubmit={e => { e.preventDefault(); onSubmit(form) }} className="space-y-3">
      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1">
          <label className="text-xs text-muted-foreground">Name *</label>
          <Input value={form.name} onChange={set('name')} placeholder="pa-fw01" required disabled={!!initial?.name} />
        </div>
        <div className="space-y-1">
          <label className="text-xs text-muted-foreground">Vendor *</label>
          <Select value={form.vendor} onChange={set('vendor')}>
            {VENDORS.map(v => <option key={v} value={v}>{VENDOR_LABELS[v]}</option>)}
          </Select>
        </div>
      </div>
      <div className="grid grid-cols-3 gap-3">
        <div className="col-span-2 space-y-1">
          <label className="text-xs text-muted-foreground">Host / IP *</label>
          <Input value={form.host} onChange={set('host')} placeholder="10.0.0.1" required />
        </div>
        <div className="space-y-1">
          <label className="text-xs text-muted-foreground">Port</label>
          <Input
            value={form.port ?? ''}
            onChange={e => setForm(f => ({ ...f, port: e.target.value ? +e.target.value : undefined }))}
            placeholder="443" type="number"
          />
        </div>
      </div>
      <div className="space-y-1">
        <label className="text-xs text-muted-foreground">Username</label>
        <Input value={form.username} onChange={set('username')} placeholder="admin" autoComplete="off" />
      </div>
      <div className="space-y-1">
        <label className="text-xs text-muted-foreground">Password</label>
        <Input value={form.password} onChange={set('password')} type="password" autoComplete="new-password" />
      </div>
      <div className="space-y-1">
        <label className="text-xs text-muted-foreground">API Key (PAN-OS)</label>
        <Input value={form.api_key} onChange={set('api_key')} placeholder="LUFRPT1…" autoComplete="off" />
      </div>
      <div className="space-y-1">
        <label className="text-xs text-muted-foreground">Notes</label>
        <Input value={form.notes} onChange={set('notes')} placeholder="Optional description" />
      </div>
      <div className="flex items-center gap-2 pt-1">
        <input type="checkbox" id="ssl" checked={form.verify_ssl}
          onChange={e => setForm(f => ({ ...f, verify_ssl: e.target.checked }))}
          className="rounded" />
        <label htmlFor="ssl" className="text-sm">Verify SSL certificate</label>
      </div>
      <div className="flex justify-end gap-2 pt-2">
        <Button type="button" variant="ghost" onClick={onClose}>Cancel</Button>
        <Button type="submit" disabled={loading}>
          {loading ? 'Saving…' : (initial?.name ? 'Update' : 'Register')}
        </Button>
      </div>
    </form>
  )
}

// ── Onboarding wizard ─────────────────────────────────────────────────────────

function settingsToDefaults(settings: SystemSetting[]): Partial<DeviceCreate> {
  const map: Record<string, SystemSetting['value']> = {}
  for (const s of settings) map[s.key] = s.value
  return {
    username: typeof map.default_username === 'string' ? map.default_username : undefined,
    password: typeof map.default_password === 'string' ? map.default_password : undefined,
    verify_ssl: typeof map.default_verify_ssl === 'boolean' ? map.default_verify_ssl : true,
  }
}

function OnboardWizard({ onClose, onDone }: { onClose: () => void; onDone: (name: string) => void }) {
  const qc = useQueryClient()
  const [step, setStep] = useState<1 | 2 | 3>(1)
  const [device, setDevice] = useState<Device | null>(null)
  const [groupId, setGroupId] = useState<string>('')
  const [syncResult, setSyncResult] = useState<{ objects: number } | null>(null)

  const { data: groups = [] } = useQuery<Group[]>({ queryKey: ['groups'], queryFn: api.groups.list })
  const { data: sysSettings = [] } = useQuery({ queryKey: ['system-settings'], queryFn: api.settings.list })

  const create = useMutation({
    mutationFn: api.devices.create,
    onSuccess: (d) => { setDevice(d); setStep(2); qc.invalidateQueries({ queryKey: ['devices'] }) },
  })

  const sync = useMutation({
    mutationFn: () => api.devices.onboard(device!.name),
    onSuccess: (result) => {
      const count = (result as any)?.object_count ?? device?.latest_object_count ?? 0
      setSyncResult({ objects: count })
      qc.invalidateQueries({ queryKey: ['devices'] })
    },
  })

  const assign = useMutation({
    mutationFn: () => api.groups.assignDevice(+groupId, device!.name),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['devices'] }); setStep(3) },
  })

  const STEPS = ['Register', 'Sync', 'Group']

  return (
    <div className="space-y-5">
      {/* Step indicator */}
      <div className="flex items-center gap-0">
        {STEPS.map((s, i) => (
          <div key={s} className="flex items-center flex-1 last:flex-none">
            <div className={cn(
              'h-6 w-6 rounded-full text-xs flex items-center justify-center font-medium flex-shrink-0',
              step > i + 1 ? 'bg-green-500 text-white' :
              step === i + 1 ? 'bg-primary text-primary-foreground' :
              'bg-muted text-muted-foreground',
            )}>
              {step > i + 1 ? <Check className="h-3.5 w-3.5" /> : i + 1}
            </div>
            <span className={cn('text-xs ml-1.5', step === i + 1 ? 'text-foreground font-medium' : 'text-muted-foreground')}>
              {s}
            </span>
            {i < STEPS.length - 1 && <div className={cn('flex-1 h-px mx-3', step > i + 1 ? 'bg-green-500' : 'bg-border')} />}
          </div>
        ))}
      </div>

      {/* Step 1: Register */}
      {step === 1 && (
        <div>
          <p className="text-sm text-muted-foreground mb-4">Enter the device details and credentials.</p>
          <DeviceForm
            initial={settingsToDefaults(sysSettings)}
            onSubmit={data => create.mutate(data)}
            onClose={onClose}
            loading={create.isPending}
          />
          {create.error && <p className="text-destructive text-xs mt-2">{String(create.error)}</p>}
        </div>
      )}

      {/* Step 2: Sync */}
      {step === 2 && device && (
        <div className="space-y-4">
          <p className="text-sm text-muted-foreground">
            Pull the current policy from <strong>{device.name}</strong> to populate the Live Policy view and enable AI analysis.
          </p>
          {!syncResult ? (
            <div className="flex flex-col items-center gap-3 py-4">
              <Button onClick={() => sync.mutate()} disabled={sync.isPending} className="w-full">
                {sync.isPending
                  ? <><RefreshCw className="h-4 w-4 mr-2 animate-spin" />Syncing…</>
                  : <><Download className="h-4 w-4 mr-2" />Sync Now</>}
              </Button>
              {sync.error && <p className="text-destructive text-xs">{String(sync.error)}</p>}
              <button onClick={() => setStep(3)} className="text-xs text-muted-foreground hover:text-foreground underline">
                Skip — I'll sync later
              </button>
            </div>
          ) : (
            <div className="space-y-3">
              <div className="flex items-center gap-2 text-sm text-green-600 dark:text-green-400">
                <Check className="h-4 w-4" />
                Synced — found <strong>{syncResult.objects.toLocaleString()}</strong> policy objects
              </div>
              <Button onClick={() => setStep(3)} className="w-full">
                Continue →
              </Button>
            </div>
          )}
        </div>
      )}

      {/* Step 3: Group */}
      {step === 3 && device && (
        <div className="space-y-4">
          <p className="text-sm text-muted-foreground">
            Assign <strong>{device.name}</strong> to an Intent group. Groups define the desired policy state that this device should conform to.
          </p>
          <div className="space-y-2">
            <label className="text-xs text-muted-foreground">Intent Group</label>
            <Select value={groupId} onChange={e => setGroupId(e.target.value)} className="w-full">
              <option value="">— select a group —</option>
              {groups.map(g => <option key={g.id} value={g.id}>{g.name}</option>)}
            </Select>
          </div>
          <div className="flex gap-2">
            <Button
              onClick={() => assign.mutate()}
              disabled={!groupId || assign.isPending}
              className="flex-1"
            >
              {assign.isPending
                ? <><RefreshCw className="h-3.5 w-3.5 mr-1.5 animate-spin" />Assigning…</>
                : <><Layers className="h-3.5 w-3.5 mr-1.5" />Assign & Finish</>}
            </Button>
            <Button variant="outline" onClick={() => onDone(device.name)}>
              Skip
            </Button>
          </div>
          {assign.error && <p className="text-destructive text-xs">{String(assign.error)}</p>}
          {/* Completed after assign */}
          {assign.isSuccess && (
            <div className="space-y-2">
              <div className="flex items-center gap-2 text-sm text-green-600 dark:text-green-400">
                <Check className="h-4 w-4" />{device.name} is now in the fold.
              </div>
              <Button className="w-full" onClick={() => onDone(device.name)}>
                Open Device →
              </Button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── Pipeline status row ───────────────────────────────────────────────────────

function DeviceRow({ device }: { device: Device }) {
  const navigate = useNavigate()
  const stage = deviceStage(device)
  const meta = STAGE_META[stage]

  return (
    <div
      className="flex items-center gap-4 px-4 py-3.5 hover:bg-accent/30 cursor-pointer transition-colors group"
      onClick={() => navigate(`/devices/${device.name}`)}
    >
      {/* Status dot */}
      <div className={cn('h-2.5 w-2.5 rounded-full flex-shrink-0', meta.color)} title={meta.hint} />

      {/* Name + vendor */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="font-medium text-sm">{device.name}</span>
          <Badge variant="outline" className="text-xs">{VENDOR_LABELS[device.vendor] ?? device.vendor}</Badge>
          {device.has_credentials && (
            <Badge variant="success" className="text-xs hidden sm:inline-flex">credentials ✓</Badge>
          )}
        </div>
        <div className="text-xs text-muted-foreground mt-0.5">
          {device.host}{device.port ? `:${device.port}` : ''}
          {device.notes && <span className="ml-2 opacity-70">· {device.notes}</span>}
        </div>
      </div>

      {/* Pipeline steps: Synced / Grouped */}
      <div className="hidden md:flex items-center gap-3 text-xs">
        <div className={cn('flex items-center gap-1', device.last_synced_at ? 'text-green-600 dark:text-green-400' : 'text-muted-foreground/50')}>
          <Wifi className="h-3.5 w-3.5" />
          {device.last_synced_at
            ? <>{device.latest_object_count?.toLocaleString() ?? '?'} objects</>
            : 'Not synced'}
        </div>
        <div className={cn('flex items-center gap-1', device.device_group_name ? 'text-blue-500' : 'text-muted-foreground/50')}>
          <Layers className="h-3.5 w-3.5" />
          {device.device_group_name ?? 'No group'}
        </div>
      </div>

      {/* Last sync + stage */}
      <div className="text-right text-xs text-muted-foreground hidden sm:block w-24 flex-shrink-0">
        {fmtRelative(device.last_synced_at)}
      </div>

      <div className={cn(
        'text-xs px-2 py-0.5 rounded-full flex-shrink-0',
        stage === 'managed'    ? 'bg-green-500/15 text-green-600 dark:text-green-400' :
        stage === 'grouped'    ? 'bg-blue-500/15 text-blue-600 dark:text-blue-400' :
        stage === 'discovered' ? 'bg-yellow-500/15 text-yellow-600 dark:text-yellow-400' :
        'bg-muted text-muted-foreground',
      )}>
        {meta.label}
      </div>

      <ChevronRight className="h-4 w-4 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0" />
    </div>
  )
}

// ── Devices page ──────────────────────────────────────────────────────────────

export function Devices() {
  const navigate = useNavigate()
  const [wizardOpen, setWizardOpen] = useState(false)
  const { data: devices = [], isLoading } = useQuery({ queryKey: ['devices'], queryFn: api.devices.list })

  const byStage = (s: Stage) => devices.filter(d => deviceStage(d) === s)

  const managed    = byStage('managed')
  const discovered = byStage('discovered')
  const grouped    = byStage('grouped')
  const registered = byStage('registered')
  const needsAction = [...discovered, ...grouped, ...registered]

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Devices</h1>
          <p className="text-muted-foreground text-sm mt-1">
            {devices.length} registered ·{' '}
            <span className="text-green-600 dark:text-green-400">{managed.length} managed</span>
            {needsAction.length > 0 && (
              <span className="text-yellow-600 dark:text-yellow-400"> · {needsAction.length} need attention</span>
            )}
          </p>
        </div>
        <Button onClick={() => setWizardOpen(true)}>
          <Plus className="h-4 w-4 mr-1.5" />Add Device
        </Button>
      </div>

      {isLoading && <div className="text-muted-foreground text-sm">Loading…</div>}

      {!isLoading && devices.length === 0 && (
        <Card>
          <CardContent className="py-16 text-center text-muted-foreground">
            <Server className="h-10 w-10 mx-auto mb-3 opacity-30" />
            <p className="font-medium">No devices yet</p>
            <p className="text-sm mt-1 mb-4">Register your first firewall to get started.</p>
            <Button onClick={() => setWizardOpen(true)}>
              <Plus className="h-4 w-4 mr-1.5" />Add Device
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Pipeline summary bar */}
      {devices.length > 0 && (
        <div className="grid grid-cols-4 gap-3">
          {([
            { stage: 'registered' as Stage, label: 'Registered',  count: registered.length },
            { stage: 'discovered' as Stage, label: 'Discovered',  count: discovered.length },
            { stage: 'grouped'    as Stage, label: 'Grouped',     count: grouped.length },
            { stage: 'managed'    as Stage, label: 'Managed',     count: managed.length },
          ]).map(({ stage, label, count }) => (
            <div key={stage} className="rounded-lg border border-border bg-card p-3 text-center">
              <div className="flex items-center justify-center gap-1.5 mb-1">
                <div className={cn('h-2 w-2 rounded-full', STAGE_META[stage].color)} />
                <span className="text-xs text-muted-foreground">{label}</span>
              </div>
              <div className="text-2xl font-semibold">{count}</div>
            </div>
          ))}
        </div>
      )}

      {/* Device list */}
      {devices.length > 0 && (
        <Card className="overflow-hidden">
          <div className="divide-y divide-border">
            {/* Managed first, then by name within groups */}
            {[...managed, ...discovered, ...grouped, ...registered].map(d => (
              <DeviceRow key={d.name} device={d} />
            ))}
          </div>
        </Card>
      )}

      {/* Onboarding wizard */}
      <Dialog open={wizardOpen} onClose={() => setWizardOpen(false)} title="Add Device" className="max-w-lg">
        <OnboardWizard
          onClose={() => setWizardOpen(false)}
          onDone={(name) => { setWizardOpen(false); navigate(`/devices/${name}`) }}
        />
      </Dialog>
    </div>
  )
}
