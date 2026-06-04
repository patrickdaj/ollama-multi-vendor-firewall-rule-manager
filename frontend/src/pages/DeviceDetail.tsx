import { useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  ChevronLeft, Download, RotateCcw, Edit, Trash2, RefreshCw,
  Wifi, Layers, Clock, ShieldCheck, Check, AlertCircle,
  CheckCircle2, GitCompare, Ghost, AlertTriangle, ChevronDown, ChevronRight,
} from 'lucide-react'
import {
  api, type Device, type DeviceCreate, type Group,
  type ZoneMapping, type Snapshot, type ComplianceItem,
} from '@/lib/api'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Select } from '@/components/ui/select'
import { Dialog } from '@/components/ui/dialog'
import { VENDOR_LABELS, OBJECT_TYPE_LABELS, fmtRelative, cn } from '@/lib/utils'
import { useAiDock } from '@/contexts/AiDockContext'

// ── Tab type ──────────────────────────────────────────────────────────────────

type Tab = 'overview' | 'compliance' | 'intent' | 'history'

const TABS: { id: Tab; label: string; icon: React.ReactNode }[] = [
  { id: 'overview',   label: 'Overview',   icon: <Wifi className="h-3.5 w-3.5" /> },
  { id: 'compliance', label: 'Compliance', icon: <ShieldCheck className="h-3.5 w-3.5" /> },
  { id: 'intent',     label: 'Intent',     icon: <Layers className="h-3.5 w-3.5" /> },
  { id: 'history',    label: 'History',    icon: <Clock className="h-3.5 w-3.5" /> },
]

// ── Compliance tab ────────────────────────────────────────────────────────────

const BUCKET_META = {
  compliant: { label: 'Compliant',  color: 'text-green-600',    bg: 'bg-green-500/10', icon: <CheckCircle2 className="h-3.5 w-3.5" /> },
  drifted:   { label: 'Drifted',    color: 'text-amber-500',    bg: 'bg-amber-500/10', icon: <GitCompare className="h-3.5 w-3.5" /> },
  missing:   { label: 'Missing',    color: 'text-blue-500',     bg: 'bg-blue-500/10',  icon: <AlertTriangle className="h-3.5 w-3.5" /> },
  orphan:    { label: 'Orphan',     color: 'text-muted-foreground', bg: 'bg-muted/20', icon: <Ghost className="h-3.5 w-3.5" /> },
}

function ComplianceSection({ title, items, bucket }: {
  title: string
  items: ComplianceItem[]
  bucket: keyof typeof BUCKET_META
}) {
  const [open, setOpen] = useState(bucket !== 'compliant' && bucket !== 'orphan')
  const meta = BUCKET_META[bucket]
  if (items.length === 0) return null
  return (
    <div className="border border-border rounded-md overflow-hidden">
      <button
        className={cn('flex items-center justify-between w-full px-4 py-3', meta.bg)}
        onClick={() => setOpen(x => !x)}
      >
        <div className={cn('flex items-center gap-2 font-medium text-sm', meta.color)}>
          {meta.icon}
          {title}
          <span className="font-semibold">({items.length})</span>
        </div>
        {open ? <ChevronDown className="h-4 w-4 text-muted-foreground" /> : <ChevronRight className="h-4 w-4 text-muted-foreground" />}
      </button>
      {open && (
        <div className="divide-y divide-border">
          {items.map((item, i) => (
            <div key={i} className="px-4 py-2.5 hover:bg-accent/20">
              <div className="flex items-center gap-3">
                <Badge variant="outline" className="text-xs capitalize flex-shrink-0">
                  {OBJECT_TYPE_LABELS[item.object_type] ?? item.object_type}
                </Badge>
                <span className="font-medium text-sm flex-1 truncate">{item.object_name}</span>
              </div>
              {bucket === 'drifted' && item.intent_data && item.live_data && (
                <div className="mt-2 grid grid-cols-2 gap-2">
                  <div>
                    <p className="text-xs text-muted-foreground mb-1">Intent</p>
                    <pre className="text-xs bg-blue-500/10 rounded p-2 overflow-auto max-h-32 whitespace-pre-wrap">
                      {JSON.stringify(item.intent_data, null, 2)}
                    </pre>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground mb-1">Live</p>
                    <pre className="text-xs bg-amber-500/10 rounded p-2 overflow-auto max-h-32 whitespace-pre-wrap">
                      {JSON.stringify(item.live_data, null, 2)}
                    </pre>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function ComplianceTab({ device }: { device: Device }) {
  const { data: groups = [] } = useQuery({ queryKey: ['groups'], queryFn: api.groups.list })
  const group = groups.find(g => g.id === device.device_group_id)

  const { data: compliance, isLoading, refetch, isFetching } = useQuery({
    queryKey: ['compliance', device.device_group_id, device.name],
    queryFn: () => api.groups.getCompliance(device.device_group_id!, device.name),
    enabled: !!device.device_group_id && !!device.last_synced_at,
  })

  if (!device.last_synced_at) {
    return (
      <Card>
        <CardContent className="py-12 text-center text-muted-foreground">
          <ShieldCheck className="h-10 w-10 mx-auto mb-3 opacity-20" />
          <p className="font-medium">No snapshot yet</p>
          <p className="text-sm mt-1">Sync this device first to compare against intent.</p>
        </CardContent>
      </Card>
    )
  }

  if (!device.device_group_id) {
    return (
      <Card>
        <CardContent className="py-12 text-center text-muted-foreground">
          <ShieldCheck className="h-10 w-10 mx-auto mb-3 opacity-20" />
          <p className="font-medium">Not assigned to an Intent group</p>
          <p className="text-sm mt-1">Assign this device to a group to see compliance.</p>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-muted-foreground">
            Comparing live snapshot to intent policy in <strong>{group?.name ?? `group #${device.device_group_id}`}</strong>
          </p>
        </div>
        <Button size="sm" variant="outline" onClick={() => refetch()} disabled={isFetching}>
          <RefreshCw className={cn('h-3.5 w-3.5 mr-1', isFetching && 'animate-spin')} />
          Refresh
        </Button>
      </div>

      {isLoading && <div className="text-muted-foreground text-sm">Computing compliance…</div>}

      {compliance && (
        <>
          {/* Score bar */}
          <div className="flex items-center gap-4">
            <div className="relative h-3 flex-1 rounded-full bg-muted overflow-hidden">
              <div
                className="absolute left-0 top-0 h-full bg-green-500 transition-all"
                style={{ width: `${compliance.score}%` }}
              />
            </div>
            <span className={cn(
              'text-sm font-bold',
              compliance.score >= 90 ? 'text-green-600' :
              compliance.score >= 60 ? 'text-amber-500' : 'text-destructive',
            )}>
              {compliance.score}% compliant
            </span>
          </div>

          {/* Summary tiles */}
          <div className="grid grid-cols-4 gap-3">
            {(Object.entries(BUCKET_META) as [keyof typeof BUCKET_META, typeof BUCKET_META[keyof typeof BUCKET_META]][]).map(([k, meta]) => (
              <div key={k} className={cn('rounded-lg p-3 text-center', meta.bg)}>
                <div className={cn('text-xl font-bold', meta.color)}>
                  {compliance[k].length}
                </div>
                <div className="text-xs text-muted-foreground mt-0.5">{meta.label}</div>
              </div>
            ))}
          </div>

          {/* Sections */}
          <ComplianceSection title="Drifted" items={compliance.drifted} bucket="drifted" />
          <ComplianceSection title="Missing from device" items={compliance.missing} bucket="missing" />
          <ComplianceSection title="Orphan (on device, not in intent)" items={compliance.orphan} bucket="orphan" />
          <ComplianceSection title="Compliant" items={compliance.compliant} bucket="compliant" />

          {compliance.drifted.length === 0 && compliance.missing.length === 0 && (
            <div className="flex items-center gap-2 text-green-600 text-sm py-2">
              <Check className="h-4 w-4" />
              Device policy is fully aligned with intent.
            </div>
          )}
        </>
      )}
    </div>
  )
}

// ── Overview tab ──────────────────────────────────────────────────────────────

function OverviewTab({ device }: { device: Device }) {
  const qc = useQueryClient()
  const [editOpen, setEditOpen] = useState(false)
  const [confirmDelete, setConfirmDelete] = useState(false)
  const navigate = useNavigate()

  const onboard = useMutation({
    mutationFn: () => api.devices.onboard(device.name),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['device', device.name] }),
  })
  const reindex = useMutation({
    mutationFn: () => api.devices.reindex(device.name),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['device', device.name] }),
  })
  const update = useMutation({
    mutationFn: (data: Partial<DeviceCreate>) => api.devices.update(device.name, data),
    onSuccess: () => { setEditOpen(false); qc.invalidateQueries({ queryKey: ['device', device.name] }) },
  })
  const remove = useMutation({
    mutationFn: () => api.devices.delete(device.name).then(() => undefined),
    onSuccess: () => navigate('/devices'),
  })

  return (
    <div className="space-y-5">
      {/* Connection details */}
      <Card>
        <CardContent className="p-5">
          <div className="flex items-start justify-between mb-4">
            <div>
              <h3 className="font-semibold">Connection</h3>
              <p className="text-xs text-muted-foreground mt-0.5">Device registration and credential details</p>
            </div>
            <Button size="sm" variant="outline" onClick={() => setEditOpen(true)}>
              <Edit className="h-3.5 w-3.5 mr-1.5" />Edit
            </Button>
          </div>
          <dl className="grid grid-cols-2 gap-x-8 gap-y-3 text-sm">
            <div>
              <dt className="text-xs text-muted-foreground">Vendor</dt>
              <dd className="font-medium mt-0.5">{VENDOR_LABELS[device.vendor] ?? device.vendor}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">Host</dt>
              <dd className="font-mono mt-0.5">{device.host ?? '—'}{device.port ? `:${device.port}` : ''}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">SSL Verify</dt>
              <dd className="mt-0.5">{device.verify_ssl ? 'Yes' : 'No'}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">Credentials</dt>
              <dd className="mt-0.5">
                {device.has_credentials
                  ? <span className="text-green-600 dark:text-green-400 flex items-center gap-1"><Check className="h-3.5 w-3.5" />Stored encrypted</span>
                  : <span className="text-yellow-600 dark:text-yellow-400 flex items-center gap-1"><AlertCircle className="h-3.5 w-3.5" />Not set</span>}
              </dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">Registered</dt>
              <dd className="mt-0.5">{new Date(device.created_at).toLocaleDateString()}</dd>
            </div>
            {device.notes && (
              <div className="col-span-2">
                <dt className="text-xs text-muted-foreground">Notes</dt>
                <dd className="mt-0.5">{device.notes}</dd>
              </div>
            )}
          </dl>
        </CardContent>
      </Card>

      {/* Sync status */}
      <Card>
        <CardContent className="p-5">
          <div className="flex items-start justify-between mb-4">
            <div>
              <h3 className="font-semibold">Sync Status</h3>
              <p className="text-xs text-muted-foreground mt-0.5">Policy snapshot and RAG index</p>
            </div>
            <div className="flex gap-2">
              <Button
                size="sm" variant="outline"
                onClick={() => onboard.mutate()}
                disabled={onboard.isPending}
                title="Pull latest policy from device"
              >
                {onboard.isPending
                  ? <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                  : <Download className="h-3.5 w-3.5" />}
                <span className="ml-1.5">Sync Now</span>
              </Button>
              <Button
                size="sm" variant="outline"
                onClick={() => reindex.mutate()}
                disabled={reindex.isPending}
                title="Re-index ChromaDB from Postgres snapshot"
              >
                {reindex.isPending
                  ? <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                  : <RotateCcw className="h-3.5 w-3.5" />}
                <span className="ml-1.5">Reindex</span>
              </Button>
            </div>
          </div>
          <dl className="grid grid-cols-3 gap-x-8 gap-y-3 text-sm">
            <div>
              <dt className="text-xs text-muted-foreground">Last Sync</dt>
              <dd className="font-medium mt-0.5">{fmtRelative(device.last_synced_at) || 'Never'}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">Snapshots</dt>
              <dd className="font-medium mt-0.5">{device.snapshot_count}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">Objects</dt>
              <dd className="font-medium mt-0.5">{device.latest_object_count?.toLocaleString() ?? '—'}</dd>
            </div>
          </dl>
          {(onboard.error || reindex.error) && (
            <p className="text-destructive text-xs mt-3">{String(onboard.error ?? reindex.error)}</p>
          )}
          {(onboard.isSuccess) && (
            <p className="text-green-600 dark:text-green-400 text-xs mt-3">Sync complete.</p>
          )}
        </CardContent>
      </Card>

      {/* Intent group */}
      <Card>
        <CardContent className="p-5">
          <h3 className="font-semibold mb-1">Intent Group</h3>
          {device.device_group_name ? (
            <div className="flex items-center gap-2 text-sm">
              <Layers className="h-4 w-4 text-blue-500" />
              <Link to="/groups" className="text-primary hover:underline font-medium">
                {device.device_group_name}
              </Link>
              <span className="text-muted-foreground text-xs">— click to manage group policy</span>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">
              Not assigned to a group.{' '}
              <Link to="/groups" className="text-primary hover:underline">Go to Intent →</Link>
            </p>
          )}
        </CardContent>
      </Card>

      {/* Danger zone */}
      <Card className="border-destructive/30">
        <CardContent className="p-5">
          <h3 className="font-semibold text-destructive mb-1">Remove Device</h3>
          <p className="text-xs text-muted-foreground mb-3">
            Removes this device and all its snapshots from the database. ChromaDB data is not affected.
          </p>
          <Button variant="destructive" size="sm" onClick={() => setConfirmDelete(true)}>
            <Trash2 className="h-3.5 w-3.5 mr-1.5" />Remove Device
          </Button>
        </CardContent>
      </Card>

      {/* Edit dialog */}
      <Dialog open={editOpen} onClose={() => setEditOpen(false)} title={`Edit ${device.name}`}>
        <DeviceEditForm device={device} onSubmit={data => update.mutate(data)} onClose={() => setEditOpen(false)} loading={update.isPending} />
      </Dialog>

      {/* Delete dialog */}
      <Dialog open={confirmDelete} onClose={() => setConfirmDelete(false)} title="Remove device?">
        <p className="text-sm text-muted-foreground mb-4">
          This removes <strong>{device.name}</strong> and all its snapshots.
        </p>
        <div className="flex justify-end gap-2">
          <Button variant="ghost" onClick={() => setConfirmDelete(false)}>Cancel</Button>
          <Button variant="destructive" onClick={() => remove.mutate()} disabled={remove.isPending}>
            {remove.isPending ? 'Removing…' : 'Remove'}
          </Button>
        </div>
      </Dialog>
    </div>
  )
}

// ── Intent tab ────────────────────────────────────────────────────────────────

function IntentTab({ device }: { device: Device }) {
  const qc = useQueryClient()
  const { addBackgroundJob } = useAiDock()
  const [newGroupId, setNewGroupId] = useState('')
  const [importOpen, setImportOpen] = useState(false)

  const { data: groups = [] } = useQuery<Group[]>({ queryKey: ['groups'], queryFn: api.groups.list })
  const { data: zones = [] } = useQuery<ZoneMapping[]>({
    queryKey: ['zones', device.name],
    queryFn: () => api.groups.listZones(device.name),
  })

  const assign = useMutation({
    mutationFn: () => api.groups.assignDevice(+newGroupId, device.name),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['device', device.name] }); setNewGroupId('') },
  })

  const startImport = useMutation({
    mutationFn: () => {
      const gid = device.device_group_id!
      return api.groups.importStart(gid, device.name)
    },
    onSuccess: (data) => {
      addBackgroundJob({
        taskId: data.task_id,
        label: `Import from ${device.name}`,
        href: `/groups`,
        startedAt: Date.now(),
      })
      setImportOpen(false)
    },
  })

  return (
    <div className="space-y-5">
      {/* Group assignment */}
      <Card>
        <CardContent className="p-5">
          <h3 className="font-semibold mb-3">Group Assignment</h3>
          {device.device_group_name ? (
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-sm">
                <Layers className="h-4 w-4 text-blue-500" />
                <span className="font-medium">{device.device_group_name}</span>
              </div>
              <div className="flex items-center gap-2">
                <Select value={newGroupId} onChange={e => setNewGroupId(e.target.value)} className="w-44">
                  <option value="">Move to…</option>
                  {groups.filter(g => g.id !== device.device_group_id).map(g => (
                    <option key={g.id} value={g.id}>{g.name}</option>
                  ))}
                </Select>
                <Button size="sm" disabled={!newGroupId || assign.isPending} onClick={() => assign.mutate()}>
                  {assign.isPending ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : 'Move'}
                </Button>
              </div>
            </div>
          ) : (
            <div className="flex items-center gap-3">
              <Select value={newGroupId} onChange={e => setNewGroupId(e.target.value)} className="flex-1">
                <option value="">Select a group…</option>
                {groups.map(g => <option key={g.id} value={g.id}>{g.name}</option>)}
              </Select>
              <Button disabled={!newGroupId || assign.isPending} onClick={() => assign.mutate()}>
                {assign.isPending ? <RefreshCw className="h-3.5 w-3.5 mr-1.5 animate-spin" /> : <Layers className="h-3.5 w-3.5 mr-1.5" />}
                Assign
              </Button>
            </div>
          )}
          {assign.error && <p className="text-destructive text-xs mt-2">{String(assign.error)}</p>}
        </CardContent>
      </Card>

      {/* Zone mappings */}
      <Card>
        <CardContent className="p-5">
          <div className="flex items-start justify-between mb-3">
            <div>
              <h3 className="font-semibold">Zone Mappings</h3>
              <p className="text-xs text-muted-foreground mt-0.5">Vendor zones → logical zones used in group policy</p>
            </div>
            <Link to="/groups" className="text-xs text-primary hover:underline">Edit in Intent →</Link>
          </div>
          {zones.length === 0 ? (
            <p className="text-sm text-muted-foreground">No zone mappings defined.</p>
          ) : (
            <div className="divide-y divide-border rounded-md border border-border overflow-hidden">
              {zones.map(z => (
                <div key={z.id} className="flex items-center justify-between px-3 py-2 text-sm">
                  <span className="font-mono text-xs">{z.vendor_zone}</span>
                  <span className="text-muted-foreground mx-2">→</span>
                  <span className="text-xs font-medium">{z.logical_zone}</span>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Import policy */}
      {device.device_group_id && device.last_synced_at && (
        <Card>
          <CardContent className="p-5">
            <h3 className="font-semibold mb-1">Import Policy into Intent</h3>
            <p className="text-xs text-muted-foreground mb-3">
              AI-normalize this device's current snapshot and add selected rules/objects to its Intent group as desired state.
            </p>
            <Button onClick={() => setImportOpen(true)} disabled={startImport.isPending}>
              {startImport.isPending
                ? <><RefreshCw className="h-3.5 w-3.5 mr-1.5 animate-spin" />Queuing…</>
                : 'Import Policy…'}
            </Button>
            {startImport.isSuccess && (
              <p className="text-green-600 dark:text-green-400 text-xs mt-2">
                Import queued — you'll get a notification when it's ready.
              </p>
            )}
          </CardContent>
        </Card>
      )}

      {/* Confirm import dialog */}
      <Dialog open={importOpen} onClose={() => setImportOpen(false)} title="Import Policy">
        <p className="text-sm text-muted-foreground mb-4">
          This will pull up to 50 objects from <strong>{device.name}</strong>'s latest snapshot, normalize them with AI, and queue a review. The job runs in the background.
        </p>
        <div className="flex justify-end gap-2">
          <Button variant="ghost" onClick={() => setImportOpen(false)}>Cancel</Button>
          <Button onClick={() => startImport.mutate()} disabled={startImport.isPending}>
            Start Import
          </Button>
        </div>
      </Dialog>
    </div>
  )
}

// ── History tab ───────────────────────────────────────────────────────────────

function HistoryTab({ device }: { device: Device }) {
  const { data: snapshots = [], isLoading } = useQuery<Snapshot[]>({
    queryKey: ['snapshots', device.name],
    queryFn: () => api.snapshots.list(device.name),
  })

  return (
    <div className="space-y-3">
      {isLoading && <div className="text-sm text-muted-foreground">Loading…</div>}
      {!isLoading && snapshots.length === 0 && (
        <Card>
          <CardContent className="py-10 text-center text-muted-foreground">
            <Clock className="h-8 w-8 mx-auto mb-2 opacity-30" />
            <p>No snapshots yet. Sync the device to capture its first snapshot.</p>
          </CardContent>
        </Card>
      )}
      <Card className="overflow-hidden">
        <div className="divide-y divide-border">
          {snapshots.map(s => (
            <div key={s.id} className="flex items-center gap-4 px-4 py-3 text-sm">
              <div className={cn(
                'h-2 w-2 rounded-full flex-shrink-0',
                s.status === 'complete' ? 'bg-green-500' :
                s.status === 'failed'   ? 'bg-destructive' : 'bg-yellow-400',
              )} />
              <div className="flex-1 min-w-0">
                <div className="font-medium">{new Date(s.created_at).toLocaleString()}</div>
                <div className="text-xs text-muted-foreground capitalize">{s.status} · triggered by {s.triggered_by}</div>
              </div>
              <div className="text-right text-xs text-muted-foreground">
                {s.object_count != null ? <>{s.object_count.toLocaleString()} objects</> : '—'}
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  )
}

// ── Edit form (inline, no wizard) ─────────────────────────────────────────────

function DeviceEditForm({ device, onSubmit, onClose, loading }: {
  device: Device
  onSubmit: (d: Partial<DeviceCreate>) => void
  onClose: () => void
  loading?: boolean
}) {
  const [form, setForm] = useState({
    host: device.host ?? '',
    port: device.port ?? ('' as string | number),
    verify_ssl: device.verify_ssl,
    username: '',
    password: '',
    api_key: '',
    notes: device.notes ?? '',
  })
  const set = (k: string) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setForm(f => ({ ...f, [k]: e.target.value }))

  return (
    <form onSubmit={e => { e.preventDefault(); onSubmit(form as Partial<DeviceCreate>) }} className="space-y-3">
      <div className="grid grid-cols-3 gap-3">
        <div className="col-span-2 space-y-1">
          <label className="text-xs text-muted-foreground">Host / IP</label>
          <Input value={form.host} onChange={set('host')} required />
        </div>
        <div className="space-y-1">
          <label className="text-xs text-muted-foreground">Port</label>
          <Input value={form.port} onChange={e => setForm(f => ({ ...f, port: e.target.value ? +e.target.value : '' }))} type="number" />
        </div>
      </div>
      <div className="space-y-1">
        <label className="text-xs text-muted-foreground">Username (leave blank to keep existing)</label>
        <Input value={form.username} onChange={set('username')} autoComplete="off" />
      </div>
      <div className="space-y-1">
        <label className="text-xs text-muted-foreground">Password (leave blank to keep existing)</label>
        <Input value={form.password} onChange={set('password')} type="password" autoComplete="new-password" />
      </div>
      <div className="space-y-1">
        <label className="text-xs text-muted-foreground">API Key (PAN-OS)</label>
        <Input value={form.api_key} onChange={set('api_key')} autoComplete="off" />
      </div>
      <div className="space-y-1">
        <label className="text-xs text-muted-foreground">Notes</label>
        <Input value={form.notes} onChange={set('notes')} />
      </div>
      <div className="flex items-center gap-2">
        <input type="checkbox" id="ssl2" checked={form.verify_ssl}
          onChange={e => setForm(f => ({ ...f, verify_ssl: e.target.checked }))} className="rounded" />
        <label htmlFor="ssl2" className="text-sm">Verify SSL</label>
      </div>
      <div className="flex justify-end gap-2 pt-2">
        <Button type="button" variant="ghost" onClick={onClose}>Cancel</Button>
        <Button type="submit" disabled={loading}>{loading ? 'Saving…' : 'Update'}</Button>
      </div>
    </form>
  )
}

// ── DeviceDetail page ─────────────────────────────────────────────────────────

export function DeviceDetail() {
  const { name } = useParams<{ name: string }>()
  const navigate = useNavigate()
  const [activeTab, setActiveTab] = useState<Tab>('overview')

  const { data: device, isLoading, error } = useQuery<Device>({
    queryKey: ['device', name],
    queryFn: () => api.devices.get(name!),
    enabled: !!name,
  })

  if (isLoading) {
    return <div className="p-6 text-muted-foreground text-sm">Loading…</div>
  }
  if (error || !device) {
    return (
      <div className="p-6">
        <p className="text-destructive">Device not found.</p>
        <Button variant="ghost" size="sm" onClick={() => navigate('/devices')} className="mt-2">
          ← Back to Devices
        </Button>
      </div>
    )
  }

  const synced = !!device.last_synced_at
  const stageColor = device.device_group_id && synced ? 'bg-green-500' :
                     device.last_synced_at ? 'bg-yellow-500' : 'bg-muted-foreground/40'

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div>
        <button
          onClick={() => navigate('/devices')}
          className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground mb-3 transition-colors"
        >
          <ChevronLeft className="h-3.5 w-3.5" />Devices
        </button>
        <div className="flex items-start gap-3">
          <div className={cn('h-3 w-3 rounded-full flex-shrink-0 mt-1.5', stageColor)} />
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2.5 flex-wrap">
              <h1 className="text-2xl font-bold">{device.name}</h1>
              <Badge variant="outline">{VENDOR_LABELS[device.vendor] ?? device.vendor}</Badge>
              {device.has_credentials && <Badge variant="success">credentials ✓</Badge>}
              {device.device_group_name && (
                <Badge variant="secondary" className="flex items-center gap-1">
                  <Layers className="h-3 w-3" />{device.device_group_name}
                </Badge>
              )}
            </div>
            <p className="text-sm text-muted-foreground mt-0.5">
              {device.host}{device.port ? `:${device.port}` : ''}
              {device.last_synced_at
                ? <> · Last sync {fmtRelative(device.last_synced_at)} · {device.latest_object_count?.toLocaleString()} objects</>
                : ' · Never synced'}
            </p>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-border">
        <div className="flex gap-0">
          {TABS.map(t => (
            <button
              key={t.id}
              onClick={() => setActiveTab(t.id)}
              className={cn(
                'flex items-center gap-1.5 px-4 py-2.5 text-sm border-b-2 -mb-px transition-colors',
                activeTab === t.id
                  ? 'border-primary text-primary font-medium'
                  : 'border-transparent text-muted-foreground hover:text-foreground',
              )}
            >
              {t.icon}
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {/* Tab content */}
      {activeTab === 'overview'   && <OverviewTab device={device} />}
      {activeTab === 'compliance' && <ComplianceTab device={device} />}
      {activeTab === 'intent'     && <IntentTab device={device} />}
      {activeTab === 'history'    && <HistoryTab device={device} />}
    </div>
  )
}
