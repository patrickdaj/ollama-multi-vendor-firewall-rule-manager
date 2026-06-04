import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Upload, Server, RefreshCw, Check, AlertTriangle, ChevronRight,
  ChevronDown, Play, RotateCcw, Clock, AlertCircle, Zap,
} from 'lucide-react'
import { api, type Device, type PushJob, type PushJobItem } from '@/lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Dialog } from '@/components/ui/dialog'
import { VENDOR_LABELS, OBJECT_TYPE_LABELS, fmtRelative, cn } from '@/lib/utils'

// ── Status helpers ────────────────────────────────────────────────────────────

const JOB_STATUS_META: Record<string, { color: string; label: string }> = {
  pending:     { color: 'text-muted-foreground', label: 'Preview ready' },
  running:     { color: 'text-blue-500',         label: 'Pushing…' },
  complete:    { color: 'text-green-600',         label: 'Complete' },
  failed:      { color: 'text-destructive',       label: 'Failed' },
  partial:     { color: 'text-amber-500',         label: 'Partial' },
  rolled_back: { color: 'text-muted-foreground', label: 'Rolled back' },
}

const ACTION_BADGE: Record<string, string> = {
  create:    'bg-green-500/15 text-green-700 border-green-500/30',
  update:    'bg-amber-500/15 text-amber-700 border-amber-500/30',
  delete:    'bg-destructive/15 text-destructive border-destructive/30',
  'no-change': 'bg-muted/50 text-muted-foreground border-border',
}

// ── Item list ─────────────────────────────────────────────────────────────────

function PushItemRow({ item }: { item: PushJobItem }) {
  const [expanded, setExpanded] = useState(false)
  return (
    <div className="border-t border-border">
      <div
        className="flex items-center gap-3 px-3 py-2 hover:bg-accent/20 cursor-pointer text-sm"
        onClick={() => setExpanded(x => !x)}
      >
        {expanded ? <ChevronDown className="h-3.5 w-3.5 text-muted-foreground flex-shrink-0" /> : <ChevronRight className="h-3.5 w-3.5 text-muted-foreground flex-shrink-0" />}
        <span className={cn('text-xs px-1.5 py-0.5 rounded border font-medium flex-shrink-0', ACTION_BADGE[item.action] ?? ACTION_BADGE['no-change'])}>
          {item.action}
        </span>
        <Badge variant="outline" className="text-xs flex-shrink-0">
          {OBJECT_TYPE_LABELS[item.object_type] ?? item.object_type}
        </Badge>
        <span className="font-mono flex-1 truncate">{item.item_name}</span>
        {item.status === 'failed' && <AlertCircle className="h-3.5 w-3.5 text-destructive flex-shrink-0" />}
        {item.status === 'success' && <Check className="h-3.5 w-3.5 text-green-600 flex-shrink-0" />}
        {item.status === 'skipped' && <span className="text-xs text-muted-foreground">skipped</span>}
      </div>
      {expanded && (
        <div className="px-8 pb-3 space-y-2">
          {item.error && (
            <p className="text-xs text-destructive">{item.error}</p>
          )}
          <pre className="text-xs bg-muted/30 rounded p-2 overflow-auto max-h-48">
            {JSON.stringify(item.vendor_payload, null, 2)}
          </pre>
        </div>
      )}
    </div>
  )
}

function JobDetail({ job, onExecute, onRollback }: {
  job: PushJob
  onExecute: () => void
  onRollback: () => void
}) {
  const [filter, setFilter] = useState<string>('all')
  const [confirmOpen, setConfirmOpen] = useState(false)

  const { data: items = [], isLoading } = useQuery({
    queryKey: ['push-job-items', job.id, filter],
    queryFn: () => api.push.getJobItems(job.id, filter === 'all' ? undefined : filter),
  })

  const statusMeta = JOB_STATUS_META[job.status] ?? JOB_STATUS_META.pending

  return (
    <div className="space-y-4">
      {/* Job header */}
      <div className="flex items-start justify-between">
        <div>
          <div className={cn('flex items-center gap-2 text-sm font-medium', statusMeta.color)}>
            {job.status === 'running' && <RefreshCw className="h-4 w-4 animate-spin" />}
            {job.status === 'complete' && <Check className="h-4 w-4" />}
            {statusMeta.label}
          </div>
          <p className="text-xs text-muted-foreground mt-1">
            {job.dry_run ? 'Preview (not pushed)' : 'Live push'} · {fmtRelative(job.created_at)}
          </p>
        </div>
        <div className="flex gap-2">
          {job.status === 'pending' && (
            <Button size="sm" onClick={() => setConfirmOpen(true)}>
              <Play className="h-3.5 w-3.5 mr-1" />Execute Push
            </Button>
          )}
          {['complete', 'partial', 'failed'].includes(job.status) && (
            <Button size="sm" variant="outline" onClick={onRollback}>
              <RotateCcw className="h-3.5 w-3.5 mr-1" />Rollback
            </Button>
          )}
        </div>
      </div>

      {/* Counts */}
      <div className="grid grid-cols-4 gap-2 text-center">
        {[
          { label: 'Create', count: job.creates, color: 'text-green-600' },
          { label: 'Update', count: job.updates, color: 'text-amber-500' },
          { label: 'No-change', count: job.no_changes, color: 'text-muted-foreground' },
          { label: 'Failed', count: job.failed, color: 'text-destructive' },
        ].map(({ label, count, color }) => (
          <div key={label} className="border border-border rounded-md p-2">
            <div className={cn('text-lg font-bold', color)}>{count}</div>
            <div className="text-xs text-muted-foreground">{label}</div>
          </div>
        ))}
      </div>

      {job.error_summary && (
        <p className="text-xs text-amber-600 bg-amber-500/10 rounded p-2">{job.error_summary}</p>
      )}

      {/* Item filter chips */}
      <div className="flex gap-1.5">
        {['all', 'create', 'update', 'no-change'].map(f => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={cn(
              'text-xs px-2 py-0.5 rounded-full border transition-colors capitalize',
              filter === f ? 'bg-primary/15 border-primary/40 text-primary font-medium' : 'border-border text-muted-foreground hover:border-primary/30',
            )}
          >
            {f === 'all' ? 'All' : f}
          </button>
        ))}
      </div>

      {/* Items */}
      {isLoading && <div className="text-muted-foreground text-sm">Loading items…</div>}
      <div className="border border-border rounded-md overflow-hidden max-h-96 overflow-y-auto">
        {items.length === 0 && !isLoading && (
          <p className="px-4 py-6 text-center text-muted-foreground text-sm">No items match this filter.</p>
        )}
        {items.map(item => <PushItemRow key={item.id} item={item} />)}
      </div>

      {/* Execute confirmation */}
      <Dialog open={confirmOpen} onClose={() => setConfirmOpen(false)} title="Execute Push?">
        <div className="space-y-4">
          <div className="bg-destructive/10 border border-destructive/30 rounded-md p-3 text-sm text-destructive">
            <AlertTriangle className="h-4 w-4 inline mr-1.5" />
            This will send {job.creates + job.updates} changes to <strong>{job.device_name}</strong>.
            This modifies live firewall configuration.
          </div>
          <p className="text-sm text-muted-foreground">
            {job.creates} objects/rules to create · {job.updates} to update
          </p>
          <div className="flex justify-end gap-2">
            <Button variant="ghost" onClick={() => setConfirmOpen(false)}>Cancel</Button>
            <Button
              variant="destructive"
              onClick={() => { setConfirmOpen(false); onExecute() }}
            >
              <Play className="h-3.5 w-3.5 mr-1" />Execute
            </Button>
          </div>
        </div>
      </Dialog>
    </div>
  )
}

// ── Device list panel ─────────────────────────────────────────────────────────

function DeviceDeployRow({
  device, latestJob, selected, onClick,
}: {
  device: Device
  latestJob: PushJob | undefined
  selected: boolean
  onClick: () => void
}) {
  const statusMeta = latestJob ? JOB_STATUS_META[latestJob.status] : null

  return (
    <div
      onClick={onClick}
      className={cn(
        'flex items-center gap-3 px-3 py-2.5 cursor-pointer hover:bg-accent transition-colors rounded-md',
        selected && 'bg-primary/10 text-primary',
      )}
    >
      <Server className="h-4 w-4 text-muted-foreground flex-shrink-0" />
      <div className="flex-1 min-w-0">
        <div className="font-medium text-sm truncate">{device.name}</div>
        <div className="text-xs text-muted-foreground">{VENDOR_LABELS[device.vendor] ?? device.vendor}</div>
      </div>
      {statusMeta ? (
        <span className={cn('text-xs font-medium', statusMeta.color)}>{statusMeta.label}</span>
      ) : (
        <span className="text-xs text-muted-foreground">Never deployed</span>
      )}
    </div>
  )
}

// ── Page root ─────────────────────────────────────────────────────────────────

export function Deploy() {
  const qc = useQueryClient()
  const [selectedDevice, setSelectedDevice] = useState<string | null>(null)
  const [selectedJobId, setSelectedJobId] = useState<number | null>(null)

  const { data: devices = [] } = useQuery({ queryKey: ['devices'], queryFn: api.devices.list })

  const { data: allJobs = [], refetch: refetchJobs } = useQuery({
    queryKey: ['push-jobs'],
    queryFn: () => api.push.listJobs(),
    refetchInterval: 5000,
  })

  const { data: deviceJobs = [] } = useQuery({
    queryKey: ['push-jobs-device', selectedDevice],
    queryFn: () => api.push.listJobs(selectedDevice ?? undefined),
    enabled: !!selectedDevice,
  })

  const selectedJob = selectedJobId
    ? deviceJobs.find(j => j.id === selectedJobId) ?? allJobs.find(j => j.id === selectedJobId)
    : deviceJobs[0]

  // Latest job per device for the sidebar
  const latestJobByDevice = new Map<string, PushJob>()
  for (const job of allJobs) {
    if (!latestJobByDevice.has(job.device_name)) {
      latestJobByDevice.set(job.device_name, job)
    }
  }

  const preview = useMutation({
    mutationFn: (deviceName: string) => {
      const device = devices.find(d => d.name === deviceName)
      return api.push.createJob({ device_name: deviceName, group_id: device?.device_group_id ?? undefined, dry_run: true })
    },
    onSuccess: (job) => {
      setSelectedJobId(job.id)
      qc.invalidateQueries({ queryKey: ['push-jobs'] })
      qc.invalidateQueries({ queryKey: ['push-jobs-device', selectedDevice] })
    },
  })

  const execute = useMutation({
    mutationFn: (jobId: number) => api.push.execute(jobId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['push-jobs'] })
      qc.invalidateQueries({ queryKey: ['push-jobs-device', selectedDevice] })
    },
  })

  const rollback = useMutation({
    mutationFn: (jobId: number) => api.push.rollback(jobId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['push-jobs'] })
      qc.invalidateQueries({ queryKey: ['push-jobs-device', selectedDevice] })
    },
  })

  const managedDevices = devices.filter(d => d.device_group_id)
  const unmanagedDevices = devices.filter(d => !d.device_group_id)

  return (
    <div className="flex h-full">
      {/* Left: device list */}
      <aside className="w-72 flex-shrink-0 flex flex-col border-r border-border">
        <div className="px-3 py-3 border-b border-border">
          <h2 className="font-semibold text-sm">Devices</h2>
          <p className="text-xs text-muted-foreground mt-0.5">Select a device to preview and push</p>
        </div>
        <div className="flex-1 overflow-auto p-2 space-y-1">
          {managedDevices.map(d => (
            <DeviceDeployRow
              key={d.name}
              device={d}
              latestJob={latestJobByDevice.get(d.name)}
              selected={selectedDevice === d.name}
              onClick={() => { setSelectedDevice(d.name); setSelectedJobId(null) }}
            />
          ))}
          {unmanagedDevices.length > 0 && (
            <>
              <p className="text-xs text-muted-foreground px-2 pt-2 pb-1">Not in a group</p>
              {unmanagedDevices.map(d => (
                <DeviceDeployRow
                  key={d.name}
                  device={d}
                  latestJob={undefined}
                  selected={selectedDevice === d.name}
                  onClick={() => setSelectedDevice(d.name)}
                />
              ))}
            </>
          )}
          {devices.length === 0 && (
            <p className="text-xs text-muted-foreground p-2">No devices registered yet.</p>
          )}
        </div>
      </aside>

      {/* Right: detail panel */}
      <main className="flex-1 overflow-auto p-6 space-y-5">
        {!selectedDevice ? (
          <div className="flex flex-col items-center justify-center h-full text-muted-foreground">
            <Upload className="h-12 w-12 mb-3 opacity-20" />
            <p className="font-medium">Select a device</p>
            <p className="text-sm mt-1">Choose a device from the left to preview and push intent policy.</p>
          </div>
        ) : (
          <>
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-xl font-bold">{selectedDevice}</h2>
                {(() => {
                  const d = devices.find(x => x.name === selectedDevice)
                  return d ? <p className="text-sm text-muted-foreground mt-0.5">{VENDOR_LABELS[d.vendor] ?? d.vendor} · Group: {d.device_group_name ?? 'none'}</p> : null
                })()}
              </div>
              <Button
                onClick={() => preview.mutate(selectedDevice)}
                disabled={preview.isPending || !devices.find(d => d.name === selectedDevice)?.device_group_id}
                title={!devices.find(d => d.name === selectedDevice)?.device_group_id ? 'Assign this device to a group first' : undefined}
              >
                {preview.isPending
                  ? <><RefreshCw className="h-3.5 w-3.5 mr-1.5 animate-spin" />Compiling…</>
                  : <><Zap className="h-3.5 w-3.5 mr-1.5" />Preview Push</>}
              </Button>
            </div>
            {preview.error && <p className="text-destructive text-sm">{String(preview.error)}</p>}

            {/* Job history */}
            {deviceJobs.length > 0 && (
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-medium">Push History</h3>
                  <Button size="sm" variant="ghost" onClick={() => refetchJobs()}>
                    <RefreshCw className="h-3.5 w-3.5" />
                  </Button>
                </div>
                <div className="flex gap-1.5 overflow-x-auto pb-1">
                  {deviceJobs.slice(0, 10).map(j => {
                    const meta = JOB_STATUS_META[j.status] ?? JOB_STATUS_META.pending
                    return (
                      <button
                        key={j.id}
                        onClick={() => setSelectedJobId(j.id)}
                        className={cn(
                          'flex-shrink-0 border rounded-md px-3 py-2 text-xs transition-colors text-left',
                          selectedJob?.id === j.id ? 'border-primary bg-primary/10' : 'border-border hover:border-primary/30',
                        )}
                      >
                        <div className={cn('font-medium', meta.color)}>{meta.label}</div>
                        <div className="text-muted-foreground mt-0.5">{fmtRelative(j.created_at)}</div>
                        <div className="text-muted-foreground">{j.dry_run ? 'preview' : 'live'} · {j.creates + j.updates} changes</div>
                      </button>
                    )
                  })}
                </div>
              </div>
            )}

            {/* Selected job detail */}
            {selectedJob && (
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Clock className="h-4 w-4" />
                    Push Job #{selectedJob.id}
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <JobDetail
                    job={selectedJob}
                    onExecute={() => execute.mutate(selectedJob.id)}
                    onRollback={() => rollback.mutate(selectedJob.id)}
                  />
                </CardContent>
              </Card>
            )}

            {deviceJobs.length === 0 && !preview.isPending && (
              <Card>
                <CardContent className="py-10 text-center text-muted-foreground">
                  <Upload className="h-8 w-8 mx-auto mb-2 opacity-20" />
                  <p className="text-sm">No push history for this device.</p>
                  <p className="text-xs mt-1">Click "Preview Push" to compile the intent policy.</p>
                </CardContent>
              </Card>
            )}
          </>
        )}
      </main>
    </div>
  )
}
