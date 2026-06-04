import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  Server, Database, GitCompare, Upload,
  TrendingUp, Clock, ShieldCheck, AlertTriangle, Zap,
} from 'lucide-react'
import { api, type Device, type PushJob } from '@/lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { VENDOR_LABELS, fmtRelative, cn } from '@/lib/utils'

function StatCard({ title, value, sub, icon: Icon, to, accent }: {
  title: string
  value: string | number
  sub?: string
  icon: React.ElementType
  to?: string
  accent?: 'green' | 'amber' | 'blue' | 'red'
}) {
  const accentColor = {
    green: 'text-green-600',
    amber: 'text-amber-500',
    blue:  'text-blue-500',
    red:   'text-destructive',
  }[accent ?? 'green'] ?? ''

  const content = (
    <Card className="hover:border-primary/40 transition-colors">
      <CardContent className="pt-4">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-xs text-muted-foreground">{title}</p>
            <p className={cn('text-2xl font-bold mt-0.5', accent ? accentColor : '')}>{value}</p>
            {sub && <p className="text-xs text-muted-foreground mt-0.5">{sub}</p>}
          </div>
          <Icon className="h-8 w-8 text-muted-foreground/30" />
        </div>
      </CardContent>
    </Card>
  )
  return to ? <Link to={to}>{content}</Link> : content
}

function DeviceRow({ device, latestJob }: { device: Device; latestJob?: PushJob }) {
  const synced = !!device.last_synced_at
  const managed = synced && !!device.device_group_id
  const dot = managed ? 'bg-green-500' : synced ? 'bg-yellow-500' : 'bg-muted-foreground/40'
  const lastPush = latestJob?.completed_at ? fmtRelative(latestJob.completed_at) : 'never'
  const pushStatus = latestJob?.status

  return (
    <div className="flex items-center justify-between py-3 border-b border-border last:border-0">
      <div className="flex items-center gap-3">
        <div className={cn('h-2 w-2 rounded-full flex-shrink-0', dot)} />
        <div>
          <Link to={`/devices/${device.name}`} className="text-sm font-medium hover:text-primary">
            {device.name}
          </Link>
          <div className="text-xs text-muted-foreground">
            {VENDOR_LABELS[device.vendor] ?? device.vendor} · {device.device_group_name ?? 'no group'}
          </div>
        </div>
      </div>
      <div className="flex items-center gap-3 text-right">
        <div>
          <div className="text-xs text-muted-foreground">
            {device.latest_object_count ? `${device.latest_object_count} objects` : 'not synced'}
          </div>
          <div className="text-xs text-muted-foreground">
            push: {pushStatus === 'complete' ? <span className="text-green-600">{lastPush}</span> : pushStatus === 'failed' ? <span className="text-destructive">failed</span> : <span>{lastPush}</span>}
          </div>
        </div>
        <Badge variant={managed ? 'success' : synced ? 'warning' : 'outline'}>
          {managed ? 'managed' : synced ? 'discovered' : 'registered'}
        </Badge>
      </div>
    </div>
  )
}

type ActivityItem =
  | { kind: 'sync'; time: string; label: string; detail: string }
  | { kind: 'push'; time: string; label: string; detail: string; status: string }

export function Dashboard() {
  const { data: devices = [] } = useQuery({ queryKey: ['devices'], queryFn: api.devices.list, refetchInterval: 30000 })
  const { data: snapshots = [] } = useQuery({ queryKey: ['snapshots'], queryFn: () => api.snapshots.list(), refetchInterval: 60000 })
  const { data: ragStatus } = useQuery({ queryKey: ['rag-status'], queryFn: api.rag.status, refetchInterval: 60000 })
  const { data: pushJobs = [] } = useQuery({ queryKey: ['push-jobs'], queryFn: () => api.push.listJobs(), refetchInterval: 15000 })

  const managedDevices = devices.filter(d => d.last_synced_at && d.device_group_id).length

  const recentSnaps = snapshots.filter(s => {
    if (!s.completed_at) return false
    return Date.now() - new Date(s.completed_at).getTime() < 86400000
  }).length

  const successfulPushes = pushJobs.filter(j => j.status === 'complete' && !j.dry_run).length
  const lastPush = pushJobs.find(j => !j.dry_run && j.status === 'complete')

  // Translation readiness: count devices with all proposals resolved
  const pushReadyDevices = managedDevices  // placeholder until we add readiness aggregation

  // Build activity feed: merge syncs + pushes, sort by time
  const activity: ActivityItem[] = [
    ...snapshots.slice(0, 15).map(s => ({
      kind: 'sync' as const,
      time: s.completed_at ?? s.created_at,
      label: s.device_name,
      detail: `${s.object_count ?? '?'} objects · ${s.triggered_by}`,
    })),
    ...pushJobs.slice(0, 10).filter(j => !j.dry_run).map(j => ({
      kind: 'push' as const,
      time: j.completed_at ?? j.created_at,
      label: j.device_name,
      detail: `${j.pushed_rules + j.pushed_objects} items`,
      status: j.status,
    })),
  ].sort((a, b) => new Date(b.time).getTime() - new Date(a.time).getTime()).slice(0, 12)

  // Latest job per device for device row
  const latestJobByDevice = new Map<string, PushJob>()
  for (const job of pushJobs) {
    if (!latestJobByDevice.has(job.device_name)) latestJobByDevice.set(job.device_name, job)
  }

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Dashboard</h1>
        <p className="text-muted-foreground text-sm mt-1">Multi-vendor firewall policy management</p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        <StatCard
          title="Devices"
          value={devices.length}
          sub={`${managedDevices} managed`}
          icon={Server}
          to="/devices"
        />
        <StatCard
          title="Push Ready"
          value={pushReadyDevices}
          sub={`of ${managedDevices} managed`}
          icon={ShieldCheck}
          to="/translations"
          accent={pushReadyDevices === managedDevices && managedDevices > 0 ? 'green' : 'amber'}
        />
        <StatCard
          title="Last Push"
          value={lastPush ? fmtRelative(lastPush.completed_at ?? lastPush.created_at) : '—'}
          sub={lastPush ? `to ${lastPush.device_name}` : 'no pushes yet'}
          icon={Upload}
          to="/deploy"
          accent={successfulPushes > 0 ? 'green' : undefined}
        />
        <StatCard
          title="RAG Index"
          value={ragStatus?.document_count.toLocaleString() ?? '—'}
          sub="policy documents"
          icon={Database}
        />
        <StatCard
          title="Syncs Today"
          value={recentSnaps}
          sub="ingestion events"
          icon={TrendingUp}
          to="/snapshots"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Devices */}
        <Card>
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="text-base">Devices</CardTitle>
              <Link to="/devices" className="text-xs text-primary hover:underline">manage →</Link>
            </div>
          </CardHeader>
          <CardContent>
            {devices.length === 0 ? (
              <div className="text-center py-6 text-muted-foreground text-sm">
                No devices registered.{' '}
                <Link to="/devices" className="text-primary hover:underline">Add one →</Link>
              </div>
            ) : (
              devices.map(d => (
                <DeviceRow key={d.name} device={d} latestJob={latestJobByDevice.get(d.name)} />
              ))
            )}
          </CardContent>
        </Card>

        {/* Activity feed */}
        <Card>
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="text-base">Activity</CardTitle>
              <Link to="/snapshots" className="text-xs text-primary hover:underline">history →</Link>
            </div>
          </CardHeader>
          <CardContent>
            {activity.length === 0 && (
              <div className="text-center py-6 text-muted-foreground text-sm">No activity yet.</div>
            )}
            {activity.map((item, i) => (
              <div key={i} className="flex items-center gap-3 py-2 border-b border-border last:border-0">
                <div className="flex-shrink-0">
                  {item.kind === 'sync' ? (
                    <GitCompare className="h-3.5 w-3.5 text-blue-500" />
                  ) : item.status === 'complete' ? (
                    <Upload className="h-3.5 w-3.5 text-green-600" />
                  ) : item.status === 'failed' ? (
                    <AlertTriangle className="h-3.5 w-3.5 text-destructive" />
                  ) : (
                    <Zap className="h-3.5 w-3.5 text-amber-500" />
                  )}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-1.5">
                    <span className="text-sm font-medium truncate">{item.label}</span>
                    <Badge variant="outline" className="text-xs flex-shrink-0">
                      {item.kind === 'sync' ? 'sync' : 'push'}
                    </Badge>
                  </div>
                  <div className="text-xs text-muted-foreground">{item.detail}</div>
                </div>
                <div className="flex items-center gap-1.5 text-right flex-shrink-0">
                  <Clock className="h-3 w-3 text-muted-foreground" />
                  <span className="text-xs text-muted-foreground">{fmtRelative(item.time)}</span>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
