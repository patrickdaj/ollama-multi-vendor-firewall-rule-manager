import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { ChevronDown, ChevronRight, Plus, Minus, Edit3, Activity } from 'lucide-react'
import { api, type Snapshot, type Diff } from '@/lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Select } from '@/components/ui/select'
import { VENDOR_LABELS, OBJECT_TYPE_LABELS, fmtDate } from '@/lib/utils'

function DiffRow({ diff }: { diff: Diff }) {
  const [expanded, setExpanded] = useState(false)
  const icon = diff.change_type === 'added'
    ? <Plus className="h-3.5 w-3.5 text-green-500 flex-shrink-0" />
    : diff.change_type === 'removed'
      ? <Minus className="h-3.5 w-3.5 text-red-500 flex-shrink-0" />
      : <Edit3 className="h-3.5 w-3.5 text-yellow-500 flex-shrink-0" />

  const badgeVariant: 'success' | 'destructive' | 'warning' =
    diff.change_type === 'added' ? 'success' : diff.change_type === 'removed' ? 'destructive' : 'warning'

  return (
    <div className="border-b border-border last:border-0">
      <div
        className="flex items-center gap-2 py-2 px-4 hover:bg-accent/20 cursor-pointer"
        onClick={() => setExpanded(e => !e)}
      >
        {icon}
        <span className="font-mono text-xs flex-1 truncate">{diff.object_name}</span>
        <span className="text-xs text-muted-foreground hidden sm:inline">
          {OBJECT_TYPE_LABELS[diff.object_type] ?? diff.object_type}
        </span>
        <Badge variant={badgeVariant} className="capitalize">{diff.change_type}</Badge>
        {expanded ? <ChevronDown className="h-3 w-3 text-muted-foreground" /> : <ChevronRight className="h-3 w-3 text-muted-foreground" />}
      </div>
      {expanded && (
        <div className="px-4 pb-3">
          <div className={`grid gap-3 ${diff.before && diff.after ? 'grid-cols-2' : 'grid-cols-1'}`}>
            {diff.before && (
              <div>
                <div className="text-xs text-muted-foreground mb-1">
                  {diff.change_type === 'modified' ? 'Before' : 'Removed'}
                </div>
                <pre className="text-xs bg-red-950/20 border border-red-900/20 rounded p-2 overflow-auto max-h-48 whitespace-pre-wrap">
                  {JSON.stringify(diff.before, null, 2)}
                </pre>
              </div>
            )}
            {diff.after && (
              <div>
                <div className="text-xs text-muted-foreground mb-1">
                  {diff.change_type === 'modified' ? 'After' : 'Added'}
                </div>
                <pre className="text-xs bg-green-950/20 border border-green-900/20 rounded p-2 overflow-auto max-h-48 whitespace-pre-wrap">
                  {JSON.stringify(diff.after, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

function SnapshotRow({ snapshot }: { snapshot: Snapshot }) {
  const [expanded, setExpanded] = useState(false)

  const { data: diffs = [], isFetching } = useQuery({
    queryKey: ['diffs', snapshot.id],
    queryFn: () => api.snapshots.diffs(snapshot.id),
    enabled: expanded,
  })

  const added = diffs.filter(d => d.change_type === 'added').length
  const removed = diffs.filter(d => d.change_type === 'removed').length
  const modified = diffs.filter(d => d.change_type === 'modified').length

  return (
    <div className="border-b border-border last:border-0">
      <div
        className="flex items-center gap-3 py-3 px-4 hover:bg-accent/20 cursor-pointer"
        onClick={() => setExpanded(e => !e)}
      >
        {expanded
          ? <ChevronDown className="h-4 w-4 text-muted-foreground flex-shrink-0" />
          : <ChevronRight className="h-4 w-4 text-muted-foreground flex-shrink-0" />}
        <Activity className="h-4 w-4 text-primary/50 flex-shrink-0" />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium">Snapshot #{snapshot.id}</span>
            <Badge variant="outline">{snapshot.triggered_by}</Badge>
          </div>
          <div className="text-xs text-muted-foreground">
            {fmtDate(snapshot.completed_at ?? snapshot.created_at)}
          </div>
        </div>
        <div className="flex items-center gap-3 flex-shrink-0">
          {expanded && !isFetching && diffs.length > 0 && (
            <div className="flex gap-2">
              {added > 0 && <span className="text-xs text-green-400">+{added}</span>}
              {modified > 0 && <span className="text-xs text-yellow-400">~{modified}</span>}
              {removed > 0 && <span className="text-xs text-red-400">-{removed}</span>}
            </div>
          )}
          <span className="text-xs text-muted-foreground">
            {snapshot.object_count?.toLocaleString()} objects
          </span>
        </div>
      </div>
      {expanded && (
        <div className="bg-secondary/20">
          {isFetching && (
            <div className="px-6 py-3 text-xs text-muted-foreground">Loading diffs…</div>
          )}
          {!isFetching && diffs.length === 0 && (
            <div className="px-6 py-3 text-xs text-muted-foreground">
              No changes vs previous snapshot.
            </div>
          )}
          {diffs.map(d => <DiffRow key={d.id} diff={d} />)}
        </div>
      )}
    </div>
  )
}

export function Snapshots() {
  const [params, setParams] = useSearchParams()
  const deviceFilter = params.get('device') ?? ''

  const { data: devices = [] } = useQuery({ queryKey: ['devices'], queryFn: api.devices.list })
  const { data: snapshots = [], isFetching } = useQuery({
    queryKey: ['snapshots', deviceFilter],
    queryFn: () => api.snapshots.list(deviceFilter || undefined),
  })

  const grouped = snapshots.reduce<Record<string, Snapshot[]>>((acc, s) => {
    (acc[s.device_name] ??= []).push(s)
    return acc
  }, {})

  return (
    <div className="p-6 space-y-4">
      <div>
        <h1 className="text-2xl font-bold">Snapshot History</h1>
        <p className="text-muted-foreground text-sm mt-1">
          Ingestion timeline and policy change diffs
        </p>
      </div>

      <Select
        value={deviceFilter}
        onChange={e => setParams(p => { p.set('device', e.target.value); return p })}
        className="w-48"
      >
        <option value="">All devices</option>
        {devices.map(d => <option key={d.name} value={d.name}>{d.name}</option>)}
      </Select>

      {isFetching && <div className="text-muted-foreground text-sm">Loading…</div>}

      {!isFetching && snapshots.length === 0 && (
        <Card>
          <CardContent className="py-12 text-center text-muted-foreground">
            <Activity className="h-10 w-10 mx-auto mb-3 opacity-30" />
            <p className="font-medium">No snapshots yet</p>
            <p className="text-sm mt-1">Onboard a device to start collecting snapshots.</p>
          </CardContent>
        </Card>
      )}

      {Object.entries(grouped).map(([deviceName, snaps]) => (
        <Card key={deviceName} className="overflow-hidden">
          <CardHeader className="py-3 px-4 border-b border-border">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              {deviceName}
              <Badge variant="outline">
                {VENDOR_LABELS[snaps[0].vendor] ?? snaps[0].vendor}
              </Badge>
              <span className="text-xs text-muted-foreground font-normal">
                {snaps.length} snapshot{snaps.length !== 1 ? 's' : ''}
              </span>
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            {snaps.map(s => <SnapshotRow key={s.id} snapshot={s} />)}
          </CardContent>
        </Card>
      ))}
    </div>
  )
}
