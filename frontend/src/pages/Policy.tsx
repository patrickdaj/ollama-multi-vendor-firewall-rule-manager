import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { Search, ChevronDown, ChevronRight, Save, X, RefreshCw } from 'lucide-react'
import { api, type PolicyObject } from '@/lib/api'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Select } from '@/components/ui/select'
import { VENDOR_LABELS, OBJECT_TYPE_LABELS } from '@/lib/utils'

function ObjectRow({ obj, onEdit }: { obj: PolicyObject; onEdit: (obj: PolicyObject) => void }) {
  const [expanded, setExpanded] = useState(false)
  const vendorColor: Record<string, string> = {
    paloalto: 'text-orange-400',
    cisco_asa: 'text-blue-400',
    cisco_ftd: 'text-cyan-400',
    fortinet: 'text-red-400',
  }

  return (
    <div className="border-b border-border last:border-0">
      <div
        className="flex items-center gap-3 py-2.5 px-3 hover:bg-accent/20 cursor-pointer"
        onClick={() => setExpanded(e => !e)}
      >
        <span className="text-muted-foreground/50">
          {expanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
        </span>
        <span className="font-mono text-sm flex-1 truncate">{obj.object_name}</span>
        <span className={`text-xs flex-shrink-0 ${vendorColor[obj.vendor] ?? 'text-muted-foreground'}`}>
          {VENDOR_LABELS[obj.vendor] ?? obj.vendor}
        </span>
        <Button
          size="sm" variant="ghost"
          className="h-6 px-2 text-xs opacity-0 group-hover:opacity-100"
          onClick={e => { e.stopPropagation(); onEdit(obj) }}
        >
          edit
        </Button>
      </div>
      {expanded && (
        <div className="px-8 pb-3">
          <pre className="text-xs text-muted-foreground bg-secondary/50 rounded p-3 overflow-auto max-h-64 whitespace-pre-wrap">
            {JSON.stringify(obj.data, null, 2)}
          </pre>
          <div className="flex justify-end mt-2">
            <Button size="sm" variant="outline" onClick={() => onEdit(obj)}>
              Edit in SOT
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}

function EditPanel({ obj, onClose }: { obj: PolicyObject; onClose: () => void }) {
  const qc = useQueryClient()
  const [value, setValue] = useState(JSON.stringify(obj.data, null, 2))
  const [error, setError] = useState('')

  const save = useMutation({
    mutationFn: () => {
      const parsed = JSON.parse(value)
      return api.snapshots.updateObject(obj.id, parsed)
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['snapshot-objects'] }); onClose() },
    onError: (e) => setError(String(e)),
  })

  const validate = () => {
    try { JSON.parse(value); setError('') } catch { setError('Invalid JSON') }
  }

  return (
    <div className="fixed inset-y-0 right-0 w-[480px] z-40 border-l border-border bg-card shadow-2xl flex flex-col">
      <div className="flex items-center justify-between p-4 border-b border-border">
        <div>
          <div className="font-semibold text-sm">{obj.object_name}</div>
          <div className="text-xs text-muted-foreground">{OBJECT_TYPE_LABELS[obj.object_type] ?? obj.object_type} · {VENDOR_LABELS[obj.vendor] ?? obj.vendor}</div>
        </div>
        <Button size="icon" variant="ghost" onClick={onClose}><X className="h-4 w-4" /></Button>
      </div>
      <div className="flex-1 overflow-auto p-4">
        <textarea
          className="w-full h-full min-h-[400px] font-mono text-xs bg-secondary/50 border border-border rounded p-3 focus:outline-none focus:ring-1 focus:ring-ring resize-none"
          value={value}
          onChange={e => { setValue(e.target.value); setError('') }}
          onBlur={validate}
          spellCheck={false}
        />
        {error && <p className="text-destructive text-xs mt-1">{error}</p>}
      </div>
      <div className="p-4 border-t border-border flex items-center justify-between">
        <p className="text-xs text-muted-foreground">Changes write to Postgres SOT.<br />Run reindex to update ChromaDB.</p>
        <div className="flex gap-2">
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button onClick={() => save.mutate()} disabled={save.isPending || !!error}>
            {save.isPending ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <Save className="h-3.5 w-3.5" />}
            Save
          </Button>
        </div>
      </div>
    </div>
  )
}

/** Reusable policy browser — pass `fixedDevice` to lock it to one device. */
export function PolicyBrowser({ fixedDevice }: { fixedDevice?: string }) {
  const [params, setParams] = useSearchParams()
  const deviceFilter = fixedDevice ?? params.get('device') ?? ''
  const typeFilter = params.get('type') ?? ''
  const [search, setSearch] = useState('')
  const [editing, setEditing] = useState<PolicyObject | null>(null)
  const [page, setPage] = useState(0)
  const PAGE = 100

  const { data: devices = [] } = useQuery({ queryKey: ['devices'], queryFn: api.devices.list })
  const { data: snapshots = [] } = useQuery({
    queryKey: ['snapshots', deviceFilter],
    queryFn: () => api.snapshots.list(deviceFilter || undefined),
  })

  const latestSnapshot = deviceFilter
    ? snapshots.find(s => s.device_name === deviceFilter)
    : snapshots[0]

  const { data: objects = [], isFetching } = useQuery({
    queryKey: ['snapshot-objects', latestSnapshot?.id, typeFilter, page],
    queryFn: () => latestSnapshot
      ? api.snapshots.objects(latestSnapshot.id, typeFilter || undefined, PAGE, page * PAGE)
      : Promise.resolve([]),
    enabled: !!latestSnapshot,
  })

  const { data: summary } = useQuery({
    queryKey: ['snapshot-summary', latestSnapshot?.id],
    queryFn: () => latestSnapshot ? api.snapshots.summary(latestSnapshot.id) : Promise.resolve(null),
    enabled: !!latestSnapshot,
  })

  const filtered = search
    ? objects.filter(o => o.object_name.toLowerCase().includes(search.toLowerCase()) ||
        JSON.stringify(o.data).toLowerCase().includes(search.toLowerCase()))
    : objects

  return (
    <div className="space-y-4 relative">
      {/* Filters */}
      <div className="flex gap-3 flex-wrap">
        {!fixedDevice && (
          <Select
            value={deviceFilter}
            onChange={e => { setParams(p => { p.set('device', e.target.value); p.delete('type'); return p }); setPage(0) }}
            className="w-48"
          >
            <option value="">All devices</option>
            {devices.map(d => <option key={d.name} value={d.name}>{d.name}</option>)}
          </Select>
        )}
        <Select
          value={typeFilter}
          onChange={e => { setParams(p => { p.set('type', e.target.value); return p }); setPage(0) }}
          className="w-52"
        >
          <option value="">All types</option>
          {summary && Object.entries(summary.types).map(([t, count]) => (
            <option key={t} value={t}>{OBJECT_TYPE_LABELS[t] ?? t} ({count})</option>
          ))}
        </Select>
        <div className="flex-1 min-w-48 relative">
          <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
          <Input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Filter by name or content…"
            className="pl-8"
          />
        </div>
      </div>

      {/* Summary badges */}
      {summary && (
        <div className="flex flex-wrap gap-1.5">
          {Object.entries(summary.types).map(([t, count]) => (
            <button
              key={t}
              onClick={() => { setParams(p => { p.set('type', t); return p }); setPage(0) }}
              className={`text-xs px-2 py-0.5 rounded-full border transition-colors ${typeFilter === t ? 'bg-primary/20 border-primary/40 text-primary' : 'border-border text-muted-foreground hover:border-primary/30'}`}
            >
              {OBJECT_TYPE_LABELS[t] ?? t} <span className="font-medium">{count}</span>
            </button>
          ))}
        </div>
      )}

      {/* Objects list */}
      <Card>
        <CardContent className="p-0">
          {isFetching && <div className="p-4 text-sm text-muted-foreground">Loading…</div>}
          {!isFetching && filtered.length === 0 && (
            <div className="p-8 text-center text-muted-foreground">
              {!latestSnapshot ? 'No snapshot yet — sync this device first.' : 'No objects match your filter.'}
            </div>
          )}
          <div className="group">
            {filtered.map(obj => (
              <ObjectRow key={obj.id} obj={obj} onEdit={setEditing} />
            ))}
          </div>
          {objects.length === PAGE && (
            <div className="flex justify-center gap-2 p-3 border-t border-border">
              {page > 0 && <Button size="sm" variant="outline" onClick={() => setPage(p => p - 1)}>Previous</Button>}
              <Button size="sm" variant="outline" onClick={() => setPage(p => p + 1)}>Next {PAGE}</Button>
            </div>
          )}
        </CardContent>
      </Card>

      {editing && <EditPanel obj={editing} onClose={() => setEditing(null)} />}
    </div>
  )
}

// Keep the standalone page route working (redirected via App.tsx but keeping export for safety)
export function Policy() {
  return (
    <div className="p-6 space-y-4">
      <div>
        <h1 className="text-2xl font-bold">Policy Browser</h1>
        <p className="text-muted-foreground text-sm mt-1">Browse and edit policy objects from the source of truth</p>
      </div>
      <PolicyBrowser />
    </div>
  )
}
