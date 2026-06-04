import { useState, useEffect } from 'react'
import { useQuery, useQueries, useMutation, useQueryClient } from '@tanstack/react-query'
import { useAiDock } from '@/contexts/AiDockContext'
import {
  ChevronRight, ChevronDown, Plus, Edit, Trash2, Layers,
  Server, RefreshCw, Check, X as XIcon, AlertCircle, Wand2,
} from 'lucide-react'
import {
  api,
  type DeviceGroup, type DeviceGroupTree, type DeviceInGroup,
  type GroupRule, type GroupObject, type ImportCandidate,
} from '@/lib/api'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Select } from '@/components/ui/select'
import { Dialog } from '@/components/ui/dialog'
import { cn, VENDOR_LABELS, OBJECT_TYPE_LABELS, fmtRelative } from '@/lib/utils'

const RULE_TYPES = ['security', 'nat', 'decryption', 'dos', 'auth']
const RULEBASES = ['pre', 'post']

function getAncestorChain(groupId: number, groups: import('@/lib/api').DeviceGroup[]): import('@/lib/api').DeviceGroup[] {
  const result: import('@/lib/api').DeviceGroup[] = []
  let current = groups.find(g => g.id === groupId)
  while (current?.parent_id) {
    const parent = groups.find(g => g.id === current!.parent_id)
    if (!parent) break
    result.unshift(parent)
    current = parent
  }
  return result
}
const OBJ_TYPES = ['address_object', 'service_object', 'service_group', 'application', 'app_group', 'url_category', 'security_profile', 'edl', 'zone']

const BASE_RULE_TEMPLATES: Record<string, object> = {
  security: { action: 'allow', src_zones: ['internal'], dst_zones: ['external'], src_addresses: ['any'], dst_addresses: ['any'], services: ['application-default'], applications: [], log: true },
  nat: { nat_type: 'ipv4', src_zones: ['internal'], dst_zones: ['external'], src_addresses: ['any'], dst_addresses: ['any'], translated_src: null, translated_dst: null },
  decryption: { action: 'decrypt', src_zones: ['internal'], dst_zones: ['external'], profile: null },
  dos: { action: 'protect', src_zones: ['internal'], dst_zones: ['external'] },
  auth: { action: 'web-form', src_zones: ['internal'], dst_zones: ['external'] },
}

// ── Shared JSON textarea ───────────────────────────────────────────────────────

function JsonTextarea({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return (
    <textarea
      value={value}
      onChange={e => onChange(e.target.value)}
      rows={8}
      className="w-full rounded-md border border-input bg-transparent px-3 py-2 text-xs font-mono shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
      spellCheck={false}
    />
  )
}

// ── Group tree ─────────────────────────────────────────────────────────────────

function GroupNode({
  node, depth, selectedId, onSelect, onAddChild, onEdit, onDelete,
}: {
  node: DeviceGroupTree
  depth: number
  selectedId: number | null
  onSelect: (id: number) => void
  onAddChild: (parentId: number) => void
  onEdit: (g: DeviceGroup) => void
  onDelete: (g: DeviceGroup) => void
}) {
  const [expanded, setExpanded] = useState(depth === 0)
  const hasChildren = node.children.length > 0
  const isSelected = selectedId === node.id

  return (
    <div>
      <div
        className={cn(
          'group flex items-center gap-1 py-1.5 pr-1 rounded-md cursor-pointer hover:bg-accent transition-colors',
          isSelected && 'bg-primary/10 text-primary',
        )}
        style={{ paddingLeft: `${8 + depth * 16}px` }}
        onClick={() => onSelect(node.id)}
      >
        <button
          className="flex-shrink-0 w-4 h-4 flex items-center justify-center"
          onClick={e => { e.stopPropagation(); setExpanded(x => !x) }}
        >
          {hasChildren
            ? (expanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />)
            : <span className="w-3" />}
        </button>
        <Layers className="h-3.5 w-3.5 flex-shrink-0 opacity-60" />
        <span className="text-sm flex-1 truncate">{node.name}</span>
        {node.device_count > 0 && (
          <Badge variant="outline" className="text-xs py-0 px-1">{node.device_count}</Badge>
        )}
        <div className="hidden group-hover:flex gap-0.5 flex-shrink-0" onClick={e => e.stopPropagation()}>
          <button className="p-0.5 rounded hover:bg-accent-foreground/10" onClick={() => onAddChild(node.id)} title="Add child group">
            <Plus className="h-3 w-3" />
          </button>
          <button className="p-0.5 rounded hover:bg-accent-foreground/10" onClick={() => onEdit(node)} title="Edit">
            <Edit className="h-3 w-3" />
          </button>
          <button className="p-0.5 rounded hover:bg-accent-foreground/10 text-destructive" onClick={() => onDelete(node)} title="Delete">
            <Trash2 className="h-3 w-3" />
          </button>
        </div>
      </div>
      {expanded && node.children.map(child => (
        <GroupNode
          key={child.id} node={child} depth={depth + 1}
          selectedId={selectedId} onSelect={onSelect}
          onAddChild={onAddChild} onEdit={onEdit} onDelete={onDelete}
        />
      ))}
    </div>
  )
}

// ── Overview tab ──────────────────────────────────────────────────────────────

function ImportReviewPanel({
  groupId,
  device,
  onDone,
}: {
  groupId: number
  device: DeviceInGroup
  onDone: () => void
}) {
  const qc = useQueryClient()
  const { addBackgroundJob } = useAiDock()
  const [rulebase, setRulebase] = useState<'pre' | 'post'>('pre')
  const [candidates, setCandidates] = useState<ImportCandidate[] | null>(null)
  const [snapshotId, setSnapshotId] = useState<number>(0)
  const [taskId, setTaskId] = useState<string | null>(null)

  // Enqueue the import task — returns immediately; global poller handles completion
  const startImport = useMutation({
    mutationFn: () => api.groups.importStart(groupId, device.name),
    onSuccess: data => {
      setTaskId(data.task_id)
      addBackgroundJob({
        taskId: data.task_id,
        label: `Import from ${device.name}`,
        href: `/groups`,
        startedAt: Date.now(),
      })
    },
  })

  // Also poll locally while the user is still on this panel for instant feedback
  const taskQuery = useQuery({
    queryKey: ['import-task', taskId],
    queryFn: () => api.tasks.get(taskId!),
    enabled: !!taskId && !candidates,
    refetchInterval: (query) => {
      const s = query.state.data?.status
      return s === 'complete' || s === 'error' ? false : 2000
    },
  })

  const taskData = taskQuery.data
  useEffect(() => {
    if (taskData?.status === 'complete' && taskData.result && !candidates) {
      setCandidates(taskData.result.candidates)
      setSnapshotId(taskData.result.snapshot_id)
      setTaskId(null)
    }
  }, [taskData])

  const confirm = useMutation({
    mutationFn: () =>
      api.groups.importConfirm(groupId, device.name, {
        snapshot_id: snapshotId,
        candidates: candidates ?? [],
        rulebase,
      }),
    onSuccess: result => {
      qc.invalidateQueries({ queryKey: ['group-rules', groupId] })
      qc.invalidateQueries({ queryKey: ['group-objects', groupId] })
      onDone()
      alert(`Import complete: ${result.rules_created} rules, ${result.objects_created} objects added.`)
    },
  })

  const toggleAll = (selected: boolean) =>
    setCandidates(cs => cs?.map(c => ({ ...c, selected })) ?? null)

  const toggle = (i: number) =>
    setCandidates(cs => cs?.map((c, j) => j === i ? { ...c, selected: !c.selected } : c) ?? null)

  return (
    <div className="space-y-4 border border-border rounded-lg p-4 bg-muted/20">
      <div className="flex items-center justify-between">
        <div>
          <h4 className="font-medium text-sm">Import Policy from {device.name}</h4>
          <p className="text-xs text-muted-foreground mt-0.5">
            AI normalizes the device's latest snapshot to vendor-agnostic form. Review and confirm.
          </p>
        </div>
        <Button variant="ghost" size="sm" onClick={onDone}>
          <XIcon className="h-4 w-4" />
        </Button>
      </div>

      {!candidates ? (
        <div className="space-y-2">
          <p className="text-xs text-muted-foreground">
            Runs each rule and object through the AI normalization pipeline in the background.
            Large configs take 1–3 minutes.
          </p>
          {taskId ? (
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <RefreshCw className="h-3.5 w-3.5 animate-spin text-primary" />
              Analyzing with AI — this runs in the background, feel free to navigate away…
            </div>
          ) : (
            <Button
              size="sm"
              onClick={() => startImport.mutate()}
              disabled={startImport.isPending}
            >
              {startImport.isPending
                ? <><RefreshCw className="h-3.5 w-3.5 mr-1.5 animate-spin" />Starting…</>
                : <><Wand2 className="h-3.5 w-3.5 mr-1.5" />Preview Import</>}
            </Button>
          )}
          {startImport.error && <p className="text-destructive text-xs">{String(startImport.error)}</p>}
        </div>
      ) : (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <span className="text-xs text-muted-foreground">
                {candidates.filter(c => c.selected).length} of {candidates.length} selected
              </span>
              <button onClick={() => toggleAll(true)} className="text-xs text-primary hover:underline">All</button>
              <button onClick={() => toggleAll(false)} className="text-xs text-primary hover:underline">None</button>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs text-muted-foreground">Add to rulebase:</span>
              <Select value={rulebase} onChange={e => setRulebase(e.target.value as 'pre' | 'post')} className="h-7 text-xs w-20">
                <option value="pre">pre</option>
                <option value="post">post</option>
              </Select>
            </div>
          </div>

          <div className="max-h-96 overflow-auto border border-border rounded-md">
            <table className="w-full text-xs">
              <thead className="bg-muted sticky top-0 z-10 shadow-sm">
                <tr className="border-b border-border">
                  <th className="px-3 py-2 w-8" />
                  <th className="text-left px-3 py-2 font-medium text-muted-foreground">Type</th>
                  <th className="text-left px-3 py-2 font-medium text-muted-foreground">Name</th>
                  <th className="text-left px-3 py-2 font-medium text-muted-foreground">Proposed (vendor-agnostic)</th>
                  <th className="text-left px-3 py-2 font-medium text-muted-foreground">AI Note</th>
                </tr>
              </thead>
              <tbody>
                {candidates.map((c, i) => (
                  <tr
                    key={i}
                    className={cn(
                      'border-t border-border cursor-pointer hover:bg-accent/20',
                      i % 2 === 0 ? 'bg-card' : 'bg-muted/10',
                      !c.selected && 'opacity-40',
                    )}
                    onClick={() => toggle(i)}
                  >
                    <td className="px-3 py-1.5 text-center">
                      <input
                        type="checkbox"
                        checked={c.selected}
                        onChange={() => toggle(i)}
                        onClick={e => e.stopPropagation()}
                        className="rounded"
                      />
                    </td>
                    <td className="px-3 py-1.5">
                      <Badge variant="outline" className="text-xs py-0">{c.object_type}</Badge>
                    </td>
                    <td className="px-3 py-1.5 font-medium">{c.object_name}</td>
                    <td className="px-3 py-1.5">
                      {Object.keys(c.proposed_base).length === 0
                        ? <span className="text-muted-foreground italic">empty — AI failed</span>
                        : <code className="text-xs bg-muted/30 rounded px-1 max-w-xs truncate block">{JSON.stringify(c.proposed_base)}</code>}
                    </td>
                    <td className="px-3 py-1.5 text-muted-foreground max-w-48 truncate" title={c.reasoning}>
                      {c.reasoning || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="flex items-center gap-2 pt-1">
            <Button
              size="sm"
              onClick={() => confirm.mutate()}
              disabled={confirm.isPending || candidates.filter(c => c.selected).length === 0}
            >
              {confirm.isPending
                ? <><RefreshCw className="h-3.5 w-3.5 mr-1.5 animate-spin" />Importing…</>
                : <><Check className="h-3.5 w-3.5 mr-1.5" />Confirm Import</>}
            </Button>
            <Button variant="outline" size="sm" onClick={() => setCandidates(null)}>
              Re-analyze
            </Button>
            {confirm.error && <span className="text-destructive text-xs">{String(confirm.error)}</span>}
          </div>
        </div>
      )}
    </div>
  )
}

function OverviewTab({ groupId }: { groupId: number }) {
  const qc = useQueryClient()
  const [assignName, setAssignName] = useState('')
  const [importDevice, setImportDevice] = useState<DeviceInGroup | null>(null)

  const { data: devices = [], isLoading } = useQuery({
    queryKey: ['group-devices', groupId],
    queryFn: () => api.groups.listDevices(groupId),
  })
  const { data: allDevices = [] } = useQuery({ queryKey: ['devices'], queryFn: api.devices.list })

  const unassigned = allDevices.filter(
    d => !devices.find(gd => gd.name === d.name)
  )

  const assign = useMutation({
    mutationFn: (name: string) => api.groups.assignDevice(groupId, name),
    onSuccess: () => {
      setAssignName('')
      qc.invalidateQueries({ queryKey: ['group-devices', groupId] })
      qc.invalidateQueries({ queryKey: ['groups-tree'] })
      qc.invalidateQueries({ queryKey: ['devices'] })
    },
  })
  const unassign = useMutation({
    mutationFn: (name: string) => api.groups.unassignDevice(groupId, name),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['group-devices', groupId] })
      qc.invalidateQueries({ queryKey: ['groups-tree'] })
    },
  })

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="font-medium text-sm">Assigned Devices</h3>
        <div className="flex gap-2">
          <Select value={assignName} onChange={e => setAssignName(e.target.value)} className="w-48 h-8 text-xs">
            <option value="">— assign device —</option>
            {unassigned.map(d => <option key={d.name} value={d.name}>{d.name} ({VENDOR_LABELS[d.vendor] ?? d.vendor})</option>)}
          </Select>
          <Button
            size="sm"
            disabled={!assignName || assign.isPending}
            onClick={() => assign.mutate(assignName)}
          >
            {assign.isPending ? <RefreshCw className="h-3 w-3 animate-spin" /> : 'Assign'}
          </Button>
        </div>
      </div>

      {isLoading && <div className="text-muted-foreground text-sm">Loading…</div>}
      {assign.error && <p className="text-destructive text-xs">{String(assign.error)}</p>}

      {devices.length === 0 && !isLoading ? (
        <Card>
          <CardContent className="py-8 text-center text-muted-foreground">
            <Server className="h-8 w-8 mx-auto mb-2 opacity-30" />
            <p className="text-sm">No devices assigned to this group.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {devices.map(d => (
            <div key={d.name} className="flex items-center justify-between px-3 py-2 rounded-md border border-border bg-card">
              <div className="flex items-center gap-2">
                <Server className="h-4 w-4 text-muted-foreground" />
                <span className="font-medium text-sm">{d.name}</span>
                <Badge variant="outline" className="text-xs">{VENDOR_LABELS[d.vendor] ?? d.vendor}</Badge>
                {d.host && <span className="text-xs text-muted-foreground">{d.host}</span>}
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs text-muted-foreground">{fmtRelative(d.last_synced_at)}</span>
                {d.last_synced_at && (
                  <Button
                    size="sm"
                    variant="outline"
                    className="h-7 px-2 text-xs"
                    onClick={() => setImportDevice(importDevice?.name === d.name ? null : d)}
                  >
                    <Wand2 className="h-3 w-3 mr-1" />Import Policy
                  </Button>
                )}
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => unassign.mutate(d.name)}
                  disabled={unassign.isPending}
                  className="text-destructive hover:text-destructive h-7 px-2"
                >
                  Unassign
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}

      {importDevice && (
        <ImportReviewPanel
          groupId={groupId}
          device={importDevice}
          onDone={() => setImportDevice(null)}
        />
      )}
    </div>
  )
}

// ── Rule form ──────────────────────────────────────────────────────────────────

function RuleForm({
  initial, onSubmit, onClose, loading,
}: {
  initial?: Partial<GroupRule>
  onSubmit: (data: Omit<GroupRule, 'id' | 'device_group_id' | 'created_at' | 'updated_at'>) => void
  onClose: () => void
  loading?: boolean
}) {
  const [name, setName] = useState(initial?.name ?? '')
  const [ruleType, setRuleType] = useState(initial?.rule_type ?? 'security')
  const [rulebase, setRulebase] = useState(initial?.rulebase ?? 'pre')
  const [position, setPosition] = useState(String(initial?.position ?? 0))
  const [description, setDescription] = useState(initial?.description ?? '')
  const [enabled, setEnabled] = useState(initial?.enabled ?? true)
  const [baseRuleStr, setBaseRuleStr] = useState(
    JSON.stringify(initial?.base_rule ?? BASE_RULE_TEMPLATES.security, null, 2)
  )
  const [jsonError, setJsonError] = useState('')

  const fillTemplate = () => setBaseRuleStr(JSON.stringify(BASE_RULE_TEMPLATES[ruleType] ?? {}, null, 2))

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    let base_rule: Record<string, unknown>
    try {
      base_rule = JSON.parse(baseRuleStr)
      setJsonError('')
    } catch {
      setJsonError('Invalid JSON in base rule')
      return
    }
    onSubmit({ name, rule_type: ruleType, rulebase, position: parseInt(position, 10), description: description || null, enabled, base_rule })
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-3">
      <div className="grid grid-cols-2 gap-3">
        <div className="col-span-2 space-y-1">
          <label className="text-xs text-muted-foreground">Name *</label>
          <Input value={name} onChange={e => setName(e.target.value)} placeholder="allow-internal-to-external" required />
        </div>
        <div className="space-y-1">
          <label className="text-xs text-muted-foreground">Type</label>
          <Select value={ruleType} onChange={e => setRuleType(e.target.value)}>
            {RULE_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
          </Select>
        </div>
        <div className="space-y-1">
          <label className="text-xs text-muted-foreground">Rulebase</label>
          <Select value={rulebase} onChange={e => setRulebase(e.target.value)}>
            {RULEBASES.map(r => <option key={r} value={r}>{r}</option>)}
          </Select>
        </div>
        <div className="space-y-1">
          <label className="text-xs text-muted-foreground">Position</label>
          <Input type="number" value={position} onChange={e => setPosition(e.target.value)} min={0} />
        </div>
        <div className="space-y-1">
          <label className="text-xs text-muted-foreground">Description</label>
          <Input value={description} onChange={e => setDescription(e.target.value)} placeholder="Optional" />
        </div>
      </div>
      <div className="flex items-center gap-2">
        <input type="checkbox" id="enabled" checked={enabled} onChange={e => setEnabled(e.target.checked)} className="rounded" />
        <label htmlFor="enabled" className="text-sm">Enabled</label>
      </div>
      <div className="space-y-1">
        <div className="flex items-center justify-between">
          <label className="text-xs text-muted-foreground">Base Rule (JSON)</label>
          <button type="button" onClick={fillTemplate} className="text-xs text-primary hover:underline">Fill template</button>
        </div>
        <JsonTextarea value={baseRuleStr} onChange={setBaseRuleStr} />
        {jsonError && <p className="text-xs text-destructive">{jsonError}</p>}
      </div>
      <div className="flex justify-end gap-2 pt-1">
        <Button type="button" variant="ghost" onClick={onClose}>Cancel</Button>
        <Button type="submit" disabled={loading}>{loading ? 'Saving…' : (initial?.id ? 'Update' : 'Create')}</Button>
      </div>
    </form>
  )
}

// ── Rules tab ─────────────────────────────────────────────────────────────────

function RulesTab({ groupId }: { groupId: number }) {
  const qc = useQueryClient()
  const [createOpen, setCreateOpen] = useState(false)
  const [editRule, setEditRule] = useState<GroupRule | null>(null)
  const [deleteRule, setDeleteRule] = useState<GroupRule | null>(null)
  const [showEffective, setShowEffective] = useState(false)
  const [effectiveType, setEffectiveType] = useState('security')
  const [typeFilter, setTypeFilter] = useState<string>('all')

  const { data: rules = [], isLoading } = useQuery({
    queryKey: ['group-rules', groupId],
    queryFn: () => api.groups.listRules(groupId),
  })
  const { data: effective, isFetching: loadingEffective } = useQuery({
    queryKey: ['effective-policy', groupId, effectiveType],
    queryFn: () => api.groups.effectivePolicy(groupId, effectiveType),
    enabled: showEffective,
  })

  const create = useMutation({
    mutationFn: (data: Parameters<typeof api.groups.createRule>[1]) => api.groups.createRule(groupId, data),
    onSuccess: () => { setCreateOpen(false); qc.invalidateQueries({ queryKey: ['group-rules', groupId] }) },
  })
  const update = useMutation({
    mutationFn: ({ id, data }: { id: number; data: Record<string, unknown> }) => api.groups.updateRule(id, data),
    onSuccess: () => { setEditRule(null); qc.invalidateQueries({ queryKey: ['group-rules', groupId] }) },
  })
  const remove = useMutation({
    mutationFn: (id: number) => api.groups.deleteRule(id),
    onSuccess: () => { setDeleteRule(null); qc.invalidateQueries({ queryKey: ['group-rules', groupId] }) },
  })

  const preRules = rules
    .filter(r => r.rulebase === 'pre' && (typeFilter === 'all' || r.rule_type === typeFilter))
    .sort((a, b) => a.position - b.position)
  const postRules = rules
    .filter(r => r.rulebase === 'post' && (typeFilter === 'all' || r.rule_type === typeFilter))
    .sort((a, b) => a.position - b.position)

  const RuleTable = ({ ruleList, label }: { ruleList: GroupRule[]; label: string }) => (
    <div className="space-y-2">
      <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wide">{label}</h4>
      {ruleList.length === 0 ? (
        <p className="text-sm text-muted-foreground italic px-2">No {label.toLowerCase()} rules defined.</p>
      ) : (
        <div className="border border-border rounded-md overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-muted/50">
              <tr>
                <th className="text-left px-3 py-2 text-xs font-medium text-muted-foreground w-10">#</th>
                <th className="text-left px-3 py-2 text-xs font-medium text-muted-foreground">Name</th>
                <th className="text-left px-3 py-2 text-xs font-medium text-muted-foreground">Type</th>
                <th className="text-left px-3 py-2 text-xs font-medium text-muted-foreground">State</th>
                <th className="px-3 py-2 w-20" />
              </tr>
            </thead>
            <tbody>
              {ruleList.map((r, i) => (
                <tr key={r.id} className={cn('border-t border-border', i % 2 === 0 ? 'bg-card' : 'bg-muted/20')}>
                  <td className="px-3 py-2 text-xs text-muted-foreground">{r.position}</td>
                  <td className="px-3 py-2">
                    <div className="font-medium">{r.name}</div>
                    {r.description && <div className="text-xs text-muted-foreground">{r.description}</div>}
                  </td>
                  <td className="px-3 py-2"><Badge variant="outline" className="text-xs">{r.rule_type}</Badge></td>
                  <td className="px-3 py-2">
                    {r.enabled
                      ? <span className="flex items-center gap-1 text-xs text-green-600"><Check className="h-3 w-3" />enabled</span>
                      : <span className="flex items-center gap-1 text-xs text-muted-foreground"><XIcon className="h-3 w-3" />disabled</span>}
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex gap-1 justify-end">
                      <Button size="sm" variant="ghost" className="h-6 px-2" onClick={() => setEditRule(r)}><Edit className="h-3 w-3" /></Button>
                      <Button size="sm" variant="ghost" className="h-6 px-2 text-destructive" onClick={() => setDeleteRule(r)}><Trash2 className="h-3 w-3" /></Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Button size="sm" onClick={() => setCreateOpen(true)}><Plus className="h-3.5 w-3.5 mr-1" />Add Rule</Button>
            <button
              onClick={() => setShowEffective(x => !x)}
              className="text-xs text-primary hover:underline"
            >
              {showEffective ? 'Hide' : 'Show'} Effective Policy
            </button>
          </div>
          {showEffective && (
            <Select value={effectiveType} onChange={e => setEffectiveType(e.target.value)} className="w-36 h-8 text-xs">
              {RULE_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
            </Select>
          )}
        </div>
        {/* Type filter chips */}
        <div className="flex gap-1.5 flex-wrap">
          {['all', ...RULE_TYPES].map(t => (
            <button
              key={t}
              onClick={() => setTypeFilter(t)}
              className={cn(
                'text-xs px-2.5 py-0.5 rounded-full border transition-colors capitalize',
                typeFilter === t
                  ? 'bg-primary/15 border-primary/40 text-primary font-medium'
                  : 'border-border text-muted-foreground hover:border-primary/30 hover:text-foreground',
              )}
            >
              {t === 'all' ? 'All' : t}
            </button>
          ))}
        </div>
      </div>

      {isLoading && <div className="text-muted-foreground text-sm">Loading…</div>}

      {showEffective && effective ? (
        <div className="space-y-4">
          <div className="text-xs text-muted-foreground">
            Ancestor chain: {effective.ancestor_chain.length > 0 ? effective.ancestor_chain.join(' → ') + ' → ' : ''}<strong>{effective.device_group_name}</strong>
          </div>
          <RuleTable ruleList={effective.pre_rules} label="Pre-rules (inherited → group)" />
          <RuleTable ruleList={effective.post_rules} label="Post-rules (group → inherited)" />
          {loadingEffective && <p className="text-xs text-muted-foreground">Refreshing…</p>}
        </div>
      ) : (
        <>
          <RuleTable ruleList={preRules} label="Pre-rules" />
          <RuleTable ruleList={postRules} label="Post-rules" />
        </>
      )}

      <Dialog open={createOpen} onClose={() => setCreateOpen(false)} title="Add Policy Rule" className="max-w-2xl">
        <RuleForm
          onSubmit={data => create.mutate(data)}
          onClose={() => setCreateOpen(false)}
          loading={create.isPending}
        />
        {create.error && <p className="text-destructive text-xs mt-2">{String(create.error)}</p>}
      </Dialog>

      <Dialog open={!!editRule} onClose={() => setEditRule(null)} title={`Edit Rule: ${editRule?.name}`} className="max-w-2xl">
        {editRule && (
          <RuleForm
            initial={editRule}
            onSubmit={data => update.mutate({ id: editRule.id, data: data as Record<string, unknown> })}
            onClose={() => setEditRule(null)}
            loading={update.isPending}
          />
        )}
        {update.error && <p className="text-destructive text-xs mt-2">{String(update.error)}</p>}
      </Dialog>

      <Dialog open={!!deleteRule} onClose={() => setDeleteRule(null)} title="Delete Rule?">
        <p className="text-sm text-muted-foreground mb-4">
          Delete rule <strong>{deleteRule?.name}</strong>? This cannot be undone.
        </p>
        <div className="flex justify-end gap-2">
          <Button variant="ghost" onClick={() => setDeleteRule(null)}>Cancel</Button>
          <Button variant="destructive" onClick={() => deleteRule && remove.mutate(deleteRule.id)} disabled={remove.isPending}>
            {remove.isPending ? 'Deleting…' : 'Delete'}
          </Button>
        </div>
      </Dialog>
    </div>
  )
}

// ── Objects tab ───────────────────────────────────────────────────────────────

function ObjectForm({
  initial, onSubmit, onClose, loading,
}: {
  initial?: Partial<GroupObject>
  onSubmit: (data: { object_type: string; object_name: string; description?: string; base_data: Record<string, unknown> }) => void
  onClose: () => void
  loading?: boolean
}) {
  const [objType, setObjType] = useState(initial?.object_type ?? 'address_object')
  const [objName, setObjName] = useState(initial?.object_name ?? '')
  const [description, setDescription] = useState(initial?.description ?? '')
  const [baseDataStr, setBaseDataStr] = useState(JSON.stringify(initial?.base_data ?? {}, null, 2))
  const [jsonError, setJsonError] = useState('')

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    let base_data: Record<string, unknown>
    try {
      base_data = JSON.parse(baseDataStr)
      setJsonError('')
    } catch {
      setJsonError('Invalid JSON in base data')
      return
    }
    onSubmit({ object_type: objType, object_name: objName, description: description || undefined, base_data })
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-3">
      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1">
          <label className="text-xs text-muted-foreground">Type *</label>
          <Select value={objType} onChange={e => setObjType(e.target.value)} disabled={!!initial?.id}>
            {OBJ_TYPES.map(t => <option key={t} value={t}>{OBJECT_TYPE_LABELS[t] ?? t}</option>)}
          </Select>
        </div>
        <div className="space-y-1">
          <label className="text-xs text-muted-foreground">Name *</label>
          <Input value={objName} onChange={e => setObjName(e.target.value)} placeholder="my-object" required disabled={!!initial?.id} />
        </div>
        <div className="col-span-2 space-y-1">
          <label className="text-xs text-muted-foreground">Description</label>
          <Input value={description} onChange={e => setDescription(e.target.value)} placeholder="Optional" />
        </div>
      </div>
      <div className="space-y-1">
        <label className="text-xs text-muted-foreground">Base Data (JSON)</label>
        <JsonTextarea value={baseDataStr} onChange={setBaseDataStr} />
        {jsonError && <p className="text-xs text-destructive">{jsonError}</p>}
      </div>
      <div className="flex justify-end gap-2 pt-1">
        <Button type="button" variant="ghost" onClick={onClose}>Cancel</Button>
        <Button type="submit" disabled={loading}>{loading ? 'Saving…' : (initial?.id ? 'Update' : 'Create')}</Button>
      </div>
    </form>
  )
}

function ObjectsTab({ groupId, groups }: { groupId: number; groups: DeviceGroup[] }) {
  const qc = useQueryClient()
  const [createOpen, setCreateOpen] = useState(false)
  const [editObj, setEditObj] = useState<GroupObject | null>(null)
  const [deleteObj, setDeleteObj] = useState<GroupObject | null>(null)
  const [showInherited, setShowInherited] = useState(false)

  const { data: objects = [], isLoading } = useQuery({
    queryKey: ['group-objects', groupId],
    queryFn: () => api.groups.listObjects(groupId),
  })

  const ancestors = getAncestorChain(groupId, groups)
  const ancestorQueries = useQueries({
    queries: ancestors.map(a => ({
      queryKey: ['group-objects', a.id],
      queryFn: () => api.groups.listObjects(a.id),
      enabled: showInherited,
    })),
  })

  type AnnotatedObject = GroupObject & { _source?: string }
  const allObjects: AnnotatedObject[] = showInherited
    ? [
        ...ancestors.flatMap((a, i) =>
          (ancestorQueries[i].data ?? []).map(o => ({
            ...o,
            _source: a.name,
          })),
        ),
        ...objects,
      ]
    : objects

  const create = useMutation({
    mutationFn: (data: Parameters<typeof api.groups.createObject>[1]) => api.groups.createObject(groupId, data),
    onSuccess: () => { setCreateOpen(false); qc.invalidateQueries({ queryKey: ['group-objects', groupId] }) },
  })
  const update = useMutation({
    mutationFn: ({ id, data }: { id: number; data: Record<string, unknown> }) => api.groups.updateObject(id, data),
    onSuccess: () => { setEditObj(null); qc.invalidateQueries({ queryKey: ['group-objects', groupId] }) },
  })
  const remove = useMutation({
    mutationFn: (id: number) => api.groups.deleteObject(id),
    onSuccess: () => { setDeleteObj(null); qc.invalidateQueries({ queryKey: ['group-objects', groupId] }) },
  })

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Button size="sm" onClick={() => setCreateOpen(true)}><Plus className="h-3.5 w-3.5 mr-1" />Add Object</Button>
          {ancestors.length > 0 && (
            <button
              onClick={() => setShowInherited(x => !x)}
              className="text-xs text-primary hover:underline"
            >
              {showInherited ? 'Hide inherited' : 'Show inherited'}
            </button>
          )}
        </div>
        {showInherited && (
          <span className="text-xs text-muted-foreground">
            {allObjects.length - objects.length} inherited · {objects.length} local
          </span>
        )}
      </div>

      {isLoading && <div className="text-muted-foreground text-sm">Loading…</div>}

      {allObjects.length === 0 && !isLoading ? (
        <Card><CardContent className="py-8 text-center text-muted-foreground text-sm">No policy objects defined in this group.</CardContent></Card>
      ) : (
        <div className="border border-border rounded-md overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-muted/50">
              <tr>
                <th className="text-left px-3 py-2 text-xs font-medium text-muted-foreground">Type</th>
                <th className="text-left px-3 py-2 text-xs font-medium text-muted-foreground">Name</th>
                <th className="text-left px-3 py-2 text-xs font-medium text-muted-foreground">Description</th>
                <th className="px-3 py-2 w-20" />
              </tr>
            </thead>
            <tbody>
              {allObjects.map((o, i) => {
                const inherited = !!o._source
                return (
                  <tr key={`${o.id}-${o._source ?? ''}`} className={cn(
                    'border-t border-border',
                    inherited ? 'opacity-60 bg-muted/10' : (i % 2 === 0 ? 'bg-card' : 'bg-muted/20'),
                  )}>
                    <td className="px-3 py-2"><Badge variant="outline" className="text-xs">{OBJECT_TYPE_LABELS[o.object_type] ?? o.object_type}</Badge></td>
                    <td className="px-3 py-2 font-medium">
                      {o.object_name}
                      {inherited && (
                        <span className="ml-1.5 text-xs text-muted-foreground font-normal">↑ {o._source}</span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-muted-foreground text-xs">{o.description ?? '—'}</td>
                    <td className="px-3 py-2">
                      {!inherited && (
                        <div className="flex gap-1 justify-end">
                          <Button size="sm" variant="ghost" className="h-6 px-2" onClick={() => setEditObj(o)}><Edit className="h-3 w-3" /></Button>
                          <Button size="sm" variant="ghost" className="h-6 px-2 text-destructive" onClick={() => setDeleteObj(o)}><Trash2 className="h-3 w-3" /></Button>
                        </div>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      <Dialog open={createOpen} onClose={() => setCreateOpen(false)} title="Add Policy Object" className="max-w-2xl">
        <ObjectForm
          onSubmit={data => create.mutate(data)}
          onClose={() => setCreateOpen(false)}
          loading={create.isPending}
        />
        {create.error && <p className="text-destructive text-xs mt-2">{String(create.error)}</p>}
      </Dialog>

      <Dialog open={!!editObj} onClose={() => setEditObj(null)} title={`Edit: ${editObj?.object_name}`} className="max-w-2xl">
        {editObj && (
          <ObjectForm
            initial={editObj}
            onSubmit={data => update.mutate({ id: editObj.id, data: data as Record<string, unknown> })}
            onClose={() => setEditObj(null)}
            loading={update.isPending}
          />
        )}
        {update.error && <p className="text-destructive text-xs mt-2">{String(update.error)}</p>}
      </Dialog>

      <Dialog open={!!deleteObj} onClose={() => setDeleteObj(null)} title="Delete Object?">
        <p className="text-sm text-muted-foreground mb-4">
          Delete <strong>{deleteObj?.object_name}</strong>? This cannot be undone.
        </p>
        <div className="flex justify-end gap-2">
          <Button variant="ghost" onClick={() => setDeleteObj(null)}>Cancel</Button>
          <Button variant="destructive" onClick={() => deleteObj && remove.mutate(deleteObj.id)} disabled={remove.isPending}>
            {remove.isPending ? 'Deleting…' : 'Delete'}
          </Button>
        </div>
      </Dialog>
    </div>
  )
}

// ── Zones tab ─────────────────────────────────────────────────────────────────

function DeviceZoneEditor({ device }: { device: DeviceInGroup }) {
  const qc = useQueryClient()
  const [rows, setRows] = useState<Array<{ logical_zone: string; vendor_zone: string }>>([])
  const [loaded, setLoaded] = useState(false)

  const { data: zones = [] } = useQuery({
    queryKey: ['zones', device.name],
    queryFn: () => api.groups.listZones(device.name),
    enabled: !loaded,
  })

  if (!loaded && zones.length >= 0 && !loaded) {
    // Seed local state once from server
    if (zones.length > 0 || loaded) {
      /* already set */
    } else {
      // Will be set on first non-empty fetch or user adds row
    }
  }

  const currentRows = loaded ? rows : zones.map(z => ({ logical_zone: z.logical_zone, vendor_zone: z.vendor_zone }))

  const save = useMutation({
    mutationFn: () => api.groups.setZones(device.name, currentRows.filter(r => r.logical_zone && r.vendor_zone)),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['zones', device.name] }),
  })

  const initAndEdit = () => {
    if (!loaded) {
      setRows(zones.map(z => ({ logical_zone: z.logical_zone, vendor_zone: z.vendor_zone })))
      setLoaded(true)
    }
  }

  const editRows = loaded ? rows : currentRows

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Server className="h-4 w-4 text-muted-foreground" />
          <span className="font-medium text-sm">{device.name}</span>
          <Badge variant="outline" className="text-xs">{VENDOR_LABELS[device.vendor] ?? device.vendor}</Badge>
        </div>
        <div className="flex gap-2">
          <Button
            size="sm"
            variant="outline"
            onClick={() => {
              initAndEdit()
              setRows(r => [...(loaded ? r : currentRows), { logical_zone: '', vendor_zone: '' }])
              if (!loaded) setLoaded(true)
            }}
          >
            <Plus className="h-3 w-3 mr-1" />Add Mapping
          </Button>
          <Button
            size="sm"
            onClick={() => save.mutate()}
            disabled={save.isPending}
          >
            {save.isPending ? <RefreshCw className="h-3 w-3 animate-spin" /> : <Check className="h-3 w-3 mr-1" />}
            Save
          </Button>
        </div>
      </div>

      {(editRows.length > 0) ? (
        <div className="border border-border rounded-md overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-muted/50">
              <tr>
                <th className="text-left px-3 py-2 text-xs font-medium text-muted-foreground">Logical Name</th>
                <th className="text-left px-3 py-2 text-xs font-medium text-muted-foreground">Device Interface / Zone</th>
                <th className="px-3 py-2 w-10" />
              </tr>
            </thead>
            <tbody>
              {editRows.map((row, i) => (
                <tr key={i} className={cn('border-t border-border', i % 2 === 0 ? 'bg-card' : 'bg-muted/20')}>
                  <td className="px-2 py-1">
                    <Input
                      value={row.logical_zone}
                      onChange={e => {
                        initAndEdit()
                        setRows(r => r.map((x, j) => j === i ? { ...x, logical_zone: e.target.value } : x))
                        if (!loaded) setLoaded(true)
                      }}
                      placeholder="internal"
                      className="h-7 text-xs"
                    />
                  </td>
                  <td className="px-2 py-1">
                    <Input
                      value={row.vendor_zone}
                      onChange={e => {
                        initAndEdit()
                        setRows(r => r.map((x, j) => j === i ? { ...x, vendor_zone: e.target.value } : x))
                        if (!loaded) setLoaded(true)
                      }}
                      placeholder="trust / eth1"
                      className="h-7 text-xs"
                    />
                  </td>
                  <td className="px-2 py-1">
                    <button
                      onClick={() => {
                        initAndEdit()
                        setRows(r => r.filter((_, j) => j !== i))
                        if (!loaded) setLoaded(true)
                      }}
                      className="text-destructive hover:text-destructive/80"
                    >
                      <XIcon className="h-3.5 w-3.5" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="text-xs text-muted-foreground italic px-2">No interface mappings configured.</p>
      )}
      {save.error && <p className="text-xs text-destructive">{String(save.error)}</p>}
    </div>
  )
}

function ZonesTab({ groupId }: { groupId: number }) {
  const { data: devices = [], isLoading } = useQuery({
    queryKey: ['group-devices', groupId],
    queryFn: () => api.groups.listDevices(groupId),
  })

  if (isLoading) return <div className="text-muted-foreground text-sm">Loading…</div>

  if (devices.length === 0) {
    return (
      <Card>
        <CardContent className="py-8 text-center text-muted-foreground text-sm">
          No devices assigned to this group. Assign devices in the Devices tab first.
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="space-y-6">
      <p className="text-xs text-muted-foreground">
        Map each device's physical interfaces and zones to the logical names used in group policy rules
        (e.g. <code className="bg-muted px-1 rounded">trust</code> → <code className="bg-muted px-1 rounded">internal</code>).
        Rules reference logical names; the push engine substitutes the device-specific name at deploy time.
      </p>
      {devices.map(d => <DeviceZoneEditor key={d.name} device={d} />)}
    </div>
  )
}

// ── Group detail panel ─────────────────────────────────────────────────────────

type Tab = 'rules' | 'objects' | 'interfacemap' | 'devices'

function GroupDetail({ groupId, groups, onDeleted }: { groupId: number; groups: DeviceGroup[]; onDeleted: () => void }) {
  const qc = useQueryClient()
  const [tab, setTab] = useState<Tab>('rules')
  const [editOpen, setEditOpen] = useState(false)
  const [deleteOpen, setDeleteOpen] = useState(false)
  const [editName, setEditName] = useState('')
  const [editDesc, setEditDesc] = useState('')
  const [editParent, setEditParent] = useState<string>('')

  const { data: group } = useQuery({
    queryKey: ['group', groupId],
    queryFn: () => api.groups.get(groupId),
  })

  const update = useMutation({
    mutationFn: (data: Record<string, unknown>) => api.groups.update(groupId, data),
    onSuccess: () => {
      setEditOpen(false)
      qc.invalidateQueries({ queryKey: ['group', groupId] })
      qc.invalidateQueries({ queryKey: ['groups-tree'] })
    },
  })
  const remove = useMutation({
    mutationFn: () => api.groups.delete(groupId),
    onSuccess: () => { setDeleteOpen(false); onDeleted() },
  })

  const openEdit = () => {
    setEditName(group?.name ?? '')
    setEditDesc(group?.description ?? '')
    setEditParent(group?.parent_id != null ? String(group.parent_id) : '')
    setEditOpen(true)
  }

  const tabs: { key: Tab; label: string }[] = [
    { key: 'rules', label: 'Rules' },
    { key: 'objects', label: 'Objects' },
    { key: 'interfacemap', label: 'Interface Map' },
    { key: 'devices', label: 'Devices' },
  ]

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-start justify-between">
        <div>
          <h2 className="text-xl font-bold">{group?.name ?? '…'}</h2>
          {group?.description && <p className="text-sm text-muted-foreground mt-0.5">{group.description}</p>}
          {group?.parent_id && (
            <p className="text-xs text-muted-foreground mt-1">
              Parent: {groups.find(g => g.id === group.parent_id)?.name ?? `#${group.parent_id}`}
            </p>
          )}
        </div>
        <div className="flex gap-2">
          <Button size="sm" variant="outline" onClick={openEdit}><Edit className="h-3.5 w-3.5 mr-1" />Edit</Button>
          <Button size="sm" variant="outline" onClick={() => setDeleteOpen(true)} className="text-destructive">
            <Trash2 className="h-3.5 w-3.5 mr-1" />Delete
          </Button>
        </div>
      </div>

      {/* Tab bar */}
      <div className="flex gap-0 border-b border-border">
        {tabs.map(t => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={cn(
              'px-4 py-2 text-sm border-b-2 -mb-px transition-colors',
              tab === t.key
                ? 'border-primary text-primary font-medium'
                : 'border-transparent text-muted-foreground hover:text-foreground',
            )}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'rules' && <RulesTab groupId={groupId} />}
      {tab === 'objects' && <ObjectsTab groupId={groupId} groups={groups} />}
      {tab === 'interfacemap' && <ZonesTab groupId={groupId} />}
      {tab === 'devices' && <OverviewTab groupId={groupId} />}

      {/* Edit dialog */}
      <Dialog open={editOpen} onClose={() => setEditOpen(false)} title="Edit Group">
        <form
          onSubmit={e => {
            e.preventDefault()
            update.mutate({
              name: editName,
              description: editDesc || null,
              parent_id: editParent ? parseInt(editParent, 10) : null,
            })
          }}
          className="space-y-3"
        >
          <div className="space-y-1">
            <label className="text-xs text-muted-foreground">Name *</label>
            <Input value={editName} onChange={e => setEditName(e.target.value)} required />
          </div>
          <div className="space-y-1">
            <label className="text-xs text-muted-foreground">Description</label>
            <Input value={editDesc} onChange={e => setEditDesc(e.target.value)} placeholder="Optional" />
          </div>
          <div className="space-y-1">
            <label className="text-xs text-muted-foreground">Parent Group</label>
            <Select value={editParent} onChange={e => setEditParent(e.target.value)}>
              <option value="">— root (no parent) —</option>
              {groups.filter(g => g.id !== groupId).map(g => (
                <option key={g.id} value={g.id}>{g.name}</option>
              ))}
            </Select>
          </div>
          <div className="flex justify-end gap-2 pt-1">
            <Button type="button" variant="ghost" onClick={() => setEditOpen(false)}>Cancel</Button>
            <Button type="submit" disabled={update.isPending}>{update.isPending ? 'Saving…' : 'Save'}</Button>
          </div>
          {update.error && <p className="text-destructive text-xs">{String(update.error)}</p>}
        </form>
      </Dialog>

      {/* Delete dialog */}
      <Dialog open={deleteOpen} onClose={() => setDeleteOpen(false)} title="Delete Group?">
        <p className="text-sm text-muted-foreground mb-4">
          Delete group <strong>{group?.name}</strong>? Groups with child groups or assigned devices cannot be deleted.
        </p>
        <div className="flex justify-end gap-2">
          <Button variant="ghost" onClick={() => setDeleteOpen(false)}>Cancel</Button>
          <Button variant="destructive" onClick={() => remove.mutate()} disabled={remove.isPending}>
            {remove.isPending ? 'Deleting…' : 'Delete'}
          </Button>
        </div>
        {remove.error && <p className="text-destructive text-xs mt-2">{String(remove.error)}</p>}
      </Dialog>
    </div>
  )
}

// ── Page root ─────────────────────────────────────────────────────────────────

export function Groups() {
  const qc = useQueryClient()
  const [selectedId, setSelectedId] = useState<number | null>(null)
  const [createOpen, setCreateOpen] = useState(false)
  const [createParentId, setCreateParentId] = useState<number | null>(null)
  const [newName, setNewName] = useState('')
  const [newDesc, setNewDesc] = useState('')
  const [newParent, setNewParent] = useState<string>('')

  const { data: tree = [], isLoading, isError, error } = useQuery({
    queryKey: ['groups-tree'],
    queryFn: api.groups.tree,
  })
  const { data: groups = [] } = useQuery({
    queryKey: ['groups'],
    queryFn: api.groups.list,
  })

  const createGroup = useMutation({
    mutationFn: () => api.groups.create({
      name: newName,
      description: newDesc || undefined,
      parent_id: newParent ? parseInt(newParent, 10) : (createParentId ?? undefined),
    }),
    onSuccess: () => {
      setCreateOpen(false)
      setNewName('')
      setNewDesc('')
      setNewParent('')
      setCreateParentId(null)
      qc.invalidateQueries({ queryKey: ['groups-tree'] })
      qc.invalidateQueries({ queryKey: ['groups'] })
    },
  })

  const openCreate = (parentId: number | null = null) => {
    setCreateParentId(parentId)
    setNewParent(parentId != null ? String(parentId) : '')
    setNewName('')
    setNewDesc('')
    setCreateOpen(true)
  }

  return (
    <div className="flex h-full">
      {/* Left: tree panel */}
      <aside className="w-64 flex-shrink-0 flex flex-col border-r border-border">
        <div className="flex items-center justify-between px-3 py-3 border-b border-border">
          <span className="text-sm font-semibold">Groups</span>
          <Button size="sm" variant="outline" className="h-7 px-2" onClick={() => openCreate(null)}>
            <Plus className="h-3.5 w-3.5" />
          </Button>
        </div>
        <div className="flex-1 overflow-auto p-2">
          {isLoading && <div className="text-muted-foreground text-xs p-2">Loading…</div>}
          {isError && (
            <div className="flex items-start gap-1.5 text-destructive text-xs p-2">
              <AlertCircle className="h-3.5 w-3.5 flex-shrink-0 mt-0.5" />
              <span>Failed to load groups: {String(error)}</span>
            </div>
          )}
          {!isLoading && !isError && tree.length === 0 && (
            <div className="text-center py-8 text-muted-foreground text-xs">
              <Layers className="h-8 w-8 mx-auto mb-2 opacity-30" />
              <p>No groups yet.</p>
              <button onClick={() => openCreate(null)} className="text-primary hover:underline mt-1">Create one</button>
            </div>
          )}
          {tree.map(root => (
            <GroupNode
              key={root.id}
              node={root}
              depth={0}
              selectedId={selectedId}
              onSelect={setSelectedId}
              onAddChild={id => openCreate(id)}
              onEdit={g => setSelectedId(g.id)}
              onDelete={g => setSelectedId(g.id)}
            />
          ))}
        </div>
      </aside>

      {/* Right: detail panel */}
      <main className="flex-1 overflow-auto">
        {selectedId != null ? (
          <GroupDetail
            key={selectedId}
            groupId={selectedId}
            groups={groups}
            onDeleted={() => { setSelectedId(null); qc.invalidateQueries({ queryKey: ['groups-tree'] }) }}
          />
        ) : (
          <div className="flex flex-col items-center justify-center h-full text-muted-foreground">
            <Layers className="h-12 w-12 mb-3 opacity-20" />
            <p className="font-medium">Select a group</p>
            <p className="text-sm mt-1">or <button onClick={() => openCreate(null)} className="text-primary hover:underline">create a new one</button></p>
          </div>
        )}
      </main>

      {/* Create group dialog */}
      <Dialog open={createOpen} onClose={() => setCreateOpen(false)} title="New Group">
        <form
          onSubmit={e => { e.preventDefault(); createGroup.mutate() }}
          className="space-y-3"
        >
          <div className="space-y-1">
            <label className="text-xs text-muted-foreground">Name *</label>
            <Input value={newName} onChange={e => setNewName(e.target.value)} placeholder="DC-East" required autoFocus />
          </div>
          <div className="space-y-1">
            <label className="text-xs text-muted-foreground">Description</label>
            <Input value={newDesc} onChange={e => setNewDesc(e.target.value)} placeholder="Optional" />
          </div>
          <div className="space-y-1">
            <label className="text-xs text-muted-foreground">Parent Group</label>
            <Select value={newParent} onChange={e => setNewParent(e.target.value)}>
              <option value="">— root (no parent) —</option>
              {groups.map(g => <option key={g.id} value={g.id}>{g.name}</option>)}
            </Select>
          </div>
          <div className="flex justify-end gap-2 pt-1">
            <Button type="button" variant="ghost" onClick={() => setCreateOpen(false)}>Cancel</Button>
            <Button type="submit" disabled={createGroup.isPending}>{createGroup.isPending ? 'Creating…' : 'Create'}</Button>
          </div>
          {createGroup.error && <p className="text-destructive text-xs mt-1">{String(createGroup.error)}</p>}
        </form>
      </Dialog>
    </div>
  )
}
