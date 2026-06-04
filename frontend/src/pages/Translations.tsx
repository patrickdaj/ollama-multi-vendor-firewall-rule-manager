import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Search, Check, X as XIcon, Edit, Trash2, Plus,
  RefreshCw, AlertCircle, ChevronDown, ChevronRight, Wand2,
  ShieldCheck, Clock, Eye, Ban, Minus, Zap,
} from 'lucide-react'
import {
  api,
  type Proposal, type ObjectTranslation, type RuleTranslation, type ReadinessItem,
} from '@/lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Select } from '@/components/ui/select'
import { Dialog } from '@/components/ui/dialog'
import { cn, VENDOR_LABELS, OBJECT_TYPE_LABELS } from '@/lib/utils'

const VENDORS = ['paloalto', 'cisco_asa', 'cisco_ftd', 'fortinet']
const PROPOSAL_STATUSES = ['pending', 'approved', 'rejected', 'modified']

// ── Status helpers ────────────────────────────────────────────────────────────

type StatusKey = 'auto' | 'approved' | 'pending' | 'review' | 'rejected' | 'not_required' | 'none'

const STATUS_META: Record<StatusKey, { label: string; color: string; icon: React.ReactNode }> = {
  auto:         { label: 'Auto',         color: 'text-emerald-600', icon: <Zap className="h-3.5 w-3.5" /> },
  approved:     { label: 'Approved',     color: 'text-green-600',   icon: <Check className="h-3.5 w-3.5" /> },
  pending:      { label: 'Pending',      color: 'text-amber-500',   icon: <Clock className="h-3.5 w-3.5" /> },
  review:       { label: 'Review',       color: 'text-blue-500',    icon: <Eye className="h-3.5 w-3.5" /> },
  rejected:     { label: 'Rejected',     color: 'text-destructive', icon: <Ban className="h-3.5 w-3.5" /> },
  not_required: { label: 'Not required', color: 'text-muted-foreground', icon: <Minus className="h-3.5 w-3.5" /> },
  none:         { label: 'No proposal',  color: 'text-muted-foreground', icon: <AlertCircle className="h-3.5 w-3.5" /> },
}

function StatusBadge({ status }: { status: string }) {
  const meta = STATUS_META[status as StatusKey] ?? STATUS_META.none
  return (
    <span className={cn('flex items-center gap-1 text-xs font-medium', meta.color)}>
      {meta.icon}
      {meta.label}
    </span>
  )
}

// ── JSON helpers ─────────────────────────────────────────────────────────────

function JsonView({ value }: { value: Record<string, unknown> }) {
  const text = JSON.stringify(value, null, 2)
  if (text === '{}') return <span className="text-muted-foreground text-xs italic">empty — awaiting AI</span>
  return <pre className="text-xs font-mono whitespace-pre-wrap bg-muted/30 rounded p-2 max-h-48 overflow-auto">{text}</pre>
}

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

// ── Readiness Matrix ──────────────────────────────────────────────────────────

function SummaryBar({ summary }: { summary: Record<string, number> }) {
  const order: StatusKey[] = ['auto', 'approved', 'review', 'pending', 'rejected', 'not_required', 'none']
  return (
    <div className="flex flex-wrap gap-4">
      {order.map(k => {
        const n = summary[k] ?? 0
        if (n === 0) return null
        const meta = STATUS_META[k]
        return (
          <div key={k} className="flex items-center gap-1.5">
            <span className={meta.color}>{meta.icon}</span>
            <span className="text-sm font-semibold">{n}</span>
            <span className="text-xs text-muted-foreground">{meta.label}</span>
          </div>
        )
      })}
    </div>
  )
}

function ReadinessRow({
  item, onGenerate, onGoToProposal,
}: {
  item: ReadinessItem
  onGenerate: (proposalId: number) => void
  onGoToProposal: (proposalId: number) => void
}) {
  const label = item.item_type === 'object'
    ? (OBJECT_TYPE_LABELS[item.object_type ?? ''] ?? item.object_type ?? '—')
    : `${item.rule_type ?? 'rule'}`
  const name = item.item_type === 'object' ? (item.object_name ?? '—') : (item.rule_name ?? `#${item.rule_id}`)

  return (
    <tr className="border-t border-border hover:bg-accent/20">
      <td className="px-3 py-2">
        <Badge variant="outline" className="text-xs capitalize">{label}</Badge>
      </td>
      <td className="px-3 py-2 font-medium text-sm">{name}</td>
      <td className="px-3 py-2">
        <StatusBadge status={item.status} />
      </td>
      <td className="px-3 py-2">
        {item.ai_model === 'fast-path' && (
          <span className="text-xs text-muted-foreground">deterministic</span>
        )}
        {item.status === 'pending' && item.proposal_id && (
          <Button size="sm" variant="outline" className="h-6 px-2 text-xs"
            onClick={() => onGenerate(item.proposal_id!)}>
            <Wand2 className="h-3 w-3 mr-1" />Generate
          </Button>
        )}
        {item.status === 'review' && item.proposal_id && (
          <Button size="sm" variant="outline" className="h-6 px-2 text-xs"
            onClick={() => onGoToProposal(item.proposal_id!)}>
            <Eye className="h-3 w-3 mr-1" />Review
          </Button>
        )}
        {item.status === 'rejected' && item.proposal_id && (
          <Button size="sm" variant="outline" className="h-6 px-2 text-xs"
            onClick={() => onGoToProposal(item.proposal_id!)}>
            Regenerate
          </Button>
        )}
        {item.status === 'none' && (
          <span className="text-xs text-muted-foreground italic">run Detect Gaps first</span>
        )}
      </td>
    </tr>
  )
}

function ReadinessSection({ title, items, onGenerate, onGoToProposal }: {
  title: string
  items: ReadinessItem[]
  onGenerate: (id: number) => void
  onGoToProposal: (id: number) => void
}) {
  const [open, setOpen] = useState(true)
  if (items.length === 0) return null
  return (
    <div>
      <button
        className="flex items-center gap-2 w-full py-1.5 text-xs font-semibold text-muted-foreground uppercase tracking-wide hover:text-foreground transition-colors"
        onClick={() => setOpen(x => !x)}
      >
        {open ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
        {title} ({items.length})
      </button>
      {open && items.map((item, i) => (
        <ReadinessRow key={i} item={item} onGenerate={onGenerate} onGoToProposal={onGoToProposal} />
      ))}
    </div>
  )
}

function ReadinessMatrix({ onShowAdvanced }: { onShowAdvanced: (proposalId?: number) => void }) {
  const qc = useQueryClient()
  const [groupId, setGroupId] = useState<string>('')
  const [vendor, setVendor] = useState<string>('cisco_asa')

  const { data: groups = [] } = useQuery({ queryKey: ['groups'], queryFn: api.groups.list })

  const { data: readiness, isLoading, refetch } = useQuery({
    queryKey: ['readiness', groupId, vendor],
    queryFn: () => api.translations.getReadiness(parseInt(groupId, 10), vendor),
    enabled: !!groupId,
  })

  const detectGaps = useMutation({
    mutationFn: () => api.groups.detectGaps(parseInt(groupId, 10), vendor),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['readiness', groupId, vendor] })
    },
  })

  const generateSingle = useMutation({
    mutationFn: (id: number) => api.translations.generateProposal(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['readiness', groupId, vendor] })
      qc.invalidateQueries({ queryKey: ['proposals'] })
    },
  })

  const generateAll = useMutation({
    mutationFn: () => api.translations.generateBatch({ target_vendor: vendor }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['readiness', groupId, vendor] })
      qc.invalidateQueries({ queryKey: ['proposals'] })
    },
  })

  const pendingCount = readiness
    ? [...readiness.objects, ...readiness.rules].filter(i => i.status === 'pending').length
    : 0
  const reviewCount = readiness
    ? [...readiness.objects, ...readiness.rules].filter(i => i.status === 'review').length
    : 0

  // Group objects by type
  const objByType: Record<string, ReadinessItem[]> = {}
  if (readiness) {
    for (const item of readiness.objects) {
      const k = item.object_type ?? 'other'
      if (!objByType[k]) objByType[k] = []
      objByType[k].push(item)
    }
  }

  return (
    <div className="space-y-5">
      {/* Controls */}
      <div className="flex gap-3 items-end flex-wrap">
        <div className="space-y-1 flex-1 min-w-48">
          <label className="text-xs text-muted-foreground">Device Group</label>
          <Select value={groupId} onChange={e => setGroupId(e.target.value)}>
            <option value="">— select group —</option>
            {groups.map(g => <option key={g.id} value={g.id}>{g.name}</option>)}
          </Select>
        </div>
        <div className="space-y-1 w-44">
          <label className="text-xs text-muted-foreground">Target Vendor</label>
          <Select value={vendor} onChange={e => setVendor(e.target.value)}>
            {VENDORS.map(v => <option key={v} value={v}>{VENDOR_LABELS[v] ?? v}</option>)}
          </Select>
        </div>
        <Button
          variant="outline"
          onClick={() => detectGaps.mutate()}
          disabled={!groupId || detectGaps.isPending}
          title="Scan for missing translations and create proposals"
        >
          {detectGaps.isPending ? <RefreshCw className="h-4 w-4 mr-1 animate-spin" /> : <Search className="h-4 w-4 mr-1" />}
          Detect Gaps
        </Button>
        <Button variant="outline" onClick={() => refetch()} disabled={!groupId || isLoading}>
          <RefreshCw className={cn('h-4 w-4 mr-1', isLoading && 'animate-spin')} />
          Refresh
        </Button>
      </div>

      {detectGaps.data && (
        <div className="flex items-center gap-3 text-sm">
          <Badge variant={detectGaps.data.proposals_created > 0 ? 'warning' : 'success'}>
            {detectGaps.data.proposals_created > 0
              ? `${detectGaps.data.proposals_created} new proposals created`
              : 'No new gaps found'}
          </Badge>
        </div>
      )}
      {detectGaps.error && (
        <p className="text-destructive text-sm flex items-center gap-1">
          <AlertCircle className="h-4 w-4" />{String(detectGaps.error)}
        </p>
      )}

      {!groupId && (
        <Card>
          <CardContent className="py-12 text-center text-muted-foreground">
            <ShieldCheck className="h-10 w-10 mx-auto mb-3 opacity-20" />
            <p className="font-medium">Select a group and vendor to see deployment readiness</p>
            <p className="text-sm mt-1">Click "Detect Gaps" to discover missing translations</p>
          </CardContent>
        </Card>
      )}

      {groupId && isLoading && (
        <div className="text-muted-foreground text-sm">Loading readiness…</div>
      )}

      {readiness && (
        <div className="space-y-4">
          {/* Summary */}
          <div className="flex items-center justify-between flex-wrap gap-3">
            <SummaryBar summary={readiness.summary} />
            <div className="flex gap-2">
              {pendingCount > 0 && (
                <Button size="sm" onClick={() => generateAll.mutate()} disabled={generateAll.isPending}>
                  {generateAll.isPending
                    ? <RefreshCw className="h-3.5 w-3.5 mr-1 animate-spin" />
                    : <Wand2 className="h-3.5 w-3.5 mr-1" />}
                  Generate All ({pendingCount})
                </Button>
              )}
              {reviewCount > 0 && (
                <Button size="sm" variant="outline" onClick={() => onShowAdvanced()}>
                  <Eye className="h-3.5 w-3.5 mr-1" />
                  Review ({reviewCount})
                </Button>
              )}
              <Button size="sm" variant="ghost" className="text-xs text-muted-foreground" onClick={() => onShowAdvanced()}>
                All proposals →
              </Button>
            </div>
          </div>

          {/* Table */}
          <div className="border border-border rounded-md overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-muted/50">
                <tr>
                  <th className="text-left px-3 py-2 text-xs font-medium text-muted-foreground w-36">Type</th>
                  <th className="text-left px-3 py-2 text-xs font-medium text-muted-foreground">Name</th>
                  <th className="text-left px-3 py-2 text-xs font-medium text-muted-foreground w-32">Status</th>
                  <th className="px-3 py-2 w-28" />
                </tr>
              </thead>
              <tbody>
                {/* Objects grouped by type */}
                {Object.entries(objByType).map(([type, items]) => (
                  <ReadinessSection
                    key={type}
                    title={OBJECT_TYPE_LABELS[type] ?? type}
                    items={items}
                    onGenerate={id => generateSingle.mutate(id)}
                    onGoToProposal={id => onShowAdvanced(id)}
                  />
                ))}
                {/* Rules */}
                {readiness.rules.length > 0 && (
                  <ReadinessSection
                    title="Rules"
                    items={readiness.rules}
                    onGenerate={id => generateSingle.mutate(id)}
                    onGoToProposal={id => onShowAdvanced(id)}
                  />
                )}
                {readiness.objects.length === 0 && readiness.rules.length === 0 && (
                  <tr>
                    <td colSpan={4} className="px-4 py-8 text-center text-muted-foreground text-sm">
                      No policy items found — make sure this group has rules and objects.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          {(generateSingle.error || generateAll.error) && (
            <p className="text-destructive text-xs">{String(generateSingle.error ?? generateAll.error)}</p>
          )}
        </div>
      )}
    </div>
  )
}

// ── Proposal card ─────────────────────────────────────────────────────────────

function ProposalCard({ proposal, onReviewed }: { proposal: Proposal; onReviewed: () => void }) {
  const qc = useQueryClient()
  const [expanded, setExpanded] = useState(false)
  const [modifying, setModifying] = useState(false)
  const [modifiedStr, setModifiedStr] = useState(JSON.stringify(proposal.proposed_translation, null, 2))
  const [reviewer, setReviewer] = useState('')
  const [jsonError, setJsonError] = useState('')

  const review = useMutation({
    mutationFn: (data: { action: string; reviewed_by?: string; modified_translation?: Record<string, unknown> }) =>
      api.translations.reviewProposal(proposal.id, data),
    onSuccess: () => onReviewed(),
  })

  const generate = useMutation({
    mutationFn: () => api.translations.generateProposal(proposal.id),
    onSuccess: result => {
      if (result.status === 'generated') {
        qc.invalidateQueries({ queryKey: ['proposals'] })
        setExpanded(true)
      }
    },
  })

  const handleApprove = () => review.mutate({ action: 'approve', reviewed_by: reviewer || undefined })
  const handleReject = () => review.mutate({ action: 'reject', reviewed_by: reviewer || undefined })
  const handleModify = () => {
    try {
      const modified_translation = JSON.parse(modifiedStr)
      setJsonError('')
      review.mutate({ action: 'modify', reviewed_by: reviewer || undefined, modified_translation })
    } catch {
      setJsonError('Invalid JSON')
    }
  }

  const isPending = review.isPending || generate.isPending

  return (
    <div className="border border-border rounded-lg bg-card overflow-hidden">
      <div
        className="flex items-center justify-between px-4 py-3 cursor-pointer hover:bg-accent/30 transition-colors"
        onClick={() => setExpanded(x => !x)}
      >
        <div className="flex items-center gap-3">
          {expanded ? <ChevronDown className="h-4 w-4 text-muted-foreground" /> : <ChevronRight className="h-4 w-4 text-muted-foreground" />}
          <Badge variant="outline" className="text-xs">{proposal.proposal_type}</Badge>
          {proposal.proposal_type === 'object' ? (
            <span className="text-sm font-medium">
              {OBJECT_TYPE_LABELS[proposal.object_type ?? ''] ?? proposal.object_type}: <strong>{proposal.object_name}</strong>
            </span>
          ) : (
            <span className="text-sm font-medium">Rule #{proposal.rule_id}</span>
          )}
          <Badge variant="outline" className="text-xs">{VENDOR_LABELS[proposal.target_vendor] ?? proposal.target_vendor}</Badge>
        </div>
        <div className="flex items-center gap-2" onClick={e => e.stopPropagation()}>
          {Object.keys(proposal.proposed_translation).length === 0 && (
            <span className="text-xs text-muted-foreground italic">awaiting AI</span>
          )}
          <Badge
            variant={proposal.status === 'pending' ? 'warning' : proposal.status === 'approved' ? 'success' : 'destructive'}
            className="text-xs"
          >
            {proposal.status}
          </Badge>
        </div>
      </div>

      {expanded && (
        <div className="border-t border-border px-4 py-4 space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1">
              <p className="text-xs font-medium text-muted-foreground">Proposed Translation</p>
              {modifying ? (
                <div className="space-y-1">
                  <JsonTextarea value={modifiedStr} onChange={setModifiedStr} />
                  {jsonError && <p className="text-xs text-destructive">{jsonError}</p>}
                </div>
              ) : (
                <JsonView value={proposal.proposed_translation} />
              )}
            </div>
            {proposal.ai_reasoning && (
              <div className="space-y-1">
                <p className="text-xs font-medium text-muted-foreground">AI Reasoning</p>
                <p className="text-xs text-muted-foreground bg-muted/30 rounded p-2">{proposal.ai_reasoning}</p>
                {proposal.ai_model && <p className="text-xs text-muted-foreground">Model: {proposal.ai_model}</p>}
              </div>
            )}
          </div>

          {proposal.status === 'pending' && (
            <div className="flex items-center gap-3 pt-1 border-t border-border">
              <Input
                value={reviewer}
                onChange={e => setReviewer(e.target.value)}
                placeholder="Your name (optional)"
                className="h-8 w-48 text-xs"
              />
              {!modifying ? (
                <>
                  {Object.keys(proposal.proposed_translation).length === 0 && (
                    <Button size="sm" variant="outline" onClick={() => generate.mutate()} disabled={isPending}>
                      {generate.isPending
                        ? <RefreshCw className="h-3.5 w-3.5 mr-1 animate-spin" />
                        : <Wand2 className="h-3.5 w-3.5 mr-1" />}
                      Generate AI
                    </Button>
                  )}
                  <Button size="sm" onClick={handleApprove} disabled={isPending} className="bg-green-600 hover:bg-green-700 text-white">
                    <Check className="h-3.5 w-3.5 mr-1" />Approve
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => setModifying(true)} disabled={isPending}>
                    <Edit className="h-3.5 w-3.5 mr-1" />Modify
                  </Button>
                  <Button size="sm" variant="outline" onClick={handleReject} disabled={isPending} className="text-destructive">
                    <XIcon className="h-3.5 w-3.5 mr-1" />Reject
                  </Button>
                </>
              ) : (
                <>
                  <Button size="sm" onClick={handleModify} disabled={isPending} className="bg-green-600 hover:bg-green-700 text-white">
                    <Check className="h-3.5 w-3.5 mr-1" />Approve Modified
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => { setModifying(false); setModifiedStr(JSON.stringify(proposal.proposed_translation, null, 2)) }} disabled={isPending}>
                    Cancel
                  </Button>
                </>
              )}
              {isPending && <RefreshCw className="h-4 w-4 animate-spin text-muted-foreground" />}
              {review.error && <span className="text-destructive text-xs">{String(review.error)}</span>}
              {generate.error && <span className="text-destructive text-xs">{String(generate.error)}</span>}
            </div>
          )}

          {proposal.status !== 'pending' && (
            <div className="text-xs text-muted-foreground border-t border-border pt-2">
              Reviewed by <strong>{proposal.reviewed_by ?? 'unknown'}</strong>
              {proposal.reviewed_at && ` on ${new Date(proposal.reviewed_at).toLocaleString()}`}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── Advanced: All Proposals ───────────────────────────────────────────────────

function AdvancedProposals({ highlightId }: { highlightId?: number }) {
  const qc = useQueryClient()
  const [statusFilter, setStatusFilter] = useState('pending')
  const [vendorFilter, setVendorFilter] = useState<string>('')
  const [batchResult, setBatchResult] = useState<{ fast_approved: number; ai_generated: number; failed: number } | null>(null)

  const { data: proposals = [], isLoading, refetch } = useQuery({
    queryKey: ['proposals', statusFilter, vendorFilter],
    queryFn: () => api.translations.listProposals(statusFilter, vendorFilter || undefined),
  })

  const batchGenerate = useMutation({
    mutationFn: () => api.translations.generateBatch({ target_vendor: vendorFilter || undefined }),
    onSuccess: result => {
      setBatchResult({
        fast_approved: (result as unknown as Record<string, number>).fast_approved ?? 0,
        ai_generated: (result as unknown as Record<string, number>).ai_generated ?? 0,
        failed: result.failed,
      })
      qc.invalidateQueries({ queryKey: ['proposals'] })
    },
  })

  const onReviewed = () => {
    qc.invalidateQueries({ queryKey: ['proposals'] })
    qc.invalidateQueries({ queryKey: ['object-translations'] })
    qc.invalidateQueries({ queryKey: ['rule-translations'] })
    qc.invalidateQueries({ queryKey: ['readiness'] })
  }

  const emptyPendingCount = proposals.filter(
    p => statusFilter === 'pending' && Object.keys(p.proposed_translation).length === 0
  ).length

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex gap-3">
          <Select value={statusFilter} onChange={e => setStatusFilter(e.target.value)} className="w-36 h-8 text-xs">
            {PROPOSAL_STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
          </Select>
          <Select value={vendorFilter} onChange={e => setVendorFilter(e.target.value)} className="w-40 h-8 text-xs">
            <option value="">All vendors</option>
            {VENDORS.map(v => <option key={v} value={v}>{VENDOR_LABELS[v] ?? v}</option>)}
          </Select>
          <Button size="sm" variant="outline" onClick={() => refetch()}>
            <RefreshCw className="h-3.5 w-3.5 mr-1" />Refresh
          </Button>
        </div>
        {emptyPendingCount > 0 && (
          <Button size="sm" onClick={() => { setBatchResult(null); batchGenerate.mutate() }} disabled={batchGenerate.isPending}>
            {batchGenerate.isPending
              ? <RefreshCw className="h-3.5 w-3.5 mr-1 animate-spin" />
              : <Wand2 className="h-3.5 w-3.5 mr-1" />}
            Generate All ({emptyPendingCount})
          </Button>
        )}
      </div>

      {batchResult && (
        <p className="text-xs text-muted-foreground">
          Batch: <span className="text-emerald-600 font-medium">{batchResult.fast_approved} auto-approved</span>
          {batchResult.ai_generated > 0 && <>, <span className="text-blue-500">{batchResult.ai_generated} AI-generated</span></>}
          {batchResult.failed > 0 && <>, <span className="text-destructive">{batchResult.failed} failed</span></>}.
        </p>
      )}

      {isLoading && <div className="text-muted-foreground text-sm">Loading…</div>}
      {!isLoading && proposals.length === 0 && (
        <div className="text-center py-6 text-muted-foreground">
          <Check className="h-8 w-8 mx-auto mb-2 opacity-30" />
          <p className="text-sm">No {statusFilter} proposals{vendorFilter ? ` for ${VENDOR_LABELS[vendorFilter]}` : ''}.</p>
        </div>
      )}
      {proposals.map(p => (
        <div key={p.id} className={cn(highlightId === p.id && 'ring-2 ring-primary rounded-lg')}>
          <ProposalCard proposal={p} onReviewed={onReviewed} />
        </div>
      ))}
    </div>
  )
}

// ── Approved translations tables ──────────────────────────────────────────────

function ObjectTranslationForm({
  initial, onSubmit, onClose, loading,
}: {
  initial?: Partial<ObjectTranslation>
  onSubmit: (data: { object_type: string; object_name: string; target_vendor: string; translation: Record<string, unknown> }) => void
  onClose: () => void
  loading?: boolean
}) {
  const [objType, setObjType] = useState(initial?.object_type ?? 'application')
  const [objName, setObjName] = useState(initial?.object_name ?? '')
  const [vendor, setVendor] = useState(initial?.target_vendor ?? 'cisco_asa')
  const [translationStr, setTranslationStr] = useState(JSON.stringify(initial?.translation ?? {}, null, 2))
  const [jsonError, setJsonError] = useState('')

  const OBJ_TYPES = ['address_object', 'service_object', 'service_group', 'application', 'app_group', 'url_category', 'security_profile', 'edl', 'zone']

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    try {
      const translation = JSON.parse(translationStr)
      setJsonError('')
      onSubmit({ object_type: objType, object_name: objName, target_vendor: vendor, translation })
    } catch {
      setJsonError('Invalid JSON')
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-3">
      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1">
          <label className="text-xs text-muted-foreground">Object Type *</label>
          <Select value={objType} onChange={e => setObjType(e.target.value)} disabled={!!initial?.id}>
            {OBJ_TYPES.map(t => <option key={t} value={t}>{OBJECT_TYPE_LABELS[t] ?? t}</option>)}
          </Select>
        </div>
        <div className="space-y-1">
          <label className="text-xs text-muted-foreground">Object Name *</label>
          <Input value={objName} onChange={e => setObjName(e.target.value)} placeholder="ssl" required disabled={!!initial?.id} />
        </div>
        <div className="col-span-2 space-y-1">
          <label className="text-xs text-muted-foreground">Target Vendor *</label>
          <Select value={vendor} onChange={e => setVendor(e.target.value)} disabled={!!initial?.id}>
            {VENDORS.map(v => <option key={v} value={v}>{VENDOR_LABELS[v] ?? v}</option>)}
          </Select>
        </div>
      </div>
      <div className="space-y-1">
        <label className="text-xs text-muted-foreground">Translation (JSON)</label>
        <JsonTextarea value={translationStr} onChange={setTranslationStr} />
        {jsonError && <p className="text-xs text-destructive">{jsonError}</p>}
      </div>
      <div className="flex justify-end gap-2 pt-1">
        <Button type="button" variant="ghost" onClick={onClose}>Cancel</Button>
        <Button type="submit" disabled={loading}>{loading ? 'Saving…' : (initial?.id ? 'Update' : 'Create')}</Button>
      </div>
    </form>
  )
}

function ObjectTranslationsSection() {
  const qc = useQueryClient()
  const [vendorFilter, setVendorFilter] = useState<string>('')
  const [createOpen, setCreateOpen] = useState(false)
  const [editItem, setEditItem] = useState<ObjectTranslation | null>(null)

  const { data: translations = [], isLoading } = useQuery({
    queryKey: ['object-translations', vendorFilter],
    queryFn: () => api.translations.listObjectTranslations(vendorFilter || undefined, 'approved'),
  })

  const upsert = useMutation({
    mutationFn: (data: Parameters<typeof api.translations.upsertObjectTranslation>[0]) =>
      api.translations.upsertObjectTranslation(data),
    onSuccess: () => { setCreateOpen(false); setEditItem(null); qc.invalidateQueries({ queryKey: ['object-translations'] }) },
  })
  const remove = useMutation({
    mutationFn: (id: number) => api.translations.deleteObjectTranslation(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['object-translations'] }),
  })

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="font-medium text-sm">Object Translations</h3>
        <div className="flex gap-2">
          <Select value={vendorFilter} onChange={e => setVendorFilter(e.target.value)} className="w-44 h-8 text-xs">
            <option value="">All vendors</option>
            {VENDORS.map(v => <option key={v} value={v}>{VENDOR_LABELS[v] ?? v}</option>)}
          </Select>
          <Button size="sm" onClick={() => setCreateOpen(true)}><Plus className="h-3.5 w-3.5 mr-1" />Add</Button>
        </div>
      </div>
      {isLoading && <div className="text-muted-foreground text-sm">Loading…</div>}
      {translations.length === 0 && !isLoading ? (
        <p className="text-sm text-muted-foreground italic py-2">No approved object translations{vendorFilter ? ` for ${VENDOR_LABELS[vendorFilter]}` : ''}.</p>
      ) : (
        <div className="border border-border rounded-md overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-muted/50">
              <tr>
                <th className="text-left px-3 py-2 text-xs font-medium text-muted-foreground">Type</th>
                <th className="text-left px-3 py-2 text-xs font-medium text-muted-foreground">Name</th>
                <th className="text-left px-3 py-2 text-xs font-medium text-muted-foreground">Vendor</th>
                <th className="text-left px-3 py-2 text-xs font-medium text-muted-foreground">Model</th>
                <th className="text-left px-3 py-2 text-xs font-medium text-muted-foreground">Translation</th>
                <th className="px-3 py-2 w-20" />
              </tr>
            </thead>
            <tbody>
              {translations.map((t, i) => (
                <tr key={t.id} className={cn('border-t border-border', i % 2 === 0 ? 'bg-card' : 'bg-muted/20')}>
                  <td className="px-3 py-2"><Badge variant="outline" className="text-xs">{OBJECT_TYPE_LABELS[t.object_type] ?? t.object_type}</Badge></td>
                  <td className="px-3 py-2 font-medium">{t.object_name}</td>
                  <td className="px-3 py-2 text-xs">{VENDOR_LABELS[t.target_vendor] ?? t.target_vendor}</td>
                  <td className="px-3 py-2 text-xs text-muted-foreground">
                    {t.ai_model === 'fast-path' ? <span className="flex items-center gap-1"><Zap className="h-3 w-3 text-emerald-500" />auto</span> : (t.ai_model ?? '—')}
                  </td>
                  <td className="px-3 py-2">
                    <code className="text-xs bg-muted/30 rounded px-1 py-0.5 max-w-xs truncate block">{JSON.stringify(t.translation)}</code>
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex gap-1 justify-end">
                      <Button size="sm" variant="ghost" className="h-6 px-2" onClick={() => setEditItem(t)}><Edit className="h-3 w-3" /></Button>
                      <Button size="sm" variant="ghost" className="h-6 px-2 text-destructive" onClick={() => remove.mutate(t.id)} disabled={remove.isPending}><Trash2 className="h-3 w-3" /></Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <Dialog open={createOpen} onClose={() => setCreateOpen(false)} title="Add Object Translation" className="max-w-2xl">
        <ObjectTranslationForm onSubmit={d => upsert.mutate(d)} onClose={() => setCreateOpen(false)} loading={upsert.isPending} />
        {upsert.error && <p className="text-destructive text-xs mt-2">{String(upsert.error)}</p>}
      </Dialog>
      <Dialog open={!!editItem} onClose={() => setEditItem(null)} title={`Edit: ${editItem?.object_name}`} className="max-w-2xl">
        {editItem && <ObjectTranslationForm initial={editItem} onSubmit={d => upsert.mutate(d)} onClose={() => setEditItem(null)} loading={upsert.isPending} />}
        {upsert.error && <p className="text-destructive text-xs mt-2">{String(upsert.error)}</p>}
      </Dialog>
    </div>
  )
}

function RuleTranslationsSection() {
  const qc = useQueryClient()
  const [vendorFilter, setVendorFilter] = useState<string>('')
  const [editItem, setEditItem] = useState<RuleTranslation | null>(null)

  const { data: translations = [], isLoading } = useQuery({
    queryKey: ['rule-translations', vendorFilter],
    queryFn: () => api.translations.listRuleTranslations(vendorFilter || undefined, 'approved'),
  })

  const upsert = useMutation({
    mutationFn: (data: Parameters<typeof api.translations.upsertRuleTranslation>[0]) =>
      api.translations.upsertRuleTranslation(data),
    onSuccess: () => { setEditItem(null); qc.invalidateQueries({ queryKey: ['rule-translations'] }) },
  })

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="font-medium text-sm">Rule Translations</h3>
        <Select value={vendorFilter} onChange={e => setVendorFilter(e.target.value)} className="w-44 h-8 text-xs">
          <option value="">All vendors</option>
          {VENDORS.map(v => <option key={v} value={v}>{VENDOR_LABELS[v] ?? v}</option>)}
        </Select>
      </div>
      {isLoading && <div className="text-muted-foreground text-sm">Loading…</div>}
      {translations.length === 0 && !isLoading ? (
        <p className="text-sm text-muted-foreground italic py-2">No approved rule translations{vendorFilter ? ` for ${VENDOR_LABELS[vendorFilter]}` : ''}.</p>
      ) : (
        <div className="border border-border rounded-md overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-muted/50">
              <tr>
                <th className="text-left px-3 py-2 text-xs font-medium text-muted-foreground">Rule ID</th>
                <th className="text-left px-3 py-2 text-xs font-medium text-muted-foreground">Vendor</th>
                <th className="text-left px-3 py-2 text-xs font-medium text-muted-foreground">Translation (override)</th>
                <th className="text-left px-3 py-2 text-xs font-medium text-muted-foreground">Approved by</th>
                <th className="px-3 py-2 w-16" />
              </tr>
            </thead>
            <tbody>
              {translations.map((t, i) => (
                <tr key={t.id} className={cn('border-t border-border', i % 2 === 0 ? 'bg-card' : 'bg-muted/20')}>
                  <td className="px-3 py-2 font-mono text-xs">#{t.rule_id}</td>
                  <td className="px-3 py-2 text-xs">{VENDOR_LABELS[t.target_vendor] ?? t.target_vendor}</td>
                  <td className="px-3 py-2">
                    <code className="text-xs bg-muted/30 rounded px-1 py-0.5 max-w-xs truncate block">{JSON.stringify(t.translation)}</code>
                  </td>
                  <td className="px-3 py-2 text-xs text-muted-foreground">{t.approved_by ?? '—'}</td>
                  <td className="px-3 py-2">
                    <Button size="sm" variant="ghost" className="h-6 px-2" onClick={() => setEditItem(t)}><Edit className="h-3 w-3" /></Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {editItem && (
        <Dialog open={!!editItem} onClose={() => setEditItem(null)} title={`Edit Rule #${editItem.rule_id} → ${VENDOR_LABELS[editItem.target_vendor] ?? editItem.target_vendor}`} className="max-w-2xl">
          <div className="space-y-3">
            <div className="space-y-1">
              <label className="text-xs text-muted-foreground">Translation override (JSON)</label>
              <JsonTextarea
                value={JSON.stringify(editItem.translation, null, 2)}
                onChange={v => setEditItem(x => x ? { ...x, translation: (() => { try { return JSON.parse(v) } catch { return x.translation } })() } : null)}
              />
            </div>
            <div className="flex justify-end gap-2">
              <Button variant="ghost" onClick={() => setEditItem(null)}>Cancel</Button>
              <Button onClick={() => upsert.mutate({ rule_id: editItem.rule_id, target_vendor: editItem.target_vendor, translation: editItem.translation })} disabled={upsert.isPending}>
                {upsert.isPending ? 'Saving…' : 'Save'}
              </Button>
            </div>
            {upsert.error && <p className="text-destructive text-xs">{String(upsert.error)}</p>}
          </div>
        </Dialog>
      )}
    </div>
  )
}

// ── Page root ─────────────────────────────────────────────────────────────────

type PageView = 'matrix' | 'advanced' | 'approved'

export function Translations() {
  const [view, setView] = useState<PageView>('matrix')
  const [highlightProposal, setHighlightProposal] = useState<number | undefined>()

  const handleShowAdvanced = (proposalId?: number) => {
    setHighlightProposal(proposalId)
    setView('advanced')
  }

  return (
    <div className="p-6 space-y-5 max-w-5xl mx-auto">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold">Translations</h1>
          <p className="text-muted-foreground text-sm mt-1">
            Deployment readiness by group and vendor — detect gaps, generate translations, approve for push.
          </p>
        </div>
      </div>

      {/* Tab bar */}
      <div className="flex gap-0 border-b border-border">
        {([
          { key: 'matrix' as PageView, label: 'Readiness Matrix' },
          { key: 'advanced' as PageView, label: 'All Proposals' },
          { key: 'approved' as PageView, label: 'Approved Translations' },
        ] as const).map(t => (
          <button
            key={t.key}
            onClick={() => setView(t.key)}
            className={cn(
              'px-4 py-2 text-sm border-b-2 -mb-px transition-colors',
              view === t.key
                ? 'border-primary text-primary font-medium'
                : 'border-transparent text-muted-foreground hover:text-foreground',
            )}
          >
            {t.label}
          </button>
        ))}
      </div>

      {view === 'matrix' && <ReadinessMatrix onShowAdvanced={handleShowAdvanced} />}

      {view === 'advanced' && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">All Proposals</CardTitle>
            <p className="text-xs text-muted-foreground">Every translation proposal — filter by status and vendor.</p>
          </CardHeader>
          <CardContent>
            <AdvancedProposals highlightId={highlightProposal} />
          </CardContent>
        </Card>
      )}

      {view === 'approved' && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Approved Translations</CardTitle>
            <p className="text-xs text-muted-foreground">
              Vendor-specific representations used at push time. Auto-approved via fast-path or manually reviewed.
            </p>
          </CardHeader>
          <CardContent className="space-y-8">
            <ObjectTranslationsSection />
            <div className="border-t border-border pt-6">
              <RuleTranslationsSection />
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
