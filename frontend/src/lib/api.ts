const BASE = '/api/v1'

async function req<T>(path: string, opts?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...opts?.headers },
    ...opts,
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail ?? res.statusText)
  }
  return res.json()
}

function qs(params: Record<string, string | number | undefined | null>): string {
  const entries = Object.entries(params)
    .filter(([, v]) => v != null)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v!))}`)
  return entries.length ? '?' + entries.join('&') : ''
}

// ── Types — observed state ────────────────────────────────────────────────────

export interface Device {
  id: number
  name: string
  vendor: string
  host: string | null
  port: number | null
  verify_ssl: boolean
  has_credentials: boolean
  notes: string | null
  created_at: string
  last_synced_at: string | null
  snapshot_count: number
  latest_object_count: number | null
  device_group_id: number | null
  device_group_name: string | null
}

export interface DeviceCreate {
  name: string
  vendor: string
  host: string
  port?: number
  verify_ssl?: boolean
  username?: string
  password?: string
  api_key?: string
  notes?: string
}

export interface Snapshot {
  id: number
  device_name: string
  vendor: string
  status: string
  triggered_by: string
  object_count: number | null
  created_at: string
  completed_at: string | null
}

export interface PolicyObject {
  id: number
  object_type: string
  object_name: string
  vendor: string
  data: Record<string, unknown>
  content_hash: string
}

export interface Diff {
  id: number
  object_type: string
  object_name: string
  change_type: 'added' | 'removed' | 'modified'
  before: Record<string, unknown> | null
  after: Record<string, unknown> | null
  created_at: string
}

export interface ChatResponse {
  session_id: string
  answer: string
  history: Array<{ role: string; content: string }>
}

// ── Types — desired state: groups ─────────────────────────────────────────────

/** A group in the hierarchy. Groups contain devices, rules, and shared objects. */
export interface Group {
  id: number
  name: string
  parent_id: number | null
  description: string | null
  created_at: string
  device_count: number
  child_count: number
}

/** Group with nested children for tree rendering. */
export interface GroupTree extends Group {
  children: GroupTree[]
}

/** Backward-compat aliases used by older components. */
export type DeviceGroup = Group
export type DeviceGroupTree = GroupTree

export interface DeviceInGroup {
  id: number
  name: string
  vendor: string
  host: string | null
  last_synced_at: string | null
}

export interface GroupRule {
  id: number
  device_group_id: number
  rule_type: string
  rulebase: string
  position: number
  name: string
  description: string | null
  enabled: boolean
  base_rule: Record<string, unknown>
  created_at: string
  updated_at: string | null
}

export interface GroupObject {
  id: number
  device_group_id: number | null
  object_type: string
  object_name: string
  description: string | null
  base_data: Record<string, unknown>
  created_at: string
  updated_at: string | null
}

export interface ZoneMapping {
  id: number
  device_id: number
  logical_zone: string
  vendor_zone: string
}

export interface EffectivePolicy {
  device_group_id: number
  device_group_name: string
  ancestor_chain: string[]
  pre_rules: GroupRule[]
  post_rules: GroupRule[]
}

export interface GapDetectionResult {
  target_vendor: string
  device_group_id: number
  missing_object_translations: Array<{ object_type: string; object_name: string }>
  missing_rule_translations: Array<{ rule_id: number; rule_name: string }>
  proposals_created: number
}

export interface ComplianceItem {
  object_type: string
  object_name: string
  /** compliant | drifted | orphan | missing */
  status: string
  intent_data: Record<string, unknown> | null
  live_data: Record<string, unknown> | null
}

export interface ComplianceResult {
  device_name: string
  group_name: string
  compliant: ComplianceItem[]
  drifted: ComplianceItem[]
  orphan: ComplianceItem[]
  missing: ComplianceItem[]
  score: number
}

// ── Types — import from device ────────────────────────────────────────────────

export interface ImportCandidate {
  object_type: string
  object_name: string
  vendor_data: Record<string, unknown>
  proposed_base: Record<string, unknown>
  reasoning: string
  selected: boolean
}

export interface ImportPreview {
  device_name: string
  vendor: string
  snapshot_id: number
  candidates: ImportCandidate[]
  total: number
  ai_processed: number
  ai_failed: number
}

export interface ImportConfirmResult {
  rules_created: number
  objects_created: number
}

// ── Types — desired state: translations ───────────────────────────────────────

export interface ObjectTranslation {
  id: number
  object_type: string
  object_name: string
  target_vendor: string
  translation: Record<string, unknown>
  status: string
  ai_reasoning: string | null
  ai_model: string | null
  approved_by: string | null
  created_at: string
  updated_at: string | null
}

export interface RuleTranslation {
  id: number
  rule_id: number
  target_vendor: string
  translation: Record<string, unknown>
  status: string
  ai_reasoning: string | null
  ai_model: string | null
  approved_by: string | null
  created_at: string
  updated_at: string | null
}

export interface Proposal {
  id: number
  proposal_type: string
  object_type: string | null
  object_name: string | null
  rule_id: number | null
  target_vendor: string
  proposed_translation: Record<string, unknown>
  ai_reasoning: string | null
  ai_model: string | null
  triggered_by: string
  status: string
  reviewed_by: string | null
  reviewed_at: string | null
  created_at: string
}

export interface GenerateResult {
  proposal_id: number
  status: string
  ai_model: string | null
  error: string | null
}

export interface BatchGenerateResult {
  processed: number
  succeeded: number
  failed: number
  results: GenerateResult[]
}

export interface ReadinessItem {
  item_type: 'object' | 'rule'
  object_type: string | null
  object_name: string | null
  rule_id: number | null
  rule_name: string | null
  rule_type: string | null
  /** auto | approved | pending | review | rejected | not_required | none */
  status: string
  proposal_id: number | null
  ai_model: string | null
}

export interface ReadinessResult {
  target_vendor: string
  device_group_id: number
  objects: ReadinessItem[]
  rules: ReadinessItem[]
  summary: Record<string, number>
}

// ── API ───────────────────────────────────────────────────────────────────────

export const api = {
  // ── Devices ─────────────────────────────────────────────────────────────────
  devices: {
    list: () => req<Device[]>('/devices'),
    get: (name: string) => req<Device>(`/devices/${name}`),
    create: (data: DeviceCreate) => req<Device>('/devices', { method: 'POST', body: JSON.stringify(data) }),
    update: (name: string, data: Partial<DeviceCreate>) => req<Device>(`/devices/${name}`, { method: 'PATCH', body: JSON.stringify(data) }),
    delete: (name: string) => fetch(`${BASE}/devices/${name}`, { method: 'DELETE' }),
    onboard: (name: string) => req<Record<string, unknown>>(`/firewall/devices/${name}/onboard`, { method: 'POST' }),
    reindex: (name: string) => req<Record<string, unknown>>(`/firewall/devices/${name}/reindex`, { method: 'POST' }),
  },

  // ── Snapshots ────────────────────────────────────────────────────────────────
  snapshots: {
    list: (device?: string) => req<Snapshot[]>(`/snapshots${device ? `?device=${device}` : ''}`),
    objects: (snapshotId: number, objectType?: string, limit = 100, offset = 0) =>
      req<PolicyObject[]>(`/snapshots/${snapshotId}/objects?limit=${limit}&offset=${offset}${objectType ? `&object_type=${objectType}` : ''}`),
    diffs: (snapshotId: number) => req<Diff[]>(`/snapshots/${snapshotId}/diffs`),
    summary: (snapshotId: number) => req<{ snapshot_id: number; types: Record<string, number> }>(`/snapshots/${snapshotId}/summary`),
    updateObject: (objectId: number, data: Record<string, unknown>) =>
      req<PolicyObject>(`/snapshots/objects/${objectId}`, { method: 'PATCH', body: JSON.stringify(data) }),
  },

  // ── Groups ───────────────────────────────────────────────────────────────────
  groups: {
    list: () => req<Group[]>('/groups'),
    tree: () => req<GroupTree[]>('/groups/tree'),
    get: (id: number) => req<Group>(`/groups/${id}`),
    create: (data: { name: string; parent_id?: number | null; description?: string }) =>
      req<Group>('/groups', { method: 'POST', body: JSON.stringify(data) }),
    update: (id: number, data: Record<string, unknown>) =>
      req<Group>(`/groups/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
    delete: (id: number) => fetch(`${BASE}/groups/${id}`, { method: 'DELETE' }),

    listDevices: (groupId: number) => req<DeviceInGroup[]>(`/groups/${groupId}/devices`),
    assignDevice: (groupId: number, deviceName: string) =>
      fetch(`${BASE}/groups/${groupId}/devices/${deviceName}`, { method: 'POST' }),
    unassignDevice: (groupId: number, deviceName: string) =>
      fetch(`${BASE}/groups/${groupId}/devices/${deviceName}`, { method: 'DELETE' }),

    listRules: (groupId: number, rulebase?: string) =>
      req<GroupRule[]>(`/groups/${groupId}/rules${qs({ rulebase })}`),
    createRule: (groupId: number, data: Omit<GroupRule, 'id' | 'device_group_id' | 'created_at' | 'updated_at'>) =>
      req<GroupRule>(`/groups/${groupId}/rules`, { method: 'POST', body: JSON.stringify(data) }),
    updateRule: (ruleId: number, data: Record<string, unknown>) =>
      req<GroupRule>(`/groups/rules/${ruleId}`, { method: 'PATCH', body: JSON.stringify(data) }),
    deleteRule: (ruleId: number) => fetch(`${BASE}/groups/rules/${ruleId}`, { method: 'DELETE' }),
    effectivePolicy: (groupId: number, ruleType = 'security') =>
      req<EffectivePolicy>(`/groups/${groupId}/effective-policy?rule_type=${ruleType}`),

    listObjects: (groupId: number) => req<GroupObject[]>(`/groups/${groupId}/objects`),
    createObject: (groupId: number, data: { object_type: string; object_name: string; description?: string; base_data?: Record<string, unknown> }) =>
      req<GroupObject>(`/groups/${groupId}/objects`, { method: 'POST', body: JSON.stringify(data) }),
    updateObject: (objectId: number, data: Record<string, unknown>) =>
      req<GroupObject>(`/groups/objects/${objectId}`, { method: 'PATCH', body: JSON.stringify(data) }),
    deleteObject: (objectId: number) => fetch(`${BASE}/groups/objects/${objectId}`, { method: 'DELETE' }),

    listZones: (deviceName: string) => req<ZoneMapping[]>(`/groups/devices/${deviceName}/zones`),
    setZones: (deviceName: string, mappings: Array<{ logical_zone: string; vendor_zone: string }>) =>
      req<ZoneMapping[]>(`/groups/devices/${deviceName}/zones`, { method: 'PUT', body: JSON.stringify(mappings) }),

    detectGaps: (groupId: number, vendor: string) =>
      req<GapDetectionResult>(`/groups/${groupId}/gaps/${vendor}`, { method: 'POST' }),

    /** Compliance drift report — compare device's live snapshot to group's intent policy. */
    getCompliance: (groupId: number, deviceName: string) =>
      req<ComplianceResult>(`/groups/${groupId}/compliance/${deviceName}`),

    /** Enqueue a background import preview; returns task_id immediately (202). */
    importStart: (groupId: number, deviceName: string, limit = 50) =>
      req<{ task_id: string; status: string }>(`/groups/${groupId}/import/${deviceName}/start${qs({ limit })}`, { method: 'POST' }),

    /** Preview AI-normalized policy from device's latest snapshot for import review. */
    importPreview: (groupId: number, deviceName: string, limit = 50) =>
      req<ImportPreview>(`/groups/${groupId}/import/${deviceName}/preview${qs({ limit })}`, { method: 'POST' }),

    /** Commit selected import candidates to the group's desired-state policy. */
    importConfirm: (
      groupId: number,
      deviceName: string,
      data: { snapshot_id: number; candidates: ImportCandidate[]; rulebase?: string },
    ) => req<ImportConfirmResult>(`/groups/${groupId}/import/${deviceName}/confirm`, {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  },

  // ── Translations ─────────────────────────────────────────────────────────────
  translations: {
    listObjectTranslations: (vendor?: string, status?: string) =>
      req<ObjectTranslation[]>(`/translations/objects${qs({ target_vendor: vendor, status })}`),
    upsertObjectTranslation: (data: { object_type: string; object_name: string; target_vendor: string; translation: Record<string, unknown> }) =>
      req<ObjectTranslation>('/translations/objects', { method: 'PUT', body: JSON.stringify(data) }),
    deleteObjectTranslation: (id: number) => fetch(`${BASE}/translations/objects/${id}`, { method: 'DELETE' }),

    listRuleTranslations: (vendor?: string, status?: string) =>
      req<RuleTranslation[]>(`/translations/rules${qs({ target_vendor: vendor, status })}`),
    upsertRuleTranslation: (data: { rule_id: number; target_vendor: string; translation: Record<string, unknown> }) =>
      req<RuleTranslation>('/translations/rules', { method: 'PUT', body: JSON.stringify(data) }),

    listProposals: (status = 'pending', vendor?: string) =>
      req<Proposal[]>(`/proposals${qs({ status, target_vendor: vendor })}`),
    reviewProposal: (id: number, data: { action: string; reviewed_by?: string; modified_translation?: Record<string, unknown> }) =>
      req<Proposal>(`/proposals/${id}/review`, { method: 'POST', body: JSON.stringify(data) }),

    /** Run AI generation for a single pending proposal. */
    generateProposal: (id: number) =>
      req<GenerateResult>(`/proposals/${id}/generate`, { method: 'POST' }),

    /** Run AI generation for all empty pending proposals matching filters. */
    generateBatch: (opts?: { target_vendor?: string; group_id?: number; proposal_type?: string }) =>
      req<BatchGenerateResult>(`/proposals/generate-batch${qs(opts ?? {})}`, { method: 'POST' }),

    /** Translation readiness for every policy item in a group for a target vendor. */
    getReadiness: (groupId: number, vendor: string) =>
      req<ReadinessResult>(`/groups/${groupId}/readiness/${vendor}`),
  },

  // ── RAG ──────────────────────────────────────────────────────────────────────
  rag: {
    search: (q: string, limit = 10) => req<{ query: string; results: Array<{ content: string; metadata: Record<string, string> }> }>(`/rag/search?q=${encodeURIComponent(q)}&limit=${limit}`),
    status: () => req<{ document_count: number; collection: string }>('/rag/status'),
  },

  // ── Chat ─────────────────────────────────────────────────────────────────────
  chat: {
    send: (sessionId: string, message: string) =>
      req<ChatResponse>('/chat', { method: 'POST', body: JSON.stringify({ session_id: sessionId, message }) }),
    clear: (sessionId: string) => fetch(`${BASE}/chat/${sessionId}`, { method: 'DELETE' }),
  },

  health: () => req<{ status: string; env: string }>('/health').catch(() => ({ status: 'error', env: '' })),

  tasks: {
    get: (taskId: string) => req<TaskStatus>(`/tasks/${taskId}`),
  },

  settings: {
    list: () => req<SystemSetting[]>('/settings'),
    upsert: (key: string, value: string | number | boolean | null) =>
      req<SystemSetting>(`/settings/${key}`, { method: 'PUT', body: JSON.stringify({ value }) }),
    delete: (key: string) => fetch(`${BASE}/settings/${key}`, { method: 'DELETE' }),
  },

  push: {
    listJobs: (deviceName?: string) =>
      req<PushJob[]>(`/push/jobs${qs({ device_name: deviceName })}`),
    getJob: (jobId: number) => req<PushJob>(`/push/jobs/${jobId}`),
    getJobItems: (jobId: number, action?: string) =>
      req<PushJobItem[]>(`/push/jobs/${jobId}/items${qs({ action })}`),
    createJob: (data: { device_name: string; group_id?: number; dry_run?: boolean }) =>
      req<PushJob>('/push/jobs', { method: 'POST', body: JSON.stringify(data) }),
    execute: (jobId: number) =>
      req<PushJob>(`/push/jobs/${jobId}/execute`, { method: 'POST' }),
    rollback: (jobId: number) =>
      req<PushJob>(`/push/jobs/${jobId}/rollback`, { method: 'POST' }),
  },
}

export interface TaskStatus {
  task_id: string
  status: 'pending' | 'complete' | 'error'
  result: ImportPreview | null
  error: string | null
}

export interface SystemSetting {
  key: string
  value: string | number | boolean | null
  updated_at: string | null
}

export interface PushJobItem {
  id: number
  item_type: string
  object_type: string
  item_name: string
  action: string
  vendor_payload: Record<string, unknown>
  status: string
  error: string | null
  sequence: number
}

export interface PushJob {
  id: number
  device_name: string
  vendor: string
  group_id: number
  triggered_by: string
  /** pending | running | complete | failed | partial | rolled_back */
  status: string
  dry_run: boolean
  started_at: string | null
  completed_at: string | null
  pushed_rules: number
  pushed_objects: number
  error_summary: string | null
  created_at: string
  creates: number
  updates: number
  no_changes: number
  failed: number
}
