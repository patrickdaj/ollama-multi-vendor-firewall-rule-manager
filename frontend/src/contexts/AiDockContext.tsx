/**
 * AiDockContext — global state for the persistent AI dock.
 *
 * Owns the WebSocket connection to /ws/agent/{sessionId} so it stays alive
 * across navigation. Exposes chat messages, task queue, dock layout state,
 * and a sendMessage() function usable from any component.
 *
 * Task lifecycle:
 *   task_start → status: 'running'
 *   task_done  → status: 'done', triggers react-query cache invalidation
 *   task_error → status: 'error'
 *
 * Reconnect: exponential back-off up to 8 s, resets on successful open.
 */
import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
} from 'react'
import { useQueryClient } from '@tanstack/react-query'

// ── Types ─────────────────────────────────────────────────────────────────────

export type DockState = 'collapsed' | 'expanded' | 'maximized'

export type TaskStatus = 'running' | 'done' | 'error'

export interface AiTask {
  id: string
  tool: string
  description: string
  status: TaskStatus
  result?: string
  error?: string
  ts: number
}

export interface Message {
  id: string
  role: 'user' | 'assistant'
  content: string
  ts: number
}

export interface Notification {
  id: string
  kind: 'done' | 'error'
  text: string
  ts: number
  action?: { label: string; href: string }
}

export interface BackgroundJob {
  taskId: string
  label: string       // e.g. "Import from asa-fw01"
  href?: string       // where to navigate on completion
  startedAt: number
}

interface AiDockContextValue {
  // Layout
  dockState: DockState
  setDockState: (s: DockState) => void
  toggle: () => void

  // Chat
  messages: Message[]
  isStreaming: boolean
  sendMessage: (text: string) => void
  clearHistory: () => void

  // Tasks
  tasks: AiTask[]
  runningCount: number

  // Notifications
  notifications: Notification[]
  dismissNotification: (id: string) => void

  // Background jobs (Huey tasks tracked globally)
  backgroundJobs: BackgroundJob[]
  addBackgroundJob: (job: BackgroundJob) => void
}

// ── Context ───────────────────────────────────────────────────────────────────

const AiDockContext = createContext<AiDockContextValue | null>(null)

export function useAiDock(): AiDockContextValue {
  const ctx = useContext(AiDockContext)
  if (!ctx) throw new Error('useAiDock must be used inside AiDockProvider')
  return ctx
}

// ── Session ID ────────────────────────────────────────────────────────────────

function getSessionId(): string {
  const key = 'ignis-ai-session'
  let id = localStorage.getItem(key)
  if (!id) {
    id = `s-${Math.random().toString(36).slice(2)}-${Date.now().toString(36)}`
    localStorage.setItem(key, id)
  }
  return id
}

// ── Query key → invalidation mapping ─────────────────────────────────────────

/**
 * Map string tokens from "invalidate" arrays to react-query key arrays.
 * Tokens like "group-devices-12" become ['group-devices', 12].
 */
function tokenToQueryKey(token: string): unknown[] {
  const groupDeviceMatch = token.match(/^group-devices-(\d+)$/)
  if (groupDeviceMatch) return ['group-devices', parseInt(groupDeviceMatch[1], 10)]

  const groupRulesMatch = token.match(/^group-rules-(\d+)$/)
  if (groupRulesMatch) return ['group-rules', parseInt(groupRulesMatch[1], 10)]

  // Simple tokens map to single-element arrays
  const map: Record<string, unknown[]> = {
    devices: ['devices'],
    groups: ['groups'],
    'groups-tree': ['groups-tree'],
    snapshots: ['snapshots'],
    proposals: ['proposals'],
    'object-translations': ['object-translations'],
    'rule-translations': ['rule-translations'],
  }
  return map[token] ?? [token]
}

// ── Provider ──────────────────────────────────────────────────────────────────

const SESSION_ID = getSessionId()
const WS_URL = () => `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws/agent/${SESSION_ID}`

const MAX_TASKS = 50
const NOTIFICATION_TTL = 5000
const MSG_STORAGE_KEY = `ignis-msgs-${SESSION_ID}`

// ── localStorage message persistence ─────────────────────────────────────────

function loadStoredMessages(): Message[] {
  try {
    const raw = localStorage.getItem(MSG_STORAGE_KEY)
    return raw ? (JSON.parse(raw) as Message[]) : []
  } catch {
    return []
  }
}

function persistMessages(msgs: Message[]) {
  try {
    localStorage.setItem(MSG_STORAGE_KEY, JSON.stringify(msgs.slice(-60)))
  } catch {}
}

function historyToMessages(history: Array<{ role: string; content: string }>): Message[] {
  return history.map((h, i) => ({
    id: `h-${i}`,
    role: h.role as 'user' | 'assistant',
    content: h.content,
    ts: Date.now() - (history.length - i) * 100,
  }))
}

// ── Provider ──────────────────────────────────────────────────────────────────

export function AiDockProvider({ children }: { children: React.ReactNode }) {
  const qc = useQueryClient()

  const [dockState, setDockState] = useState<DockState>('collapsed')
  const [messages, setMessages] = useState<Message[]>(loadStoredMessages)
  const [tasks, setTasks] = useState<AiTask[]>([])
  const [notifications, setNotifications] = useState<Notification[]>([])
  const [isStreaming, setIsStreaming] = useState(false)
  const [backgroundJobs, setBackgroundJobs] = useState<BackgroundJob[]>(() => {
    try { return JSON.parse(localStorage.getItem('ignis-bg-jobs') ?? '[]') } catch { return [] }
  })

  const wsRef = useRef<WebSocket | null>(null)
  const retryDelay = useRef(500)
  const streamingMsgId = useRef<string | null>(null)

  // Persist messages whenever they change (skip empty placeholder during streaming)
  useEffect(() => {
    if (!isStreaming) persistMessages(messages)
  }, [messages, isStreaming])

  // ── Notification helpers ──────────────────────────────────────────────────

  const addNotification = useCallback((kind: 'done' | 'error', text: string, href?: string) => {
    const id = Math.random().toString(36).slice(2)
    const action = href ? { label: 'View', href } : undefined
    setNotifications(ns => [...ns, { id, kind, text, ts: Date.now(), action }])
    setTimeout(() => {
      setNotifications(ns => ns.filter(n => n.id !== id))
    }, NOTIFICATION_TTL)
  }, [])

  const dismissNotification = useCallback((id: string) => {
    setNotifications(ns => ns.filter(n => n.id !== id))
  }, [])

  // ── Background job tracking ───────────────────────────────────────────────

  const addBackgroundJob = useCallback((job: BackgroundJob) => {
    setBackgroundJobs(js => {
      const updated = [...js, job]
      localStorage.setItem('ignis-bg-jobs', JSON.stringify(updated))
      return updated
    })
  }, [])

  // Poll all pending background jobs every 3 s; fire notification on completion
  useEffect(() => {
    if (backgroundJobs.length === 0) return
    const timer = setInterval(async () => {
      const remaining: BackgroundJob[] = []
      for (const job of backgroundJobs) {
        try {
          const res = await fetch(`/api/v1/tasks/${job.taskId}`)
          const data = await res.json()
          if (data.status === 'complete') {
            const total = data.result?.total ?? '?'
            const failed = data.result?.ai_failed ?? 0
            const detail = failed ? ` (${failed} failed)` : ''
            addNotification('done', `${job.label} ready — ${total} objects${detail}`, job.href)
          } else if (data.status === 'error') {
            addNotification('error', `${job.label} failed: ${data.error ?? 'unknown error'}`)
          } else {
            remaining.push(job)
          }
        } catch {
          remaining.push(job)
        }
      }
      setBackgroundJobs(remaining)
      localStorage.setItem('ignis-bg-jobs', JSON.stringify(remaining))
    }, 3000)
    return () => clearInterval(timer)
  }, [backgroundJobs, addNotification])

  // ── WS message handler ────────────────────────────────────────────────────

  const handleMessage = useCallback((raw: MessageEvent<string>) => {
    let event: Record<string, unknown>
    try {
      event = JSON.parse(raw.data)
    } catch {
      return
    }

    const type = event.type as string

    if (type === 'start') {
      setIsStreaming(true)
      const id = Math.random().toString(36).slice(2)
      streamingMsgId.current = id
      setMessages(ms => [...ms, { id, role: 'assistant', content: '', ts: Date.now() }])
      return
    }

    if (type === 'token') {
      const content = (event.content as string) ?? ''
      const id = streamingMsgId.current
      if (id) {
        setMessages(ms =>
          ms.map(m => m.id === id ? { ...m, content: m.content + content } : m)
        )
      }
      return
    }

    if (type === 'task_start') {
      const task: AiTask = {
        id: event.task_id as string,
        tool: (event.tool as string) ?? '',
        description: (event.description as string) ?? 'Working…',
        status: 'running',
        ts: Date.now(),
      }
      setTasks(ts => [task, ...ts].slice(0, MAX_TASKS))
      return
    }

    if (type === 'task_done') {
      const taskId = event.task_id as string
      const result = (event.result as string) ?? ''
      const invalidate = (event.invalidate as string[]) ?? []
      setTasks(ts => ts.map(t => t.id === taskId ? { ...t, status: 'done', result } : t))
      addNotification('done', result || 'Task completed')
      for (const token of invalidate) {
        qc.invalidateQueries({ queryKey: tokenToQueryKey(token) })
      }
      return
    }

    if (type === 'task_error') {
      const taskId = event.task_id as string
      const error = (event.error as string) ?? 'Unknown error'
      setTasks(ts => ts.map(t => t.id === taskId ? { ...t, status: 'error', error } : t))
      addNotification('error', error)
      return
    }

    if (type === 'end') {
      setIsStreaming(false)
      streamingMsgId.current = null
      const history = (event.history as Array<{ role: string; content: string }>) ?? []
      // Server history is authoritative — but only if it has content
      if (history.length > 0) {
        setMessages(historyToMessages(history))
      }
      return
    }

    if (type === 'history') {
      const history = (event.history as Array<{ role: string; content: string }>) ?? []
      // On restore: prefer server history; fall back to localStorage (survives container restarts)
      if (history.length > 0) {
        setMessages(historyToMessages(history))
      }
      // If server returns empty, existing localStorage-seeded state is kept as-is
    }
  }, [qc, addNotification])

  // ── WebSocket lifecycle ───────────────────────────────────────────────────

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return

    const ws = new WebSocket(WS_URL())

    ws.onopen = () => {
      retryDelay.current = 500
      ws.send(JSON.stringify({ action: 'restore' }))
    }

    ws.onmessage = handleMessage

    ws.onclose = () => {
      wsRef.current = null
      const delay = retryDelay.current
      retryDelay.current = Math.min(delay * 2, 8000)
      setTimeout(connect, delay)
    }

    ws.onerror = () => ws.close()

    wsRef.current = ws
  }, [handleMessage])

  useEffect(() => {
    connect()
    return () => { wsRef.current?.close() }
  }, [connect])

  // ── Public API ────────────────────────────────────────────────────────────

  const sendMessage = useCallback((text: string) => {
    const trimmed = text.trim()
    if (!trimmed) return

    setMessages(ms => [
      ...ms,
      { id: Math.random().toString(36).slice(2), role: 'user', content: trimmed, ts: Date.now() },
    ])
    setDockState(s => s === 'collapsed' ? 'expanded' : s)

    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ action: 'chat', message: trimmed }))
    } else {
      connect()
      const check = setInterval(() => {
        if (wsRef.current?.readyState === WebSocket.OPEN) {
          wsRef.current.send(JSON.stringify({ action: 'chat', message: trimmed }))
          clearInterval(check)
        }
      }, 200)
      setTimeout(() => clearInterval(check), 8000)
    }
  }, [connect])

  const clearHistory = useCallback(() => {
    setMessages([])
    try { localStorage.removeItem(MSG_STORAGE_KEY) } catch {}
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ action: 'clear' }))
    }
  }, [])

  const toggle = useCallback(() => {
    setDockState(s => s === 'collapsed' ? 'expanded' : 'collapsed')
  }, [])

  const runningCount = tasks.filter(t => t.status === 'running').length

  return (
    <AiDockContext.Provider value={{
      dockState, setDockState, toggle,
      messages, isStreaming, sendMessage, clearHistory,
      tasks, runningCount,
      notifications, dismissNotification,
      backgroundJobs, addBackgroundJob,
    }}>
      {children}
    </AiDockContext.Provider>
  )
}
