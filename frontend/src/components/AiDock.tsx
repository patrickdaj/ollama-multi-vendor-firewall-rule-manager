/**
 * AiDock — persistent AI assistant panel fixed to the bottom of every page.
 *
 * Three layout states:
 *   collapsed  — 52px slim bar; input always visible
 *   expanded   — 45vh; message history + task list
 *   maximized  — 80vh; same, more room
 */
import { useEffect, useRef, useState, useCallback, type KeyboardEvent } from 'react'
import {
  Flame, ChevronUp, ChevronDown, Maximize2, Minimize2,
  X, Check, AlertCircle, Loader2, Trash2, MessageSquare, ExternalLink,
} from 'lucide-react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import remarkBreaks from 'remark-breaks'
import { useAiDock, type AiTask, type Message } from '@/contexts/AiDockContext'
import { cn } from '@/lib/utils'

// ── Heights ───────────────────────────────────────────────────────────────────

const COLLAPSED_H = 52
const EXPANDED_H = '45vh'
const MAXIMIZED_H = '80vh'

// ── Markdown renderer ─────────────────────────────────────────────────────────

function AssistantMarkdown({ content }: { content: string }) {
  return (
    <ReactMarkdown
      remarkPlugins={[remarkGfm, remarkBreaks]}
      components={{
        p: ({ children }) => <p className="mb-2 last:mb-0">{children}</p>,
        ul: ({ children }) => <ul className="mb-2 ml-4 list-disc space-y-0.5">{children}</ul>,
        ol: ({ children }) => <ol className="mb-2 ml-4 list-decimal space-y-0.5">{children}</ol>,
        li: ({ children }) => <li>{children}</li>,
        strong: ({ children }) => <strong className="font-semibold">{children}</strong>,
        em: ({ children }) => <em className="italic opacity-80">{children}</em>,
        code: ({ className, children }) => {
          const isBlock = Boolean(className?.startsWith('language-'))
          return isBlock ? (
            <pre className="mb-2 overflow-x-auto rounded bg-background/40 p-2 font-mono text-xs">
              <code className={className}>{children}</code>
            </pre>
          ) : (
            <code className="rounded bg-background/40 px-1 py-0.5 font-mono text-[11px]">{children}</code>
          )
        },
        pre: ({ children }) => <>{children}</>,
        h1: ({ children }) => <p className="mb-1 font-bold">{children}</p>,
        h2: ({ children }) => <p className="mb-1 font-bold">{children}</p>,
        h3: ({ children }) => <p className="mb-0.5 font-semibold text-xs uppercase tracking-wide opacity-70">{children}</p>,
        table: ({ children }) => (
          <div className="mb-2 overflow-x-auto -mx-1">
            <table className="w-full text-xs border-collapse">{children}</table>
          </div>
        ),
        thead: ({ children }) => <thead>{children}</thead>,
        th: ({ children }) => (
          <th className="px-2 py-1 text-left font-semibold border-b border-border/60 whitespace-nowrap bg-background/20">{children}</th>
        ),
        tbody: ({ children }) => <tbody>{children}</tbody>,
        tr: ({ children }) => <tr className="border-b border-border/20">{children}</tr>,
        td: ({ children }) => <td className="px-2 py-1 align-top">{children}</td>,
      }}
    >
      {content}
    </ReactMarkdown>
  )
}

// ── Task pill ─────────────────────────────────────────────────────────────────

function TaskPill({ task, onClick }: { task: AiTask; onClick?: () => void }) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs whitespace-nowrap border',
        'transition-opacity hover:opacity-80',
        task.status === 'running' && 'border-primary/30 bg-primary/10 text-primary',
        task.status === 'done' && 'border-green-500/30 bg-green-500/10 text-green-600 dark:text-green-400',
        task.status === 'error' && 'border-destructive/30 bg-destructive/10 text-destructive',
      )}
      title={task.result ?? task.error ?? task.description}
    >
      {task.status === 'running' && <Loader2 className="h-2.5 w-2.5 animate-spin flex-shrink-0" />}
      {task.status === 'done' && <Check className="h-2.5 w-2.5 flex-shrink-0" />}
      {task.status === 'error' && <AlertCircle className="h-2.5 w-2.5 flex-shrink-0" />}
      <span className="max-w-[140px] truncate">{task.description}</span>
    </button>
  )
}

// ── Message bubble ────────────────────────────────────────────────────────────

function MessageBubble({ msg }: { msg: Message }) {
  const isUser = msg.role === 'user'
  return (
    <div className={cn('flex', isUser ? 'justify-end' : 'justify-start')}>
      <div
        className={cn(
          'rounded-2xl px-3 py-2 text-sm',
          isUser
            ? 'max-w-[85%] bg-primary text-primary-foreground rounded-br-sm leading-relaxed'
            : 'w-full bg-muted text-foreground rounded-bl-sm',
        )}
      >
        {isUser
          ? (msg.content || <span className="opacity-40 italic">…</span>)
          : (msg.content
            ? <AssistantMarkdown content={msg.content} />
            : <span className="opacity-40 italic">…</span>)
        }
      </div>
    </div>
  )
}

// ── Task list (expanded view) ─────────────────────────────────────────────────

function TaskList({ tasks }: { tasks: AiTask[] }) {
  const [expanded, setExpanded] = useState<string | null>(null)
  if (tasks.length === 0) return null

  return (
    <div className="border-b border-border/50 px-3 py-2 space-y-1 max-h-[30%] overflow-y-auto">
      <p className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground mb-1">Tasks</p>
      {tasks.map(t => (
        <div key={t.id}>
          <button
            onClick={() => setExpanded(exp => exp === t.id ? null : t.id)}
            className={cn(
              'w-full flex items-center gap-2 text-xs rounded px-2 py-1 text-left',
              'hover:bg-background/30 transition-colors',
              t.status === 'running' && 'text-primary',
              t.status === 'done' && 'text-green-600 dark:text-green-400',
              t.status === 'error' && 'text-destructive',
            )}
          >
            {t.status === 'running' && <Loader2 className="h-3 w-3 animate-spin flex-shrink-0" />}
            {t.status === 'done' && <Check className="h-3 w-3 flex-shrink-0" />}
            {t.status === 'error' && <AlertCircle className="h-3 w-3 flex-shrink-0" />}
            <span className="flex-1 truncate">{t.description}</span>
            {(t.result || t.error) && (
              <ChevronDown className={cn('h-3 w-3 flex-shrink-0 transition-transform', expanded === t.id && 'rotate-180')} />
            )}
          </button>
          {expanded === t.id && (t.result || t.error) && (
            <p className={cn(
              'mx-7 mt-0.5 text-xs leading-snug opacity-80',
              t.status === 'error' && 'text-destructive',
            )}>
              {t.result || t.error}
            </p>
          )}
        </div>
      ))}
    </div>
  )
}

// ── Notifications ─────────────────────────────────────────────────────────────

export function NotificationToasts() {
  const { notifications, dismissNotification, backgroundJobs } = useAiDock()
  const runningJobs = backgroundJobs.length
  if (notifications.length === 0 && runningJobs === 0) return null

  return (
    <div className="fixed top-3 right-4 z-[60] flex flex-col gap-2 pointer-events-none">
      {/* Running-jobs pill */}
      {runningJobs > 0 && (
        <div className={cn(
          'flex items-center gap-2 rounded-full border px-3 py-1.5 shadow-md pointer-events-auto',
          'bg-background/90 backdrop-blur-md text-xs text-muted-foreground border-border/60',
        )}>
          <Loader2 className="h-3 w-3 animate-spin text-primary" />
          {runningJobs === 1 ? '1 background task running…' : `${runningJobs} background tasks running…`}
        </div>
      )}
      {/* Completion / error toasts */}
      {notifications.map(n => (
        <div
          key={n.id}
          className={cn(
            'flex items-start gap-2 rounded-lg border px-3 py-2.5 shadow-lg pointer-events-auto',
            'bg-background/90 backdrop-blur-md text-sm max-w-sm',
            'animate-in slide-in-from-right-4 fade-in-0 duration-200',
            n.kind === 'done' && 'border-green-500/40',
            n.kind === 'error' && 'border-destructive/40 text-destructive',
          )}
        >
          {n.kind === 'done'
            ? <Check className="h-4 w-4 flex-shrink-0 mt-0.5 text-green-500" />
            : <AlertCircle className="h-4 w-4 flex-shrink-0 mt-0.5" />}
          <span className="flex-1 leading-snug">{n.text}</span>
          {n.action && (
            <a
              href={n.action.href}
              className="flex-shrink-0 flex items-center gap-1 text-xs text-primary hover:underline font-medium"
            >
              {n.action.label}
              <ExternalLink className="h-3 w-3" />
            </a>
          )}
          <button
            onClick={() => dismissNotification(n.id)}
            className="flex-shrink-0 opacity-50 hover:opacity-100 transition-opacity"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      ))}
    </div>
  )
}

// ── Main dock ─────────────────────────────────────────────────────────────────

export function AiDock() {
  const {
    dockState, setDockState, toggle,
    messages, isStreaming, sendMessage, clearHistory,
    tasks, runningCount,
  } = useAiDock()

  const [input, setInput] = useState('')
  const msgListRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLTextAreaElement>(null)
  const isExpanded = dockState !== 'collapsed'

  const recentTasks = tasks.slice(0, 3)
  const msgCount = messages.length

  // Auto-scroll message list to bottom
  useEffect(() => {
    if (isExpanded && msgListRef.current) {
      msgListRef.current.scrollTop = msgListRef.current.scrollHeight
    }
  }, [messages, isExpanded])

  // Focus input when dock opens
  useEffect(() => {
    if (isExpanded) setTimeout(() => inputRef.current?.focus(), 50)
  }, [isExpanded])

  const submit = useCallback(() => {
    if (!input.trim() || isStreaming) return
    sendMessage(input.trim())
    setInput('')
    // Reset textarea height
    if (inputRef.current) inputRef.current.style.height = '36px'
  }, [input, isStreaming, sendMessage])

  const onKeyDown = useCallback((e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      submit()
    }
  }, [submit])

  // ── Collapsed bar ─────────────────────────────────────────────────────────

  const CollapsedBar = (
    <div className="flex items-center gap-3 px-4 h-[52px]">
      {/* Brand */}
      <button
        onClick={toggle}
        className="flex items-center gap-1.5 flex-shrink-0 hover:opacity-80 transition-opacity"
      >
        <Flame className="h-4 w-4 text-primary" />
        <span className="text-sm font-semibold text-foreground">Ignis AI</span>
      </button>

      {/* Recent task pills — clicking any expands the dock to task view */}
      {recentTasks.length > 0 && (
        <div className="flex items-center gap-1.5 flex-shrink-0">
          {recentTasks.map(t => (
            <TaskPill key={t.id} task={t} onClick={() => setDockState('expanded')} />
          ))}
          {tasks.length > 3 && (
            <button
              onClick={() => setDockState('expanded')}
              className="text-xs text-muted-foreground hover:text-foreground transition-colors"
            >
              +{tasks.length - 3} more
            </button>
          )}
        </div>
      )}

      {/* Input — clicking opens dock */}
      <div className="flex-1 min-w-0">
        <textarea
          ref={inputRef}
          rows={1}
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={onKeyDown}
          onFocus={() => { if (dockState === 'collapsed') setDockState('expanded') }}
          placeholder="Ask anything or describe a task…"
          className="w-full resize-none bg-transparent border-0 outline-none text-sm placeholder:text-muted-foreground leading-[36px] h-9 overflow-hidden"
          spellCheck={false}
        />
      </div>

      {/* Message count badge + running indicator */}
      <div className="flex items-center gap-2 flex-shrink-0">
        {runningCount > 0 && (
          <div className="flex items-center gap-1 text-primary text-xs">
            <Loader2 className="h-3 w-3 animate-spin" />
            <span>{runningCount}</span>
          </div>
        )}
        {msgCount > 0 && runningCount === 0 && (
          <button
            onClick={() => setDockState('expanded')}
            className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
            title="View conversation"
          >
            <MessageSquare className="h-3.5 w-3.5" />
            <span>{msgCount}</span>
          </button>
        )}
        <button
          onClick={toggle}
          className="p-1.5 rounded-md hover:bg-accent/50 transition-colors"
          title="Expand AI dock"
        >
          <ChevronUp className="h-4 w-4 text-muted-foreground" />
        </button>
      </div>
    </div>
  )

  // ── Expanded panel ────────────────────────────────────────────────────────

  const ExpandedPanel = (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="flex items-center gap-3 px-4 py-2.5 border-b border-border/50 flex-shrink-0">
        <Flame className="h-4 w-4 text-primary flex-shrink-0" />
        <span className="text-sm font-semibold">Ignis AI</span>

        {runningCount > 0 && (
          <div className="flex items-center gap-1 text-xs text-primary">
            <Loader2 className="h-3 w-3 animate-spin" />
            <span>{runningCount} running</span>
          </div>
        )}

        <div className="flex-1" />

        {messages.length > 0 && (
          <button
            onClick={clearHistory}
            className="p-1.5 rounded-md hover:bg-accent/50 transition-colors text-muted-foreground hover:text-foreground"
            title="Clear conversation"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        )}

        <button
          onClick={() => setDockState(dockState === 'maximized' ? 'expanded' : 'maximized')}
          className="p-1.5 rounded-md hover:bg-accent/50 transition-colors text-muted-foreground"
          title={dockState === 'maximized' ? 'Restore' : 'Maximize'}
        >
          {dockState === 'maximized'
            ? <Minimize2 className="h-3.5 w-3.5" />
            : <Maximize2 className="h-3.5 w-3.5" />}
        </button>

        <button
          onClick={() => setDockState('collapsed')}
          className="p-1.5 rounded-md hover:bg-accent/50 transition-colors text-muted-foreground"
          title="Collapse"
        >
          <ChevronDown className="h-3.5 w-3.5" />
        </button>
      </div>

      {/* Task list — collapsible, shows all tasks with expandable results */}
      {tasks.length > 0 && <TaskList tasks={tasks} />}

      {/* Message list */}
      <div
        ref={msgListRef}
        className="flex-1 overflow-y-auto px-4 py-3 space-y-3 min-h-0"
      >
        {messages.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-center text-muted-foreground">
            <Flame className="h-8 w-8 mb-2 opacity-20" />
            <p className="text-sm font-medium">Ignis AI</p>
            <p className="text-xs mt-1 max-w-xs opacity-70">
              Ask about your firewall policy, or describe a task —
              add devices, create groups, search rules, and more.
            </p>
          </div>
        ) : (
          messages.map(msg => <MessageBubble key={msg.id} msg={msg} />)
        )}

        {/* Streaming typing indicator */}
        {isStreaming && messages[messages.length - 1]?.role === 'user' && (
          <div className="flex justify-start">
            <div className="bg-muted rounded-2xl rounded-bl-sm px-3 py-2">
              <div className="flex gap-1">
                {[0, 150, 300].map(delay => (
                  <span
                    key={delay}
                    className="w-1.5 h-1.5 bg-muted-foreground/50 rounded-full animate-bounce"
                    style={{ animationDelay: `${delay}ms` }}
                  />
                ))}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Input bar */}
      <div className="border-t border-border/50 px-4 py-2.5 flex items-end gap-2 flex-shrink-0">
        <textarea
          ref={inputRef}
          rows={1}
          value={input}
          onChange={e => {
            setInput(e.target.value)
            const el = e.target
            el.style.height = 'auto'
            el.style.height = Math.min(el.scrollHeight, 100) + 'px'
          }}
          onKeyDown={onKeyDown}
          placeholder="Ask anything… (Shift+Enter for newline)"
          disabled={isStreaming}
          className={cn(
            'flex-1 resize-none bg-transparent border-0 outline-none text-sm',
            'placeholder:text-muted-foreground leading-relaxed min-h-[36px]',
            isStreaming && 'opacity-50 cursor-not-allowed',
          )}
          spellCheck={false}
          style={{ height: '36px' }}
        />
        <button
          onClick={submit}
          disabled={!input.trim() || isStreaming}
          className={cn(
            'flex-shrink-0 h-8 px-3 rounded-lg text-xs font-medium transition-colors',
            'bg-primary text-primary-foreground hover:bg-primary/90',
            'disabled:opacity-40 disabled:cursor-not-allowed',
          )}
        >
          {isStreaming ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : 'Send'}
        </button>
      </div>
    </div>
  )

  // ── Render ────────────────────────────────────────────────────────────────

  const height = dockState === 'collapsed'
    ? `${COLLAPSED_H}px`
    : dockState === 'expanded'
      ? EXPANDED_H
      : MAXIMIZED_H

  return (
    <div
      style={{ height, transition: 'height 220ms cubic-bezier(0.4,0,0.2,1)' }}
      className={cn(
        'fixed bottom-0 left-0 right-0 z-50 flex flex-col',
        'border-t border-border/50 bg-background/30 backdrop-blur-xl shadow-2xl',
      )}
    >
      {dockState === 'collapsed' ? CollapsedBar : ExpandedPanel}
    </div>
  )
}
