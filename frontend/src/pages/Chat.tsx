import { useState, useEffect, useRef, useCallback } from 'react'
import { Link } from 'react-router-dom'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import type { Components } from 'react-markdown'
import { Send, Trash2, RefreshCw, Bot, User } from 'lucide-react'
import { api } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card } from '@/components/ui/card'

interface Message {
  role: 'user' | 'assistant'
  content: string
  streaming?: boolean
}

function mkSessionId() {
  return Math.random().toString(36).slice(2) + Date.now().toString(36)
}

const mdComponents: Components = {
  a: ({ href, children }) => {
    if (href?.startsWith('/')) {
      return (
        <Link
          to={href}
          className="text-primary underline underline-offset-2 hover:text-primary/80 font-medium"
        >
          {children}
        </Link>
      )
    }
    return (
      <a href={href} target="_blank" rel="noopener noreferrer"
        className="text-primary underline underline-offset-2 hover:text-primary/80">
        {children}
      </a>
    )
  },
  p: ({ children }) => <p className="mb-1.5 last:mb-0 leading-relaxed">{children}</p>,
  ul: ({ children }) => <ul className="list-disc pl-4 space-y-0.5 my-1">{children}</ul>,
  ol: ({ children }) => <ol className="list-decimal pl-4 space-y-0.5 my-1">{children}</ol>,
  li: ({ children }) => <li className="leading-relaxed">{children}</li>,
  strong: ({ children }) => <strong className="font-semibold text-foreground">{children}</strong>,
  code: ({ children, className }) => {
    const isBlock = className?.includes('language-')
    return isBlock
      ? <pre className="bg-background/60 border border-border rounded-md p-3 text-xs font-mono overflow-x-auto my-2 whitespace-pre"><code>{children}</code></pre>
      : <code className="bg-background/60 border border-border/50 rounded px-1 py-0.5 text-xs font-mono">{children}</code>
  },
  pre: ({ children }) => <>{children}</>,
}

function MessageBubble({ msg }: { msg: Message }) {
  const isUser = msg.role === 'user'
  return (
    <div className={`flex gap-3 ${isUser ? 'flex-row-reverse' : ''}`}>
      <div className={`h-7 w-7 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5 ${isUser ? 'bg-primary/20' : 'bg-secondary'}`}>
        {isUser
          ? <User className="h-3.5 w-3.5 text-primary" />
          : <Bot className="h-3.5 w-3.5 text-muted-foreground" />}
      </div>
      <div className={`max-w-[78%] rounded-2xl px-4 py-2.5 text-sm ${isUser ? 'bg-primary/15 rounded-tr-sm' : 'bg-secondary rounded-tl-sm'}`}>
        {isUser
          ? <p className="leading-relaxed whitespace-pre-wrap">{msg.content}</p>
          : (
            <ReactMarkdown remarkPlugins={[remarkGfm]} components={mdComponents}>
              {msg.content}
            </ReactMarkdown>
          )}
        {msg.streaming && (
          <span className="inline-block h-3.5 w-0.5 bg-current opacity-70 animate-pulse ml-0.5" />
        )}
      </div>
    </div>
  )
}

export function Chat() {
  const [sessionId] = useState(mkSessionId)
  const [messages, setMessages] = useState<Message[]>([])
  const [input, setInput] = useState('')
  const [connected, setConnected] = useState(false)
  const [sending, setSending] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)
  const bottomRef = useRef<HTMLDivElement>(null)

  const openWs = useCallback(() => {
    const existing = wsRef.current
    if (existing && existing.readyState < WebSocket.CLOSING) existing.close()

    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const ws = new WebSocket(`${proto}://${window.location.host}/ws/chat/${sessionId}`)
    wsRef.current = ws

    ws.onopen = () => setConnected(true)
    ws.onclose = () => { setConnected(false); setSending(false) }
    ws.onerror = () => ws.close()
    ws.onmessage = (e) => {
      const msg = JSON.parse(e.data as string)
      if (msg.type === 'start') {
        setMessages(prev => [...prev, { role: 'assistant', content: '', streaming: true }])
      } else if (msg.type === 'token') {
        setMessages(prev => {
          const copy = [...prev]
          const last = copy[copy.length - 1]
          if (last?.streaming) copy[copy.length - 1] = { ...last, content: last.content + (msg.content as string) }
          return copy
        })
      } else if (msg.type === 'end') {
        setSending(false)
        setMessages(prev => {
          const copy = [...prev]
          const last = copy[copy.length - 1]
          if (last?.streaming) copy[copy.length - 1] = { ...last, streaming: false }
          return copy
        })
      }
    }
  }, [sessionId])

  useEffect(() => {
    openWs()
    return () => wsRef.current?.close()
  }, [openWs])

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  const send = () => {
    const text = input.trim()
    if (!text || sending || !connected) return
    setInput('')
    setSending(true)
    setMessages(prev => [...prev, { role: 'user', content: text }])
    wsRef.current?.send(JSON.stringify({ action: 'chat', message: text }))
  }

  const clearChat = async () => {
    await api.chat.clear(sessionId)
    setMessages([])
  }

  return (
    <div className="flex flex-col h-full p-6 gap-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Chat</h1>
          <p className="text-muted-foreground text-sm mt-1">
            Ask questions about your firewall policies
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className={`h-2 w-2 rounded-full ${connected ? 'bg-green-500' : 'bg-red-500'}`} />
          <span className="text-xs text-muted-foreground">
            {connected ? 'connected' : 'disconnected'}
          </span>
          <Button
            size="sm" variant="outline"
            onClick={clearChat}
            disabled={messages.length === 0}
            title="Clear history"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </Button>
          {!connected && (
            <Button size="sm" variant="outline" onClick={openWs} title="Reconnect">
              <RefreshCw className="h-3.5 w-3.5" />
            </Button>
          )}
        </div>
      </div>

      <Card className="flex-1 overflow-auto p-4">
        {messages.length === 0 ? (
          <div className="h-full flex items-center justify-center">
            <div className="text-center text-muted-foreground">
              <Bot className="h-12 w-12 mx-auto mb-3 opacity-20" />
              <p className="font-medium text-sm">Ask anything about your firewall policies</p>
              <p className="text-xs mt-1">
                Try "Show me all rules that allow traffic from any source"
              </p>
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            {messages.map((msg, i) => <MessageBubble key={i} msg={msg} />)}
            <div ref={bottomRef} />
          </div>
        )}
      </Card>

      <div className="flex gap-2">
        <Input
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send() } }}
          placeholder="Ask about firewall rules, objects, or policies…"
          disabled={!connected || sending}
          className="flex-1"
        />
        <Button onClick={send} disabled={!input.trim() || !connected || sending}>
          {sending
            ? <RefreshCw className="h-4 w-4 animate-spin" />
            : <Send className="h-4 w-4" />}
        </Button>
      </div>
    </div>
  )
}
