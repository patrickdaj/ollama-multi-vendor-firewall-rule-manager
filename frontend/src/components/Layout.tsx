import { useState, useEffect } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import {
  Flame, LayoutDashboard, Server, Layers,
  Activity, ArrowLeftRight, Settings, Upload,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { AiDock, NotificationToasts } from '@/components/AiDock'
import { useAiDock } from '@/contexts/AiDockContext'

const nav = [
  { to: '/',             label: 'Dashboard',    icon: LayoutDashboard },
  { to: '/devices',      label: 'Devices',      icon: Server },
  { to: '/groups',       label: 'Intent',       icon: Layers },
  { to: '/translations', label: 'Translations', icon: ArrowLeftRight },
  { to: '/deploy',       label: 'Deploy',       icon: Upload },
  { to: '/snapshots',    label: 'History',      icon: Activity },
  { to: '/settings',     label: 'Settings',     icon: Settings },
]

const NAV_COLLAPSED_KEY = 'ignis-nav-collapsed'

function RunningIndicator() {
  const { runningCount } = useAiDock()
  if (runningCount === 0) return null
  return (
    <span className="absolute -top-0.5 -right-0.5 h-2 w-2 rounded-full bg-primary animate-pulse" />
  )
}

export function Layout() {
  const [collapsed, setCollapsed] = useState(
    () => localStorage.getItem(NAV_COLLAPSED_KEY) === 'true'
  )
  const [version, setVersion] = useState<string | null>(null)
  const { dockState, setDockState } = useAiDock()

  // Persist collapse state
  const toggle = () => {
    setCollapsed(c => {
      localStorage.setItem(NAV_COLLAPSED_KEY, String(!c))
      return !c
    })
  }

  // Fetch version once on mount
  useEffect(() => {
    fetch('/health')
      .then(r => r.json())
      .then(d => setVersion(d.version ?? null))
      .catch(() => {})
  }, [])

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      {/* Sidebar */}
      <aside
        className={cn(
          'flex-shrink-0 flex flex-col border-r border-border bg-card transition-[width] duration-200',
          collapsed ? 'w-14' : 'w-52',
        )}
      >
        {/* Brand — click flame to collapse/expand */}
        <button
          onClick={toggle}
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          className={cn(
            'flex items-center border-b border-border w-full text-left hover:bg-accent/50 transition-colors',
            collapsed ? 'justify-center px-0 py-4' : 'gap-2.5 px-4 py-4',
          )}
        >
          <div className="relative flex-shrink-0">
            <Flame className="h-6 w-6 text-primary" />
            <RunningIndicator />
          </div>
          {!collapsed && (
            <div className="min-w-0">
              <div className="text-sm font-semibold leading-tight">Ignis</div>
              {version && (
                <div className="text-[10px] text-muted-foreground font-mono leading-tight">
                  v{version}
                </div>
              )}
            </div>
          )}
        </button>

        {/* Nav links */}
        <nav className="flex-1 p-2 space-y-0.5 overflow-y-auto">
          {nav.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              title={collapsed ? label : undefined}
              className={({ isActive }) =>
                cn(
                  'flex items-center rounded-md text-sm transition-colors',
                  collapsed ? 'justify-center px-0 py-2' : 'gap-3 px-3 py-2',
                  isActive
                    ? 'bg-primary/15 text-primary font-medium'
                    : 'text-muted-foreground hover:bg-accent hover:text-foreground',
                )
              }
            >
              <Icon className="h-4 w-4 flex-shrink-0" />
              {!collapsed && label}
            </NavLink>
          ))}
        </nav>

        {!collapsed && (
          <div className="p-3 border-t border-border">
            <div className="text-[10px] text-muted-foreground text-center">
              No cloud · No telemetry
            </div>
          </div>
        )}
      </aside>

      {/* Main content — clicking collapses the AI dock */}
      <main
        className="flex-1 overflow-auto pb-[52px] min-w-0"
        onClick={() => { if (dockState !== 'collapsed') setDockState('collapsed') }}
      >
        <Outlet />
      </main>

      <AiDock />
      <NotificationToasts />
    </div>
  )
}
