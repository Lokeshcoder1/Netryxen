// src/components/layout/Sidebar.tsx
import { Link, useLocation } from 'react-router-dom'
import {
  LayoutDashboard, Radio, Waves, ShieldAlert,
  BrainCircuit, Activity, Server,
} from 'lucide-react'
import { cn } from '../../lib/utils'

const nav = [
  { to: '/',            icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/capture',     icon: Radio,           label: 'Capture' },
  { to: '/flows',       icon: Waves,           label: 'Flows' },
  { to: '/alerts',      icon: ShieldAlert,     label: 'Alerts' },
  { to: '/predictions', icon: Activity,        label: 'Predictions' },
  { to: '/model',       icon: BrainCircuit,    label: 'ML Model' },
  { to: '/sessions',    icon: Server,          label: 'Sessions' },
]

export function Sidebar() {
  const { pathname } = useLocation()

  return (
    <aside className="fixed inset-y-0 left-0 w-56 bg-slate-900 border-r border-slate-700/50 flex flex-col z-30">
      {/* Logo */}
      <div className="px-5 py-5 border-b border-slate-700/50">
        <div className="flex items-center gap-2.5">
          <div className="rounded-lg bg-sky-600 p-1.5">
            <ShieldAlert className="w-5 h-5 text-white" />
          </div>
          <div>
            <p className="text-sm font-bold text-white leading-none">NETRYXEN</p>
            <p className="text-xs text-slate-400 mt-0.5">NIDS Dashboard</p>
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 space-y-0.5 overflow-y-auto">
        {nav.map(({ to, icon: Icon, label }) => {
          const active = pathname === to || (to !== '/' && pathname.startsWith(to))
          return (
            <Link
              key={to}
              to={to}
              className={cn(
                'flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm transition-colors',
                active
                  ? 'bg-sky-600/20 text-sky-300 font-medium'
                  : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200',
              )}
            >
              <Icon className="w-4 h-4 shrink-0" />
              {label}
            </Link>
          )
        })}
      </nav>

      {/* Footer */}
      <div className="px-4 py-3 border-t border-slate-700/50">
        <p className="text-xs text-slate-500">Backend: localhost:8000</p>
      </div>
    </aside>
  )
}
