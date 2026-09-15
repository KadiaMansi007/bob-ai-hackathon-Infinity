import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard, AlertTriangle, Layers, Shield, Target, FileText, Activity
} from 'lucide-react'

const nav = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/alerts', icon: AlertTriangle, label: 'Alert Feed' },
  { to: '/incidents', icon: Layers, label: 'Incidents' },
  { to: '/mitre', icon: Target, label: 'MITRE ATT&CK' },
]

export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-screen overflow-hidden bg-[#141824]">
      {/* Sidebar */}
      <aside className="w-56 flex-shrink-0 bg-[#1a2035] border-r border-[#2e3a4e] flex flex-col">
        <div className="p-4 border-b border-[#2e3a4e]">
          <div className="flex items-center gap-2">
            <Shield className="text-blue-400" size={20} />
            <span className="font-bold text-sm text-white leading-tight">
              Infinity<br />
              <span className="text-blue-400 font-normal text-xs">Threat Platform</span>
            </span>
          </div>
        </div>
        <nav className="flex-1 p-2 space-y-1 overflow-y-auto">
          {nav.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2 rounded text-sm transition-colors ${
                  isActive
                    ? 'bg-blue-600/20 text-blue-400'
                    : 'text-slate-400 hover:text-white hover:bg-white/5'
                }`
              }
            >
              <Icon size={16} />
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="p-3 border-t border-[#2e3a4e]">
          <div className="text-xs text-slate-500 flex items-center gap-1">
            <Activity size={10} className="text-blue-400" />
            Powered by IBM Bob
          </div>
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 overflow-y-auto p-6">
        {children}
      </main>
    </div>
  )
}
