import React from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import { motion } from 'framer-motion'
import {
  Shield,
  BarChart3,
  Upload,
  Search,
  History,
  Settings,
  FileText,
  Activity,
  X
} from 'lucide-react'

interface SidebarProps {
  onClose: () => void
}

const Sidebar: React.FC<SidebarProps> = ({ onClose }) => {
  const location = useLocation()

  const navigation = [
    { name: 'Dashboard', href: '/dashboard', icon: BarChart3 },
    { name: 'Upload Files', href: '/upload', icon: Upload },
    { name: 'Analysis', href: '/analysis', icon: Search },
    { name: 'History', href: '/history', icon: History },
    { name: 'Detection Rules', href: '/rules', icon: FileText },
    { name: 'Settings', href: '/settings', icon: Settings },
  ]

  return (
    <div className="flex flex-col w-70 bg-slate-900/95 backdrop-blur-sm border-r border-slate-800">
      {/* Header */}
      <div className="flex items-center justify-between p-6 border-b border-slate-800">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-primary-600 rounded-lg">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">SecuNik</h1>
            <p className="text-sm text-slate-400">LogX Platform</p>
          </div>
        </div>
        <button
          onClick={onClose}
          className="p-2 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors lg:hidden"
        >
          <X className="w-5 h-5" />
        </button>
      </div>

      {/* Status Indicator */}
      <div className="px-6 py-4 border-b border-slate-800">
        <div className="flex items-center space-x-3 p-3 bg-slate-800/50 rounded-lg">
          <div className="status-indicator status-online"></div>
          <div>
            <p className="text-sm font-medium text-white">System Status</p>
            <p className="text-xs text-slate-400">All systems operational</p>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-6 py-4 space-y-2">
        {navigation.map((item) => {
          const Icon = item.icon
          const isActive = location.pathname === item.href || 
                          (item.href === '/analysis' && location.pathname.startsWith('/analysis'))
          
          return (
            <NavLink
              key={item.name}
              to={item.href}
              className={({ isActive: linkActive }) => {
                const active = linkActive || isActive
                return `group flex items-center px-3 py-3 text-sm font-medium rounded-lg transition-all duration-200 ${
                  active
                    ? 'bg-primary-600 text-white shadow-lg'
                    : 'text-slate-300 hover:text-white hover:bg-slate-800'
                }`
              }}
            >
              {({ isActive: linkActive }) => {
                const active = linkActive || isActive
                return (
                  <>
                    <Icon className={`mr-3 h-5 w-5 transition-colors ${
                      active ? 'text-white' : 'text-slate-400 group-hover:text-white'
                    }`} />
                    {item.name}
                    {active && (
                      <motion.div
                        layoutId="activeTab"
                        className="ml-auto w-2 h-2 bg-white rounded-full"
                        initial={false}
                        transition={{ type: "spring", stiffness: 500, damping: 30 }}
                      />
                    )}
                  </>
                )
              }}
            </NavLink>
          )
        })}
      </nav>

      {/* Footer */}
      <div className="p-6 border-t border-slate-800">
        <div className="flex items-center space-x-3 p-3 bg-slate-800/30 rounded-lg">
          <Activity className="w-5 h-5 text-primary-400" />
          <div>
            <p className="text-sm font-medium text-white">Real-time Monitoring</p>
            <p className="text-xs text-slate-400">Active threat detection</p>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Sidebar