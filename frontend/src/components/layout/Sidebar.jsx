import React, { useState } from 'react';
import { NavLink } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  Upload,
  Activity,
  Clock,
  Shield,
  Settings,
  Database,
  FileSearch,
  AlertTriangle,
  BarChart2,
  Cpu,
  Code,
  HelpCircle,
  LogOut,
} from 'lucide-react';
import clsx from 'clsx';

const Sidebar = () => {
  const [expandedSection, setExpandedSection] = useState(null);

  // Navigation items
  const navigationItems = [
    {
      section: 'Main',
      items: [
        {
          name: 'Upload',
          path: '/upload',
          icon: Upload,
          description: 'Upload files for analysis',
          badge: null,
        },
        {
          name: 'Analysis',
          path: '/analysis',
          icon: Activity,
          description: 'View current analysis',
          badge: { text: 'Live', color: 'bg-green-500' },
        },
        {
          name: 'History',
          path: '/history',
          icon: Clock,
          description: 'Analysis history',
          badge: null,
        },
        {
          name: 'Rules',
          path: '/rules',
          icon: Shield,
          description: 'Manage detection rules',
          badge: { text: '127', color: 'bg-cyber-600' },
        },
      ],
    },
    {
      section: 'Advanced',
      items: [
        {
          name: 'IOC Database',
          path: '/iocs',
          icon: Database,
          description: 'Indicators of Compromise',
          badge: { text: 'New', color: 'bg-yellow-500' },
        },
        {
          name: 'File Browser',
          path: '/files',
          icon: FileSearch,
          description: 'Browse analyzed files',
          badge: null,
        },
        {
          name: 'Threat Intel',
          path: '/threats',
          icon: AlertTriangle,
          description: 'Threat intelligence feeds',
          badge: null,
        },
        {
          name: 'Reports',
          path: '/reports',
          icon: BarChart2,
          description: 'Generate reports',
          badge: null,
        },
      ],
    },
    {
      section: 'System',
      items: [
        {
          name: 'Performance',
          path: '/performance',
          icon: Cpu,
          description: 'System performance',
          badge: null,
        },
        {
          name: 'API Docs',
          path: '/api-docs',
          icon: Code,
          description: 'API documentation',
          badge: null,
        },
        {
          name: 'Settings',
          path: '/settings',
          icon: Settings,
          description: 'Application settings',
          badge: null,
        },
      ],
    },
  ];

  // Logo and brand
  const Logo = () => (
    <div className="flex items-center gap-3 mb-8">
      <div className="relative w-10 h-10 bg-gradient-to-br from-cyber-500 to-blue-600 rounded-lg flex items-center justify-center shadow-lg shadow-cyber-500/30">
        <Shield className="w-6 h-6 text-white" />
        <div className="absolute inset-0 bg-cyber-400 rounded-lg animate-ping opacity-20"></div>
      </div>
      <div>
        <h1 className="text-xl font-bold text-gray-100 font-cyber">SecuNik</h1>
        <p className="text-xs text-gray-500">LogX Platform</p>
      </div>
    </div>
  );

  // Navigation link component
  const NavItem = ({ item, isActive }) => (
    <motion.div
      whileHover={{ x: 4 }}
      whileTap={{ scale: 0.98 }}
    >
      <NavLink
        to={item.path}
        className={({ isActive }) =>
          clsx(
            'group flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-200',
            isActive
              ? 'bg-cyber-600/20 text-cyber-400 border border-cyber-600/30'
              : 'text-gray-400 hover:text-gray-100 hover:bg-gray-800'
          )
        }
      >
        <item.icon size={20} className="flex-shrink-0" />
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium truncate">{item.name}</p>
          {isActive && (
            <p className="text-xs text-gray-500 truncate">{item.description}</p>
          )}
        </div>
        {item.badge && (
          <span className={clsx(
            'px-2 py-0.5 text-xs font-medium rounded-full',
            item.badge.color,
            'text-white'
          )}>
            {item.badge.text}
          </span>
        )}
      </NavLink>
    </motion.div>
  );

  return (
    <aside className="w-64 h-full bg-gray-800 border-r border-gray-700 flex flex-col">
      {/* Header */}
      <div className="p-6 pb-0">
        <Logo />
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-4 pb-4 overflow-y-auto scrollbar-thin">
        {navigationItems.map((section, index) => (
          <div key={section.section} className={clsx(index > 0 && 'mt-6')}>
            <button
              onClick={() => setExpandedSection(
                expandedSection === section.section ? null : section.section
              )}
              className="flex items-center justify-between w-full px-3 py-2 text-xs font-semibold text-gray-500 uppercase tracking-wider hover:text-gray-300 transition-colors"
            >
              <span>{section.section}</span>
              <motion.span
                animate={{ rotate: expandedSection === section.section ? 180 : 0 }}
                transition={{ duration: 0.2 }}
              >
                <ChevronDown size={14} />
              </motion.span>
            </button>
            
            <motion.div
              initial={false}
              animate={{
                height: expandedSection === section.section || expandedSection === null ? 'auto' : 0,
                opacity: expandedSection === section.section || expandedSection === null ? 1 : 0,
              }}
              transition={{ duration: 0.2 }}
              className="overflow-hidden"
            >
              <div className="mt-2 space-y-1">
                {section.items.map(item => (
                  <NavItem key={item.path} item={item} />
                ))}
              </div>
            </motion.div>
          </div>
        ))}
      </nav>

      {/* Footer */}
      <div className="p-4 border-t border-gray-700">
        {/* User info */}
        <div className="flex items-center gap-3 p-3 bg-gray-900 rounded-lg mb-3">
          <div className="w-8 h-8 bg-gradient-to-br from-cyber-500 to-blue-600 rounded-full flex items-center justify-center text-white text-sm font-medium">
            A
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-medium text-gray-100 truncate">Admin User</p>
            <p className="text-xs text-gray-500">admin@secunik.com</p>
          </div>
        </div>

        {/* Actions */}
        <div className="flex gap-2">
          <button className="flex-1 flex items-center justify-center gap-2 px-3 py-2 text-sm text-gray-400 hover:text-gray-100 hover:bg-gray-800 rounded-lg transition-colors">
            <HelpCircle size={16} />
            <span>Help</span>
          </button>
          <button className="flex-1 flex items-center justify-center gap-2 px-3 py-2 text-sm text-gray-400 hover:text-gray-100 hover:bg-gray-800 rounded-lg transition-colors">
            <LogOut size={16} />
            <span>Logout</span>
          </button>
        </div>
      </div>
    </aside>
  );
};

// ChevronDown icon component
const ChevronDown = ({ size }) => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
  >
    <polyline points="6 9 12 15 18 9"></polyline>
  </svg>
);

export default Sidebar;