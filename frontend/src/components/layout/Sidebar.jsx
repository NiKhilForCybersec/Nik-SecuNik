import React, { useState } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
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
  ChevronRight,
  ChevronDown,
  Moon,
  Sun,
} from 'lucide-react';
import clsx from 'clsx';
import { useThemeStore } from '@/stores/themeStore';
import { useAuthStore } from '@/stores/authStore';

const Sidebar = () => {
  const location = useLocation();
  const [expandedSection, setExpandedSection] = useState('Main');
  const { theme, toggleTheme } = useThemeStore();
  const { logout } = useAuthStore();

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

  const toggleSection = (section) => {
    setExpandedSection(expandedSection === section ? null : section);
  };

  return (
    <aside className="w-64 h-full bg-gray-800 border-r border-gray-700 flex flex-col">
      {/* Logo */}
      <div className="h-16 flex items-center justify-center border-b border-gray-700">
        <motion.div
          whileHover={{ scale: 1.05 }}
          className="flex items-center space-x-2"
        >
          <Shield className="w-8 h-8 text-cyber-500" />
          <span className="text-xl font-bold text-gradient">
            SecuNik LogX
          </span>
        </motion.div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-4 scrollbar-thin">
        {navigationItems.map((group) => (
          <div key={group.section} className="mb-4">
            <button
              onClick={() => toggleSection(group.section)}
              className="w-full px-4 py-2 flex items-center justify-between text-sm font-medium text-gray-400 hover:text-white transition-colors"
            >
              <span>{group.section}</span>
              {expandedSection === group.section ? (
                <ChevronDown className="w-4 h-4" />
              ) : (
                <ChevronRight className="w-4 h-4" />
              )}
            </button>

            <AnimatePresence>
              {expandedSection === group.section && (
                <motion.div
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: 'auto', opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  transition={{ duration: 0.2 }}
                  className="overflow-hidden"
                >
                  {group.items.map((item) => {
                    const Icon = item.icon;
                    const isActive = location.pathname === item.path;
                    const isImplemented = ['/upload', '/analysis', '/history', '/rules', '/settings'].includes(item.path);

                    return (
                      <NavLink
                        key={item.path}
                        to={isImplemented ? item.path : '#'}
                        className={clsx(
                          'flex items-center space-x-3 px-4 py-2.5 mx-2 rounded-lg transition-all duration-200',
                          isActive
                            ? 'bg-cyber-500/20 text-cyber-400 border-l-4 border-cyber-500'
                            : isImplemented
                            ? 'text-gray-400 hover:text-white hover:bg-gray-700/50'
                            : 'text-gray-600 cursor-not-allowed'
                        )}
                        onClick={(e) => {
                          if (!isImplemented) {
                            e.preventDefault();
                          }
                        }}
                      >
                        <Icon className="w-5 h-5 flex-shrink-0" />
                        <div className="flex-1">
                          <span className="text-sm font-medium">{item.name}</span>
                          {!isImplemented && (
                            <span className="text-xs text-gray-600 block">Coming soon</span>
                          )}
                        </div>
                        {item.badge && isImplemented && (
                          <span
                            className={clsx(
                              'px-2 py-0.5 text-xs font-medium rounded-full',
                              item.badge.color,
                              'text-white'
                            )}
                          >
                            {item.badge.text}
                          </span>
                        )}
                      </NavLink>
                    );
                  })}
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        ))}
      </nav>

      {/* Bottom actions */}
      <div className="p-4 border-t border-gray-700 space-y-2">
        <button
          onClick={toggleTheme}
          className="w-full flex items-center space-x-3 px-4 py-2 text-gray-400 hover:text-white hover:bg-gray-700/50 rounded-lg transition-colors"
        >
          {theme === 'dark' ? (
            <Moon className="w-5 h-5" />
          ) : (
            <Sun className="w-5 h-5" />
          )}
          <span className="text-sm">Toggle Theme</span>
        </button>

        <button
          onClick={() => window.open('https://docs.secunik.com', '_blank')}
          className="w-full flex items-center space-x-3 px-4 py-2 text-gray-400 hover:text-white hover:bg-gray-700/50 rounded-lg transition-colors"
        >
          <HelpCircle className="w-5 h-5" />
          <span className="text-sm">Help & Docs</span>
        </button>

        <button
          onClick={logout}
          className="w-full flex items-center space-x-3 px-4 py-2 text-gray-400 hover:text-white hover:bg-gray-700/50 rounded-lg transition-colors"
        >
          <LogOut className="w-5 h-5" />
          <span className="text-sm">Logout</span>
        </button>
      </div>
    </aside>
  );
};

export default Sidebar;