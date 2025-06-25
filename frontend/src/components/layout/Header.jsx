import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Link, useLocation } from 'react-router-dom';
import { 
  Menu, 
  X, 
  Bell, 
  Search, 
  User, 
  ChevronRight,
  Settings,
  LogOut,
  Shield,
  Activity,
  ChevronDown,
  Moon,
  Sun,
  HelpCircle,
  Terminal
} from 'lucide-react';
import { format } from 'date-fns';
import clsx from 'clsx';
import { useThemeStore } from '@/stores/themeStore';
import { useNotificationStore } from '@/stores/notificationStore';
import { useAuthStore } from '@/stores/authStore';

const Header = ({ sidebarOpen, setSidebarOpen, mobileMenuOpen, setMobileMenuOpen }) => {
  const [showNotifications, setShowNotifications] = useState(false);
  const [showUserMenu, setShowUserMenu] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [showSearch, setShowSearch] = useState(false);
  
  const location = useLocation();
  const { theme, toggleTheme } = useThemeStore();
  const { notifications, markAsRead, clearAll } = useNotificationStore();
  const { user, logout } = useAuthStore();
  
  const unreadCount = notifications.filter(n => !n.read).length;

  // Get page title based on route
  const getPageTitle = () => {
    const path = location.pathname;
    if (path.includes('/upload')) return 'File Upload';
    if (path.includes('/analysis')) return 'Analysis Dashboard';
    if (path.includes('/history')) return 'Analysis History';
    if (path.includes('/rules')) return 'Rule Management';
    if (path.includes('/settings')) return 'Settings';
    return 'SecuNik LogX';
  };

  // Breadcrumb navigation
  const getBreadcrumbs = () => {
    const paths = location.pathname.split('/').filter(Boolean);
    const breadcrumbs = [{ label: 'Home', path: '/' }];
    
    let currentPath = '';
    paths.forEach((path, index) => {
      currentPath += `/${path}`;
      breadcrumbs.push({
        label: path.charAt(0).toUpperCase() + path.slice(1).replace(/-/g, ' '),
        path: currentPath,
        isLast: index === paths.length - 1,
      });
    });
    
    return breadcrumbs;
  };

  // Handle search submit
  const handleSearch = (e) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      // Implement search functionality
      console.log('Search:', searchQuery);
    }
  };

  // System status (mock - replace with real status check)
  const systemStatus = {
    api: 'operational',
    analysis: 'operational',
    database: 'operational',
  };

  const getSystemStatusColor = () => {
    const statuses = Object.values(systemStatus);
    if (statuses.every(s => s === 'operational')) return 'text-green-500';
    if (statuses.some(s => s === 'error')) return 'text-red-500';
    return 'text-yellow-500';
  };

  return (
    <>
      <header className="bg-gray-800 border-b border-gray-700 px-4 lg:px-6 h-16 flex items-center justify-between flex-shrink-0 relative z-30">
        <div className="flex items-center gap-4 flex-1">
          {/* Mobile menu button */}
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="lg:hidden p-2 text-gray-400 hover:text-gray-100 hover:bg-gray-700 rounded-lg transition-colors"
            aria-label="Toggle mobile menu"
          >
            {mobileMenuOpen ? <X size={20} /> : <Menu size={20} />}
          </button>

          {/* Desktop sidebar toggle */}
          <button
            onClick={() => setSidebarOpen(!sidebarOpen)}
            className="hidden lg:block p-2 text-gray-400 hover:text-gray-100 hover:bg-gray-700 rounded-lg transition-colors"
            aria-label="Toggle sidebar"
          >
            <Menu size={20} />
          </button>

          {/* Breadcrumbs */}
          <nav className="hidden md:flex items-center gap-2 text-sm">
            {getBreadcrumbs().map((crumb, index) => (
              <React.Fragment key={crumb.path}>
                {index > 0 && <ChevronRight size={16} className="text-gray-600" />}
                {crumb.isLast ? (
                  <span className="text-gray-400">{crumb.label}</span>
                ) : (
                  <Link
                    to={crumb.path}
                    className="text-gray-500 hover:text-gray-300 transition-colors"
                  >
                    {crumb.label}
                  </Link>
                )}
              </React.Fragment>
            ))}
          </nav>

          {/* System Status Indicator */}
          <div className="hidden xl:flex items-center gap-2 ml-auto mr-4">
            <span className="text-xs text-gray-500">System Status:</span>
            <span className={clsx('flex items-center gap-1', getSystemStatusColor())}>
              <span className="w-2 h-2 bg-current rounded-full animate-pulse"></span>
              <span className="text-xs font-medium">
                {Object.values(systemStatus).every(s => s === 'operational') ? 'All Systems Operational' : 'Degraded Performance'}
              </span>
            </span>
          </div>
        </div>

        {/* Header Actions */}
        <div className="flex items-center gap-3">
          {/* Search - Mobile Toggle */}
          <button
            onClick={() => setShowSearch(!showSearch)}
            className="md:hidden p-2 text-gray-400 hover:text-gray-100 hover:bg-gray-700 rounded-lg transition-colors"
            aria-label="Toggle search"
          >
            <Search size={20} />
          </button>

          {/* Search - Desktop */}
          <form onSubmit={handleSearch} className="hidden md:block relative">
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search files, rules, IOCs..."
              className="w-64 pl-10 pr-4 py-2 bg-gray-900 border border-gray-700 rounded-lg text-sm text-gray-100 placeholder-gray-500 focus:border-cyber-500 focus:ring-1 focus:ring-cyber-500 transition-all duration-200"
            />
            <Search className="absolute left-3 top-2.5 text-gray-500" size={18} />
            {searchQuery && (
              <button
                type="button"
                onClick={() => setSearchQuery('')}
                className="absolute right-3 top-2.5 text-gray-500 hover:text-gray-300"
              >
                <X size={16} />
              </button>
            )}
          </form>

          {/* Quick Actions */}
          <div className="hidden lg:flex items-center gap-2">
            <button
              className="p-2 text-gray-400 hover:text-gray-100 hover:bg-gray-700 rounded-lg transition-colors"
              title="Terminal"
            >
              <Terminal size={20} />
            </button>
            <button
              className="p-2 text-gray-400 hover:text-gray-100 hover:bg-gray-700 rounded-lg transition-colors"
              title="Real-time Monitor"
            >
              <Activity size={20} />
            </button>
          </div>

          {/* Theme Toggle */}
          <button
            onClick={toggleTheme}
            className="p-2 text-gray-400 hover:text-gray-100 hover:bg-gray-700 rounded-lg transition-colors"
            title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
          >
            {theme === 'dark' ? <Sun size={20} /> : <Moon size={20} />}
          </button>

          {/* Notifications */}
          <div className="relative">
            <button
              onClick={() => setShowNotifications(!showNotifications)}
              className="relative p-2 text-gray-400 hover:text-gray-100 hover:bg-gray-700 rounded-lg transition-colors"
              aria-label="Notifications"
            >
              <Bell size={20} />
              {unreadCount > 0 && (
                <span className="absolute top-1 right-1 min-w-[18px] h-[18px] bg-red-500 text-white text-xs rounded-full flex items-center justify-center font-medium">
                  {unreadCount > 9 ? '9+' : unreadCount}
                </span>
              )}
            </button>

            {/* Notifications dropdown */}
            <AnimatePresence>
              {showNotifications && (
                <motion.div
                  initial={{ opacity: 0, y: -10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  className="absolute right-0 mt-2 w-96 bg-gray-800 border border-gray-700 rounded-lg shadow-xl"
                >
                  <div className="p-4 border-b border-gray-700 flex items-center justify-between">
                    <h3 className="font-semibold text-gray-100">Notifications</h3>
                    {notifications.length > 0 && (
                      <button
                        onClick={clearAll}
                        className="text-xs text-gray-500 hover:text-gray-300"
                      >
                        Clear all
                      </button>
                    )}
                  </div>
                  <div className="max-h-96 overflow-y-auto">
                    {notifications.length === 0 ? (
                      <div className="p-8 text-center">
                        <Bell className="mx-auto text-gray-600 mb-3" size={32} />
                        <p className="text-gray-500">No notifications</p>
                      </div>
                    ) : (
                      notifications.map((notification) => (
                        <div
                          key={notification.id}
                          onClick={() => markAsRead(notification.id)}
                          className={clsx(
                            'p-4 hover:bg-gray-700/50 transition-colors border-b border-gray-700 last:border-0 cursor-pointer',
                            !notification.read && 'bg-gray-700/30'
                          )}
                        >
                          <div className="flex items-start gap-3">
                            <div className={clsx(
                              'mt-1 p-2 rounded-lg',
                              notification.type === 'success' && 'bg-green-500/20 text-green-500',
                              notification.type === 'error' && 'bg-red-500/20 text-red-500',
                              notification.type === 'warning' && 'bg-yellow-500/20 text-yellow-500',
                              notification.type === 'info' && 'bg-blue-500/20 text-blue-500',
                            )}>
                              {notification.type === 'success' && <Shield size={16} />}
                              {notification.type === 'error' && <X size={16} />}
                              {notification.type === 'warning' && <Bell size={16} />}
                              {notification.type === 'info' && <Activity size={16} />}
                            </div>
                            <div className="flex-1 min-w-0">
                              <p className="text-sm text-gray-100">{notification.title}</p>
                              {notification.message && (
                                <p className="text-xs text-gray-500 mt-1">{notification.message}</p>
                              )}
                              <p className="text-xs text-gray-600 mt-2">
                                {format(new Date(notification.timestamp), 'MMM d, h:mm a')}
                              </p>
                            </div>
                            {!notification.read && (
                              <span className="w-2 h-2 bg-cyber-500 rounded-full mt-2"></span>
                            )}
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* User menu */}
          <div className="relative">
            <button
              onClick={() => setShowUserMenu(!showUserMenu)}
              className="flex items-center gap-2 p-2 text-gray-400 hover:text-gray-100 hover:bg-gray-700 rounded-lg transition-colors"
            >
              <div className="w-8 h-8 bg-gradient-to-br from-cyber-500 to-blue-600 rounded-full flex items-center justify-center text-white text-sm font-medium">
                {user?.name?.[0]?.toUpperCase() || 'U'}
              </div>
              <ChevronDown size={16} />
            </button>

            {/* User dropdown */}
            <AnimatePresence>
              {showUserMenu && (
                <motion.div
                  initial={{ opacity: 0, y: -10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  className="absolute right-0 mt-2 w-64 bg-gray-800 border border-gray-700 rounded-lg shadow-xl"
                >
                  <div className="p-4 border-b border-gray-700">
                    <p className="font-medium text-gray-100">{user?.name || 'User'}</p>
                    <p className="text-sm text-gray-500">{user?.email || 'user@example.com'}</p>
                  </div>
                  <div className="p-2">
                    <Link
                      to="/settings"
                      className="flex items-center gap-3 px-3 py-2 text-sm text-gray-400 hover:text-gray-100 hover:bg-gray-700 rounded-lg transition-colors"
                    >
                      <Settings size={16} />
                      Settings
                    </Link>
                    <Link
                      to="/help"
                      className="flex items-center gap-3 px-3 py-2 text-sm text-gray-400 hover:text-gray-100 hover:bg-gray-700 rounded-lg transition-colors"
                    >
                      <HelpCircle size={16} />
                      Help & Docs
                    </Link>
                    <hr className="my-2 border-gray-700" />
                    <button
                      onClick={logout}
                      className="flex items-center gap-3 w-full px-3 py-2 text-sm text-gray-400 hover:text-gray-100 hover:bg-gray-700 rounded-lg transition-colors"
                    >
                      <LogOut size={16} />
                      Logout
                    </button>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </header>

      {/* Mobile Search Bar */}
      <AnimatePresence>
        {showSearch && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="md:hidden bg-gray-800 border-b border-gray-700 px-4 py-3"
          >
            <form onSubmit={handleSearch} className="relative">
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search files, rules, IOCs..."
                className="w-full pl-10 pr-10 py-2 bg-gray-900 border border-gray-700 rounded-lg text-sm text-gray-100 placeholder-gray-500 focus:border-cyber-500 focus:ring-1 focus:ring-cyber-500"
                autoFocus
              />
              <Search className="absolute left-3 top-2.5 text-gray-500" size={18} />
              <button
                type="button"
                onClick={() => {
                  setSearchQuery('');
                  setShowSearch(false);
                }}
                className="absolute right-3 top-2.5 text-gray-500 hover:text-gray-300"
              >
                <X size={18} />
              </button>
            </form>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Click outside handlers */}
      {(showNotifications || showUserMenu) && (
        <div
          className="fixed inset-0 z-20"
          onClick={() => {
            setShowNotifications(false);
            setShowUserMenu(false);
          }}
        />
      )}
    </>
  );
};

// Placeholder stores (if not already created)
if (!window.useThemeStore) {
  window.useThemeStore = () => ({
    theme: 'dark',
    toggleTheme: () => console.log('Toggle theme'),
  });
}

if (!window.useNotificationStore) {
  window.useNotificationStore = () => ({
    notifications: [],
    markAsRead: () => {},
    clearAll: () => {},
  });
}

if (!window.useAuthStore) {
  window.useAuthStore = () => ({
    user: { name: 'Admin User', email: 'admin@secunik.com' },
    logout: () => console.log('Logout'),
  });
}

export const useThemeStore = window.useThemeStore;
export const useNotificationStore = window.useNotificationStore;
export const useAuthStore = window.useAuthStore;

export default Header;