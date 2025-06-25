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
      console.log('Searching for:', searchQuery);
      // Implement search functionality
    }
  };

  return (
    <>
      <header className="h-16 bg-gray-800 border-b border-gray-700 flex items-center justify-between px-4 lg:px-6">
        {/* Left side */}
        <div className="flex items-center space-x-4">
          {/* Mobile menu button */}
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="lg:hidden p-2 hover:bg-gray-700 rounded-lg transition-colors"
          >
            {mobileMenuOpen ? (
              <X className="w-6 h-6 text-gray-400" />
            ) : (
              <Menu className="w-6 h-6 text-gray-400" />
            )}
          </button>

          {/* Desktop sidebar toggle */}
          <button
            onClick={() => setSidebarOpen(!sidebarOpen)}
            className="hidden lg:block p-2 hover:bg-gray-700 rounded-lg transition-colors"
          >
            <Menu className="w-6 h-6 text-gray-400" />
          </button>

          {/* Breadcrumbs */}
          <nav className="hidden lg:flex items-center space-x-2 text-sm">
            {getBreadcrumbs().map((crumb, index) => (
              <React.Fragment key={crumb.path}>
                {index > 0 && (
                  <ChevronRight className="w-4 h-4 text-gray-600" />
                )}
                {crumb.isLast ? (
                  <span className="text-gray-400">{crumb.label}</span>
                ) : (
                  <Link
                    to={crumb.path}
                    className="text-gray-500 hover:text-white transition-colors"
                  >
                    {crumb.label}
                  </Link>
                )}
              </React.Fragment>
            ))}
          </nav>
        </div>

        {/* Right side */}
        <div className="flex items-center space-x-3">
          {/* Search button */}
          <button
            onClick={() => setShowSearch(!showSearch)}
            className="p-2 hover:bg-gray-700 rounded-lg transition-colors"
          >
            <Search className="w-5 h-5 text-gray-400" />
          </button>

          {/* Terminal button */}
          <button
            onClick={() => console.log('Open terminal')}
            className="p-2 hover:bg-gray-700 rounded-lg transition-colors"
          >
            <Terminal className="w-5 h-5 text-gray-400" />
          </button>

          {/* Notifications */}
          <div className="relative">
            <button
              onClick={() => setShowNotifications(!showNotifications)}
              className="p-2 hover:bg-gray-700 rounded-lg transition-colors relative"
            >
              <Bell className="w-5 h-5 text-gray-400" />
              {unreadCount > 0 && (
                <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full"></span>
              )}
            </button>

            {/* Notifications dropdown */}
            <AnimatePresence>
              {showNotifications && (
                <motion.div
                  initial={{ opacity: 0, y: -10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  className="absolute right-0 mt-2 w-80 bg-gray-800 border border-gray-700 rounded-lg shadow-lg z-50"
                >
                  <div className="p-4 border-b border-gray-700">
                    <div className="flex items-center justify-between">
                      <h3 className="text-sm font-semibold text-white">Notifications</h3>
                      {notifications.length > 0 && (
                        <button
                          onClick={clearAll}
                          className="text-xs text-gray-400 hover:text-white"
                        >
                          Clear all
                        </button>
                      )}
                    </div>
                  </div>
                  <div className="max-h-96 overflow-y-auto">
                    {notifications.length === 0 ? (
                      <p className="p-4 text-center text-gray-500 text-sm">
                        No notifications
                      </p>
                    ) : (
                      notifications.map((notification) => (
                        <div
                          key={notification.id}
                          className={clsx(
                            'p-4 border-b border-gray-800 hover:bg-gray-700/50 cursor-pointer',
                            !notification.read && 'bg-gray-700/30'
                          )}
                          onClick={() => markAsRead(notification.id)}
                        >
                          <div className="flex items-start space-x-3">
                            <Activity className="w-5 h-5 text-cyber-500 mt-0.5" />
                            <div className="flex-1">
                              <p className="text-sm font-medium text-white">
                                {notification.title}
                              </p>
                              <p className="text-xs text-gray-400 mt-1">
                                {notification.message}
                              </p>
                              <p className="text-xs text-gray-500 mt-2">
                                {format(notification.timestamp, 'PPp')}
                              </p>
                            </div>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* Theme toggle */}
          <button
            onClick={toggleTheme}
            className="p-2 hover:bg-gray-700 rounded-lg transition-colors"
          >
            {theme === 'dark' ? (
              <Moon className="w-5 h-5 text-gray-400" />
            ) : (
              <Sun className="w-5 h-5 text-gray-400" />
            )}
          </button>

          {/* User menu */}
          <div className="relative">
            <button
              onClick={() => setShowUserMenu(!showUserMenu)}
              className="flex items-center space-x-2 p-2 hover:bg-gray-700 rounded-lg transition-colors"
            >
              <div className="w-8 h-8 bg-gray-700 rounded-full flex items-center justify-center">
                <User className="w-5 h-5 text-gray-400" />
              </div>
              <ChevronDown className="w-4 h-4 text-gray-400" />
            </button>

            {/* User dropdown */}
            <AnimatePresence>
              {showUserMenu && (
                <motion.div
                  initial={{ opacity: 0, y: -10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  className="absolute right-0 mt-2 w-56 bg-gray-800 border border-gray-700 rounded-lg shadow-lg z-50"
                >
                  <div className="p-4 border-b border-gray-700">
                    <p className="text-sm font-medium text-white">
                      {user?.name || 'Admin User'}
                    </p>
                    <p className="text-xs text-gray-400 mt-1">
                      {user?.email || 'admin@secunik.com'}
                    </p>
                  </div>
                  <div className="p-2">
                    <Link
                      to="/settings"
                      className="flex items-center space-x-3 px-3 py-2 text-sm text-gray-300 hover:text-white hover:bg-gray-700 rounded-lg transition-colors"
                      onClick={() => setShowUserMenu(false)}
                    >
                      <Settings className="w-4 h-4" />
                      <span>Settings</span>
                    </Link>
                    <Link
                      to="/api-docs"
                      className="flex items-center space-x-3 px-3 py-2 text-sm text-gray-300 hover:text-white hover:bg-gray-700 rounded-lg transition-colors"
                      onClick={() => setShowUserMenu(false)}
                    >
                      <HelpCircle className="w-4 h-4" />
                      <span>API Docs</span>
                    </Link>
                    <hr className="my-2 border-gray-700" />
                    <button
                      onClick={() => {
                        setShowUserMenu(false);
                        logout();
                      }}
                      className="flex items-center space-x-3 px-3 py-2 text-sm text-red-400 hover:text-red-300 hover:bg-gray-700 rounded-lg transition-colors w-full"
                    >
                      <LogOut className="w-4 h-4" />
                      <span>Logout</span>
                    </button>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </header>

      {/* Search overlay */}
      <AnimatePresence>
        {showSearch && (
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="absolute top-16 left-0 right-0 bg-gray-800 border-b border-gray-700 p-4 z-40"
          >
            <form onSubmit={handleSearch} className="max-w-2xl mx-auto">
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search files, analysis, rules..."
                className="w-full px-4 pl-10 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:border-cyber-500 focus:ring-1 focus:ring-cyber-500 focus:outline-none"
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

export default Header;