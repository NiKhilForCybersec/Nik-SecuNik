import React, { Suspense, lazy, useEffect } from 'react';
import { Routes, Route, Navigate, useLocation, Link, Outlet } from 'react-router-dom';
import { AnimatePresence, motion } from 'framer-motion';
import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { Shield, Upload as UploadIcon, Activity, History as HistoryIcon, FileCode, Settings as SettingsIcon, Moon, Sun, Menu, X } from 'lucide-react';

// Zustand stores
export const useThemeStore = create(
  persist(
    (set) => ({
      theme: 'dark',
      toggleTheme: () => set((state) => ({ theme: state.theme === 'dark' ? 'light' : 'dark' })),
      setTheme: (theme) => set({ theme }),
      initializeTheme: () => {
        const savedTheme = localStorage.getItem('theme-storage');
        if (savedTheme) {
          const parsed = JSON.parse(savedTheme);
          set({ theme: parsed.state.theme });
        }
      },
    }),
    {
      name: 'theme-storage',
    }
  )
);

export const useAuthStore = create((set) => ({
  isAuthenticated: false,
  user: null,
  login: (user) => set({ isAuthenticated: true, user }),
  logout: () => set({ isAuthenticated: false, user: null }),
}));

// Layout Component
const Layout = ({ children }) => {
  const [sidebarOpen, setSidebarOpen] = React.useState(true);
  const { theme, toggleTheme } = useThemeStore();
  const location = useLocation();

  const navItems = [
    { path: '/upload', label: 'Upload', icon: UploadIcon },
    { path: '/analysis', label: 'Analysis', icon: Activity },
    { path: '/history', label: 'History', icon: HistoryIcon },
    { path: '/rules', label: 'Rules', icon: FileCode },
    { path: '/settings', label: 'Settings', icon: SettingsIcon },
  ];

  return (
    <div className="flex h-screen bg-gray-900">
      {/* Sidebar */}
      <motion.aside
        initial={false}
        animate={{ width: sidebarOpen ? 256 : 64 }}
        className="bg-gray-800 border-r border-gray-700 flex flex-col"
      >
        {/* Logo */}
        <div className="p-4 border-b border-gray-700">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Shield className="w-8 h-8 text-cyber-500 flex-shrink-0" />
              {sidebarOpen && (
                <h1 className="text-xl font-bold font-cyber text-gradient">
                  SecuNik LogX
                </h1>
              )}
            </div>
            <button
              onClick={() => setSidebarOpen(!sidebarOpen)}
              className="p-1 hover:bg-gray-700 rounded transition-colors"
            >
              {sidebarOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-4">
          <ul className="space-y-2">
            {navItems.map(({ path, label, icon: Icon }) => {
              const isActive = location.pathname.startsWith(path);
              return (
                <li key={path}>
                  <Link
                    to={path}
                    className={`
                      flex items-center gap-3 px-3 py-2 rounded-lg transition-all duration-200
                      ${isActive 
                        ? 'bg-gray-700 text-cyber-400 shadow-inner-glow' 
                        : 'text-gray-400 hover:text-gray-300 hover:bg-gray-700/50'
                      }
                    `}
                  >
                    <Icon className="w-5 h-5 flex-shrink-0" />
                    {sidebarOpen && <span className="font-medium">{label}</span>}
                  </Link>
                </li>
              );
            })}
          </ul>
        </nav>

        {/* Theme Toggle */}
        <div className="p-4 border-t border-gray-700">
          <button
            onClick={toggleTheme}
            className="flex items-center gap-3 w-full px-3 py-2 rounded-lg text-gray-400 hover:text-gray-300 hover:bg-gray-700/50 transition-all duration-200"
          >
            {theme === 'dark' ? <Moon className="w-5 h-5" /> : <Sun className="w-5 h-5" />}
            {sidebarOpen && <span>Toggle Theme</span>}
          </button>
        </div>
      </motion.aside>

      {/* Main Content */}
      <main className="flex-1 overflow-auto">
        {children}
      </main>
    </div>
  );
};

// Page Components
const Upload = () => (
  <div className="p-8">
    <h2 className="text-3xl font-bold mb-6">Upload Files</h2>
    <div className="card-cyber">
      <div className="border-2 border-dashed border-gray-600 rounded-lg p-16 text-center hover:border-cyber-500 transition-colors">
        <UploadIcon className="w-16 h-16 text-cyber-500 mx-auto mb-4" />
        <p className="text-xl mb-2">Drop files here or click to browse</p>
        <p className="text-gray-400">Supports logs, PCAPs, forensic images, and more</p>
        <button className="btn-cyber mt-6">Select Files</button>
      </div>
    </div>
  </div>
);

const Analysis = () => (
  <div className="p-8">
    <h2 className="text-3xl font-bold mb-6">Analysis Dashboard</h2>
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
      <div className="card-cyber">
        <h3 className="text-lg font-semibold mb-2 text-cyber-400">Total Events</h3>
        <p className="text-3xl font-bold">0</p>
      </div>
      <div className="card-cyber">
        <h3 className="text-lg font-semibold mb-2 text-orange-400">Threats Detected</h3>
        <p className="text-3xl font-bold">0</p>
      </div>
      <div className="card-cyber">
        <h3 className="text-lg font-semibold mb-2 text-green-400">Files Analyzed</h3>
        <p className="text-3xl font-bold">0</p>
      </div>
    </div>
  </div>
);

const History = () => (
  <div className="p-8">
    <h2 className="text-3xl font-bold mb-6">Analysis History</h2>
    <div className="card-cyber">
      <p className="text-gray-400 text-center py-8">No analysis history yet</p>
    </div>
  </div>
);

const Rules = () => (
  <div className="p-8">
    <h2 className="text-3xl font-bold mb-6">Detection Rules</h2>
    <div className="card-cyber">
      <div className="flex justify-between items-center mb-4">
        <h3 className="text-lg font-semibold">YARA Rules</h3>
        <button className="btn-cyber-primary">Import Rules</button>
      </div>
      <p className="text-gray-400">No rules loaded</p>
    </div>
  </div>
);

const Settings = () => (
  <div className="p-8">
    <h2 className="text-3xl font-bold mb-6">Settings</h2>
    <div className="space-y-6">
      <div className="card-cyber">
        <h3 className="text-lg font-semibold mb-4">API Configuration</h3>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-2">VirusTotal API Key</label>
            <input type="password" className="input-cyber w-full" placeholder="Enter your API key" />
          </div>
          <div>
            <label className="block text-sm font-medium mb-2">OpenAI API Key</label>
            <input type="password" className="input-cyber w-full" placeholder="Enter your API key" />
          </div>
        </div>
      </div>
    </div>
  </div>
);

const NotFound = () => (
  <div className="p-8 text-center">
    <h2 className="text-3xl font-bold mb-4">404 - Page Not Found</h2>
    <p className="text-gray-400 mb-6">The page you're looking for doesn't exist.</p>
    <Link to="/" className="btn-cyber">Go Home</Link>
  </div>
);

// Loading component
const PageLoader = () => (
  <div className="flex items-center justify-center min-h-[400px]">
    <div className="relative">
      <div className="w-16 h-16 border-4 border-cyber-500/20 rounded-full"></div>
      <div className="w-16 h-16 border-4 border-cyber-500 border-t-transparent rounded-full animate-spin absolute inset-0"></div>
    </div>
  </div>
);

// Auth guard component
const ProtectedRoute = ({ children }) => {
  const isAuthenticated = useAuthStore(state => state.isAuthenticated);
  const location = useLocation();

  if (!isAuthenticated) {
    // For now, we'll just render the children since auth isn't implemented
    return children;
  }

  return children;
};

// Page transition variants
const pageVariants = {
  initial: {
    opacity: 0,
    y: 20,
  },
  in: {
    opacity: 1,
    y: 0,
  },
  out: {
    opacity: 0,
    y: -20,
  },
};

const pageTransition = {
  type: 'tween',
  ease: 'anticipate',
  duration: 0.3,
};

// Main App component
function App() {
  const location = useLocation();
  const { theme, initializeTheme } = useThemeStore();

  // Initialize theme on mount
  useEffect(() => {
    initializeTheme();
  }, [initializeTheme]);

  // Apply theme class to document
  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark');
  }, [theme]);

  // Log route changes in development
  useEffect(() => {
    if (import.meta.env.DEV) {
      console.log('Route changed to:', location.pathname);
    }
  }, [location]);

  return (
    <Layout>
      <AnimatePresence mode="wait">
        <motion.div
          key={location.pathname}
          initial="initial"
          animate="in"
          exit="out"
          variants={pageVariants}
          transition={pageTransition}
          className="h-full"
        >
          <Suspense fallback={<PageLoader />}>
            <Routes location={location} key={location.pathname}>
              {/* Redirect root to upload */}
              <Route path="/" element={<Navigate to="/upload" replace />} />
              
              {/* Main routes */}
              <Route
                path="/upload"
                element={
                  <ProtectedRoute>
                    <Upload />
                  </ProtectedRoute>
                }
              />
              
              <Route
                path="/analysis"
                element={
                  <ProtectedRoute>
                    <Analysis />
                  </ProtectedRoute>
                }
              />
              
              <Route
                path="/analysis/:id"
                element={
                  <ProtectedRoute>
                    <Analysis />
                  </ProtectedRoute>
                }
              />
              
              <Route
                path="/history"
                element={
                  <ProtectedRoute>
                    <History />
                  </ProtectedRoute>
                }
              />
              
              <Route
                path="/rules"
                element={
                  <ProtectedRoute>
                    <Rules />
                  </ProtectedRoute>
                }
              />
              
              <Route
                path="/settings"
                element={
                  <ProtectedRoute>
                    <Settings />
                  </ProtectedRoute>
                }
              />
              
              {/* 404 page */}
              <Route path="*" element={<NotFound />} />
            </Routes>
          </Suspense>
        </motion.div>
      </AnimatePresence>
    </Layout>
  );
}

export default App;