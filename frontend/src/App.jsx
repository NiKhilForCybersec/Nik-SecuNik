import React, { Suspense, lazy, useEffect } from 'react';
import { Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { AnimatePresence, motion } from 'framer-motion';
import Layout from '@/components/layout/Layout';

// Lazy load pages for better performance
const Upload = lazy(() => import('@/pages/placeholders').then(module => ({ default: module.Upload })));
const Analysis = lazy(() => import('@/pages/placeholders').then(module => ({ default: module.Analysis })));
const History = lazy(() => import('@/pages/placeholders').then(module => ({ default: module.History })));
const Rules = lazy(() => import('@/pages/placeholders').then(module => ({ default: module.Rules })));
const Settings = lazy(() => import('@/pages/placeholders').then(module => ({ default: module.Settings })));
const NotFound = lazy(() => import('@/pages/NotFound'));

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
    // Redirect to login if we have auth enabled
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

// Temporary store implementations until real stores are created
const useAuthStore = () => ({ isAuthenticated: true });
const useThemeStore = () => ({
  theme: 'dark',
  initializeTheme: () => {
    document.documentElement.classList.add('dark');
  },
});

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