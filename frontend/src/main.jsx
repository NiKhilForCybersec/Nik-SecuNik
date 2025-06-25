import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ReactQueryDevtools } from '@tanstack/react-query-devtools';
import { Toaster } from 'react-hot-toast';
import App from './App';
import './index.css';

// Create a client for React Query
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5 * 60 * 1000, // 5 minutes
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

// Error Boundary Component
class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('Error caught by boundary:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-gray-900 flex items-center justify-center p-4">
          <div className="bg-gray-800 border border-red-500 rounded-lg p-8 max-w-lg w-full">
            <div className="flex items-center mb-4">
              <svg className="w-8 h-8 text-red-500 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <h1 className="text-2xl font-bold text-gray-100">Application Error</h1>
            </div>
            <p className="text-gray-400 mb-4">
              Something went wrong. The application encountered an unexpected error.
            </p>
            <details className="mb-6">
              <summary className="cursor-pointer text-sm text-gray-500 hover:text-gray-300">
                Error details
              </summary>
              <pre className="mt-2 text-xs text-red-400 bg-gray-900 p-3 rounded overflow-auto">
                {this.state.error?.toString()}
              </pre>
            </details>
            <button
              onClick={() => window.location.reload()}
              className="w-full bg-cyber-600 hover:bg-cyber-700 text-white font-medium py-2 px-4 rounded-lg transition-colors duration-200"
            >
              Reload Application
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

// Check for required environment variables
const requiredEnvVars = ['VITE_API_URL'];
const missingEnvVars = requiredEnvVars.filter(varName => !import.meta.env[varName]);

if (missingEnvVars.length > 0) {
  console.warn('Missing required environment variables:', missingEnvVars);
}

// Root element
const rootElement = document.getElementById('root');

if (!rootElement) {
  throw new Error('Failed to find the root element');
}

// Create React root and render
const root = ReactDOM.createRoot(rootElement);

root.render(
  <React.StrictMode>
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <App />
          
          {/* Toast notifications */}
          <Toaster
            position="top-right"
            reverseOrder={false}
            gutter={8}
            toastOptions={{
              duration: 4000,
              style: {
                background: '#1f2937',
                color: '#f3f4f6',
                border: '1px solid #374151',
              },
              success: {
                iconTheme: {
                  primary: '#10b981',
                  secondary: '#1f2937',
                },
                style: {
                  border: '1px solid #10b981',
                },
              },
              error: {
                iconTheme: {
                  primary: '#ef4444',
                  secondary: '#1f2937',
                },
                style: {
                  border: '1px solid #ef4444',
                },
              },
              loading: {
                iconTheme: {
                  primary: '#06b6d4',
                  secondary: '#1f2937',
                },
              },
            }}
          />
          
          {/* React Query Devtools - only in development */}
          {import.meta.env.DEV && (
            <ReactQueryDevtools 
              initialIsOpen={false}
              buttonPosition="bottom-left"
            />
          )}
        </BrowserRouter>
      </QueryClientProvider>
    </ErrorBoundary>
  </React.StrictMode>
);

// Enable React DevTools in production (optional)
if (typeof window !== 'undefined') {
  window.React = React;
}