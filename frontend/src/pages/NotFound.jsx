import React from 'react';
import { Link } from 'react-router-dom';
import { Home, AlertTriangle } from 'lucide-react';

const NotFound = () => {
  return (
    <div className="min-h-[600px] flex items-center justify-center p-4">
      <div className="text-center max-w-md">
        {/* 404 Animation */}
        <div className="relative mb-8">
          <h1 className="text-9xl font-bold text-gray-800 select-none">404</h1>
          <div className="absolute inset-0 flex items-center justify-center">
            <AlertTriangle className="w-24 h-24 text-cyber-500 animate-pulse" />
          </div>
        </div>

        {/* Error Message */}
        <h2 className="text-3xl font-bold text-gray-100 mb-4 glitch" data-text="Page Not Found">
          Page Not Found
        </h2>
        <p className="text-gray-400 mb-8">
          The page you're looking for doesn't exist or has been moved.
        </p>

        {/* Action Buttons */}
        <div className="flex flex-col sm:flex-row gap-4 justify-center">
          <Link
            to="/"
            className="inline-flex items-center gap-2 px-6 py-3 bg-cyber-600 hover:bg-cyber-700 text-white font-medium rounded-lg transition-colors duration-200"
          >
            <Home size={20} />
            Go Home
          </Link>
          <button
            onClick={() => window.history.back()}
            className="inline-flex items-center gap-2 px-6 py-3 bg-gray-800 hover:bg-gray-700 text-gray-100 font-medium rounded-lg border border-gray-700 transition-colors duration-200"
          >
            Go Back
          </button>
        </div>

        {/* Additional Help */}
        <div className="mt-12 p-6 bg-gray-800/50 rounded-lg border border-gray-700">
          <p className="text-sm text-gray-400 mb-3">
            If you believe this is an error, try these pages:
          </p>
          <div className="flex flex-wrap gap-3 justify-center">
            <Link to="/upload" className="text-cyber-400 hover:text-cyber-300 text-sm">
              Upload Files
            </Link>
            <span className="text-gray-600">•</span>
            <Link to="/history" className="text-cyber-400 hover:text-cyber-300 text-sm">
              Analysis History
            </Link>
            <span className="text-gray-600">•</span>
            <Link to="/rules" className="text-cyber-400 hover:text-cyber-300 text-sm">
              Rules
            </Link>
            <span className="text-gray-600">•</span>
            <Link to="/settings" className="text-cyber-400 hover:text-cyber-300 text-sm">
              Settings
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};

export default NotFound;