import React from 'react';

const LoadingSpinner = ({ 
  size = 'md', 
  color = 'cyan',
  fullScreen = false,
  text = '',
  overlay = false 
}) => {
  const sizes = {
    xs: 'w-4 h-4',
    sm: 'w-6 h-6',
    md: 'w-8 h-8',
    lg: 'w-12 h-12',
    xl: 'w-16 h-16'
  };

  const colors = {
    cyan: 'text-cyan-500',
    white: 'text-white',
    gray: 'text-gray-500',
    blue: 'text-blue-500',
    green: 'text-green-500',
    red: 'text-red-500',
    yellow: 'text-yellow-500',
    purple: 'text-purple-500'
  };

  const spinner = (
    <div className="flex flex-col items-center justify-center space-y-4">
      <div className="relative">
        {/* Outer ring */}
        <div className={`
          ${sizes[size]} 
          rounded-full border-4 border-gray-700
          animate-pulse
        `} />
        
        {/* Spinning ring */}
        <div className={`
          absolute inset-0
          ${sizes[size]} 
          rounded-full border-4 border-transparent
          ${colors[color]}
          border-t-current border-r-current
          animate-spin
        `} />

        {/* Inner dot */}
        <div className={`
          absolute inset-0 m-auto
          w-2 h-2 rounded-full
          ${colors[color]}
          animate-pulse
        `} />
      </div>

      {text && (
        <p className="text-sm text-gray-400 animate-pulse">
          {text}
        </p>
      )}

      {/* Cyber effect dots */}
      <div className="flex space-x-1">
        {[...Array(3)].map((_, i) => (
          <div
            key={i}
            className={`
              w-1.5 h-1.5 rounded-full
              ${colors[color]} opacity-40
              animate-bounce
            `}
            style={{ animationDelay: `${i * 0.15}s` }}
          />
        ))}
      </div>
    </div>
  );

  if (fullScreen) {
    return (
      <div className="fixed inset-0 bg-gray-900 flex items-center justify-center z-50">
        {spinner}
      </div>
    );
  }

  if (overlay) {
    return (
      <div className="absolute inset-0 bg-gray-900/75 backdrop-blur-sm flex items-center justify-center rounded-lg z-40">
        {spinner}
      </div>
    );
  }

  return spinner;
};

// Inline loading spinner for buttons and small spaces
export const InlineSpinner = ({ size = 'xs', color = 'current' }) => {
  const sizes = {
    xs: 'w-3 h-3',
    sm: 'w-4 h-4',
    md: 'w-5 h-5'
  };

  return (
    <svg 
      className={`animate-spin ${sizes[size]} ${color === 'current' ? '' : `text-${color}-500`}`}
      xmlns="http://www.w3.org/2000/svg" 
      fill="none" 
      viewBox="0 0 24 24"
    >
      <circle 
        className="opacity-25" 
        cx="12" 
        cy="12" 
        r="10" 
        stroke="currentColor" 
        strokeWidth="4"
      />
      <path 
        className="opacity-75" 
        fill="currentColor" 
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
      />
    </svg>
  );
};

// Skeleton loader for content
export const SkeletonLoader = ({ lines = 3, className = '' }) => {
  return (
    <div className={`space-y-3 ${className}`}>
      {[...Array(lines)].map((_, i) => (
        <div key={i} className="animate-pulse">
          <div 
            className="h-4 bg-gray-700 rounded"
            style={{ width: `${Math.random() * 40 + 60}%` }}
          />
        </div>
      ))}
    </div>
  );
};

// Progress loader
export const ProgressLoader = ({ progress = 0, text = '', color = 'cyan' }) => {
  const colors = {
    cyan: 'bg-cyan-500',
    blue: 'bg-blue-500',
    green: 'bg-green-500',
    yellow: 'bg-yellow-500',
    red: 'bg-red-500'
  };

  return (
    <div className="w-full space-y-2">
      {text && (
        <div className="flex justify-between text-sm">
          <span className="text-gray-400">{text}</span>
          <span className="text-white">{progress}%</span>
        </div>
      )}
      <div className="w-full h-2 bg-gray-700 rounded-full overflow-hidden">
        <div 
          className={`h-full ${colors[color]} transition-all duration-300 ease-out`}
          style={{ width: `${progress}%` }}
        >
          <div className="h-full w-full bg-gradient-to-r from-transparent to-white/20 animate-shimmer" />
        </div>
      </div>
    </div>
  );
};

export default LoadingSpinner;