import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ChevronUpIcon, ChevronDownIcon } from '@heroicons/react/24/outline';

const VARIANTS = {
  default: {
    container: 'bg-gray-800/50 border-gray-700',
    header: 'border-gray-700',
    content: ''
  },
  cyber: {
    container: 'bg-gray-900/50 border-cyber-blue/30 shadow-cyber',
    header: 'border-cyber-blue/30',
    content: 'cyber-grid'
  },
  danger: {
    container: 'bg-red-900/10 border-red-500/30',
    header: 'border-red-500/30',
    content: ''
  },
  success: {
    container: 'bg-green-900/10 border-green-500/30',
    header: 'border-green-500/30',
    content: ''
  },
  warning: {
    container: 'bg-yellow-900/10 border-yellow-500/30',
    header: 'border-yellow-500/30',
    content: ''
  }
};

export default function Card({
  children,
  title,
  subtitle,
  actions,
  variant = 'default',
  collapsible = false,
  defaultExpanded = true,
  loading = false,
  error = null,
  className = '',
  headerClassName = '',
  contentClassName = '',
  noPadding = false,
  ...props
}) {
  const [isExpanded, setIsExpanded] = useState(defaultExpanded);
  const variantStyles = VARIANTS[variant] || VARIANTS.default;

  // Loading skeleton
  if (loading) {
    return (
      <div className={`rounded-lg border backdrop-blur ${variantStyles.container} ${className}`} {...props}>
        <div className="p-6">
          <div className="animate-pulse">
            <div className="h-4 bg-gray-700 rounded w-1/4 mb-4"></div>
            <div className="space-y-3">
              <div className="h-3 bg-gray-700 rounded"></div>
              <div className="h-3 bg-gray-700 rounded w-5/6"></div>
              <div className="h-3 bg-gray-700 rounded w-4/6"></div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Error state
  if (error) {
    return (
      <div className={`rounded-lg border backdrop-blur bg-red-900/10 border-red-500/30 ${className}`} {...props}>
        <div className="p-6">
          <div className="flex items-center space-x-3">
            <div className="flex-shrink-0">
              <svg className="h-5 w-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
              </svg>
            </div>
            <div className="flex-1">
              <h3 className="text-sm font-medium text-red-400">Error</h3>
              <p className="text-sm text-red-300 mt-1">{error}</p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  const hasHeader = title || subtitle || actions || collapsible;

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className={`rounded-lg border backdrop-blur transition-all duration-200 ${variantStyles.container} ${className}`}
      {...props}
    >
      {/* Cyber variant background effect */}
      {variant === 'cyber' && (
        <div className="absolute inset-0 rounded-lg overflow-hidden pointer-events-none">
          <div className="absolute inset-0 opacity-10">
            <div className="absolute inset-0" 
                 style={{
                   backgroundImage: `
                     repeating-linear-gradient(
                       0deg,
                       transparent,
                       transparent 2px,
                       rgba(0, 255, 255, 0.1) 2px,
                       rgba(0, 255, 255, 0.1) 4px
                     ),
                     repeating-linear-gradient(
                       90deg,
                       transparent,
                       transparent 2px,
                       rgba(0, 255, 255, 0.1) 2px,
                       rgba(0, 255, 255, 0.1) 4px
                     )
                   `
                 }}
            />
          </div>
          
          {/* Animated corner brackets */}
          <div className="absolute top-0 left-0 w-6 h-6 border-t-2 border-l-2 border-cyber-blue animate-pulse" />
          <div className="absolute top-0 right-0 w-6 h-6 border-t-2 border-r-2 border-cyber-blue animate-pulse" />
          <div className="absolute bottom-0 left-0 w-6 h-6 border-b-2 border-l-2 border-cyber-blue animate-pulse" />
          <div className="absolute bottom-0 right-0 w-6 h-6 border-b-2 border-r-2 border-cyber-blue animate-pulse" />
        </div>
      )}

      {/* Header */}
      {hasHeader && (
        <div className={`
          ${noPadding ? 'px-6 py-4' : 'p-4'}
          ${(title || subtitle || actions) ? `border-b ${variantStyles.header}` : ''}
          ${headerClassName}
        `}>
          <div className="flex items-center justify-between">
            <div className="flex-1">
              {title && (
                <h3 className="text-lg font-medium text-white">
                  {title}
                </h3>
              )}
              {subtitle && (
                <p className="text-sm text-gray-400 mt-1">
                  {subtitle}
                </p>
              )}
            </div>

            <div className="flex items-center space-x-3 ml-4">
              {actions}
              
              {collapsible && (
                <button
                  onClick={() => setIsExpanded(!isExpanded)}
                  className="text-gray-400 hover:text-white transition-colors p-1"
                  aria-label={isExpanded ? 'Collapse' : 'Expand'}
                >
                  <motion.div
                    animate={{ rotate: isExpanded ? 0 : 180 }}
                    transition={{ duration: 0.2 }}
                  >
                    <ChevronUpIcon className="h-5 w-5" />
                  </motion.div>
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Content */}
      <AnimatePresence initial={false}>
        {(!collapsible || isExpanded) && (
          <motion.div
            initial={collapsible ? { height: 0, opacity: 0 } : {}}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className={`
              ${noPadding ? '' : 'p-6'}
              ${variantStyles.content}
              ${contentClassName}
              relative
            `}>
              {children}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Bottom glow effect for certain variants */}
      {(variant === 'cyber' || variant === 'danger' || variant === 'success') && (
        <div className={`
          absolute bottom-0 left-0 right-0 h-px
          ${variant === 'cyber' ? 'bg-gradient-to-r from-transparent via-cyber-blue to-transparent' :
            variant === 'danger' ? 'bg-gradient-to-r from-transparent via-red-500 to-transparent' :
            'bg-gradient-to-r from-transparent via-green-500 to-transparent'}
          opacity-50
        `} />
      )}
    </motion.div>
  );
}

// Compound components for better composition
export const CardHeader = ({ children, className = '' }) => (
  <div className={`px-6 py-4 border-b border-gray-700 ${className}`}>
    {children}
  </div>
);

export const CardContent = ({ children, className = '' }) => (
  <div className={`p-6 ${className}`}>
    {children}
  </div>
);

export const CardFooter = ({ children, className = '' }) => (
  <div className={`px-6 py-4 border-t border-gray-700 ${className}`}>
    {children}
  </div>
);