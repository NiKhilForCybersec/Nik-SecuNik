import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ChevronDown, ChevronUp } from 'lucide-react';
import clsx from 'clsx';

const Card = ({
  children,
  title,
  subtitle,
  actions,
  variant = 'default',
  padding = true,
  loading = false,
  error = null,
  collapsible = false,
  defaultExpanded = true,
  className,
  ...props
}) => {
  const [isExpanded, setIsExpanded] = useState(defaultExpanded);

  const variantStyles = {
    default: {
      container: 'bg-gray-800/50 border-gray-700',
      header: 'border-gray-700',
    },
    primary: {
      container: 'bg-cyber-900/20 border-cyber-600',
      header: 'border-cyber-600',
    },
    danger: {
      container: 'bg-red-900/20 border-red-600',
      header: 'border-red-600',
    },
    success: {
      container: 'bg-green-900/20 border-green-600',
      header: 'border-green-600',
    },
  };

  const styles = variantStyles[variant] || variantStyles.default;

  // Loading state
  if (loading) {
    return (
      <div className={clsx('rounded-lg border backdrop-blur', styles.container, className)} {...props}>
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
      <div className={clsx('rounded-lg border backdrop-blur bg-red-900/10 border-red-500/30', className)} {...props}>
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
      className={clsx('rounded-lg border backdrop-blur transition-all duration-200', styles.container, className)}
      {...props}
    >
      {/* Cyber effect corners */}
      {variant === 'primary' && (
        <>
          <div className="absolute top-0 left-0 w-3 h-3 border-t-2 border-l-2 border-cyber-500 rounded-tl-lg" />
          <div className="absolute top-0 right-0 w-3 h-3 border-t-2 border-r-2 border-cyber-500 rounded-tr-lg" />
          <div className="absolute bottom-0 left-0 w-3 h-3 border-b-2 border-l-2 border-cyber-500 rounded-bl-lg" />
          <div className="absolute bottom-0 right-0 w-3 h-3 border-b-2 border-r-2 border-cyber-500 rounded-br-lg" />
        </>
      )}

      {/* Header */}
      {hasHeader && (
        <div
          className={clsx(
            'flex items-center justify-between border-b',
            padding ? 'p-4' : 'px-4 py-3',
            styles.header,
            collapsible && 'cursor-pointer select-none'
          )}
          onClick={collapsible ? () => setIsExpanded(!isExpanded) : undefined}
        >
          <div className="flex-1">
            {title && (
              <h3 className="text-lg font-semibold text-gray-100">{title}</h3>
            )}
            {subtitle && (
              <p className="text-sm text-gray-400 mt-1">{subtitle}</p>
            )}
          </div>

          <div className="flex items-center space-x-3">
            {actions}
            {collapsible && (
              <motion.div
                animate={{ rotate: isExpanded ? 0 : -180 }}
                transition={{ duration: 0.2 }}
              >
                <ChevronDown className="w-5 h-5 text-gray-400" />
              </motion.div>
            )}
          </div>
        </div>
      )}

      {/* Content */}
      <AnimatePresence initial={false}>
        {(!collapsible || isExpanded) && (
          <motion.div
            initial={collapsible ? { height: 0, opacity: 0 } : false}
            animate={{ height: 'auto', opacity: 1 }}
            exit={collapsible ? { height: 0, opacity: 0 } : false}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className={padding ? 'p-4' : ''}>
              {children}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
};

export default Card;