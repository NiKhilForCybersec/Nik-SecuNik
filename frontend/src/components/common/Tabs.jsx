import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import clsx from 'clsx';

const Tabs = ({
  tabs = [],
  defaultTab,
  onChange,
  variant = 'default',
  size = 'md',
  fullWidth = false,
  className,
}) => {
  const [activeTab, setActiveTab] = useState(defaultTab || tabs[0]?.id);

  const handleTabChange = (tabId) => {
    setActiveTab(tabId);
    onChange?.(tabId);
  };

  const variants = {
    default: {
      container: 'border-b border-gray-700',
      tab: 'text-gray-400 hover:text-white',
      activeTab: 'text-cyber-400',
      indicator: 'bg-cyber-500',
    },
    pills: {
      container: 'bg-gray-800 p-1 rounded-lg',
      tab: 'text-gray-400 hover:text-white rounded-md',
      activeTab: 'text-white bg-gray-700',
      indicator: null,
    },
    cyber: {
      container: 'border-b-2 border-gray-800',
      tab: 'text-gray-500 hover:text-gray-300',
      activeTab: 'text-cyber-400',
      indicator: 'bg-gradient-to-r from-cyber-400 to-cyber-600',
    },
  };

  const sizes = {
    sm: 'text-sm px-3 py-1.5',
    md: 'text-base px-4 py-2',
    lg: 'text-lg px-6 py-3',
  };

  const activeTabData = tabs.find(tab => tab.id === activeTab);
  const variantStyles = variants[variant];

  return (
    <div className={className}>
      {/* Tab Headers */}
      <div className={clsx(variantStyles.container, 'relative')}>
        <div className={clsx(
          'flex',
          fullWidth ? 'w-full' : 'inline-flex',
          variant === 'pills' && 'space-x-1'
        )}>
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;

            return (
              <button
                key={tab.id}
                onClick={() => handleTabChange(tab.id)}
                disabled={tab.disabled}
                className={clsx(
                  'relative flex items-center space-x-2 font-medium transition-all duration-200',
                  sizes[size],
                  fullWidth && 'flex-1',
                  isActive ? variantStyles.activeTab : variantStyles.tab,
                  tab.disabled && 'opacity-50 cursor-not-allowed'
                )}
              >
                {Icon && <Icon className={clsx(
                  size === 'sm' ? 'w-4 h-4' : size === 'lg' ? 'w-6 h-6' : 'w-5 h-5'
                )} />}
                <span>{tab.label}</span>
                {tab.badge && (
                  <span className={clsx(
                    'ml-2 px-2 py-0.5 text-xs font-medium rounded-full',
                    isActive ? 'bg-cyber-500/20 text-cyber-300' : 'bg-gray-700 text-gray-400'
                  )}>
                    {tab.badge}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* Active Indicator */}
        {variant === 'default' && variantStyles.indicator && (
          <motion.div
            layoutId="activeTab"
            className={clsx(
              'absolute bottom-0 h-0.5',
              variantStyles.indicator
            )}
            style={{
              left: `${(tabs.findIndex(t => t.id === activeTab) / tabs.length) * 100}%`,
              width: `${100 / tabs.length}%`,
            }}
            transition={{ type: 'spring', stiffness: 500, damping: 30 }}
          />
        )}
      </div>

      {/* Tab Content */}
      <AnimatePresence mode="wait">
        <motion.div
          key={activeTab}
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -10 }}
          transition={{ duration: 0.2 }}
          className="mt-4"
        >
          {activeTabData?.content || tabs.find(tab => tab.id === activeTab)?.render?.()}
        </motion.div>
      </AnimatePresence>
    </div>
  );
};

export default Tabs;