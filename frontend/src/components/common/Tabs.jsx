import React, { useState, useEffect, useRef } from 'react';

const Tabs = ({
  tabs = [],
  activeTab: controlledActiveTab,
  onChange,
  variant = 'default',
  size = 'md',
  fullWidth = false,
  className = ''
}) => {
  const [internalActiveTab, setInternalActiveTab] = useState(0);
  const [indicatorStyle, setIndicatorStyle] = useState({});
  const tabRefs = useRef([]);

  // Use controlled or internal state
  const activeTab = controlledActiveTab !== undefined ? controlledActiveTab : internalActiveTab;
  const setActiveTab = controlledActiveTab !== undefined ? onChange : setInternalActiveTab;

  // Update indicator position
  useEffect(() => {
    const activeTabElement = tabRefs.current[activeTab];
    if (activeTabElement) {
      setIndicatorStyle({
        left: activeTabElement.offsetLeft,
        width: activeTabElement.offsetWidth
      });
    }
  }, [activeTab, tabs]);

  const variants = {
    default: {
      container: 'border-b border-gray-700',
      tab: 'text-gray-400 hover:text-white',
      activeTab: 'text-cyan-400',
      indicator: 'bg-cyan-500'
    },
    pills: {
      container: 'bg-gray-800 p-1 rounded-lg',
      tab: 'text-gray-400 hover:text-white hover:bg-gray-700 rounded-md',
      activeTab: 'text-white bg-gray-700',
      indicator: 'hidden'
    },
    underline: {
      container: '',
      tab: 'text-gray-400 hover:text-white border-b-2 border-transparent',
      activeTab: 'text-cyan-400 border-cyan-400',
      indicator: 'hidden'
    }
  };

  const sizes = {
    sm: 'text-sm px-3 py-1.5',
    md: 'text-base px-4 py-2',
    lg: 'text-lg px-6 py-3'
  };

  const currentVariant = variants[variant] || variants.default;

  return (
    <div className={className}>
      <div className={`relative ${currentVariant.container}`}>
        <div className={`flex ${fullWidth ? 'w-full' : ''}`}>
          {tabs.map((tab, index) => {
            const isActive = activeTab === index;
            const isDisabled = tab.disabled;

            return (
              <button
                key={index}
                ref={el => tabRefs.current[index] = el}
                onClick={() => !isDisabled && setActiveTab(index)}
                disabled={isDisabled}
                className={`
                  ${sizes[size]}
                  ${fullWidth ? 'flex-1' : ''}
                  ${isActive ? currentVariant.activeTab : currentVariant.tab}
                  ${isDisabled ? 'opacity-50 cursor-not-allowed' : ''}
                  font-medium transition-all duration-200
                  flex items-center justify-center space-x-2
                `}
              >
                {tab.icon && <span>{tab.icon}</span>}
                <span>{tab.label}</span>
                {tab.badge && (
                  <span className={`
                    ml-2 px-2 py-0.5 text-xs rounded-full
                    ${isActive ? 'bg-cyan-500/20 text-cyan-400' : 'bg-gray-700 text-gray-300'}
                  `}>
                    {tab.badge}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* Animated indicator for default variant */}
        {variant === 'default' && (
          <div
            className={`
              absolute bottom-0 h-0.5 transition-all duration-300
              ${currentVariant.indicator}
            `}
            style={indicatorStyle}
          />
        )}
      </div>

      {/* Tab content */}
      {tabs[activeTab]?.content && (
        <div className="mt-4">
          {tabs[activeTab].content}
        </div>
      )}
    </div>
  );
};

// Vertical tabs variant
export const VerticalTabs = ({
  tabs = [],
  activeTab: controlledActiveTab,
  onChange,
  className = ''
}) => {
  const [internalActiveTab, setInternalActiveTab] = useState(0);

  const activeTab = controlledActiveTab !== undefined ? controlledActiveTab : internalActiveTab;
  const setActiveTab = controlledActiveTab !== undefined ? onChange : setInternalActiveTab;

  return (
    <div className={`flex ${className}`}>
      {/* Tab list */}
      <div className="w-48 flex-shrink-0 border-r border-gray-700 pr-4">
        <div className="space-y-1">
          {tabs.map((tab, index) => {
            const isActive = activeTab === index;
            const isDisabled = tab.disabled;

            return (
              <button
                key={index}
                onClick={() => !isDisabled && setActiveTab(index)}
                disabled={isDisabled}
                className={`
                  w-full px-4 py-2 text-left rounded-lg
                  ${isActive 
                    ? 'bg-cyan-500/10 text-cyan-400 border-l-2 border-cyan-500' 
                    : 'text-gray-400 hover:text-white hover:bg-gray-800'
                  }
                  ${isDisabled ? 'opacity-50 cursor-not-allowed' : ''}
                  transition-all duration-200
                  flex items-center space-x-3
                `}
              >
                {tab.icon && <span>{tab.icon}</span>}
                <span className="flex-1">{tab.label}</span>
                {tab.badge && (
                  <span className={`
                    px-2 py-0.5 text-xs rounded-full
                    ${isActive ? 'bg-cyan-500/20 text-cyan-400' : 'bg-gray-700 text-gray-300'}
                  `}>
                    {tab.badge}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* Tab content */}
      <div className="flex-1 pl-6">
        {tabs[activeTab]?.content}
      </div>
    </div>
  );
};

// Tab panel component for lazy loading
export const TabPanel = ({ children, isActive }) => {
  if (!isActive) return null;
  return <>{children}</>;
};

export default Tabs;