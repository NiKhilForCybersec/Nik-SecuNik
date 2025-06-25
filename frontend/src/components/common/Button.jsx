import React from 'react';
import { motion } from 'framer-motion';

const VARIANTS = {
  primary: {
    base: 'bg-cyber-blue text-white border-cyber-blue hover:bg-cyber-blue/80 hover:shadow-cyber',
    disabled: 'bg-gray-700 text-gray-400 border-gray-700 cursor-not-allowed',
    loading: 'bg-cyber-blue/70 text-white/70 border-cyber-blue/70'
  },
  secondary: {
    base: 'bg-gray-800 text-gray-300 border-gray-600 hover:bg-gray-700 hover:text-white hover:border-gray-500',
    disabled: 'bg-gray-800 text-gray-500 border-gray-700 cursor-not-allowed',
    loading: 'bg-gray-800 text-gray-500 border-gray-700'
  },
  danger: {
    base: 'bg-red-600 text-white border-red-600 hover:bg-red-700 hover:shadow-red',
    disabled: 'bg-gray-700 text-gray-400 border-gray-700 cursor-not-allowed',
    loading: 'bg-red-600/70 text-white/70 border-red-600/70'
  },
  ghost: {
    base: 'bg-transparent text-gray-400 border-transparent hover:text-white hover:bg-gray-800/50',
    disabled: 'bg-transparent text-gray-600 border-transparent cursor-not-allowed',
    loading: 'bg-transparent text-gray-600 border-transparent'
  }
};

const SIZES = {
  sm: 'px-3 py-1.5 text-sm',
  md: 'px-4 py-2',
  lg: 'px-6 py-3 text-lg'
};

export default function Button({
  children,
  variant = 'primary',
  size = 'md',
  icon: Icon,
  iconPosition = 'left',
  loading = false,
  disabled = false,
  fullWidth = false,
  className = '',
  onClick,
  type = 'button',
  ...props
}) {
  const variantStyles = VARIANTS[variant] || VARIANTS.primary;
  const sizeStyles = SIZES[size] || SIZES.md;
  
  // Determine which style to use based on state
  const getStateStyles = () => {
    if (disabled) return variantStyles.disabled;
    if (loading) return variantStyles.loading;
    return variantStyles.base;
  };

  // Loading spinner component
  const LoadingSpinner = () => (
    <svg 
      className={`animate-spin ${size === 'sm' ? 'h-3 w-3' : size === 'lg' ? 'h-5 w-5' : 'h-4 w-4'}`}
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

  const content = (
    <>
      {/* Left Icon or Loading Spinner */}
      {(loading || (Icon && iconPosition === 'left')) && (
        <span className={children ? 'mr-2' : ''}>
          {loading ? <LoadingSpinner /> : <Icon className={`${size === 'sm' ? 'h-4 w-4' : size === 'lg' ? 'h-6 w-6' : 'h-5 w-5'}`} />}
        </span>
      )}
      
      {/* Button Text */}
      {children && <span>{children}</span>}
      
      {/* Right Icon */}
      {!loading && Icon && iconPosition === 'right' && (
        <span className={children ? 'ml-2' : ''}>
          <Icon className={`${size === 'sm' ? 'h-4 w-4' : size === 'lg' ? 'h-6 w-6' : 'h-5 w-5'}`} />
        </span>
      )}
    </>
  );

  const baseClasses = `
    inline-flex items-center justify-center font-medium rounded-lg 
    border transition-all duration-200 focus:outline-none 
    focus:ring-2 focus:ring-offset-2 focus:ring-offset-gray-900
    ${variant === 'primary' ? 'focus:ring-cyber-blue' : 
      variant === 'danger' ? 'focus:ring-red-500' : 
      'focus:ring-gray-600'}
    ${fullWidth ? 'w-full' : ''}
    ${sizeStyles}
    ${getStateStyles()}
    ${className}
  `;

  // For non-ghost buttons, add cyber effects
  const shouldShowEffects = variant !== 'ghost' && !disabled && !loading;

  return (
    <motion.button
      type={type}
      className={baseClasses}
      onClick={onClick}
      disabled={disabled || loading}
      whileHover={!disabled && !loading ? { scale: 1.02 } : {}}
      whileTap={!disabled && !loading ? { scale: 0.98 } : {}}
      {...props}
    >
      {/* Cyber hover effect for primary/danger buttons */}
      {shouldShowEffects && (variant === 'primary' || variant === 'danger') && (
        <span className="absolute inset-0 rounded-lg overflow-hidden">
          <span className={`
            absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-300
            bg-gradient-to-r ${variant === 'primary' ? 'from-cyber-blue/20 to-cyber-purple/20' : 'from-red-500/20 to-red-700/20'}
          `} />
        </span>
      )}
      
      {/* Button content */}
      <span className="relative z-10 inline-flex items-center">
        {content}
      </span>

      {/* Glitch effect on hover for primary button */}
      {shouldShowEffects && variant === 'primary' && (
        <>
          <span className="absolute inset-0 rounded-lg opacity-0 hover:opacity-100 transition-opacity duration-200 pointer-events-none">
            <span className="absolute inset-0 rounded-lg animate-glitch-1 bg-cyber-blue/20" />
            <span className="absolute inset-0 rounded-lg animate-glitch-2 bg-cyber-purple/20" />
          </span>
        </>
      )}
    </motion.button>
  );
}

// Re-export for easy access
export const ButtonGroup = ({ children, className = '' }) => (
  <div className={`inline-flex items-center space-x-2 ${className}`}>
    {children}
  </div>
);