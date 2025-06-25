import React, { useEffect, useRef } from 'react';
import { X, AlertCircle, CheckCircle, AlertTriangle, Info } from 'lucide-react';
import Button from './Button';

const Modal = ({
  isOpen,
  onClose,
  title,
  children,
  size = 'md',
  closeOnOverlay = true,
  closeOnEsc = true,
  showCloseButton = true,
  footer,
  className = '',
  variant = 'default'
}) => {
  const modalRef = useRef(null);

  // Handle ESC key
  useEffect(() => {
    const handleEsc = (e) => {
      if (closeOnEsc && e.key === 'Escape' && isOpen) {
        onClose();
      }
    };

    if (isOpen) {
      document.addEventListener('keydown', handleEsc);
      document.body.style.overflow = 'hidden';
    }

    return () => {
      document.removeEventListener('keydown', handleEsc);
      document.body.style.overflow = 'unset';
    };
  }, [isOpen, onClose, closeOnEsc]);

  // Handle click outside
  const handleOverlayClick = (e) => {
    if (closeOnOverlay && e.target === e.currentTarget) {
      onClose();
    }
  };

  if (!isOpen) return null;

  const sizes = {
    sm: 'max-w-md',
    md: 'max-w-lg',
    lg: 'max-w-2xl',
    xl: 'max-w-4xl',
    full: 'max-w-7xl'
  };

  const variants = {
    default: 'bg-gray-900 border-gray-800',
    danger: 'bg-gray-900 border-red-500/50',
    warning: 'bg-gray-900 border-yellow-500/50',
    success: 'bg-gray-900 border-green-500/50',
    info: 'bg-gray-900 border-blue-500/50'
  };

  return (
    <div 
      className="fixed inset-0 z-50 overflow-y-auto"
      onClick={handleOverlayClick}
    >
      {/* Backdrop */}
      <div className="fixed inset-0 bg-black/70 backdrop-blur-sm animate-fadeIn" />

      {/* Modal */}
      <div className="flex min-h-full items-center justify-center p-4">
        <div
          ref={modalRef}
          className={`
            relative w-full ${sizes[size]}
            ${variants[variant]}
            border rounded-lg shadow-2xl
            animate-slideIn
            ${className}
          `}
        >
          {/* Header */}
          {(title || showCloseButton) && (
            <div className="flex items-center justify-between p-6 border-b border-gray-800">
              {title && (
                <h3 className="text-xl font-semibold text-white">
                  {title}
                </h3>
              )}
              {showCloseButton && (
                <button
                  onClick={onClose}
                  className="
                    p-2 hover:bg-gray-800 rounded-lg 
                    transition-colors ml-auto
                  "
                >
                  <X className="w-5 h-5 text-gray-400" />
                </button>
              )}
            </div>
          )}

          {/* Content */}
          <div className="p-6 max-h-[calc(100vh-200px)] overflow-y-auto">
            {children}
          </div>

          {/* Footer */}
          {footer && (
            <div className="flex items-center justify-end space-x-3 p-6 border-t border-gray-800">
              {footer}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

// Confirm Dialog Component
export const ConfirmModal = ({
  isOpen,
  onClose,
  onConfirm,
  title = 'Confirm Action',
  message,
  confirmText = 'Confirm',
  cancelText = 'Cancel',
  variant = 'default',
  loading = false
}) => {
  const variantConfig = {
    default: {
      icon: <Info className="w-12 h-12 text-blue-500" />,
      buttonVariant: 'primary'
    },
    danger: {
      icon: <AlertCircle className="w-12 h-12 text-red-500" />,
      buttonVariant: 'danger'
    },
    warning: {
      icon: <AlertTriangle className="w-12 h-12 text-yellow-500" />,
      buttonVariant: 'warning'
    },
    success: {
      icon: <CheckCircle className="w-12 h-12 text-green-500" />,
      buttonVariant: 'success'
    }
  };

  const config = variantConfig[variant] || variantConfig.default;

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      size="sm"
      variant={variant}
      showCloseButton={false}
    >
      <div className="text-center">
        <div className="mx-auto flex items-center justify-center mb-4">
          {config.icon}
        </div>
        <h3 className="text-lg font-semibold text-white mb-2">
          {title}
        </h3>
        {message && (
          <p className="text-gray-400 mb-6">
            {message}
          </p>
        )}
        <div className="flex justify-center space-x-3">
          <Button
            onClick={onClose}
            variant="secondary"
            disabled={loading}
          >
            {cancelText}
          </Button>
          <Button
            onClick={onConfirm}
            variant={config.buttonVariant}
            loading={loading}
          >
            {confirmText}
          </Button>
        </div>
      </div>
    </Modal>
  );
};

// Alert Modal Component
export const AlertModal = ({
  isOpen,
  onClose,
  title,
  message,
  variant = 'info',
  buttonText = 'OK'
}) => {
  const variantConfig = {
    info: {
      icon: <Info className="w-12 h-12 text-blue-500" />,
      bgColor: 'bg-blue-500/10',
      borderColor: 'border-blue-500/50'
    },
    success: {
      icon: <CheckCircle className="w-12 h-12 text-green-500" />,
      bgColor: 'bg-green-500/10',
      borderColor: 'border-green-500/50'
    },
    warning: {
      icon: <AlertTriangle className="w-12 h-12 text-yellow-500" />,
      bgColor: 'bg-yellow-500/10',
      borderColor: 'border-yellow-500/50'
    },
    error: {
      icon: <AlertCircle className="w-12 h-12 text-red-500" />,
      bgColor: 'bg-red-500/10',
      borderColor: 'border-red-500/50'
    }
  };

  const config = variantConfig[variant] || variantConfig.info;

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      size="sm"
      showCloseButton={false}
    >
      <div className="text-center">
        <div className={`
          mx-auto w-20 h-20 rounded-full flex items-center justify-center mb-4
          ${config.bgColor} ${config.borderColor} border
        `}>
          {config.icon}
        </div>
        {title && (
          <h3 className="text-lg font-semibold text-white mb-2">
            {title}
          </h3>
        )}
        {message && (
          <p className="text-gray-400 mb-6">
            {message}
          </p>
        )}
        <Button
          onClick={onClose}
          variant="primary"
        >
          {buttonText}
        </Button>
      </div>
    </Modal>
  );
};

export default Modal;