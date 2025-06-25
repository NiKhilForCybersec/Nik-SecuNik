import { useEffect, useState, useCallback, useRef } from 'react';
import { websocketService } from '../services/websocketService';

/**
 * React hook for WebSocket connection management
 * @param {Object} options - Hook options
 * @returns {Object} WebSocket state and methods
 */
export const useWebSocket = (options = {}) => {
  const [isConnected, setIsConnected] = useState(false);
  const [isConnecting, setIsConnecting] = useState(false);
  const [connectionError, setConnectionError] = useState(null);
  const [lastMessage, setLastMessage] = useState(null);
  const [messageHistory, setMessageHistory] = useState([]);
  const eventHandlersRef = useRef(new Map());
  const optionsRef = useRef(options);

  // Update options ref
  useEffect(() => {
    optionsRef.current = options;
  }, [options]);

  // Setup connection status listeners
  useEffect(() => {
    const handleConnected = (data) => {
      setIsConnected(true);
      setIsConnecting(false);
      setConnectionError(null);
      if (optionsRef.current.onConnect) {
        optionsRef.current.onConnect(data);
      }
    };

    const handleDisconnected = (data) => {
      setIsConnected(false);
      setIsConnecting(false);
      if (optionsRef.current.onDisconnect) {
        optionsRef.current.onDisconnect(data);
      }
    };

    const handleReconnecting = (data) => {
      setIsConnecting(true);
      if (optionsRef.current.onReconnecting) {
        optionsRef.current.onReconnecting(data);
      }
    };

    const handleError = (error) => {
      setConnectionError(error);
      if (optionsRef.current.onError) {
        optionsRef.current.onError(error);
      }
    };

    const handleMessage = (data) => {
      setLastMessage(data);
      if (optionsRef.current.keepHistory !== false) {
        setMessageHistory(prev => {
          const maxHistory = optionsRef.current.maxHistory || 100;
          const newHistory = [...prev, { ...data, timestamp: Date.now() }];
          return newHistory.slice(-maxHistory);
        });
      }
      if (optionsRef.current.onMessage) {
        optionsRef.current.onMessage(data);
      }
    };

    // Add listeners
    websocketService.on('connected', handleConnected);
    websocketService.on('disconnected', handleDisconnected);
    websocketService.on('reconnecting', handleReconnecting);
    websocketService.on('error', handleError);
    websocketService.on('message', handleMessage);

    // Get initial status
    const status = websocketService.getStatus();
    setIsConnected(status.isConnected);
    setIsConnecting(status.isConnecting);

    // Cleanup
    return () => {
      websocketService.off('connected', handleConnected);
      websocketService.off('disconnected', handleDisconnected);
      websocketService.off('reconnecting', handleReconnecting);
      websocketService.off('error', handleError);
      websocketService.off('message', handleMessage);
    };
  }, []);

  // Auto-connect on mount if requested
  useEffect(() => {
    if (options.autoConnect !== false && !isConnected && !isConnecting) {
      websocketService.connect(options.url, {
        autoReconnect: options.autoReconnect !== false,
        auth: options.auth
      });
    }

    // Disconnect on unmount if requested
    return () => {
      if (options.disconnectOnUnmount) {
        // Remove all event handlers registered by this hook
        eventHandlersRef.current.forEach((handler, event) => {
          websocketService.off(event, handler);
        });
        eventHandlersRef.current.clear();
        
        // Disconnect if no other components are using the connection
        const hasOtherListeners = websocketService.listenerCount('message') > 0;
        if (!hasOtherListeners) {
          websocketService.disconnect();
        }
      }
    };
  }, []);

  /**
   * Send message through WebSocket
   */
  const sendMessage = useCallback((data) => {
    return websocketService.send(data);
  }, []);

  /**
   * Subscribe to specific event
   */
  const subscribe = useCallback((event, handler) => {
    // Store handler reference for cleanup
    eventHandlersRef.current.set(event, handler);
    websocketService.on(event, handler);

    // Return unsubscribe function
    return () => {
      websocketService.off(event, handler);
      eventHandlersRef.current.delete(event);
    };
  }, []);

  /**
   * Subscribe to analysis updates
   */
  const subscribeToAnalysis = useCallback((analysisId) => {
    websocketService.subscribeToAnalysis(analysisId);
    
    return () => {
      websocketService.unsubscribeFromAnalysis(analysisId);
    };
  }, []);

  /**
   * Connect to WebSocket server
   */
  const connect = useCallback((url, connectOptions) => {
    setIsConnecting(true);
    websocketService.connect(url || options.url, {
      ...options,
      ...connectOptions
    });
  }, [options]);

  /**
   * Disconnect from WebSocket server
   */
  const disconnect = useCallback(() => {
    websocketService.disconnect();
  }, []);

  /**
   * Clear message history
   */
  const clearHistory = useCallback(() => {
    setMessageHistory([]);
  }, []);

  /**
   * Get connection status
   */
  const getStatus = useCallback(() => {
    return websocketService.getStatus();
  }, []);

  return {
    // State
    isConnected,
    isConnecting,
    connectionError,
    lastMessage,
    messageHistory,
    
    // Methods
    sendMessage,
    subscribe,
    subscribeToAnalysis,
    connect,
    disconnect,
    clearHistory,
    getStatus
  };
};

/**
 * Hook for subscribing to analysis updates
 * @param {string} analysisId - Analysis ID to subscribe to
 * @param {Object} handlers - Event handlers
 */
export const useAnalysisSubscription = (analysisId, handlers = {}) => {
  const [progress, setProgress] = useState(null);
  const [status, setStatus] = useState(null);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const { subscribe, subscribeToAnalysis, isConnected } = useWebSocket({
    autoConnect: true
  });

  useEffect(() => {
    if (!analysisId || !isConnected) return;

    // Subscribe to analysis channel
    const unsubscribeChannel = subscribeToAnalysis(analysisId);

    // Subscribe to specific events
    const unsubscribeProgress = subscribe('analysis:progress', (data) => {
      if (data.analysis_id === analysisId) {
        setProgress(data.progress);
        setStatus(data.status);
        if (handlers.onProgress) {
          handlers.onProgress(data);
        }
      }
    });

    const unsubscribeComplete = subscribe('analysis:complete', (data) => {
      if (data.analysis_id === analysisId) {
        setResult(data.result);
        setStatus('completed');
        if (handlers.onComplete) {
          handlers.onComplete(data);
        }
      }
    });

    const unsubscribeError = subscribe('analysis:error', (data) => {
      if (data.analysis_id === analysisId) {
        setError(data.error);
        setStatus('error');
        if (handlers.onError) {
          handlers.onError(data);
        }
      }
    });

    // Cleanup
    return () => {
      unsubscribeChannel();
      unsubscribeProgress();
      unsubscribeComplete();
      unsubscribeError();
    };
  }, [analysisId, isConnected, subscribe, subscribeToAnalysis]);

  return {
    progress,
    status,
    result,
    error
  };
};

/**
 * Hook for system notifications
 * @param {Object} options - Notification options
 */
export const useNotifications = (options = {}) => {
  const [notifications, setNotifications] = useState([]);
  const { subscribe, isConnected } = useWebSocket({ autoConnect: true });

  useEffect(() => {
    if (!isConnected) return;

    const unsubscribe = subscribe('notification', (notification) => {
      setNotifications(prev => {
        const maxNotifications = options.maxNotifications || 50;
        const newNotifications = [
          { ...notification, id: Date.now(), timestamp: new Date() },
          ...prev
        ];
        return newNotifications.slice(0, maxNotifications);
      });

      if (options.onNotification) {
        options.onNotification(notification);
      }
    });

    // Subscribe to notifications channel
    websocketService.subscribeToNotifications();

    return unsubscribe;
  }, [isConnected, subscribe, options]);

  const clearNotifications = useCallback(() => {
    setNotifications([]);
  }, []);

  const removeNotification = useCallback((id) => {
    setNotifications(prev => prev.filter(n => n.id !== id));
  }, []);

  return {
    notifications,
    clearNotifications,
    removeNotification
  };
};

export default useWebSocket;