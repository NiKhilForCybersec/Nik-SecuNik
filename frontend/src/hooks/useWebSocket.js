import { useEffect, useState, useCallback, useRef } from 'react';
import { io } from 'socket.io-client';
import { useAuthStore } from '@/stores/authStore';
import { useNotificationStore } from '@/stores/notificationStore';
import { WS_EVENTS } from '@/utils/constants';

export const useWebSocket = (namespace = '') => {
  const [isConnected, setIsConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState(null);
  const socketRef = useRef(null);
  const { token } = useAuthStore();
  const { addNotification } = useNotificationStore();

  useEffect(() => {
    if (!token) return;

    const wsUrl = import.meta.env.VITE_WS_URL || 'ws://localhost:8000';
    const socketPath = namespace ? `/${namespace}` : '';

    // Create socket connection
    socketRef.current = io(wsUrl + socketPath, {
      auth: {
        token,
      },
      transports: ['websocket'],
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
    });

    // Connection handlers
    socketRef.current.on('connect', () => {
      console.log(`[WebSocket] Connected to ${namespace || 'default'}`);
      setIsConnected(true);
    });

    socketRef.current.on('disconnect', (reason) => {
      console.log(`[WebSocket] Disconnected: ${reason}`);
      setIsConnected(false);
    });

    socketRef.current.on('error', (error) => {
      console.error('[WebSocket] Error:', error);
    });

    // Message handlers
    socketRef.current.on(WS_EVENTS.ANALYSIS_UPDATE, (data) => {
      setLastMessage({ type: WS_EVENTS.ANALYSIS_UPDATE, data });
    });

    socketRef.current.on(WS_EVENTS.ANALYSIS_COMPLETE, (data) => {
      setLastMessage({ type: WS_EVENTS.ANALYSIS_COMPLETE, data });
      addNotification({
        type: 'success',
        title: 'Analysis Complete',
        message: `Analysis for ${data.filename} has completed`,
      });
    });

    socketRef.current.on(WS_EVENTS.ANALYSIS_ERROR, (data) => {
      setLastMessage({ type: WS_EVENTS.ANALYSIS_ERROR, data });
      addNotification({
        type: 'error',
        title: 'Analysis Error',
        message: data.error || 'An error occurred during analysis',
      });
    });

    socketRef.current.on(WS_EVENTS.NOTIFICATION, (data) => {
      addNotification(data);
    });

    // Cleanup
    return () => {
      if (socketRef.current) {
        socketRef.current.disconnect();
        socketRef.current = null;
      }
    };
  }, [token, namespace, addNotification]);

  // Send message
  const sendMessage = useCallback((event, data) => {
    if (socketRef.current && isConnected) {
      socketRef.current.emit(event, data);
    } else {
      console.warn('[WebSocket] Not connected, cannot send message');
    }
  }, [isConnected]);

  // Subscribe to specific events
  const subscribe = useCallback((event, handler) => {
    if (socketRef.current) {
      socketRef.current.on(event, handler);
      return () => socketRef.current.off(event, handler);
    }
  }, []);

  return {
    isConnected,
    lastMessage,
    sendMessage,
    subscribe,
  };
};