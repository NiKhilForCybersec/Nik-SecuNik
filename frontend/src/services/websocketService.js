import EventEmitter from 'events';

class WebSocketService extends EventEmitter {
  constructor() {
    super();
    this.ws = null;
    this.url = null;
    this.reconnectInterval = 5000;
    this.maxReconnectAttempts = 10;
    this.reconnectAttempts = 0;
    this.messageQueue = [];
    this.isConnecting = false;
    this.isConnected = false;
    this.heartbeatInterval = null;
    this.reconnectTimeout = null;
    this.connectionId = null;
  }

  /**
   * Connect to WebSocket server
   * @param {string} url - WebSocket URL
   * @param {Object} options - Connection options
   */
  connect(url, options = {}) {
    if (this.isConnected || this.isConnecting) {
      console.warn('WebSocket already connected or connecting');
      return;
    }

    this.url = url || this.buildURL();
    this.isConnecting = true;
    this.options = options;

    try {
      this.ws = new WebSocket(this.url);
      this.setupEventHandlers();
    } catch (error) {
      console.error('WebSocket connection error:', error);
      this.handleConnectionError(error);
    }
  }

  /**
   * Build WebSocket URL from current location
   * @private
   */
  buildURL() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    const path = '/ws';
    return `${protocol}//${host}${path}`;
  }

  /**
   * Setup WebSocket event handlers
   * @private
   */
  setupEventHandlers() {
    if (!this.ws) return;

    this.ws.onopen = this.handleOpen.bind(this);
    this.ws.onmessage = this.handleMessage.bind(this);
    this.ws.onerror = this.handleError.bind(this);
    this.ws.onclose = this.handleClose.bind(this);
  }

  /**
   * Handle WebSocket open event
   * @private
   */
  handleOpen(event) {
    console.log('WebSocket connected');
    this.isConnecting = false;
    this.isConnected = true;
    this.reconnectAttempts = 0;
    this.connectionId = Date.now().toString();

    // Send queued messages
    this.flushMessageQueue();

    // Start heartbeat
    this.startHeartbeat();

    // Emit connected event
    this.emit('connected', { connectionId: this.connectionId });

    // Send authentication if needed
    if (this.options.auth) {
      this.send({
        type: 'auth',
        token: this.options.auth
      });
    }
  }

  /**
   * Handle incoming WebSocket message
   * @private
   */
  handleMessage(event) {
    try {
      const data = JSON.parse(event.data);
      
      // Handle special message types
      switch (data.type) {
        case 'pong':
          // Heartbeat response
          break;
        case 'error':
          this.emit('error', data);
          break;
        case 'analysis_progress':
          this.emit('analysis:progress', data);
          break;
        case 'analysis_complete':
          this.emit('analysis:complete', data);
          break;
        case 'analysis_error':
          this.emit('analysis:error', data);
          break;
        case 'notification':
          this.emit('notification', data);
          break;
        default:
          // Emit generic message event
          this.emit('message', data);
          // Emit specific event if type is provided
          if (data.type) {
            this.emit(data.type, data);
          }
      }
    } catch (error) {
      console.error('Error parsing WebSocket message:', error);
      this.emit('error', { type: 'parse_error', error: error.message });
    }
  }

  /**
   * Handle WebSocket error
   * @private
   */
  handleError(error) {
    console.error('WebSocket error:', error);
    this.emit('error', { type: 'connection_error', error });
  }

  /**
   * Handle WebSocket close event
   * @private
   */
  handleClose(event) {
    console.log('WebSocket closed', event.code, event.reason);
    this.isConnected = false;
    this.isConnecting = false;
    this.ws = null;

    // Stop heartbeat
    this.stopHeartbeat();

    // Emit disconnected event
    this.emit('disconnected', {
      code: event.code,
      reason: event.reason,
      wasClean: event.wasClean
    });

    // Handle reconnection
    if (!event.wasClean && this.shouldReconnect()) {
      this.scheduleReconnect();
    }
  }

  /**
   * Handle connection error
   * @private
   */
  handleConnectionError(error) {
    this.isConnecting = false;
    this.emit('error', { type: 'connection_failed', error });
    
    if (this.shouldReconnect()) {
      this.scheduleReconnect();
    }
  }

  /**
   * Check if should attempt reconnection
   * @private
   */
  shouldReconnect() {
    return this.reconnectAttempts < this.maxReconnectAttempts && 
           this.options.autoReconnect !== false;
  }

  /**
   * Schedule reconnection attempt
   * @private
   */
  scheduleReconnect() {
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
    }

    const delay = Math.min(
      this.reconnectInterval * Math.pow(1.5, this.reconnectAttempts),
      30000 // Max 30 seconds
    );

    console.log(`Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts + 1})`);
    
    this.reconnectTimeout = setTimeout(() => {
      this.reconnectAttempts++;
      this.connect(this.url, this.options);
    }, delay);

    this.emit('reconnecting', {
      attempt: this.reconnectAttempts + 1,
      maxAttempts: this.maxReconnectAttempts,
      delay
    });
  }

  /**
   * Send message through WebSocket
   * @param {Object|string} data - Data to send
   */
  send(data) {
    const message = typeof data === 'string' ? data : JSON.stringify(data);

    if (this.isConnected && this.ws && this.ws.readyState === WebSocket.OPEN) {
      try {
        this.ws.send(message);
        return true;
      } catch (error) {
        console.error('Error sending WebSocket message:', error);
        this.messageQueue.push(message);
        return false;
      }
    } else {
      // Queue message if not connected
      this.messageQueue.push(message);
      // Try to connect if not already attempting
      if (!this.isConnecting && !this.isConnected) {
        this.connect();
      }
      return false;
    }
  }

  /**
   * Flush queued messages
   * @private
   */
  flushMessageQueue() {
    while (this.messageQueue.length > 0 && this.isConnected) {
      const message = this.messageQueue.shift();
      try {
        this.ws.send(message);
      } catch (error) {
        console.error('Error sending queued message:', error);
        // Put it back in the queue
        this.messageQueue.unshift(message);
        break;
      }
    }
  }

  /**
   * Start heartbeat to keep connection alive
   * @private
   */
  startHeartbeat() {
    this.stopHeartbeat();
    this.heartbeatInterval = setInterval(() => {
      if (this.isConnected) {
        this.send({ type: 'ping', timestamp: Date.now() });
      }
    }, 30000); // Every 30 seconds
  }

  /**
   * Stop heartbeat
   * @private
   */
  stopHeartbeat() {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }
  }

  /**
   * Disconnect from WebSocket server
   */
  disconnect() {
    this.stopHeartbeat();
    
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = null;
    }

    if (this.ws) {
      this.ws.close(1000, 'Client disconnect');
      this.ws = null;
    }

    this.isConnected = false;
    this.isConnecting = false;
    this.messageQueue = [];
    this.reconnectAttempts = 0;
  }

  /**
   * Subscribe to analysis updates
   * @param {string} analysisId - Analysis ID to subscribe to
   */
  subscribeToAnalysis(analysisId) {
    this.send({
      type: 'subscribe',
      channel: 'analysis',
      id: analysisId
    });
  }

  /**
   * Unsubscribe from analysis updates
   * @param {string} analysisId - Analysis ID to unsubscribe from
   */
  unsubscribeFromAnalysis(analysisId) {
    this.send({
      type: 'unsubscribe',
      channel: 'analysis',
      id: analysisId
    });
  }

  /**
   * Subscribe to system notifications
   */
  subscribeToNotifications() {
    this.send({
      type: 'subscribe',
      channel: 'notifications'
    });
  }

  /**
   * Get connection status
   * @returns {Object} Connection status
   */
  getStatus() {
    return {
      isConnected: this.isConnected,
      isConnecting: this.isConnecting,
      reconnectAttempts: this.reconnectAttempts,
      queuedMessages: this.messageQueue.length,
      connectionId: this.connectionId
    };
  }

  /**
   * Wait for connection
   * @param {number} timeout - Timeout in milliseconds
   * @returns {Promise} Resolves when connected
   */
  waitForConnection(timeout = 10000) {
    return new Promise((resolve, reject) => {
      if (this.isConnected) {
        resolve();
        return;
      }

      const timer = setTimeout(() => {
        this.off('connected', handleConnect);
        reject(new Error('Connection timeout'));
      }, timeout);

      const handleConnect = () => {
        clearTimeout(timer);
        resolve();
      };

      this.once('connected', handleConnect);
    });
  }
}

// Create and export a singleton instance
const websocketService = new WebSocketService();
export { websocketService };