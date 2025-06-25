import { WS_URL } from './api'

class WebSocketService {
  constructor() {
    this.ws = null
    this.reconnectAttempts = 0
    this.maxReconnectAttempts = 5
    this.reconnectInterval = 1000
    this.subscribers = new Map()
    this.isConnecting = false
  }

  connect() {
    if (this.isConnecting || (this.ws && this.ws.readyState === WebSocket.OPEN)) {
      return Promise.resolve()
    }

    this.isConnecting = true

    return new Promise((resolve, reject) => {
      try {
        this.ws = new WebSocket(WS_URL)

        this.ws.onopen = () => {
          console.log('WebSocket connected')
          this.isConnecting = false
          this.reconnectAttempts = 0
          resolve()
        }

        this.ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data)
            this.handleMessage(data)
          } catch (error) {
            console.error('Failed to parse WebSocket message:', error)
          }
        }

        this.ws.onclose = (event) => {
          console.log('WebSocket disconnected:', event.code, event.reason)
          this.isConnecting = false
          this.reconnect()
        }

        this.ws.onerror = (error) => {
          console.error('WebSocket error:', error)
          this.isConnecting = false
          reject(error)
        }
      } catch (error) {
        this.isConnecting = false
        reject(error)
      }
    })
  }

  disconnect() {
    if (this.ws) {
      this.ws.close()
      this.ws = null
    }
    this.subscribers.clear()
  }

  reconnect() {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error('Max reconnection attempts reached')
      return
    }

    const delay = this.reconnectInterval * Math.pow(2, this.reconnectAttempts)
    this.reconnectAttempts++

    setTimeout(() => {
      console.log(`Attempting to reconnect (${this.reconnectAttempts}/${this.maxReconnectAttempts})`)
      this.connect().catch(error => {
        console.error('Reconnection failed:', error)
      })
    }, delay)
  }

  send(message) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message))
      return true
    }
    return false
  }

  subscribe(channel, callback, options = {}) {
    const subscriptionId = `${channel}_${Date.now()}_${Math.random()}`
    
    this.subscribers.set(subscriptionId, {
      channel,
      callback,
      options
    })

    // Send subscription message if connected
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.send({
        action: 'subscribe',
        channel,
        ...options
      })
    }

    return subscriptionId
  }

  unsubscribe(subscriptionId) {
    const subscription = this.subscribers.get(subscriptionId)
    if (subscription) {
      this.subscribers.delete(subscriptionId)
      
      // Send unsubscribe message if connected
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.send({
          action: 'unsubscribe',
          channel: subscription.channel,
          ...subscription.options
        })
      }
    }
  }

  subscribeToAnalysis(analysisId, callback) {
    return this.subscribe('analysis', callback, { analysis_id: analysisId })
  }

  subscribeToSystemStatus(callback) {
    return this.subscribe('system_status', callback)
  }

  subscribeToThreatAlerts(callback) {
    return this.subscribe('threat_alerts', callback)
  }

  handleMessage(data) {
    // Handle different message types
    switch (data.type) {
      case 'analysis_progress':
      case 'analysis_complete':
      case 'analysis_error':
        this.notifySubscribers('analysis', data)
        break
      case 'system_status':
        this.notifySubscribers('system_status', data)
        break
      case 'threat_alert':
        this.notifySubscribers('threat_alerts', data)
        break
      case 'pong':
        // Handle ping/pong for connection health
        break
      default:
        console.log('Unknown message type:', data.type)
    }
  }

  notifySubscribers(channel, data) {
    this.subscribers.forEach((subscription) => {
      if (subscription.channel === channel) {
        try {
          subscription.callback(data)
        } catch (error) {
          console.error('Error in WebSocket callback:', error)
        }
      }
    })
  }

  // Health check
  ping() {
    return this.send({ action: 'ping' })
  }

  // Get connection status
  getStatus() {
    if (!this.ws) return 'disconnected'
    
    switch (this.ws.readyState) {
      case WebSocket.CONNECTING:
        return 'connecting'
      case WebSocket.OPEN:
        return 'connected'
      case WebSocket.CLOSING:
        return 'closing'
      case WebSocket.CLOSED:
        return 'disconnected'
      default:
        return 'unknown'
    }
  }
}

// Create singleton instance
const websocketService = new WebSocketService()

export default websocketService