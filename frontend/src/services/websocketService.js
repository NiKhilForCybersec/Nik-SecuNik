import { WS_URL } from './api'

class WebSocketService {
  constructor() {
    this.ws = null
    this.reconnectAttempts = 0
    this.maxReconnectAttempts = 5
    this.reconnectInterval = 1000
    this.subscribers = new Map()
    this.isConnecting = false
    this.messageQueue = []
  }

  connect() {
    if (this.isConnecting || (this.ws && this.ws.readyState === WebSocket.OPEN)) {
      return Promise.resolve()
    }

    this.isConnecting = true

    return new Promise((resolve, reject) => {
      try {
        // Connect to /api/analyze/ws for analysis updates
        this.ws = new WebSocket(`${WS_URL}/api/analyze/ws`)

        this.ws.onopen = () => {
          console.log('WebSocket connected to SecuNik LogX backend')
          this.isConnecting = false
          this.reconnectAttempts = 0
          
          // Send queued messages
          while (this.messageQueue.length > 0) {
            const message = this.messageQueue.shift()
            this.ws.send(JSON.stringify(message))
          }
          
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
    this.messageQueue = []
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
    } else {
      // Queue message for when connection is restored
      this.messageQueue.push(message)
      return false
    }
  }

  // Subscribe to analysis updates
  subscribe(analysisId, callback) {
    const subscriptionId = `analysis_${analysisId}_${Date.now()}_${Math.random()}`
    
    this.subscribers.set(subscriptionId, {
      analysisId,
      callback
    })

    // Send subscription message if connected
    this.send({
      action: 'subscribe',
      analysis_id: analysisId
    })

    return subscriptionId
  }

  unsubscribe(subscriptionId) {
    const subscription = this.subscribers.get(subscriptionId)
    if (subscription) {
      this.subscribers.delete(subscriptionId)
      
      // Send unsubscribe message if connected
      this.send({
        action: 'unsubscribe',
        analysis_id: subscription.analysisId
      })
    }
  }

  // Subscribe to specific analysis
  subscribeToAnalysis(analysisId, callback) {
    return this.subscribe(analysisId, callback)
  }

  handleMessage(data) {
    // Handle different message types based on SecuNik LogX backend structure
    switch (data.type) {
      case 'connected':
        console.log('WebSocket connection confirmed')
        break
        
      case 'analysis_started':
        this.notifyAnalysisSubscribers(data.analysis_id, data)
        break
        
      case 'analysis_progress':
        this.notifyAnalysisSubscribers(data.analysis_id, data)
        break
        
      case 'analysis_completed':
        this.notifyAnalysisSubscribers(data.analysis_id, data)
        break
        
      case 'analysis_failed':
        this.notifyAnalysisSubscribers(data.analysis_id, data)
        break
        
      case 'stage_completed':
        this.notifyAnalysisSubscribers(data.analysis_id, data)
        break
        
      case 'ioc_found':
        this.notifyAnalysisSubscribers(data.analysis_id, data)
        break
        
      case 'threat_detected':
        this.notifyAnalysisSubscribers(data.analysis_id, data)
        break
        
      case 'pong':
        // Handle ping/pong for connection health
        break
        
      default:
        console.log('Unknown message type:', data.type, data)
    }
  }

  notifyAnalysisSubscribers(analysisId, data) {
    this.subscribers.forEach((subscription) => {
      if (subscription.analysisId === analysisId) {
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