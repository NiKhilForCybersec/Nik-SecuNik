import { useEffect, useRef, useState, useCallback } from 'react'
import { wsManager, WebSocketEventType, WebSocketMessage } from '../services/websocket'

export const useWebSocket = () => {
  const [isConnected, setIsConnected] = useState(wsManager.isConnected())
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null)

  useEffect(() => {
    const checkConnection = setInterval(() => {
      setIsConnected(wsManager.isConnected())
    }, 1000)

    return () => clearInterval(checkConnection)
  }, [])

  const subscribe = useCallback((
    eventType: WebSocketEventType | '*',
    handler: (message: WebSocketMessage) => void
  ) => {
    return wsManager.subscribe(eventType, handler)
  }, [])

  const send = useCallback((message: any) => {
    wsManager.send(message)
  }, [])

  return {
    isConnected,
    lastMessage,
    subscribe,
    send,
    wsManager
  }
}

export const useAnalysisUpdates = (analysisId?: string) => {
  const [progress, setProgress] = useState(0)
  const [status, setStatus] = useState<string>('queued')
  const [results, setResults] = useState<any>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!analysisId) return

    const unsubscribeProgress = wsManager.subscribe('analysis_progress', (message) => {
      if (message.data.analysis_id === analysisId) {
        setProgress(message.data.progress)
        setStatus(message.data.status)
      }
    })

    const unsubscribeComplete = wsManager.subscribe('analysis_complete', (message) => {
      if (message.data.analysis_id === analysisId) {
        setProgress(100)
        setStatus('completed')
        setResults(message.data.results)
      }
    })

    const unsubscribeError = wsManager.subscribe('analysis_error', (message) => {
      if (message.data.analysis_id === analysisId) {
        setStatus('failed')
        setError(message.data.error.message)
      }
    })

    return () => {
      unsubscribeProgress()
      unsubscribeComplete()
      unsubscribeError()
    }
  }, [analysisId])

  return { progress, status, results, error }
}

export const useThreatAlerts = (onAlert?: (alert: any) => void) => {
  const [alerts, setAlerts] = useState<any[]>([])

  useEffect(() => {
    const unsubscribe = wsManager.subscribe('threat_alert', (message) => {
      const alert = message.data
      setAlerts(prev => [alert, ...prev].slice(0, 50)) // Keep last 50 alerts
      
      if (onAlert) {
        onAlert(alert)
      }
    })

    return unsubscribe
  }, [onAlert])

  return alerts
}