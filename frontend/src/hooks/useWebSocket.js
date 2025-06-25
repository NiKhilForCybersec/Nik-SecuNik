import { useEffect, useRef, useCallback } from 'react'
import websocketService from '../services/websocketService'

export const useWebSocket = () => {
  const isConnected = useRef(false)

  useEffect(() => {
    const connect = async () => {
      try {
        await websocketService.connect()
        isConnected.current = true
      } catch (error) {
        console.error('Failed to connect to WebSocket:', error)
        isConnected.current = false
      }
    }

    connect()

    return () => {
      websocketService.disconnect()
      isConnected.current = false
    }
  }, [])

  const subscribe = useCallback((channel, callback, options) => {
    return websocketService.subscribe(channel, callback, options)
  }, [])

  const unsubscribe = useCallback((subscriptionId) => {
    websocketService.unsubscribe(subscriptionId)
  }, [])

  const send = useCallback((message) => {
    return websocketService.send(message)
  }, [])

  const getStatus = useCallback(() => {
    return websocketService.getStatus()
  }, [])

  return {
    subscribe,
    unsubscribe,
    send,
    getStatus,
    isConnected: isConnected.current
  }
}

export const useAnalysisUpdates = (analysisId, onUpdate) => {
  const { subscribe, unsubscribe } = useWebSocket()

  useEffect(() => {
    if (!analysisId || !onUpdate) return

    const subscriptionId = subscribe('analysis', onUpdate, { analysis_id: analysisId })

    return () => {
      unsubscribe(subscriptionId)
    }
  }, [analysisId, onUpdate, subscribe, unsubscribe])
}

export const useSystemStatus = (onStatusUpdate) => {
  const { subscribe, unsubscribe } = useWebSocket()

  useEffect(() => {
    if (!onStatusUpdate) return

    const subscriptionId = subscribe('system_status', onStatusUpdate)

    return () => {
      unsubscribe(subscriptionId)
    }
  }, [onStatusUpdate, subscribe, unsubscribe])
}

export const useThreatAlerts = (onAlert) => {
  const { subscribe, unsubscribe } = useWebSocket()

  useEffect(() => {
    if (!onAlert) return

    const subscriptionId = subscribe('threat_alerts', onAlert)

    return () => {
      unsubscribe(subscriptionId)
    }
  }, [onAlert, subscribe, unsubscribe])
}