import { useState, useCallback, useEffect, useRef } from 'react'
import { analysisService } from '../services/analysisService'
import { wsManager } from '../services/websocket'
import toast from 'react-hot-toast'

export interface AnalysisState {
  id: string
  status: 'queued' | 'processing' | 'completed' | 'failed' | 'cancelled'
  progress: number
  results: any | null
  error: string | null
  startTime: string
  endTime?: string
  uploadId: string
  analyzers: string[]
}

interface UseAnalysisOptions {
  autoStart?: boolean
  onProgress?: (progress: number) => void
  onComplete?: (results: any) => void
  onError?: (error: any) => void
}

export const useAnalysis = (options: UseAnalysisOptions = {}) => {
  const [analyses, setAnalyses] = useState<Map<string, AnalysisState>>(new Map())
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<any>(null)
  const progressCallbacks = useRef<Map<string, (progress: number) => void>>(new Map())

  // Subscribe to WebSocket updates
  useEffect(() => {
    const unsubscribeProgress = wsManager.subscribe('analysis_progress', (message) => {
      const { analysis_id, progress, status } = message.data
      
      setAnalyses(prev => {
        const updated = new Map(prev)
        const existing = updated.get(analysis_id)
        if (existing) {
          updated.set(analysis_id, {
            ...existing,
            progress,
            status
          })
        }
        return updated
      })
      
      // Call progress callback if registered
      const callback = progressCallbacks.current.get(analysis_id)
      if (callback) {
        callback(progress)
      }
      
      if (options.onProgress) {
        options.onProgress(progress)
      }
    })

    const unsubscribeComplete = wsManager.subscribe('analysis_complete', (message) => {
      const { analysis_id, results } = message.data
      
      setAnalyses(prev => {
        const updated = new Map(prev)
        const existing = updated.get(analysis_id)
        if (existing) {
          updated.set(analysis_id, {
            ...existing,
            status: 'completed',
            progress: 100,
            results,
            endTime: new Date().toISOString()
          })
        }
        return updated
      })
      
      toast.success('Analysis completed successfully')
      
      if (options.onComplete) {
        options.onComplete(results)
      }
    })

    const unsubscribeError = wsManager.subscribe('analysis_error', (message) => {
      const { analysis_id, error } = message.data
      
      setAnalyses(prev => {
        const updated = new Map(prev)
        const existing = updated.get(analysis_id)
        if (existing) {
          updated.set(analysis_id, {
            ...existing,
            status: 'failed',
            error: error.message,
            endTime: new Date().toISOString()
          })
        }
        return updated
      })
      
      toast.error(`Analysis failed: ${error.message}`)
      
      if (options.onError) {
        options.onError(error)
      }
    })

    return () => {
      unsubscribeProgress()
      unsubscribeComplete()
      unsubscribeError()
    }
  }, [options])

  const startAnalysis = useCallback(async (
    uploadId: string, 
    analysisOptions: any = {},
    onProgress?: (progress: number) => void
  ) => {
    setLoading(true)
    setError(null)

    try {
      const result = await analysisService.startAnalysis(uploadId, analysisOptions)
      
      const analysisState: AnalysisState = {
        id: result.analysis_id,
        status: 'queued',
        progress: 0,
        results: null,
        error: null,
        startTime: new Date().toISOString(),
        uploadId,
        analyzers: analysisOptions.analyzers || []
      }
      
      setAnalyses(prev => new Map(prev).set(result.analysis_id, analysisState))
      
      // Register progress callback if provided
      if (onProgress) {
        progressCallbacks.current.set(result.analysis_id, onProgress)
      }
      
      toast.success('Analysis started successfully')
      return result
    } catch (error: any) {
      setError(error)
      toast.error(error.message || 'Failed to start analysis')
      throw error
    } finally {
      setLoading(false)
    }
  }, [])

  const getAnalysisStatus = useCallback(async (analysisId: string) => {
    try {
      const status = await analysisService.getAnalysisStatus(analysisId)
      
      setAnalyses(prev => {
        const updated = new Map(prev)
        const existing = updated.get(analysisId)
        if (existing) {
          updated.set(analysisId, { ...existing, ...status })
        }
        return updated
      })

      return status
    } catch (error) {
      console.error('Failed to get analysis status:', error)
      throw error
    }
  }, [])

  const getAnalysisResults = useCallback(async (analysisId: string) => {
    try {
      const results = await analysisService.getAnalysisResults(analysisId)
      
      setAnalyses(prev => {
        const updated = new Map(prev)
        const existing = updated.get(analysisId)
        if (existing) {
          updated.set(analysisId, { 
            ...existing, 
            results,
            status: 'completed'
          })
        }
        return updated
      })

      return results
    } catch (error) {
      console.error('Failed to get analysis results:', error)
      throw error
    }
  }, [])

  const cancelAnalysis = useCallback(async (analysisId: string) => {
    try {
      await analysisService.cancelAnalysis(analysisId)
      
      setAnalyses(prev => {
        const updated = new Map(prev)
        const existing = updated.get(analysisId)
        if (existing) {
          updated.set(analysisId, { 
            ...existing, 
            status: 'cancelled',
            endTime: new Date().toISOString()
          })
        }
        return updated
      })
      
      // Remove progress callback
      progressCallbacks.current.delete(analysisId)
      
      toast.success('Analysis cancelled')
    } catch (error) {
      console.error('Failed to cancel analysis:', error)
      throw error
    }
  }, [])

  const retryAnalysis = useCallback(async (analysisId: string) => {
    const analysis = analyses.get(analysisId)
    if (!analysis) {
      throw new Error('Analysis not found')
    }
    
    return startAnalysis(analysis.uploadId, { analyzers: analysis.analyzers })
  }, [analyses, startAnalysis])

  const clearAnalysis = useCallback((analysisId: string) => {
    setAnalyses(prev => {
      const updated = new Map(prev)
      updated.delete(analysisId)
      return updated
    })
    progressCallbacks.current.delete(analysisId)
  }, [])

  return {
    analyses: Array.from(analyses.values()),
    loading,
    error,
    startAnalysis,
    getAnalysisStatus,
    getAnalysisResults,
    cancelAnalysis,
    retryAnalysis,
    clearAnalysis,
    getAnalysisById: (id: string) => analyses.get(id)
  }
}

export const useAnalysisById = (analysisId: string | undefined) => {
  const { analyses, ...rest } = useAnalysis()
  const analysis = analysisId ? analyses.find(a => a.id === analysisId) : undefined
  
  return {
    analysis,
    ...rest
  }
}