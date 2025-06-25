import { useState, useCallback } from 'react'
import { analysisService } from '../services/analysisService'
import { useAnalysisUpdates } from './useWebSocket'
import toast from 'react-hot-toast'

export const useAnalysis = () => {
  const [analyses, setAnalyses] = useState(new Map())
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const startAnalysis = useCallback(async (uploadId, options = {}) => {
    setLoading(true)
    setError(null)

    try {
      const result = await analysisService.startAnalysis(uploadId, options)
      
      setAnalyses(prev => new Map(prev).set(result.analysis_id, {
        ...result,
        status: 'started',
        progress: 0,
        results: null
      }))

      toast.success('Analysis started successfully')
      return result
    } catch (error) {
      setError(error)
      toast.error(error.message || 'Failed to start analysis')
      throw error
    } finally {
      setLoading(false)
    }
  }, [])

  const getAnalysisStatus = useCallback(async (analysisId) => {
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

  const getAnalysisResults = useCallback(async (analysisId) => {
    try {
      const results = await analysisService.getAnalysisResults(analysisId)
      
      setAnalyses(prev => {
        const updated = new Map(prev)
        const existing = updated.get(analysisId)
        if (existing) {
          updated.set(analysisId, { ...existing, results, status: 'completed' })
        }
        return updated
      })

      return results
    } catch (error) {
      console.error('Failed to get analysis results:', error)
      throw error
    }
  }, [])

  const cancelAnalysis = useCallback(async (analysisId) => {
    try {
      await analysisService.cancelAnalysis(analysisId)
      
      setAnalyses(prev => {
        const updated = new Map(prev)
        const existing = updated.get(analysisId)
        if (existing) {
          updated.set(analysisId, { ...existing, status: 'cancelled' })
        }
        return updated
      })

      toast.success('Analysis cancelled')
    } catch (error) {
      toast.error(error.message || 'Failed to cancel analysis')
      throw error
    }
  }, [])

  const updateAnalysisFromWebSocket = useCallback((data) => {
    const analysisId = data.analysis_id
    if (!analysisId) return

    setAnalyses(prev => {
      const updated = new Map(prev)
      const existing = updated.get(analysisId)
      
      if (existing) {
        const updatedAnalysis = { ...existing }
        
        switch (data.type) {
          case 'analysis_started':
            updatedAnalysis.status = 'analyzing'
            updatedAnalysis.progress = 0
            break
            
          case 'analysis_progress':
            updatedAnalysis.progress = data.progress
            updatedAnalysis.current_stage = data.current_stage
            updatedAnalysis.status = 'analyzing'
            break
            
          case 'stage_completed':
            if (!updatedAnalysis.stages_completed) {
              updatedAnalysis.stages_completed = []
            }
            updatedAnalysis.stages_completed.push(data.stage)
            break
            
          case 'analysis_completed':
            updatedAnalysis.status = 'completed'
            updatedAnalysis.progress = 100
            updatedAnalysis.results = data.results
            toast.success('Analysis completed successfully')
            break
            
          case 'analysis_failed':
            updatedAnalysis.status = 'failed'
            updatedAnalysis.error = data.error
            toast.error(`Analysis failed: ${data.error}`)
            break
            
          case 'threat_detected':
            if (!updatedAnalysis.threats_detected) {
              updatedAnalysis.threats_detected = []
            }
            updatedAnalysis.threats_detected.push(data.threat)
            toast.warning(`Threat detected: ${data.threat.type}`)
            break
            
          case 'ioc_found':
            if (!updatedAnalysis.iocs_found) {
              updatedAnalysis.iocs_found = []
            }
            updatedAnalysis.iocs_found.push(data.ioc)
            break
        }
        
        updated.set(analysisId, updatedAnalysis)
      }
      
      return updated
    })
  }, [])

  return {
    analyses,
    loading,
    error,
    startAnalysis,
    getAnalysisStatus,
    getAnalysisResults,
    cancelAnalysis,
    updateAnalysisFromWebSocket
  }
}

export const useAnalysisById = (analysisId) => {
  const { analyses, updateAnalysisFromWebSocket } = useAnalysis()
  
  useAnalysisUpdates(analysisId, updateAnalysisFromWebSocket)
  
  return analyses.get(analysisId) || null
}