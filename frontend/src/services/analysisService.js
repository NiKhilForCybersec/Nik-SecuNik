import apiClient from './api'

export const analysisService = {
  // Start analysis
  async startAnalysis(fileId, options = {}) {
    try {
      const response = await apiClient.post('/analysis/start', {
        file_id: fileId,
        analyzers: options.analyzers || ['yara', 'sigma', 'mitre', 'ai'],
        priority: options.priority || 'normal',
        options: {
          deep_scan: options.deepScan || true,
          extract_iocs: options.extractIocs || true,
          correlation: options.correlation || true,
          ...options.analysisOptions
        }
      })
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Check analysis status
  async getAnalysisStatus(analysisId) {
    try {
      const response = await apiClient.get(`/analysis/${analysisId}/status`)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Get analysis results
  async getAnalysisResults(analysisId) {
    try {
      const response = await apiClient.get(`/analysis/${analysisId}/results`)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Cancel analysis
  async cancelAnalysis(analysisId) {
    try {
      const response = await apiClient.post(`/analysis/${analysisId}/cancel`)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  handleError(error) {
    if (error.response?.data) {
      return {
        error: error.response.data.error || 'Analysis failed',
        message: error.response.data.message || 'An error occurred during analysis',
        details: error.response.data.details || {}
      }
    }
    return {
      error: 'NetworkError',
      message: 'Failed to connect to server',
      details: {}
    }
  }
}