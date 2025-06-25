import apiClient from './api'

export const analysisService = {
  // Start analysis using /api/analyze/{upload_id}
  async startAnalysis(uploadId, options = {}) {
    try {
      const response = await apiClient.post(`/analyze/${uploadId}`, {
        analyzers: options.analyzers || ['yara', 'sigma', 'mitre', 'ai', 'patterns'],
        options: {
          deep_scan: options.deepScan || true,
          extract_iocs: options.extractIocs || true,
          check_virustotal: options.checkVirusTotal || true,
          ...options.analysisOptions
        }
      })
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Check analysis status using /api/analyze/status/{analysis_id}
  async getAnalysisStatus(analysisId) {
    try {
      const response = await apiClient.get(`/analyze/status/${analysisId}`)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Get analysis results using /api/analyze/result/{analysis_id}
  async getAnalysisResults(analysisId) {
    try {
      const response = await apiClient.get(`/analyze/result/${analysisId}`)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Cancel analysis using /api/analyze/cancel/{analysis_id}
  async cancelAnalysis(analysisId) {
    try {
      const response = await apiClient.post(`/analyze/cancel/${analysisId}`)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Export analysis report
  async exportAnalysis(analysisId, format = 'json') {
    try {
      const response = await apiClient.get(`/analyze/export/${analysisId}?format=${format}`, {
        responseType: format === 'pdf' ? 'blob' : 'json'
      })
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  handleError(error) {
    if (error.response?.data) {
      return {
        error: error.response.data.detail?.message || 'Analysis failed',
        message: error.response.data.detail?.message || 'An error occurred during analysis',
        error_code: error.response.data.detail?.error_code,
        status_code: error.response.status,
        details: error.response.data.detail?.details || {}
      }
    }
    return {
      error: 'NetworkError',
      message: 'Failed to connect to server',
      status_code: 0,
      type: 'network_error'
    }
  }
}