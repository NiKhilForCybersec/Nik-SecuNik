import apiClient from './api'

export const historyService = {
  // Get analysis history using /api/history/
  async getHistory(params = {}) {
    try {
      const queryParams = new URLSearchParams()
      
      if (params.limit) queryParams.append('limit', params.limit)
      if (params.offset) queryParams.append('offset', params.offset)
      if (params.start_date) queryParams.append('start_date', params.start_date)
      if (params.end_date) queryParams.append('end_date', params.end_date)
      if (params.min_threat_score) queryParams.append('min_threat_score', params.min_threat_score)
      if (params.severity) queryParams.append('severity', params.severity)
      if (params.file_type) queryParams.append('file_type', params.file_type)
      if (params.has_iocs !== undefined) queryParams.append('has_iocs', params.has_iocs)
      if (params.search) queryParams.append('search', params.search)

      const response = await apiClient.get(`/history/?${queryParams.toString()}`)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Get analysis details using /api/history/{analysis_id}
  async getAnalysisDetails(analysisId) {
    try {
      const response = await apiClient.get(`/history/${analysisId}`)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Delete analysis using /api/history/{analysis_id}
  async deleteAnalysis(analysisId) {
    try {
      const response = await apiClient.delete(`/history/${analysisId}`)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Add tags to analysis using /api/history/{analysis_id}/tags
  async addTags(analysisId, tags) {
    try {
      const response = await apiClient.post(`/history/${analysisId}/tags`, tags)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Update notes using /api/history/{analysis_id}/notes
  async updateNotes(analysisId, notes) {
    try {
      const response = await apiClient.put(`/history/${analysisId}/notes`, notes)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Get history statistics using /api/history/stats
  async getHistoryStats(days = 30) {
    try {
      const response = await apiClient.get(`/history/stats?days=${days}`)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Export history using /api/history/export/{format}
  async exportHistory(format = 'json') {
    try {
      const response = await apiClient.get(`/history/export/${format}`, {
        responseType: 'blob'
      })
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Compare analyses using /api/history/compare
  async compareAnalyses(analysisIds) {
    try {
      const response = await apiClient.post('/history/compare', analysisIds)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Get timeline events using /api/history/timeline/events
  async getTimelineEvents(params = {}) {
    try {
      const queryParams = new URLSearchParams()
      
      if (params.start_date) queryParams.append('start_date', params.start_date)
      if (params.end_date) queryParams.append('end_date', params.end_date)

      const response = await apiClient.get(`/history/timeline/events?${queryParams.toString()}`)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  handleError(error) {
    if (error.response?.data) {
      return {
        error: error.response.data.detail?.message || 'History operation failed',
        message: error.response.data.detail?.message || 'An error occurred',
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