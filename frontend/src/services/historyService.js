import apiClient from './api'

export const historyService = {
  // Get analysis history
  async getHistory(params = {}) {
    try {
      const queryParams = new URLSearchParams()
      
      if (params.limit) queryParams.append('limit', params.limit)
      if (params.offset) queryParams.append('offset', params.offset)
      if (params.startDate) queryParams.append('start_date', params.startDate)
      if (params.endDate) queryParams.append('end_date', params.endDate)
      if (params.severity) queryParams.append('severity', params.severity)
      if (params.fileType) queryParams.append('file_type', params.fileType)
      if (params.search) queryParams.append('search', params.search)

      const response = await apiClient.get(`/history?${queryParams.toString()}`)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Export history
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

  // Delete analysis
  async deleteAnalysis(analysisId) {
    try {
      const response = await apiClient.delete(`/analysis/${analysisId}`)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  handleError(error) {
    if (error.response?.data) {
      return {
        error: error.response.data.error || 'History operation failed',
        message: error.response.data.message || 'An error occurred',
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