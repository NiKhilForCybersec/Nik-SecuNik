import apiClient from './api'

export const rulesService = {
  // Get rules
  async getRules(params = {}) {
    try {
      const queryParams = new URLSearchParams()
      
      if (params.type) queryParams.append('type', params.type)
      if (params.category) queryParams.append('category', params.category)
      if (params.enabled !== undefined) queryParams.append('enabled', params.enabled)
      if (params.search) queryParams.append('search', params.search)

      const response = await apiClient.get(`/rules?${queryParams.toString()}`)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Create rule
  async createRule(ruleData) {
    try {
      const response = await apiClient.post('/rules', ruleData)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Update rule
  async updateRule(ruleId, ruleData) {
    try {
      const response = await apiClient.put(`/rules/${ruleId}`, ruleData)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Delete rule
  async deleteRule(ruleId) {
    try {
      const response = await apiClient.delete(`/rules/${ruleId}`)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Test rule
  async testRule(ruleData, testData) {
    try {
      const response = await apiClient.post('/rules/test', {
        rule: ruleData,
        test_data: testData
      })
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Import rules
  async importRules(file) {
    try {
      const formData = new FormData()
      formData.append('file', file)

      const response = await apiClient.post('/rules/import', formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        }
      })
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Export rules
  async exportRules(format = 'json') {
    try {
      const response = await apiClient.get(`/rules/export/${format}`, {
        responseType: 'blob'
      })
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  handleError(error) {
    if (error.response?.data) {
      return {
        error: error.response.data.error || 'Rules operation failed',
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