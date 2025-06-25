import apiClient from './api'

export const rulesService = {
  // Get rules using /api/rules/
  async getRules(params = {}) {
    try {
      const queryParams = new URLSearchParams()
      
      if (params.type) queryParams.append('type', params.type)
      if (params.category) queryParams.append('category', params.category)
      if (params.enabled_only !== undefined) queryParams.append('enabled_only', params.enabled_only)
      if (params.tags) queryParams.append('tags', params.tags)
      if (params.severity) queryParams.append('severity', params.severity)
      if (params.search) queryParams.append('search', params.search)
      if (params.limit) queryParams.append('limit', params.limit)
      if (params.offset) queryParams.append('offset', params.offset)

      const response = await apiClient.get(`/rules/?${queryParams.toString()}`)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Create rule using /api/rules/
  async createRule(ruleData) {
    try {
      const response = await apiClient.post('/rules/', ruleData)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Get rule details using /api/rules/{rule_id}
  async getRule(ruleId) {
    try {
      const response = await apiClient.get(`/rules/${ruleId}`)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Update rule using /api/rules/{rule_id}
  async updateRule(ruleId, ruleData) {
    try {
      const response = await apiClient.put(`/rules/${ruleId}`, ruleData)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Delete rule using /api/rules/{rule_id}
  async deleteRule(ruleId) {
    try {
      const response = await apiClient.delete(`/rules/${ruleId}`)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Test rule using /api/rules/{rule_id}/test
  async testRule(ruleId, testData) {
    try {
      const response = await apiClient.post(`/rules/${ruleId}/test`, testData)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Validate rule syntax
  async validateRule(ruleData) {
    try {
      const response = await apiClient.post('/rules/validate', ruleData)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Import rules using /api/rules/import
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

  // Export rules using /api/rules/export/{format}
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

  // Get rule statistics
  async getRuleStats() {
    try {
      const response = await apiClient.get('/rules/stats/summary')
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Get rule categories
  async getCategories() {
    try {
      const response = await apiClient.get('/rules/categories')
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  handleError(error) {
    if (error.response?.data) {
      return {
        error: error.response.data.detail?.message || 'Rules operation failed',
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