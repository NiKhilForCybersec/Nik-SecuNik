import apiClient from './api'

export const virusTotalService = {
  // Scan hash with VirusTotal
  async scanHash(hash, type = 'file') {
    try {
      const response = await apiClient.post('/virustotal/scan', {
        hash,
        type
      })
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Get VirusTotal report
  async getReport(hash) {
    try {
      const response = await apiClient.get(`/virustotal/report/${hash}`)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Scan URL
  async scanUrl(url) {
    try {
      const response = await apiClient.post('/virustotal/scan', {
        url,
        type: 'url'
      })
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Get scan statistics
  async getStats() {
    try {
      const response = await apiClient.get('/virustotal/stats')
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  handleError(error) {
    if (error.response?.data) {
      return {
        error: error.response.data.error || 'VirusTotal operation failed',
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