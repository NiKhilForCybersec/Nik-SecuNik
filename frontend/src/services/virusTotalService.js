import apiClient from './api'

export const virusTotalService = {
  // Scan resource using /api/virustotal/scan
  async scan(resourceType, resourceValue, forceRescan = false) {
    try {
      const response = await apiClient.post('/virustotal/scan', {
        resource_type: resourceType, // 'file', 'ip', 'domain', 'url'
        resource_value: resourceValue,
        force_rescan: forceRescan
      })
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Bulk scan using /api/virustotal/scan/bulk
  async bulkScan(resources) {
    try {
      const response = await apiClient.post('/virustotal/scan/bulk', {
        resources: resources
      })
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Get cached report using /api/virustotal/report/{type}/{value}
  async getCachedReport(resourceType, resourceValue) {
    try {
      const response = await apiClient.get(`/virustotal/report/${resourceType}/${encodeURIComponent(resourceValue)}`)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Check quota using /api/virustotal/quota
  async getQuota() {
    try {
      const response = await apiClient.get('/virustotal/quota')
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Clear cache using /api/virustotal/cache/clear
  async clearCache(olderThanDays = 7) {
    try {
      const response = await apiClient.post(`/virustotal/cache/clear?older_than_days=${olderThanDays}`)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Get statistics using /api/virustotal/stats
  async getStats(days = 7) {
    try {
      const response = await apiClient.get(`/virustotal/stats?days=${days}`)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Extract IOCs using /api/virustotal/iocs/extract
  async extractIOCs(fileHash) {
    try {
      const response = await apiClient.post('/virustotal/iocs/extract', {
        file_hash: fileHash
      })
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Convenience methods for specific resource types
  async scanFile(hash, forceRescan = false) {
    return this.scan('file', hash, forceRescan)
  },

  async scanIP(ip) {
    return this.scan('ip', ip)
  },

  async scanDomain(domain) {
    return this.scan('domain', domain)
  },

  async scanUrl(url) {
    return this.scan('url', url)
  },

  handleError(error) {
    if (error.response?.data) {
      return {
        error: error.response.data.detail?.message || 'VirusTotal operation failed',
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