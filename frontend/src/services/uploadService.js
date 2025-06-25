import apiClient from './api'

export const uploadService = {
  // Upload single file to /api/upload/file
  async uploadFile(file, options = {}) {
    const formData = new FormData()
    formData.append('file', file)
    
    // Add optional parameters
    if (options.autoAnalyze) {
      formData.append('auto_analyze', 'true')
    }
    
    if (options.tags && Array.isArray(options.tags)) {
      formData.append('tags', JSON.stringify(options.tags))
    }

    try {
      const response = await apiClient.post('/upload/file', formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        },
        onUploadProgress: (progressEvent) => {
          if (options.onProgress) {
            const percentCompleted = Math.round(
              (progressEvent.loaded * 100) / progressEvent.total
            )
            options.onProgress(percentCompleted)
          }
        }
      })
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Check upload status
  async getUploadStatus(uploadId) {
    try {
      const response = await apiClient.get(`/upload/status/${uploadId}`)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // List uploads
  async listUploads(params = {}) {
    try {
      const queryParams = new URLSearchParams()
      
      if (params.limit) queryParams.append('limit', params.limit)
      if (params.offset) queryParams.append('offset', params.offset)

      const response = await apiClient.get(`/upload/list?${queryParams.toString()}`)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Delete upload
  async deleteUpload(uploadId) {
    try {
      const response = await apiClient.delete(`/upload/${uploadId}`)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  handleError(error) {
    if (error.response?.data) {
      return {
        error: error.response.data.detail?.message || 'Upload failed',
        message: error.response.data.detail?.message || 'An error occurred during upload',
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