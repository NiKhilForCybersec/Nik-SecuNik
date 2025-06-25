import apiClient from './api'

export const uploadService = {
  // Single file upload
  async uploadFile(file, onProgress = null) {
    const formData = new FormData()
    formData.append('file', file)

    try {
      const response = await apiClient.post('/upload', formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        },
        onUploadProgress: (progressEvent) => {
          if (onProgress) {
            const percentCompleted = Math.round(
              (progressEvent.loaded * 100) / progressEvent.total
            )
            onProgress(percentCompleted)
          }
        }
      })
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  // Batch file upload
  async uploadFiles(files, onProgress = null) {
    const formData = new FormData()
    files.forEach(file => {
      formData.append('files', file)
    })

    try {
      const response = await apiClient.post('/upload/batch', formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        },
        onUploadProgress: (progressEvent) => {
          if (onProgress) {
            const percentCompleted = Math.round(
              (progressEvent.loaded * 100) / progressEvent.total
            )
            onProgress(percentCompleted)
          }
        }
      })
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  },

  handleError(error) {
    if (error.response?.data) {
      return {
        error: error.response.data.error || 'Upload failed',
        message: error.response.data.message || 'An error occurred during upload',
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