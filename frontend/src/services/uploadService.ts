import apiClient, { ApiError } from './api'

export interface UploadOptions {
  autoAnalyze?: boolean
  tags?: string[]
  priority?: 'low' | 'normal' | 'high'
  onProgress?: (progress: number) => void
  onChunkComplete?: (chunkIndex: number, totalChunks: number) => void
}

export interface UploadResult {
  id: string
  filename: string
  file_size: number
  status: 'uploading' | 'parsing' | 'parsed' | 'failed'
  upload_time: string
  message?: string
}

export interface UploadStatus {
  id: string
  status: string
  progress?: number
  message?: string
  details?: any
}

class UploadService {
  private uploadQueue: Map<string, AbortController> = new Map()

  async uploadFile(file: File, options: UploadOptions = {}): Promise<UploadResult> {
    // Validate file
    this.validateFile(file)
    
    const formData = new FormData()
    formData.append('file', file)
    
    // Add optional parameters
    if (options.autoAnalyze !== undefined) {
      formData.append('auto_analyze', String(options.autoAnalyze))
    }
    
    if (options.tags && options.tags.length > 0) {
      formData.append('tags', JSON.stringify(options.tags))
    }
    
    if (options.priority) {
      formData.append('priority', options.priority)
    }

    // Create abort controller
    const abortController = new AbortController()
    const uploadId = `${Date.now()}-${file.name}`
    this.uploadQueue.set(uploadId, abortController)

    try {
      const response = await apiClient.post<UploadResult>('/upload/file', formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        },
        signal: abortController.signal,
        onUploadProgress: (progressEvent) => {
          if (options.onProgress && progressEvent.total) {
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
    } finally {
      this.uploadQueue.delete(uploadId)
    }
  }

  private validateFile(file: File): void {
    const MAX_FILE_SIZE = parseInt(import.meta.env.VITE_MAX_FILE_SIZE) || 1073741824 // 1GB
    const ALLOWED_TYPES = import.meta.env.VITE_ALLOWED_FILE_TYPES?.split(',') || []
    
    // Check file size
    if (file.size > MAX_FILE_SIZE) {
      throw new Error(`File size exceeds maximum allowed size of ${MAX_FILE_SIZE / 1024 / 1024}MB`)
    }
    
    // Check file type
    const extension = '.' + file.name.split('.').pop()?.toLowerCase()
    if (!ALLOWED_TYPES.includes(extension)) {
      throw new Error(`File type ${extension} is not supported`)
    }
    
    // Validate file name
    if (!/^[\w\-. ]+$/.test(file.name)) {
      throw new Error('File name contains invalid characters')
    }
  }

  async getUploadStatus(uploadId: string): Promise<UploadStatus> {
    try {
      const response = await apiClient.get<UploadStatus>(`/upload/status/${uploadId}`)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  }

  async cancelUpload(uploadId: string): Promise<void> {
    const controller = this.uploadQueue.get(uploadId)
    if (controller) {
      controller.abort()
      this.uploadQueue.delete(uploadId)
    }
    
    try {
      await apiClient.post(`/upload/cancel/${uploadId}`)
    } catch (error) {
      // Ignore errors when cancelling
      console.warn('Error cancelling upload:', error)
    }
  }

  async listUploads(params: {
    limit?: number
    offset?: number
    status?: string
    start_date?: string
    end_date?: string
  } = {}): Promise<{
    uploads: UploadResult[]
    total: number
    limit: number
    offset: number
  }> {
    try {
      const queryParams = new URLSearchParams()
      
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) {
          queryParams.append(key, String(value))
        }
      })

      const response = await apiClient.get(`/upload/list?${queryParams.toString()}`)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  }

  async deleteUpload(uploadId: string): Promise<void> {
    try {
      await apiClient.delete(`/upload/${uploadId}`)
    } catch (error) {
      throw this.handleError(error)
    }
  }

  async retryUpload(uploadId: string): Promise<UploadResult> {
    try {
      const response = await apiClient.post<UploadResult>(`/upload/retry/${uploadId}`)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  }

  private handleError(error: any): ApiError {
    if (error.response?.data) {
      return error.response.data
    }
    
    if (error.code === 'ECONNABORTED') {
      return {
        error: 'UploadTimeout',
        message: 'Upload timed out. Please try again.',
        status_code: 408,
        type: 'timeout'
      }
    }
    
    if (error.message === 'Network Error') {
      return {
        error: 'NetworkError',
        message: 'Network error. Please check your connection.',
        status_code: 0,
        type: 'network_error'
      }
    }
    
    return {
      error: 'UnknownError',
      message: error.message || 'An unknown error occurred',
      status_code: 500,
      type: 'unknown'
    }
  }
}

export const uploadService = new UploadService()