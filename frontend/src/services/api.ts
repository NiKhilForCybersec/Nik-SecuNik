import axios, { AxiosInstance, AxiosError, AxiosRequestConfig } from 'axios'
import toast from 'react-hot-toast'

// API Configuration
const API_BASE = import.meta.env.VITE_API_URL || '/api'
const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8000/ws'

interface ApiError {
  error: string
  message: string
  error_code?: string
  status_code: number
  details?: Record<string, any>
  type?: string
}

// Create axios instance with proper typing
const apiClient: AxiosInstance = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
    'X-Client-Version': '1.0.0'
  },
  validateStatus: (status) => status < 500
})

// Request interceptor for auth and request tracking
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('access_token')
    if (token && config.headers) {
      config.headers.Authorization = `Bearer ${token}`
    }
    
    // Add request ID for tracking
    config.headers['X-Request-ID'] = `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
    
    return config
  },
  (error) => {
    console.error('Request error:', error)
    return Promise.reject(error)
  }
)

// Response interceptor for error handling and retry logic
apiClient.interceptors.response.use(
  (response) => {
    // Handle successful responses
    return response
  },
  async (error: AxiosError<ApiError>) => {
    const originalRequest = error.config as AxiosRequestConfig & { _retry?: boolean }
    
    // Handle network errors
    if (!error.response) {
      toast.error('Network error. Please check your connection.')
      return Promise.reject({
        error: 'NetworkError',
        message: 'Failed to connect to server',
        status_code: 0,
        type: 'network_error'
      })
    }
    
    // Handle 401 Unauthorized
    if (error.response.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true
      localStorage.removeItem('access_token')
      // Optionally redirect to login
      window.location.href = '/login'
      return Promise.reject(error.response.data)
    }
    
    // Handle 429 Rate Limiting
    if (error.response.status === 429) {
      const retryAfter = error.response.headers['retry-after']
      toast.error(`Rate limited. Try again in ${retryAfter || '60'} seconds.`)
      return Promise.reject(error.response.data)
    }
    
    // Handle other errors
    if (error.response.status >= 500) {
      toast.error('Server error. Please try again later.')
    }
    
    return Promise.reject(error.response.data || error)
  }
)

export { apiClient, API_BASE, WS_URL }
export type { ApiError }
export default apiClient