import axios from 'axios'

// API Configuration
const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000/api'
const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8000/ws'

// Create axios instance
const apiClient = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json'
  }
})

// Request interceptor for auth
apiClient.interceptors.request.use(
  config => {
    const token = localStorage.getItem('access_token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  error => Promise.reject(error)
)

// Response interceptor for error handling
apiClient.interceptors.response.use(
  response => response,
  error => {
    if (error.response?.status === 401) {
      // Handle token expiration
      localStorage.removeItem('access_token')
      console.warn('Authentication token expired')
    }
    return Promise.reject(error)
  }
)

export { apiClient, API_BASE, WS_URL }
export default apiClient