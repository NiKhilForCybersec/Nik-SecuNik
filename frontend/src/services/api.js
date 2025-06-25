import axios from 'axios';
import toast from 'react-hot-toast';
import Cookies from 'js-cookie';

// Create axios instance with default config
const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8000/api',
  timeout: 30000, // 30 seconds
  headers: {
    'Content-Type': 'application/json',
  },
});

// Token management
const TOKEN_KEY = 'auth_token';
const REFRESH_TOKEN_KEY = 'refresh_token';

export const tokenManager = {
  getToken: () => Cookies.get(TOKEN_KEY),
  setToken: (token) => Cookies.set(TOKEN_KEY, token, { expires: 7 }), // 7 days
  removeToken: () => Cookies.remove(TOKEN_KEY),
  
  getRefreshToken: () => Cookies.get(REFRESH_TOKEN_KEY),
  setRefreshToken: (token) => Cookies.set(REFRESH_TOKEN_KEY, token, { expires: 30 }), // 30 days
  removeRefreshToken: () => Cookies.remove(REFRESH_TOKEN_KEY),
};

// Request interceptor
api.interceptors.request.use(
  (config) => {
    // Add auth token if available
    const token = tokenManager.getToken();
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }

    // Add request ID for tracking
    config.headers['X-Request-ID'] = generateRequestId();

    // Log request in development
    if (import.meta.env.DEV) {
      console.log(`🚀 ${config.method?.toUpperCase()} ${config.url}`, {
        data: config.data,
        params: config.params,
      });
    }

    return config;
  },
  (error) => {
    console.error('Request error:', error);
    return Promise.reject(error);
  }
);

// Response interceptor
api.interceptors.response.use(
  (response) => {
    // Log response in development
    if (import.meta.env.DEV) {
      console.log(`✅ Response from ${response.config.url}:`, response.data);
    }

    return response;
  },
  async (error) => {
    const originalRequest = error.config;

    // Log error in development
    if (import.meta.env.DEV) {
      console.error(`❌ Error from ${originalRequest?.url}:`, error);
    }

    // Handle 401 Unauthorized
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      try {
        // Try to refresh token
        const refreshToken = tokenManager.getRefreshToken();
        if (refreshToken) {
          const response = await api.post('/auth/refresh', {
            refresh_token: refreshToken,
          });

          const { access_token, refresh_token: newRefreshToken } = response.data;
          tokenManager.setToken(access_token);
          tokenManager.setRefreshToken(newRefreshToken);

          // Retry original request
          originalRequest.headers.Authorization = `Bearer ${access_token}`;
          return api(originalRequest);
        }
      } catch (refreshError) {
        // Refresh failed, redirect to login
        tokenManager.removeToken();
        tokenManager.removeRefreshToken();
        window.location.href = '/login';
        return Promise.reject(refreshError);
      }
    }

    // Handle other errors
    handleApiError(error);
    return Promise.reject(error);
  }
);

// Error handler
const handleApiError = (error) => {
  let message = 'An unexpected error occurred';
  
  if (error.response) {
    // Server responded with error
    const { status, data } = error.response;
    
    switch (status) {
      case 400:
        message = data.detail || 'Invalid request';
        break;
      case 403:
        message = 'You do not have permission to perform this action';
        break;
      case 404:
        message = 'Resource not found';
        break;
      case 422:
        message = data.detail?.[0]?.msg || 'Validation error';
        break;
      case 429:
        message = 'Too many requests. Please try again later';
        break;
      case 500:
        message = 'Server error. Please try again later';
        break;
      default:
        message = data.detail || data.message || message;
    }
  } else if (error.request) {
    // Request made but no response
    message = 'Network error. Please check your connection';
  }

  // Show error toast
  toast.error(message);
};

// Generate unique request ID
const generateRequestId = () => {
  return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
};

// API methods with retry logic
const apiWithRetry = {
  async get(url, config = {}) {
    return retryRequest(() => api.get(url, config));
  },

  async post(url, data, config = {}) {
    return retryRequest(() => api.post(url, data, config));
  },

  async put(url, data, config = {}) {
    return retryRequest(() => api.put(url, data, config));
  },

  async patch(url, data, config = {}) {
    return retryRequest(() => api.patch(url, data, config));
  },

  async delete(url, config = {}) {
    return retryRequest(() => api.delete(url, config));
  },
};

// Retry logic for failed requests
const retryRequest = async (requestFn, retries = 3, delay = 1000) => {
  try {
    return await requestFn();
  } catch (error) {
    if (retries > 0 && shouldRetry(error)) {
      await new Promise(resolve => setTimeout(resolve, delay));
      return retryRequest(requestFn, retries - 1, delay * 2);
    }
    throw error;
  }
};

// Determine if request should be retried
const shouldRetry = (error) => {
  // Retry on network errors or 5xx server errors
  return !error.response || error.response.status >= 500;
};

// File upload with progress
export const uploadFile = async (file, onProgress) => {
  const formData = new FormData();
  formData.append('file', file);

  return api.post('/upload/file', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
    onUploadProgress: (progressEvent) => {
      const percentCompleted = Math.round(
        (progressEvent.loaded * 100) / progressEvent.total
      );
      onProgress?.(percentCompleted);
    },
  });
};

// Bulk file upload
export const uploadFiles = async (files, onProgress) => {
  const formData = new FormData();
  files.forEach(file => formData.append('files', file));

  return api.post('/upload/multiple', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
    onUploadProgress: (progressEvent) => {
      const percentCompleted = Math.round(
        (progressEvent.loaded * 100) / progressEvent.total
      );
      onProgress?.(percentCompleted);
    },
  });
};

// WebSocket connection helper
export const createWebSocketConnection = (path) => {
  const wsUrl = import.meta.env.VITE_WS_URL || 'ws://localhost:8000';
  const token = tokenManager.getToken();
  
  const ws = new WebSocket(`${wsUrl}${path}?token=${token}`);
  
  ws.onopen = () => {
    console.log('WebSocket connected');
  };
  
  ws.onerror = (error) => {
    console.error('WebSocket error:', error);
    toast.error('Real-time connection failed');
  };
  
  ws.onclose = () => {
    console.log('WebSocket disconnected');
  };
  
  return ws;
};

// Export configured instance and methods
export default {
  ...apiWithRetry,
  instance: api,
  uploadFile,
  uploadFiles,
  createWebSocketConnection,
  tokenManager,
};