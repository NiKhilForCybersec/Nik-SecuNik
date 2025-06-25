import apiClient, { ApiError } from './api'

export interface HistoryEntry {
  id: string
  upload_id: string
  file_name: string
  file_type: string
  file_size: number
  analysis_date: string
  threat_score: number
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical'
  iocs_found: number
  findings_count: number
  mitre_techniques: string[]
  status: 'completed' | 'failed' | 'cancelled'
  tags?: string[]
  notes?: string
}

export interface HistoryStats {
  total_analyses: number
  by_severity: Record<string, number>
  by_file_type: Record<string, number>
  by_date: Array<{ date: string; count: number }>
  top_techniques: Array<{ technique: string; count: number }>
  total_iocs: number
  total_threats_found: number
  average_threat_score: number
  threat_score_avg: number
}

export interface HistoryFilters {
  limit?: number
  offset?: number
  search?: string
  severity?: string
  file_type?: string
  start_date?: string
  end_date?: string
  tags?: string[]
  min_threat_score?: number
  max_threat_score?: number
}

class HistoryService {
  async getHistory(filters: HistoryFilters = {}): Promise<{
    items: HistoryEntry[]
    total: number
    limit: number
    offset: number
    has_more: boolean
  }> {
    try {
      const queryParams = new URLSearchParams()
      
      Object.entries(filters).forEach(([key, value]) => {
        if (value !== undefined) {
          if (Array.isArray(value)) {
            value.forEach(v => queryParams.append(key, String(v)))
          } else {
            queryParams.append(key, String(value))
          }
        }
      })

      const response = await apiClient.get(`/history?${queryParams.toString()}`)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  }

  async getHistoryStats(days: number = 30): Promise<HistoryStats> {
    try {
      const response = await apiClient.get(`/history/stats?days=${days}`)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  }

  async getAnalysisDetails(analysisId: string): Promise<any> {
    try {
      const response = await apiClient.get(`/history/${analysisId}`)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  }

  async deleteAnalysis(analysisId: string): Promise<void> {
    try {
      await apiClient.delete(`/history/${analysisId}`)
    } catch (error) {
      throw this.handleError(error)
    }
  }

  async bulkDeleteAnalyses(analysisIds: string[]): Promise<{
    deleted: number
    failed: number
    errors: string[]
  }> {
    try {
      const response = await apiClient.post('/history/bulk-delete', {
        analysis_ids: analysisIds
      })
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  }

  async updateAnalysisNotes(analysisId: string, notes: string): Promise<void> {
    try {
      await apiClient.patch(`/history/${analysisId}/notes`, { notes })
    } catch (error) {
      throw this.handleError(error)
    }
  }

  async updateAnalysisTags(analysisId: string, tags: string[]): Promise<void> {
    try {
      await apiClient.patch(`/history/${analysisId}/tags`, { tags })
    } catch (error) {
      throw this.handleError(error)
    }
  }

  async exportHistory(format: 'json' | 'csv' | 'pdf' = 'json', filters: HistoryFilters = {}): Promise<any> {
    try {
      const queryParams = new URLSearchParams()
      queryParams.append('format', format)
      
      Object.entries(filters).forEach(([key, value]) => {
        if (value !== undefined) {
          if (Array.isArray(value)) {
            value.forEach(v => queryParams.append(key, String(v)))
          } else {
            queryParams.append(key, String(value))
          }
        }
      })

      const response = await apiClient.get(`/history/export?${queryParams.toString()}`, {
        responseType: format === 'pdf' ? 'blob' : 'json'
      })
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  }

  async searchHistory(query: string, filters: Omit<HistoryFilters, 'search'> = {}): Promise<{
    items: HistoryEntry[]
    total: number
    query: string
    suggestions: string[]
  }> {
    try {
      const queryParams = new URLSearchParams()
      queryParams.append('q', query)
      
      Object.entries(filters).forEach(([key, value]) => {
        if (value !== undefined) {
          if (Array.isArray(value)) {
            value.forEach(v => queryParams.append(key, String(v)))
          } else {
            queryParams.append(key, String(value))
          }
        }
      })

      const response = await apiClient.get(`/history/search?${queryParams.toString()}`)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  }

  async getHistoryTrends(period: 'day' | 'week' | 'month' = 'week', days: number = 30): Promise<{
    timeline: Array<{
      date: string
      total_analyses: number
      threat_detections: number
      average_threat_score: number
    }>
    trends: {
      analyses_trend: number
      threat_trend: number
      score_trend: number
    }
  }> {
    try {
      const response = await apiClient.get(`/history/trends?period=${period}&days=${days}`)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  }

  async getTopThreats(days: number = 30, limit: number = 10): Promise<{
    top_iocs: Array<{ value: string; type: string; count: number; threat_score: number }>
    top_techniques: Array<{ technique: string; count: number; severity: string }>
    top_file_types: Array<{ file_type: string; count: number; avg_threat_score: number }>
  }> {
    try {
      const response = await apiClient.get(`/history/top-threats?days=${days}&limit=${limit}`)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  }

  async generateReport(
    filters: HistoryFilters = {},
    options: {
      format: 'pdf' | 'html' | 'json'
      include_charts: boolean
      include_details: boolean
      template?: string
    } = { format: 'pdf', include_charts: true, include_details: true }
  ): Promise<any> {
    try {
      const response = await apiClient.post('/history/report', {
        filters,
        options
      }, {
        responseType: options.format === 'pdf' ? 'blob' : 'json'
      })
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
        error: 'HistoryTimeout',
        message: 'History request timed out. Please try again.',
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

export const historyService = new HistoryService()