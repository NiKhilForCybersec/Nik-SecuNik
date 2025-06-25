import apiClient, { ApiError } from './api'

export interface AnalysisOptions {
  analyzers?: string[]
  deepScan?: boolean
  extractIocs?: boolean
  checkVirusTotal?: boolean
  priority?: 'low' | 'normal' | 'high'
  customRules?: string[]
  timeout?: number
}

export interface AnalysisResult {
  analysis_id: string
  status: 'queued' | 'processing' | 'completed' | 'failed' | 'cancelled'
  progress: number
  start_time: string
  end_time?: string
  message?: string
}

export interface AnalysisStatus {
  id: string
  status: string
  progress: number
  current_stage?: string
  estimated_time_remaining?: number
  error?: string
}

export interface AnalysisResults {
  analysis_id: string
  upload_id: string
  filename: string
  file_type: string
  file_size: number
  analysis_time: string
  threat_score: number
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical'
  summary: string
  findings: Finding[]
  iocs: IOC[]
  yara_results: YaraResult[]
  sigma_results: SigmaResult[]
  mitre_results: MitreResult
  ai_insights?: AIInsights
  virustotal_results?: VirusTotalResult
  metadata: Record<string, any>
}

export interface Finding {
  id: string
  type: 'yara_match' | 'sigma_match' | 'ai_detection' | 'pattern_match' | 'anomaly'
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical'
  title: string
  description: string
  evidence: string[]
  confidence: number
  timestamp?: string
  rule_name?: string
  tags?: string[]
}

export interface IOC {
  type: 'ip' | 'domain' | 'url' | 'hash' | 'email' | 'file_path' | 'registry_key'
  value: string
  context: string
  confidence: number
  tags?: string[]
  threat_types?: string[]
}

export interface YaraResult {
  rule: string
  matches: number
  severity: string
  meta?: Record<string, any>
  tags?: string[]
}

export interface SigmaResult {
  rule: string
  title: string
  level: string
  description: string
  matches: number
  tags?: string[]
}

export interface MitreResult {
  techniques: MitreTechnique[]
  tactics: string[]
  kill_chain_phases: string[]
}

export interface MitreTechnique {
  technique_id: string
  technique_name: string
  tactic: string
  description: string
  confidence: number
  evidence: string[]
}

export interface AIInsights {
  analysis: string
  key_findings: string[]
  recommendations: string[]
  confidence: number
  model_version: string
}

export interface VirusTotalResult {
  scan_id: string
  positives: number
  total: number
  scan_date: string
  permalink: string
  scans: Record<string, any>
}

class AnalysisService {
  async startAnalysis(uploadId: string, options: AnalysisOptions = {}): Promise<AnalysisResult> {
    try {
      const response = await apiClient.post<AnalysisResult>('/analysis/start', {
        upload_id: uploadId,
        analyzers: options.analyzers || ['yara', 'sigma', 'mitre', 'ai'],
        deep_scan: options.deepScan || false,
        extract_iocs: options.extractIocs || true,
        check_virustotal: options.checkVirusTotal || false,
        priority: options.priority || 'normal',
        custom_rules: options.customRules || [],
        timeout: options.timeout || 3600
      })
      
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  }

  async getAnalysisStatus(analysisId: string): Promise<AnalysisStatus> {
    try {
      const response = await apiClient.get<AnalysisStatus>(`/analysis/status/${analysisId}`)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  }

  async getAnalysisResults(analysisId: string): Promise<AnalysisResults> {
    try {
      const response = await apiClient.get<AnalysisResults>(`/analysis/results/${analysisId}`)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  }

  async cancelAnalysis(analysisId: string): Promise<void> {
    try {
      await apiClient.post(`/analysis/cancel/${analysisId}`)
    } catch (error) {
      throw this.handleError(error)
    }
  }

  async retryAnalysis(analysisId: string): Promise<AnalysisResult> {
    try {
      const response = await apiClient.post<AnalysisResult>(`/analysis/retry/${analysisId}`)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  }

  async listAnalyses(params: {
    limit?: number
    offset?: number
    status?: string
    start_date?: string
    end_date?: string
    upload_id?: string
  } = {}): Promise<{
    analyses: AnalysisResult[]
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

      const response = await apiClient.get(`/analysis/list?${queryParams.toString()}`)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  }

  async exportAnalysis(analysisId: string, format: 'json' | 'csv' | 'pdf' = 'json'): Promise<any> {
    try {
      const response = await apiClient.get(`/analysis/export/${analysisId}?format=${format}`, {
        responseType: format === 'pdf' ? 'blob' : 'json'
      })
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  }

  async getAnalysisStatistics(days: number = 30): Promise<{
    total_analyses: number
    by_status: Record<string, number>
    by_severity: Record<string, number>
    by_analyzer: Record<string, number>
    average_processing_time: number
    threat_score_distribution: Array<{ range: string; count: number }>
  }> {
    try {
      const response = await apiClient.get(`/analysis/statistics?days=${days}`)
      return response.data
    } catch (error) {
      throw this.handleError(error)
    }
  }

  async compareAnalyses(analysisIds: string[]): Promise<{
    analyses: AnalysisResults[]
    comparison: {
      common_iocs: IOC[]
      common_techniques: MitreTechnique[]
      similarity_score: number
      differences: string[]
    }
  }> {
    try {
      const response = await apiClient.post('/analysis/compare', {
        analysis_ids: analysisIds
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
        error: 'AnalysisTimeout',
        message: 'Analysis request timed out. Please try again.',
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

export const analysisService = new AnalysisService()