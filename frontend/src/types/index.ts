// API Response Types
export interface ApiResponse<T = any> {
  data?: T
  error?: string
  message?: string
  status_code?: number
}

export interface PaginatedResponse<T> {
  items: T[]
  total: number
  limit: number
  offset: number
  has_more: boolean
}

// File Upload Types
export interface UploadedFile {
  id: string
  filename: string
  file_size: number
  file_type: string
  upload_time: string
  status: 'uploading' | 'parsing' | 'parsed' | 'failed'
  parse_result?: ParseResult
  tags?: string[]
  metadata?: Record<string, any>
}

export interface ParseResult {
  parser_used: string
  entries_count: number
  parse_time: number
  errors: string[]
  warnings: string[]
}

// Analysis Types
export interface Analysis {
  id: string
  upload_id: string
  status: 'queued' | 'processing' | 'completed' | 'failed' | 'cancelled'
  progress: number
  start_time: string
  end_time?: string
  analyzers: string[]
  results?: AnalysisResults
  error?: string
}

export interface AnalysisResults {
  upload_id: string
  filename: string
  file_type: string
  analysis_time: string
  threat_score: number
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical'
  summary: string
  findings: Finding[]
  iocs: IOC[]
  mitre_techniques: MitreTechnique[]
  recommendations: string[]
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

export interface MitreTechnique {
  technique_id: string
  technique_name: string
  tactic: string
  description: string
  confidence: number
  evidence: string[]
}

// Rule Types
export interface Rule {
  id: string
  name: string
  type: 'yara' | 'sigma' | 'custom'
  category: string
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical'
  description: string
  content: string
  tags: string[]
  enabled: boolean
  created_at: string
  updated_at: string
  author?: string
  references?: string[]
  false_positives?: string[]
  mitre_attack?: string[]
}

// History Types
export interface HistoryEntry {
  id: string
  upload_id: string
  filename: string
  file_type: string
  file_size: number
  analysis_time: string
  threat_score: number
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical'
  findings_count: number
  iocs_count: number
  mitre_techniques: string[]
  tags?: string[]
  notes?: string
}

// System Types
export interface SystemStatus {
  status: 'healthy' | 'degraded' | 'down'
  version: string
  uptime: number
  services: ServiceStatus[]
  stats: SystemStats
}

export interface ServiceStatus {
  name: string
  status: 'online' | 'offline' | 'error'
  latency?: number
  error?: string
}

export interface SystemStats {
  total_analyses: number
  active_analyses: number
  storage_used: number
  storage_total: number
  cpu_usage: number
  memory_usage: number
}

// WebSocket Types
export interface WebSocketMessage {
  type: string
  data: any
  timestamp: string
  id?: string
}

// User Settings
export interface UserSettings {
  theme: 'light' | 'dark' | 'auto'
  notifications: {
    email: boolean
    browser: boolean
    analysis_complete: boolean
    threat_detected: boolean
    system_alerts: boolean
  }
  analysis: {
    auto_analyze: boolean
    default_analyzers: string[]
    deep_scan: boolean
  }
  display: {
    items_per_page: number
    default_view: 'grid' | 'list'
    show_previews: boolean
  }
}