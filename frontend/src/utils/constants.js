// API endpoints
export const API_ENDPOINTS = {
  // Upload
  UPLOAD: '/upload',
  UPLOAD_FILE: '/upload/file',
  UPLOAD_BATCH: '/upload/batch',
  UPLOAD_STATUS: '/upload/status',
  SUPPORTED_FORMATS: '/upload/supported-formats',
  
  // Analysis
  ANALYSIS: '/analysis',
  ANALYSIS_START: '/analysis/start',
  ANALYSIS_STATUS: '/analysis/status',
  ANALYSIS_RESULTS: '/analysis/results',
  ANALYSIS_EXPORT: '/analysis/export',
  
  // History
  HISTORY: '/history',
  HISTORY_SEARCH: '/history/search',
  HISTORY_DELETE: '/history/delete',
  
  // Rules
  RULES: '/rules',
  RULES_IMPORT: '/rules/import',
  RULES_EXPORT: '/rules/export',
  RULES_TEST: '/rules/test',
  RULES_SYNC: '/rules/sync',
  
  // VirusTotal
  VT_SCAN: '/virustotal/scan',
  VT_REPORT: '/virustotal/report',
  
  // WebSocket
  WS_ANALYSIS: '/ws/analysis',
};

// File size limits
export const FILE_SIZE = {
  MAX_UPLOAD: 500 * 1024 * 1024, // 500MB
  MAX_BATCH: 2 * 1024 * 1024 * 1024, // 2GB
  CHUNK_SIZE: 10 * 1024 * 1024, // 10MB chunks
};

// Analysis stages
export const ANALYSIS_STAGES = {
  UPLOADED: 'uploaded',
  PARSING: 'parsing',
  ANALYZING: 'analyzing',
  ENRICHING: 'enriching',
  COMPLETE: 'complete',
  ERROR: 'error',
};

// Rule types
export const RULE_TYPES = {
  YARA: 'yara',
  SIGMA: 'sigma',
  CUSTOM: 'custom',
  COMMUNITY: 'community',
};

// Severity levels
export const SEVERITY_LEVELS = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFO: 'info',
};

// WebSocket events
export const WS_EVENTS = {
  CONNECT: 'connect',
  DISCONNECT: 'disconnect',
  ANALYSIS_UPDATE: 'analysis_update',
  ANALYSIS_COMPLETE: 'analysis_complete',
  ANALYSIS_ERROR: 'analysis_error',
  NOTIFICATION: 'notification',
};

// Storage keys
export const STORAGE_KEYS = {
  AUTH_TOKEN: 'auth_token',
  THEME: 'theme',
  PREFERENCES: 'user_preferences',
  RECENT_SEARCHES: 'recent_searches',
};

// Pagination defaults
export const PAGINATION = {
  DEFAULT_PAGE_SIZE: 20,
  PAGE_SIZE_OPTIONS: [10, 20, 50, 100],
};

// Toast messages
export const TOAST_MESSAGES = {
  UPLOAD_SUCCESS: 'File uploaded successfully',
  UPLOAD_ERROR: 'Failed to upload file',
  ANALYSIS_STARTED: 'Analysis started',
  ANALYSIS_COMPLETE: 'Analysis completed',
  RULE_SAVED: 'Rule saved successfully',
  RULE_DELETED: 'Rule deleted successfully',
  EXPORT_SUCCESS: 'Export completed',
  EXPORT_ERROR: 'Export failed',
};