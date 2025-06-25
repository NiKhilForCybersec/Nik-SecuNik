// API Configuration
export const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';
export const WS_BASE_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8000/ws';

// File Upload Constants
export const MAX_FILE_SIZE = 500 * 1024 * 1024; // 500MB
export const MAX_FILES_PER_UPLOAD = 10;
export const CHUNK_SIZE = 1024 * 1024; // 1MB chunks for large file uploads

// Supported File Types
export const FILE_CATEGORIES = {
  logs: {
    name: 'Log Files',
    extensions: ['.log', '.txt', '.syslog', '.out'],
    icon: '📄',
    color: 'blue'
  },
  windows: {
    name: 'Windows Logs',
    extensions: ['.evtx', '.evt', '.etl'],
    icon: '🪟',
    color: 'cyan'
  },
  network: {
    name: 'Network Captures',
    extensions: ['.pcap', '.pcapng', '.cap', '.dmp'],
    icon: '🌐',
    color: 'green'
  },
  forensics: {
    name: 'Forensic Images',
    extensions: ['.dd', '.e01', '.aff', '.raw', '.img'],
    icon: '🔍',
    color: 'purple'
  },
  archives: {
    name: 'Archives',
    extensions: ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2'],
    icon: '📦',
    color: 'orange'
  },
  documents: {
    name: 'Documents',
    extensions: ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'],
    icon: '📋',
    color: 'red'
  },
  email: {
    name: 'Email',
    extensions: ['.eml', '.msg', '.mbox', '.pst', '.ost'],
    icon: '📧',
    color: 'yellow'
  },
  structured: {
    name: 'Structured Data',
    extensions: ['.json', '.xml', '.csv', '.yaml', '.yml'],
    icon: '📊',
    color: 'indigo'
  },
  database: {
    name: 'Databases',
    extensions: ['.db', '.sqlite', '.sql', '.mdb'],
    icon: '🗄️',
    color: 'pink'
  },
  mobile: {
    name: 'Mobile',
    extensions: ['.logcat', '.ios', '.backup'],
    icon: '📱',
    color: 'teal'
  }
};

// Analysis Status
export const ANALYSIS_STATUS = {
  PENDING: 'pending',
  QUEUED: 'queued',
  PROCESSING: 'processing',
  COMPLETED: 'completed',
  ERROR: 'error',
  CANCELLED: 'cancelled'
};

// Analysis Stages
export const ANALYSIS_STAGES = [
  { id: 'upload', label: 'Upload', icon: '📤' },
  { id: 'parse', label: 'Parse', icon: '🔍' },
  { id: 'extract', label: 'Extract IOCs', icon: '🎯' },
  { id: 'analyze', label: 'Analyze', icon: '🧪' },
  { id: 'detect', label: 'Detect Threats', icon: '🛡️' },
  { id: 'report', label: 'Generate Report', icon: '📊' }
];

// Severity Levels
export const SEVERITY_LEVELS = {
  CRITICAL: {
    value: 'critical',
    label: 'Critical',
    color: 'red',
    weight: 10
  },
  HIGH: {
    value: 'high',
    label: 'High',
    color: 'orange',
    weight: 7
  },
  MEDIUM: {
    value: 'medium',
    label: 'Medium',
    color: 'yellow',
    weight: 4
  },
  LOW: {
    value: 'low',
    label: 'Low',
    color: 'green',
    weight: 1
  },
  INFO: {
    value: 'info',
    label: 'Info',
    color: 'blue',
    weight: 0
  }
};

// IOC Types
export const IOC_TYPES = {
  IP: {
    value: 'ip',
    label: 'IP Address',
    pattern: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
    icon: '🌐'
  },
  DOMAIN: {
    value: 'domain',
    label: 'Domain',
    pattern: /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/,
    icon: '🏛️'
  },
  URL: {
    value: 'url',
    label: 'URL',
    pattern: /^https?:\/\/.+/,
    icon: '🔗'
  },
  EMAIL: {
    value: 'email',
    label: 'Email',
    pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
    icon: '📧'
  },
  MD5: {
    value: 'md5',
    label: 'MD5 Hash',
    pattern: /^[a-fA-F0-9]{32}$/,
    icon: '#️⃣'
  },
  SHA1: {
    value: 'sha1',
    label: 'SHA1 Hash',
    pattern: /^[a-fA-F0-9]{40}$/,
    icon: '#️⃣'
  },
  SHA256: {
    value: 'sha256',
    label: 'SHA256 Hash',
    pattern: /^[a-fA-F0-9]{64}$/,
    icon: '#️⃣'
  },
  FILE_PATH: {
    value: 'file_path',
    label: 'File Path',
    pattern: /^.+$/,
    icon: '📁'
  },
  REGISTRY: {
    value: 'registry',
    label: 'Registry Key',
    pattern: /^HKEY_.+/,
    icon: '🗝️'
  }
};

// Rule Types
export const RULE_TYPES = {
  YARA: {
    value: 'yara',
    label: 'YARA',
    extension: '.yar',
    icon: '🛡️'
  },
  SIGMA: {
    value: 'sigma',
    label: 'Sigma',
    extension: '.yml',
    icon: '🎯'
  },
  CUSTOM: {
    value: 'custom',
    label: 'Custom',
    extension: '.json',
    icon: '⚡'
  }
};

// Time Ranges
export const TIME_RANGES = [
  { value: '1h', label: 'Last Hour' },
  { value: '24h', label: 'Last 24 Hours' },
  { value: '7d', label: 'Last 7 Days' },
  { value: '30d', label: 'Last 30 Days' },
  { value: '90d', label: 'Last 90 Days' },
  { value: 'custom', label: 'Custom Range' }
];

// Export Formats
export const EXPORT_FORMATS = [
  { value: 'json', label: 'JSON', icon: '📄' },
  { value: 'csv', label: 'CSV', icon: '📊' },
  { value: 'pdf', label: 'PDF', icon: '📑' },
  { value: 'html', label: 'HTML', icon: '🌐' }
];

// Chart Colors
export const CHART_COLORS = {
  primary: '#06b6d4', // cyan-500
  secondary: '#8b5cf6', // violet-500
  success: '#10b981', // emerald-500
  warning: '#f59e0b', // amber-500
  danger: '#ef4444', // red-500
  info: '#3b82f6', // blue-500
  dark: '#1f2937', // gray-800
  light: '#f3f4f6' // gray-100
};

// Notification Types
export const NOTIFICATION_TYPES = {
  SUCCESS: {
    value: 'success',
    icon: '✅',
    color: 'green'
  },
  ERROR: {
    value: 'error',
    icon: '❌',
    color: 'red'
  },
  WARNING: {
    value: 'warning',
    icon: '⚠️',
    color: 'yellow'
  },
  INFO: {
    value: 'info',
    icon: 'ℹ️',
    color: 'blue'
  }
};

// Pagination
export const PAGINATION = {
  DEFAULT_PAGE_SIZE: 20,
  PAGE_SIZE_OPTIONS: [10, 20, 50, 100],
  MAX_PAGE_SIZE: 100
};

// WebSocket Events
export const WS_EVENTS = {
  CONNECT: 'connect',
  DISCONNECT: 'disconnect',
  ERROR: 'error',
  ANALYSIS_PROGRESS: 'analysis:progress',
  ANALYSIS_COMPLETE: 'analysis:complete',
  ANALYSIS_ERROR: 'analysis:error',
  NOTIFICATION: 'notification'
};

// Local Storage Keys
export const STORAGE_KEYS = {
  THEME: 'secunik_theme',
  SIDEBAR_COLLAPSED: 'secunik_sidebar_collapsed',
  VIEW_PREFERENCES: 'secunik_view_preferences',
  RECENT_SEARCHES: 'secunik_recent_searches'
};

// Keyboard Shortcuts
export const SHORTCUTS = {
  NEW_UPLOAD: 'cmd+u, ctrl+u',
  SEARCH: 'cmd+k, ctrl+k',
  TOGGLE_SIDEBAR: 'cmd+b, ctrl+b',
  EXPORT: 'cmd+e, ctrl+e',
  HELP: 'cmd+/, ctrl+/'
};

// API Endpoints
export const API_ENDPOINTS = {
  // Upload
  UPLOAD_FILE: '/upload/file',
  UPLOAD_MULTIPLE: '/upload/multiple',
  UPLOAD_FORMATS: '/upload/supported-formats',
  
  // Analysis
  ANALYZE: '/analyze',
  ANALYSIS_STATUS: '/analyze/status',
  ANALYSIS_RESULT: '/analyze/result',
  ANALYSIS_EXPORT: '/analyze/export',
  
  // History
  HISTORY: '/history',
  HISTORY_EXPORT: '/history/export',
  HISTORY_TIMELINE: '/history/timeline/events',
  
  // Rules
  RULES: '/rules',
  RULES_VALIDATE: '/rules/validate',
  RULES_IMPORT: '/rules/import',
  RULES_EXPORT: '/rules/export',
  
  // VirusTotal
  VT_SCAN: '/virustotal/scan',
  VT_REPORT: '/virustotal/report',
  VT_QUOTA: '/virustotal/quota',
  
  // Settings
  SETTINGS: '/settings',
  SETTINGS_WEBHOOK: '/settings/test-webhook',
  SETTINGS_STORAGE: '/settings/clear-storage'
};

// Error Messages
export const ERROR_MESSAGES = {
  GENERIC: 'An error occurred. Please try again.',
  NETWORK: 'Network error. Please check your connection.',
  UNAUTHORIZED: 'You are not authorized to perform this action.',
  NOT_FOUND: 'The requested resource was not found.',
  FILE_TOO_LARGE: 'File size exceeds the maximum limit.',
  INVALID_FILE_TYPE: 'Invalid file type.',
  ANALYSIS_FAILED: 'Analysis failed. Please try again.',
  RULE_INVALID: 'Invalid rule syntax.',
  API_KEY_INVALID: 'Invalid API key.',
  QUOTA_EXCEEDED: 'API quota exceeded. Please try again later.'
};

// Success Messages
export const SUCCESS_MESSAGES = {
  FILE_UPLOADED: 'File uploaded successfully.',
  ANALYSIS_STARTED: 'Analysis started.',
  ANALYSIS_COMPLETE: 'Analysis completed successfully.',
  RULE_CREATED: 'Rule created successfully.',
  RULE_UPDATED: 'Rule updated successfully.',
  RULE_DELETED: 'Rule deleted successfully.',
  SETTINGS_SAVED: 'Settings saved successfully.',
  EXPORT_COMPLETE: 'Export completed successfully.'
};

// Default Settings
export const DEFAULT_SETTINGS = {
  theme: 'dark',
  notifications: {
    enabled: true,
    sound: false,
    desktop: false,
    email: false
  },
  analysis: {
    autoStart: true,
    deepScan: false,
    extractIOCs: true,
    runYara: true,
    runSigma: true,
    aiAnalysis: false
  },
  display: {
    dateFormat: 'YYYY-MM-DD HH:mm:ss',
    timezone: 'local',
    pageSize: 20
  }
};