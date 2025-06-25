// API Configuration
export const API_CONFIG = {
  MAX_FILE_SIZE: parseInt(import.meta.env.VITE_MAX_FILE_SIZE) || 1073741824, // 1GB
  ALLOWED_FILE_TYPES: import.meta.env.VITE_ALLOWED_FILE_TYPES?.split(',') || [
    // Log files
    '.log', '.txt', '.syslog',
    // Network captures
    '.pcap', '.pcapng', '.cap',
    // Archives
    '.zip', '.rar', '.7z', '.tar', '.gz',
    // Email files
    '.eml', '.msg', '.mbox',
    // System files
    '.evt', '.evtx', '.reg',
    // Database files
    '.sql', '.db', '.sqlite',
    // Structured data
    '.json', '.xml', '.csv', '.yaml', '.yml',
    // Documents
    '.pdf', '.doc', '.docx', '.xls', '.xlsx',
    // Code files
    '.js', '.py', '.sh', '.ps1', '.bat',
    // Binary files
    '.exe', '.dll', '.so'
  ],
  UPLOAD_CHUNK_SIZE: parseInt(import.meta.env.VITE_CHUNK_SIZE) || 1024 * 1024, // 1MB chunks
  MAX_CONCURRENT_UPLOADS: 3
}

// Analysis Configuration
export const ANALYSIS_CONFIG = {
  ANALYZERS: {
    YARA: 'yara',
    SIGMA: 'sigma',
    MITRE: 'mitre',
    AI: 'ai',
    IOC: 'ioc',
    PATTERN: 'pattern'
  },
  PRIORITIES: {
    LOW: 'low',
    NORMAL: 'normal',
    HIGH: 'high'
  },
  STATUSES: {
    QUEUED: 'queued',
    PROCESSING: 'processing',
    COMPLETED: 'completed',
    FAILED: 'failed',
    CANCELLED: 'cancelled'
  }
}

// Threat Levels
export const THREAT_LEVELS = {
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical'
}

// Rule Types
export const RULE_TYPES = {
  YARA: 'yara',
  SIGMA: 'sigma',
  CUSTOM: 'custom'
}

// File Type Categories
export const FILE_CATEGORIES = {
  LOGS: 'logs',
  NETWORK: 'network',
  SYSTEM: 'system',
  EMAIL: 'email',
  DOCUMENTS: 'documents',
  ARCHIVES: 'archives',
  CODE: 'code',
  DATABASE: 'database',
  FORENSICS: 'forensics',
  MOBILE: 'mobile',
  CLOUD: 'cloud'
}

// WebSocket Events
export const WS_EVENTS = {
  ANALYSIS_PROGRESS: 'analysis_progress',
  ANALYSIS_COMPLETE: 'analysis_complete',
  ANALYSIS_ERROR: 'analysis_error',
  SYSTEM_STATUS: 'system_status',
  THREAT_ALERT: 'threat_alert'
}

// UI Constants
export const UI_CONFIG = {
  ITEMS_PER_PAGE: parseInt(import.meta.env.VITE_ITEMS_PER_PAGE) || 20,
  DEBOUNCE_DELAY: parseInt(import.meta.env.VITE_DEBOUNCE_DELAY) || 300,
  TOAST_DURATION: parseInt(import.meta.env.VITE_TOAST_DURATION) || 4000,
  ANIMATION_DURATION: parseInt(import.meta.env.VITE_ANIMATION_DURATION) || 300
}

// Color Schemes
export const COLORS = {
  THREAT_LEVELS: {
    low: 'text-green-400 bg-green-900/30',
    medium: 'text-yellow-400 bg-yellow-900/30',
    high: 'text-orange-400 bg-orange-900/30',
    critical: 'text-red-400 bg-red-900/30'
  },
  STATUS: {
    queued: 'text-blue-400 bg-blue-900/30',
    processing: 'text-yellow-400 bg-yellow-900/30',
    completed: 'text-green-400 bg-green-900/30',
    failed: 'text-red-400 bg-red-900/30',
    cancelled: 'text-gray-400 bg-gray-900/30'
  },
  SEVERITY: {
    info: 'text-blue-400 bg-blue-900/30',
    low: 'text-green-400 bg-green-900/30',
    medium: 'text-yellow-400 bg-yellow-900/30',
    high: 'text-orange-400 bg-orange-900/30',
    critical: 'text-red-400 bg-red-900/30'
  }
}

// MITRE ATT&CK Tactics
export const MITRE_TACTICS = {
  'initial-access': 'Initial Access',
  'execution': 'Execution',
  'persistence': 'Persistence',
  'privilege-escalation': 'Privilege Escalation',
  'defense-evasion': 'Defense Evasion',
  'credential-access': 'Credential Access',
  'discovery': 'Discovery',
  'lateral-movement': 'Lateral Movement',
  'collection': 'Collection',
  'command-and-control': 'Command and Control',
  'exfiltration': 'Exfiltration',
  'impact': 'Impact'
}

// IOC Types
export const IOC_TYPES = {
  IP: 'ip_address',
  DOMAIN: 'domain',
  URL: 'url',
  HASH: 'hash',
  EMAIL: 'email',
  FILE_PATH: 'file_path',
  REGISTRY_KEY: 'registry_key',
  MUTEX: 'mutex',
  USER_AGENT: 'user_agent'
}

// Export formats
export const EXPORT_FORMATS = {
  JSON: 'json',
  CSV: 'csv',
  PDF: 'pdf',
  XML: 'xml'
}