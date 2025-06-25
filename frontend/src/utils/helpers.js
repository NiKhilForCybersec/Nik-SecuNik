import { API_CONFIG, THREAT_LEVELS, COLORS } from './constants'

// File validation helpers
export const validateFile = (file) => {
  const errors = []
  
  // Check file size
  if (file.size > API_CONFIG.MAX_FILE_SIZE) {
    errors.push(`File size exceeds maximum limit of ${formatFileSize(API_CONFIG.MAX_FILE_SIZE)}`)
  }
  
  // Check file type
  const extension = getFileExtension(file.name)
  if (!API_CONFIG.ALLOWED_FILE_TYPES.includes(extension)) {
    errors.push(`File type ${extension} is not supported`)
  }
  
  return {
    isValid: errors.length === 0,
    errors
  }
}

export const getFileExtension = (filename) => {
  if (!filename) return ''
  const lastDot = filename.lastIndexOf('.')
  return lastDot !== -1 ? filename.substring(lastDot).toLowerCase() : ''
}

export const getFileType = (filename) => {
  const extension = getFileExtension(filename)
  
  const typeMap = {
    // Log files
    '.log': 'System Log',
    '.txt': 'Text File',
    '.syslog': 'Syslog',
    
    // Network captures
    '.pcap': 'Network Capture',
    '.pcapng': 'Network Capture',
    '.cap': 'Network Capture',
    
    // Archives
    '.zip': 'ZIP Archive',
    '.rar': 'RAR Archive',
    '.7z': '7-Zip Archive',
    '.tar': 'TAR Archive',
    '.gz': 'Gzip Archive',
    
    // Email files
    '.eml': 'Email Message',
    '.msg': 'Outlook Message',
    '.mbox': 'Mailbox Archive',
    
    // System files
    '.evt': 'Windows Event Log',
    '.evtx': 'Windows Event Log',
    '.reg': 'Registry File',
    
    // Database files
    '.sql': 'SQL Database',
    '.db': 'Database File',
    '.sqlite': 'SQLite Database',
    
    // Structured data
    '.json': 'JSON Data',
    '.xml': 'XML Data',
    '.csv': 'CSV Data',
    '.yaml': 'YAML Data',
    '.yml': 'YAML Data',
    
    // Documents
    '.pdf': 'PDF Document',
    '.doc': 'Word Document',
    '.docx': 'Word Document',
    '.xls': 'Excel Spreadsheet',
    '.xlsx': 'Excel Spreadsheet',
    
    // Code files
    '.js': 'JavaScript',
    '.py': 'Python Script',
    '.sh': 'Shell Script',
    '.ps1': 'PowerShell Script',
    '.bat': 'Batch File',
    
    // Binary files
    '.exe': 'Executable',
    '.dll': 'Dynamic Library',
    '.so': 'Shared Object'
  }
  
  return typeMap[extension] || 'Unknown'
}

// File size formatting
export const formatFileSize = (bytes) => {
  if (!bytes || bytes === 0) return '0 Bytes'
  
  const k = 1024
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

// Threat level helpers
export const getThreatLevelColor = (level) => {
  return COLORS.THREAT_LEVELS[level] || COLORS.THREAT_LEVELS.low
}

export const getThreatLevelScore = (level) => {
  const scores = {
    [THREAT_LEVELS.LOW]: 25,
    [THREAT_LEVELS.MEDIUM]: 50,
    [THREAT_LEVELS.HIGH]: 75,
    [THREAT_LEVELS.CRITICAL]: 100
  }
  return scores[level] || 0
}

export const getThreatLevelFromScore = (score) => {
  if (score >= 80) return THREAT_LEVELS.CRITICAL
  if (score >= 60) return THREAT_LEVELS.HIGH
  if (score >= 30) return THREAT_LEVELS.MEDIUM
  return THREAT_LEVELS.LOW
}

// Status helpers
export const getStatusColor = (status) => {
  return COLORS.STATUS[status] || COLORS.STATUS.queued
}

export const getSeverityColor = (severity) => {
  return COLORS.SEVERITY[severity] || COLORS.SEVERITY.info
}

// Hash generation
export const generateFileHash = async (file) => {
  try {
    const buffer = await file.arrayBuffer()
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
    return `sha256:${hashHex}`
  } catch (error) {
    console.error('Error generating file hash:', error)
    return null
  }
}

// URL helpers
export const isValidURL = (string) => {
  try {
    new URL(string)
    return true
  } catch (_) {
    return false
  }
}

export const extractDomain = (url) => {
  try {
    return new URL(url).hostname
  } catch (_) {
    return url
  }
}

// IP address helpers
export const isValidIPv4 = (ip) => {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/
  if (!ipv4Regex.test(ip)) return false
  
  const parts = ip.split('.')
  return parts.every(part => {
    const num = parseInt(part, 10)
    return num >= 0 && num <= 255
  })
}

export const isValidIPv6 = (ip) => {
  const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/
  return ipv6Regex.test(ip)
}

export const isValidIP = (ip) => {
  return isValidIPv4(ip) || isValidIPv6(ip)
}

// Hash helpers
export const isValidHash = (hash) => {
  const hashRegexes = {
    md5: /^[a-fA-F0-9]{32}$/,
    sha1: /^[a-fA-F0-9]{40}$/,
    sha256: /^[a-fA-F0-9]{64}$/,
    sha512: /^[a-fA-F0-9]{128}$/
  }
  
  return Object.values(hashRegexes).some(regex => regex.test(hash))
}

export const getHashType = (hash) => {
  const hashTypes = {
    32: 'MD5',
    40: 'SHA1',
    64: 'SHA256',
    128: 'SHA512'
  }
  
  return hashTypes[hash.length] || 'Unknown'
}

// Array helpers
export const chunk = (array, size) => {
  const chunks = []
  for (let i = 0; i < array.length; i += size) {
    chunks.push(array.slice(i, i + size))
  }
  return chunks
}

export const unique = (array, key = null) => {
  if (key) {
    const seen = new Set()
    return array.filter(item => {
      const value = item[key]
      if (seen.has(value)) {
        return false
      }
      seen.add(value)
      return true
    })
  }
  return [...new Set(array)]
}

// Debounce helper
export const debounce = (func, wait) => {
  let timeout
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout)
      func(...args)
    }
    clearTimeout(timeout)
    timeout = setTimeout(later, wait)
  }
}

// Throttle helper
export const throttle = (func, limit) => {
  let inThrottle
  return function() {
    const args = arguments
    const context = this
    if (!inThrottle) {
      func.apply(context, args)
      inThrottle = true
      setTimeout(() => inThrottle = false, limit)
    }
  }
}

// Local storage helpers
export const setLocalStorage = (key, value) => {
  try {
    localStorage.setItem(key, JSON.stringify(value))
    return true
  } catch (error) {
    console.error('Error setting localStorage:', error)
    return false
  }
}

export const getLocalStorage = (key, defaultValue = null) => {
  try {
    const item = localStorage.getItem(key)
    return item ? JSON.parse(item) : defaultValue
  } catch (error) {
    console.error('Error getting localStorage:', error)
    return defaultValue
  }
}

export const removeLocalStorage = (key) => {
  try {
    localStorage.removeItem(key)
    return true
  } catch (error) {
    console.error('Error removing localStorage:', error)
    return false
  }
}

// Download helpers
export const downloadFile = (data, filename, type = 'application/json') => {
  const blob = new Blob([data], { type })
  const url = window.URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  window.URL.revokeObjectURL(url)
}

export const downloadJSON = (data, filename) => {
  const jsonString = JSON.stringify(data, null, 2)
  downloadFile(jsonString, filename, 'application/json')
}

export const downloadCSV = (data, filename) => {
  if (!Array.isArray(data) || data.length === 0) return
  
  const headers = Object.keys(data[0])
  const csvContent = [
    headers.join(','),
    ...data.map(row => headers.map(header => `"${row[header] || ''}"`).join(','))
  ].join('\n')
  
  downloadFile(csvContent, filename, 'text/csv')
}

// Error handling helpers
export const handleApiError = (error) => {
  if (error.response?.data) {
    return {
      message: error.response.data.message || 'An error occurred',
      details: error.response.data.details || {},
      status: error.response.status
    }
  }
  
  if (error.request) {
    return {
      message: 'Network error - please check your connection',
      details: {},
      status: 0
    }
  }
  
  return {
    message: error.message || 'An unexpected error occurred',
    details: {},
    status: 0
  }
}

// Copy to clipboard
export const copyToClipboard = async (text) => {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch (error) {
    console.error('Failed to copy to clipboard:', error)
    return false
  }
}

// Generate unique ID
export const generateId = () => {
  return Date.now().toString(36) + Math.random().toString(36).substr(2)
}

// Sleep helper
export const sleep = (ms) => {
  return new Promise(resolve => setTimeout(resolve, ms))
}