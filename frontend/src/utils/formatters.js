import { FILE_CATEGORIES, SEVERITY_LEVELS, IOC_TYPES } from './constants';

/**
 * Format bytes to human readable string
 * @param {number} bytes - Number of bytes
 * @param {number} decimals - Number of decimal places
 * @returns {string} Formatted string
 */
export const formatBytes = (bytes, decimals = 2) => {
  if (bytes === 0) return '0 Bytes';
  if (!bytes || bytes < 0) return 'Unknown';

  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB'];

  const i = Math.floor(Math.log(bytes) / Math.log(k));
  const size = parseFloat((bytes / Math.pow(k, i)).toFixed(dm));

  return `${size} ${sizes[i]}`;
};

/**
 * Format date/time to readable string
 * @param {string|Date|number} date - Date to format
 * @param {Object} options - Formatting options
 * @returns {string} Formatted date string
 */
export const formatDateTime = (date, options = {}) => {
  if (!date) return 'N/A';

  const d = new Date(date);
  if (isNaN(d.getTime())) return 'Invalid Date';

  const {
    format = 'full',
    timezone = 'local',
    relative = false
  } = options;

  // Relative time formatting
  if (relative) {
    return formatRelativeTime(d);
  }

  // Format options
  const formatOptions = {
    short: {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    },
    medium: {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    },
    full: {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    },
    date: {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    },
    time: {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    }
  };

  const selectedFormat = formatOptions[format] || formatOptions.full;

  if (timezone === 'utc') {
    selectedFormat.timeZone = 'UTC';
  }

  return d.toLocaleString('en-US', selectedFormat);
};

/**
 * Format relative time
 * @param {Date} date - Date to format
 * @returns {string} Relative time string
 */
export const formatRelativeTime = (date) => {
  const now = new Date();
  const diffMs = now - date;
  const diffSec = Math.floor(diffMs / 1000);
  const diffMin = Math.floor(diffSec / 60);
  const diffHour = Math.floor(diffMin / 60);
  const diffDay = Math.floor(diffHour / 24);

  if (diffSec < 60) {
    return 'just now';
  } else if (diffMin < 60) {
    return `${diffMin} minute${diffMin !== 1 ? 's' : ''} ago`;
  } else if (diffHour < 24) {
    return `${diffHour} hour${diffHour !== 1 ? 's' : ''} ago`;
  } else if (diffDay < 7) {
    return `${diffDay} day${diffDay !== 1 ? 's' : ''} ago`;
  } else if (diffDay < 30) {
    const weeks = Math.floor(diffDay / 7);
    return `${weeks} week${weeks !== 1 ? 's' : ''} ago`;
  } else if (diffDay < 365) {
    const months = Math.floor(diffDay / 30);
    return `${months} month${months !== 1 ? 's' : ''} ago`;
  } else {
    const years = Math.floor(diffDay / 365);
    return `${years} year${years !== 1 ? 's' : ''} ago`;
  }
};

/**
 * Format duration in seconds to readable string
 * @param {number} seconds - Duration in seconds
 * @returns {string} Formatted duration
 */
export const formatDuration = (seconds) => {
  if (!seconds || seconds < 0) return '0s';

  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = Math.floor(seconds % 60);

  const parts = [];
  if (hours > 0) parts.push(`${hours}h`);
  if (minutes > 0) parts.push(`${minutes}m`);
  if (secs > 0 || parts.length === 0) parts.push(`${secs}s`);

  return parts.join(' ');
};

/**
 * Format number with commas
 * @param {number} num - Number to format
 * @param {number} decimals - Decimal places
 * @returns {string} Formatted number
 */
export const formatNumber = (num, decimals = 0) => {
  if (num === null || num === undefined) return '0';
  
  return new Intl.NumberFormat('en-US', {
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals
  }).format(num);
};

/**
 * Format percentage
 * @param {number} value - Value to format
 * @param {number} decimals - Decimal places
 * @returns {string} Formatted percentage
 */
export const formatPercentage = (value, decimals = 1) => {
  if (value === null || value === undefined) return '0%';
  return `${(value * 100).toFixed(decimals)}%`;
};

/**
 * Get file icon based on filename/extension
 * @param {string} filename - File name
 * @returns {string} Icon emoji
 */
export const getFileIcon = (filename) => {
  if (!filename) return '📄';

  const ext = filename.toLowerCase().substring(filename.lastIndexOf('.'));
  
  for (const [category, config] of Object.entries(FILE_CATEGORIES)) {
    if (config.extensions.includes(ext)) {
      return config.icon;
    }
  }

  // Special cases
  if (filename.toLowerCase().includes('log')) return '📄';
  if (filename.toLowerCase().includes('dump')) return '💾';
  
  return '📎';
};

/**
 * Get file category based on extension
 * @param {string} filename - File name
 * @returns {Object} Category info
 */
export const getFileCategory = (filename) => {
  if (!filename) return { name: 'Unknown', color: 'gray' };

  const ext = filename.toLowerCase().substring(filename.lastIndexOf('.'));
  
  for (const [key, config] of Object.entries(FILE_CATEGORIES)) {
    if (config.extensions.includes(ext)) {
      return config;
    }
  }

  return { name: 'Other', color: 'gray', icon: '📎' };
};

/**
 * Get severity color
 * @param {string} severity - Severity level
 * @returns {string} Color class
 */
export const getSeverityColor = (severity) => {
  const level = SEVERITY_LEVELS[severity?.toUpperCase()];
  return level ? level.color : 'gray';
};

/**
 * Get severity weight
 * @param {string} severity - Severity level
 * @returns {number} Severity weight
 */
export const getSeverityWeight = (severity) => {
  const level = SEVERITY_LEVELS[severity?.toUpperCase()];
  return level ? level.weight : 0;
};

/**
 * Truncate string with ellipsis
 * @param {string} str - String to truncate
 * @param {number} length - Max length
 * @returns {string} Truncated string
 */
export const truncate = (str, length = 50) => {
  if (!str) return '';
  if (str.length <= length) return str;
  return str.substring(0, length) + '...';
};

/**
 * Format file path for display
 * @param {string} path - File path
 * @param {number} maxLength - Max display length
 * @returns {string} Formatted path
 */
export const formatFilePath = (path, maxLength = 50) => {
  if (!path) return '';
  if (path.length <= maxLength) return path;

  const parts = path.split(/[/\\]/);
  const filename = parts[parts.length - 1];
  
  if (filename.length >= maxLength) {
    return '.../' + truncate(filename, maxLength - 4);
  }

  let result = filename;
  for (let i = parts.length - 2; i >= 0; i--) {
    const newResult = parts[i] + '/' + result;
    if (newResult.length > maxLength) {
      return '.../' + result;
    }
    result = newResult;
  }

  return result;
};

/**
 * Format IOC value for display
 * @param {string} value - IOC value
 * @param {string} type - IOC type
 * @returns {string} Formatted value
 */
export const formatIOC = (value, type) => {
  if (!value) return '';

  switch (type) {
    case 'ip':
      return value;
    case 'domain':
      return value.toLowerCase();
    case 'url':
      return truncate(value, 80);
    case 'email':
      return value.toLowerCase();
    case 'md5':
    case 'sha1':
    case 'sha256':
      return value.toUpperCase();
    case 'file_path':
      return formatFilePath(value);
    default:
      return value;
  }
};

/**
 * Get IOC type icon
 * @param {string} type - IOC type
 * @returns {string} Icon emoji
 */
export const getIOCIcon = (type) => {
  const iocType = IOC_TYPES[type?.toUpperCase()];
  return iocType ? iocType.icon : '🔍';
};

/**
 * Format threat score
 * @param {number} score - Threat score (0-100)
 * @returns {Object} Formatted score with color
 */
export const formatThreatScore = (score) => {
  if (score === null || score === undefined) {
    return { value: 'N/A', color: 'gray', level: 'unknown' };
  }

  const numScore = Number(score);
  
  if (numScore >= 80) {
    return { value: numScore, color: 'red', level: 'critical' };
  } else if (numScore >= 60) {
    return { value: numScore, color: 'orange', level: 'high' };
  } else if (numScore >= 40) {
    return { value: numScore, color: 'yellow', level: 'medium' };
  } else if (numScore >= 20) {
    return { value: numScore, color: 'blue', level: 'low' };
  } else {
    return { value: numScore, color: 'green', level: 'safe' };
  }
};

/**
 * Format analysis status
 * @param {string} status - Analysis status
 * @returns {Object} Status with color and icon
 */
export const formatAnalysisStatus = (status) => {
  const statusMap = {
    pending: { color: 'gray', icon: '⏳', label: 'Pending' },
    queued: { color: 'blue', icon: '📋', label: 'Queued' },
    processing: { color: 'yellow', icon: '⚡', label: 'Processing' },
    completed: { color: 'green', icon: '✅', label: 'Completed' },
    error: { color: 'red', icon: '❌', label: 'Error' },
    cancelled: { color: 'gray', icon: '🚫', label: 'Cancelled' }
  };

  return statusMap[status] || statusMap.pending;
};

/**
 * Pluralize word
 * @param {number} count - Count
 * @param {string} singular - Singular form
 * @param {string} plural - Plural form (optional)
 * @returns {string} Pluralized string
 */
export const pluralize = (count, singular, plural = null) => {
  if (count === 1) return `${count} ${singular}`;
  return `${count} ${plural || singular + 's'}`;
};

/**
 * Format error message
 * @param {Error|string} error - Error object or message
 * @returns {string} Formatted error message
 */
export const formatError = (error) => {
  if (typeof error === 'string') return error;
  if (error.message) return error.message;
  if (error.error) return error.error;
  return 'An unknown error occurred';
};

/**
 * Generate unique ID
 * @returns {string} Unique ID
 */
export const generateId = () => {
  return Date.now().toString(36) + Math.random().toString(36).substr(2);
};

/**
 * Format list as string
 * @param {Array} items - Array of items
 * @param {string} conjunction - Conjunction word (and/or)
 * @returns {string} Formatted list
 */
export const formatList = (items, conjunction = 'and') => {
  if (!items || items.length === 0) return '';
  if (items.length === 1) return items[0];
  if (items.length === 2) return `${items[0]} ${conjunction} ${items[1]}`;
  
  const lastItem = items[items.length - 1];
  const otherItems = items.slice(0, -1);
  return `${otherItems.join(', ')}, ${conjunction} ${lastItem}`;
};