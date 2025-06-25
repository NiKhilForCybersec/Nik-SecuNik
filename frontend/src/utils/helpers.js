import { IOC_TYPES } from './constants';

/**
 * Debounce function
 * @param {Function} func - Function to debounce
 * @param {number} wait - Wait time in milliseconds
 * @returns {Function} Debounced function
 */
export const debounce = (func, wait = 300) => {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
};

/**
 * Throttle function
 * @param {Function} func - Function to throttle
 * @param {number} limit - Limit in milliseconds
 * @returns {Function} Throttled function
 */
export const throttle = (func, limit = 100) => {
  let inThrottle;
  return function(...args) {
    if (!inThrottle) {
      func.apply(this, args);
      inThrottle = true;
      setTimeout(() => inThrottle = false, limit);
    }
  };
};

/**
 * Deep clone object
 * @param {*} obj - Object to clone
 * @returns {*} Cloned object
 */
export const deepClone = (obj) => {
  if (obj === null || typeof obj !== 'object') return obj;
  if (obj instanceof Date) return new Date(obj.getTime());
  if (obj instanceof Array) return obj.map(item => deepClone(item));
  if (obj instanceof Object) {
    const clonedObj = {};
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        clonedObj[key] = deepClone(obj[key]);
      }
    }
    return clonedObj;
  }
};

/**
 * Deep merge objects
 * @param {Object} target - Target object
 * @param {Object} source - Source object
 * @returns {Object} Merged object
 */
export const deepMerge = (target, source) => {
  const output = { ...target };
  if (isObject(target) && isObject(source)) {
    Object.keys(source).forEach(key => {
      if (isObject(source[key])) {
        if (!(key in target)) {
          Object.assign(output, { [key]: source[key] });
        } else {
          output[key] = deepMerge(target[key], source[key]);
        }
      } else {
        Object.assign(output, { [key]: source[key] });
      }
    });
  }
  return output;
};

/**
 * Check if value is object
 * @param {*} item - Value to check
 * @returns {boolean} True if object
 */
export const isObject = (item) => {
  return item && typeof item === 'object' && !Array.isArray(item);
};

/**
 * Group array by key
 * @param {Array} array - Array to group
 * @param {string|Function} key - Key to group by
 * @returns {Object} Grouped object
 */
export const groupBy = (array, key) => {
  return array.reduce((result, item) => {
    const groupKey = typeof key === 'function' ? key(item) : item[key];
    if (!result[groupKey]) result[groupKey] = [];
    result[groupKey].push(item);
    return result;
  }, {});
};

/**
 * Sort array by multiple keys
 * @param {Array} array - Array to sort
 * @param {Array} keys - Keys to sort by
 * @returns {Array} Sorted array
 */
export const sortByMultiple = (array, keys) => {
  return array.sort((a, b) => {
    for (const key of keys) {
      const direction = key.startsWith('-') ? -1 : 1;
      const actualKey = key.replace(/^-/, '');
      
      if (a[actualKey] < b[actualKey]) return -1 * direction;
      if (a[actualKey] > b[actualKey]) return 1 * direction;
    }
    return 0;
  });
};

/**
 * Parse query string
 * @param {string} queryString - Query string to parse
 * @returns {Object} Parsed query object
 */
export const parseQueryString = (queryString) => {
  const params = new URLSearchParams(queryString);
  const result = {};
  for (const [key, value] of params) {
    result[key] = value;
  }
  return result;
};

/**
 * Build query string from object
 * @param {Object} params - Parameters object
 * @returns {string} Query string
 */
export const buildQueryString = (params) => {
  const searchParams = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      searchParams.append(key, value);
    }
  });
  return searchParams.toString();
};

/**
 * Download file
 * @param {Blob|string} data - File data
 * @param {string} filename - File name
 * @param {string} mimeType - MIME type
 */
export const downloadFile = (data, filename, mimeType = 'application/octet-stream') => {
  const blob = data instanceof Blob ? data : new Blob([data], { type: mimeType });
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  window.URL.revokeObjectURL(url);
};

/**
 * Copy text to clipboard
 * @param {string} text - Text to copy
 * @returns {Promise} Promise that resolves when copied
 */
export const copyToClipboard = async (text) => {
  if (navigator.clipboard) {
    return navigator.clipboard.writeText(text);
  }
  
  // Fallback for older browsers
  const textArea = document.createElement('textarea');
  textArea.value = text;
  textArea.style.position = 'fixed';
  textArea.style.left = '-999999px';
  document.body.appendChild(textArea);
  textArea.focus();
  textArea.select();
  
  try {
    document.execCommand('copy');
  } catch (err) {
    console.error('Failed to copy:', err);
    throw err;
  } finally {
    document.body.removeChild(textArea);
  }
};

/**
 * Generate random ID
 * @param {number} length - ID length
 * @returns {string} Random ID
 */
export const generateRandomId = (length = 8) => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
};

/**
 * Extract IOCs from text
 * @param {string} text - Text to extract IOCs from
 * @returns {Array} Array of extracted IOCs
 */
export const extractIOCs = (text) => {
  const iocs = [];
  
  // Extract IPs
  const ipRegex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
  const ips = text.match(ipRegex) || [];
  ips.forEach(ip => {
    iocs.push({ type: 'ip', value: ip });
  });
  
  // Extract domains
  const domainRegex = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi;
  const domains = text.match(domainRegex) || [];
  domains.forEach(domain => {
    // Filter out common false positives
    if (!domain.match(/\.(jpg|jpeg|png|gif|pdf|doc|docx|xls|xlsx)$/i)) {
      iocs.push({ type: 'domain', value: domain.toLowerCase() });
    }
  });
  
  // Extract URLs
  const urlRegex = /https?:\/\/[^\s<>"{}|\\^`\[\]]+/gi;
  const urls = text.match(urlRegex) || [];
  urls.forEach(url => {
    iocs.push({ type: 'url', value: url });
  });
  
  // Extract hashes
  const md5Regex = /\b[a-fA-F0-9]{32}\b/g;
  const sha1Regex = /\b[a-fA-F0-9]{40}\b/g;
  const sha256Regex = /\b[a-fA-F0-9]{64}\b/g;
  
  const md5s = text.match(md5Regex) || [];
  const sha1s = text.match(sha1Regex) || [];
  const sha256s = text.match(sha256Regex) || [];
  
  md5s.forEach(hash => iocs.push({ type: 'md5', value: hash.toUpperCase() }));
  sha1s.forEach(hash => iocs.push({ type: 'sha1', value: hash.toUpperCase() }));
  sha256s.forEach(hash => iocs.push({ type: 'sha256', value: hash.toUpperCase() }));
  
  // Extract emails
  const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
  const emails = text.match(emailRegex) || [];
  emails.forEach(email => {
    iocs.push({ type: 'email', value: email.toLowerCase() });
  });
  
  // Remove duplicates
  const uniqueIOCs = [];
  const seen = new Set();
  iocs.forEach(ioc => {
    const key = `${ioc.type}:${ioc.value}`;
    if (!seen.has(key)) {
      seen.add(key);
      uniqueIOCs.push(ioc);
    }
  });
  
  return uniqueIOCs;
};

/**
 * Validate IOC
 * @param {string} value - IOC value
 * @param {string} type - IOC type
 * @returns {boolean} True if valid
 */
export const validateIOC = (value, type) => {
  const iocType = IOC_TYPES[type?.toUpperCase()];
  if (!iocType || !iocType.pattern) return false;
  return iocType.pattern.test(value);
};

/**
 * Calculate file hash (SHA-256)
 * @param {File|Blob} file - File to hash
 * @returns {Promise<string>} Hash value
 */
export const calculateFileHash = async (file) => {
  const buffer = await file.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
};

/**
 * Parse CSV data
 * @param {string} csvText - CSV text
 * @param {Object} options - Parse options
 * @returns {Array} Parsed data
 */
export const parseCSV = (csvText, options = {}) => {
  const { delimiter = ',', hasHeaders = true } = options;
  const lines = csvText.split('\n').filter(line => line.trim());
  
  if (lines.length === 0) return [];
  
  const headers = hasHeaders ? lines[0].split(delimiter).map(h => h.trim()) : [];
  const startIndex = hasHeaders ? 1 : 0;
  
  return lines.slice(startIndex).map(line => {
    const values = line.split(delimiter).map(v => v.trim());
    
    if (hasHeaders) {
      const obj = {};
      headers.forEach((header, index) => {
        obj[header] = values[index] || '';
      });
      return obj;
    }
    
    return values;
  });
};

/**
 * Format error for display
 * @param {Error|string|Object} error - Error to format
 * @returns {string} Formatted error message
 */
export const formatErrorMessage = (error) => {
  if (typeof error === 'string') return error;
  
  if (error.response?.data?.message) return error.response.data.message;
  if (error.response?.data?.error) return error.response.data.error;
  if (error.message) return error.message;
  if (error.error) return error.error;
  
  return 'An unexpected error occurred';
};

/**
 * Retry function with exponential backoff
 * @param {Function} fn - Function to retry
 * @param {number} maxRetries - Maximum retries
 * @param {number} delay - Initial delay in ms
 * @returns {Promise} Result of function
 */
export const retryWithBackoff = async (fn, maxRetries = 3, delay = 1000) => {
  let lastError;
  
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      if (i < maxRetries - 1) {
        await new Promise(resolve => setTimeout(resolve, delay * Math.pow(2, i)));
      }
    }
  }
  
  throw lastError;
};

/**
 * Memoize function
 * @param {Function} fn - Function to memoize
 * @returns {Function} Memoized function
 */
export const memoize = (fn) => {
  const cache = new Map();
  
  return (...args) => {
    const key = JSON.stringify(args);
    if (cache.has(key)) {
      return cache.get(key);
    }
    
    const result = fn(...args);
    cache.set(key, result);
    return result;
  };
};

/**
 * Check if browser supports feature
 * @param {string} feature - Feature to check
 * @returns {boolean} True if supported
 */
export const isFeatureSupported = (feature) => {
  const features = {
    webgl: () => {
      try {
        const canvas = document.createElement('canvas');
        return !!(canvas.getContext('webgl') || canvas.getContext('experimental-webgl'));
      } catch (e) {
        return false;
      }
    },
    webworker: () => typeof Worker !== 'undefined',
    websocket: () => typeof WebSocket !== 'undefined',
    localstorage: () => {
      try {
        localStorage.setItem('test', 'test');
        localStorage.removeItem('test');
        return true;
      } catch (e) {
        return false;
      }
    },
    crypto: () => window.crypto && window.crypto.subtle
  };
  
  return features[feature] ? features[feature]() : false;
};

/**
 * Get browser info
 * @returns {Object} Browser information
 */
export const getBrowserInfo = () => {
  const ua = navigator.userAgent;
  let browser = 'Unknown';
  let version = 'Unknown';
  
  if (ua.indexOf('Chrome') > -1) {
    browser = 'Chrome';
    version = ua.match(/Chrome\/([\d.]+)/)?.[1] || 'Unknown';
  } else if (ua.indexOf('Firefox') > -1) {
    browser = 'Firefox';
    version = ua.match(/Firefox\/([\d.]+)/)?.[1] || 'Unknown';
  } else if (ua.indexOf('Safari') > -1) {
    browser = 'Safari';
    version = ua.match(/Version\/([\d.]+)/)?.[1] || 'Unknown';
  } else if (ua.indexOf('Edge') > -1) {
    browser = 'Edge';
    version = ua.match(/Edge\/([\d.]+)/)?.[1] || 'Unknown';
  }
  
  return {
    browser,
    version,
    userAgent: ua,
    platform: navigator.platform,
    language: navigator.language
  };
};