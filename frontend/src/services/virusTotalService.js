import api from './api';

class VirusTotalService {
  constructor() {
    this.cache = new Map();
    this.cacheTimeout = 5 * 60 * 1000; // 5 minutes
  }

  /**
   * Scan single IOC (IP, domain, hash, URL)
   * @param {string} value - IOC value
   * @param {string} type - IOC type (ip, domain, hash, url)
   * @returns {Promise} Scan results
   */
  async scanIOC(value, type) {
    // Check cache first
    const cacheKey = `${type}:${value}`;
    const cached = this.getFromCache(cacheKey);
    if (cached) {
      return cached;
    }

    try {
      const response = await api.post('/virustotal/scan', {
        value,
        type,
        force_rescan: false
      });

      // Cache the result
      this.setCache(cacheKey, response.data);
      
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Bulk scan multiple IOCs
   * @param {Array} iocs - Array of {value, type} objects
   * @returns {Promise} Bulk scan results
   */
  async bulkScanIOCs(iocs) {
    // Filter out cached results
    const uncachedIOCs = [];
    const results = [];

    for (const ioc of iocs) {
      const cacheKey = `${ioc.type}:${ioc.value}`;
      const cached = this.getFromCache(cacheKey);
      if (cached) {
        results.push({
          ...ioc,
          ...cached,
          from_cache: true
        });
      } else {
        uncachedIOCs.push(ioc);
      }
    }

    if (uncachedIOCs.length === 0) {
      return results;
    }

    try {
      const response = await api.post('/virustotal/scan/bulk', {
        iocs: uncachedIOCs,
        skip_rate_limit: false
      });

      // Cache and merge results
      const newResults = response.data.results || [];
      newResults.forEach(result => {
        const cacheKey = `${result.type}:${result.value}`;
        this.setCache(cacheKey, result);
        results.push({
          ...result,
          from_cache: false
        });
      });

      return {
        results,
        quota_remaining: response.data.quota_remaining,
        errors: response.data.errors || []
      };
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get detailed report for a resource
   * @param {string} resource - Resource ID (hash, scan ID)
   * @returns {Promise} Detailed report
   */
  async getReport(resource) {
    const cacheKey = `report:${resource}`;
    const cached = this.getFromCache(cacheKey);
    if (cached) {
      return cached;
    }

    try {
      const response = await api.get(`/virustotal/report/${resource}`);
      
      // Cache the report
      this.setCache(cacheKey, response.data);
      
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get API quota information
   * @returns {Promise} Quota information
   */
  async getQuota() {
    try {
      const response = await api.get('/virustotal/quota');
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get file report by hash
   * @param {string} hash - File hash (MD5, SHA1, SHA256)
   * @returns {Promise} File report
   */
  async getFileReport(hash) {
    const cacheKey = `file:${hash}`;
    const cached = this.getFromCache(cacheKey);
    if (cached) {
      return cached;
    }

    try {
      const response = await api.get(`/virustotal/file/${hash}`);
      
      // Cache the result
      this.setCache(cacheKey, response.data);
      
      return response.data;
    } catch (error) {
      if (error.response?.status === 404) {
        return {
          found: false,
          hash,
          message: 'File not found in VirusTotal database'
        };
      }
      throw this.handleError(error);
    }
  }

  /**
   * Submit file for scanning
   * @param {File} file - File to scan
   * @param {Function} onProgress - Progress callback
   * @returns {Promise} Scan submission result
   */
  async submitFile(file, onProgress) {
    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await api.post('/virustotal/file/scan', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
        onUploadProgress: (progressEvent) => {
          if (progressEvent.lengthComputable && onProgress) {
            const percentCompleted = Math.round(
              (progressEvent.loaded * 100) / progressEvent.total
            );
            onProgress(percentCompleted);
          }
        },
      });

      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get URL report
   * @param {string} url - URL to check
   * @returns {Promise} URL report
   */
  async getURLReport(url) {
    const cacheKey = `url:${url}`;
    const cached = this.getFromCache(cacheKey);
    if (cached) {
      return cached;
    }

    try {
      const response = await api.post('/virustotal/url/report', { url });
      
      // Cache the result
      this.setCache(cacheKey, response.data);
      
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get domain report
   * @param {string} domain - Domain to check
   * @returns {Promise} Domain report
   */
  async getDomainReport(domain) {
    const cacheKey = `domain:${domain}`;
    const cached = this.getFromCache(cacheKey);
    if (cached) {
      return cached;
    }

    try {
      const response = await api.get(`/virustotal/domain/${domain}`);
      
      // Cache the result
      this.setCache(cacheKey, response.data);
      
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get IP address report
   * @param {string} ip - IP address to check
   * @returns {Promise} IP report
   */
  async getIPReport(ip) {
    const cacheKey = `ip:${ip}`;
    const cached = this.getFromCache(cacheKey);
    if (cached) {
      return cached;
    }

    try {
      const response = await api.get(`/virustotal/ip/${ip}`);
      
      // Cache the result
      this.setCache(cacheKey, response.data);
      
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get comments for a resource
   * @param {string} resource - Resource ID
   * @returns {Promise} Comments
   */
  async getComments(resource) {
    try {
      const response = await api.get(`/virustotal/comments/${resource}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Add comment to a resource
   * @param {string} resource - Resource ID
   * @param {string} comment - Comment text
   * @returns {Promise} Comment submission result
   */
  async addComment(resource, comment) {
    try {
      const response = await api.post(`/virustotal/comments/${resource}`, { comment });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get related samples
   * @param {string} hash - File hash
   * @returns {Promise} Related samples
   */
  async getRelatedSamples(hash) {
    try {
      const response = await api.get(`/virustotal/file/${hash}/related`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get behavior report for a file
   * @param {string} hash - File hash
   * @returns {Promise} Behavior analysis
   */
  async getBehaviorReport(hash) {
    try {
      const response = await api.get(`/virustotal/file/${hash}/behavior`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Search VirusTotal database
   * @param {string} query - Search query
   * @param {Object} options - Search options
   * @returns {Promise} Search results
   */
  async search(query, options = {}) {
    try {
      const response = await api.post('/virustotal/search', {
        query,
        limit: options.limit || 20,
        offset: options.offset || 0
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Clear cache
   */
  clearCache() {
    this.cache.clear();
  }

  /**
   * Get from cache
   * @private
   */
  getFromCache(key) {
    const cached = this.cache.get(key);
    if (cached && Date.now() - cached.timestamp < this.cacheTimeout) {
      return cached.data;
    }
    this.cache.delete(key);
    return null;
  }

  /**
   * Set cache
   * @private
   */
  setCache(key, data) {
    this.cache.set(key, {
      data,
      timestamp: Date.now()
    });
  }

  /**
   * Calculate threat level from VT data
   * @param {Object} vtData - VirusTotal data
   * @returns {Object} Threat level assessment
   */
  calculateThreatLevel(vtData) {
    if (!vtData || !vtData.positives) {
      return { level: 'unknown', score: 0, color: 'gray' };
    }

    const detectionRatio = vtData.positives / vtData.total;
    
    if (detectionRatio === 0) {
      return { level: 'clean', score: 0, color: 'green' };
    } else if (detectionRatio < 0.1) {
      return { level: 'low', score: detectionRatio * 100, color: 'yellow' };
    } else if (detectionRatio < 0.3) {
      return { level: 'medium', score: detectionRatio * 100, color: 'orange' };
    } else if (detectionRatio < 0.6) {
      return { level: 'high', score: detectionRatio * 100, color: 'red' };
    } else {
      return { level: 'critical', score: detectionRatio * 100, color: 'darkred' };
    }
  }

  /**
   * Handle and format errors
   * @param {Error} error - The error to handle
   * @returns {Error} Formatted error
   */
  handleError(error) {
    if (error.response) {
      const message = error.response.data?.message || error.response.data?.error || 'VirusTotal operation failed';
      const err = new Error(message);
      err.status = error.response.status;
      err.details = error.response.data;
      
      // Handle rate limiting
      if (error.response.status === 429) {
        err.message = 'VirusTotal API rate limit exceeded. Please try again later.';
        err.retryAfter = error.response.headers['retry-after'];
      }
      
      return err;
    } else if (error.request) {
      return new Error('No response from server. Please check your connection.');
    } else {
      return error;
    }
  }
}

// Create and export a singleton instance
const virusTotalService = new VirusTotalService();
export { virusTotalService };