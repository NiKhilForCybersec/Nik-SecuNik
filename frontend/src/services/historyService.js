import api from './api';

class HistoryService {
  /**
   * Get analysis history with filtering and pagination
   * @param {Object} params - Query parameters
   * @returns {Promise} Paginated history results
   */
  async getHistory(params = {}) {
    try {
      const queryParams = new URLSearchParams({
        page: params.page || 1,
        limit: params.limit || 20,
        search: params.search || '',
        severity: params.severity || '',
        status: params.status || '',
        file_type: params.fileType || '',
        start_date: params.startDate || '',
        end_date: params.endDate || '',
        sort_by: params.sortBy || 'created_at',
        sort_order: params.sortOrder || 'desc',
        tags: params.tags ? params.tags.join(',') : ''
      });

      // Remove empty parameters
      for (const [key, value] of queryParams.entries()) {
        if (!value) {
          queryParams.delete(key);
        }
      }

      const response = await api.get(`/history?${queryParams}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get specific analysis from history
   * @param {string} id - Analysis ID
   * @returns {Promise} Analysis details
   */
  async getAnalysis(id) {
    try {
      const response = await api.get(`/history/${id}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Delete analysis from history
   * @param {string} id - Analysis ID
   * @returns {Promise} Deletion result
   */
  async deleteAnalysis(id) {
    try {
      const response = await api.delete(`/history/${id}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Bulk delete analyses
   * @param {string[]} ids - Array of analysis IDs
   * @returns {Promise} Bulk deletion result
   */
  async bulkDelete(ids) {
    try {
      const response = await api.post('/history/bulk-delete', { ids });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Export history data
   * @param {Object} params - Export parameters
   * @returns {Promise} Export data or download URL
   */
  async exportHistory(params = {}) {
    try {
      const queryParams = new URLSearchParams({
        format: params.format || 'csv',
        ids: params.ids ? params.ids.join(',') : '',
        start_date: params.startDate || '',
        end_date: params.endDate || '',
        include_details: params.includeDetails || false
      });

      const response = await api.get(`/history/export?${queryParams}`, {
        responseType: params.format === 'csv' ? 'blob' : 'json'
      });

      if (params.format === 'csv') {
        // Create download link for CSV
        const blob = new Blob([response.data], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `analysis-history-${new Date().toISOString().split('T')[0]}.csv`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        window.URL.revokeObjectURL(url);
        return { success: true, format: 'csv' };
      }

      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get timeline events for visualization
   * @param {Object} params - Query parameters
   * @returns {Promise} Timeline event data
   */
  async getTimelineEvents(params = {}) {
    try {
      const queryParams = new URLSearchParams({
        start_date: params.startDate || '',
        end_date: params.endDate || '',
        granularity: params.granularity || 'hour',
        event_types: params.eventTypes ? params.eventTypes.join(',') : ''
      });

      const response = await api.get(`/history/timeline/events?${queryParams}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Search history with advanced filters
   * @param {Object} searchParams - Search parameters
   * @returns {Promise} Search results
   */
  async searchHistory(searchParams) {
    try {
      const response = await api.post('/history/search', {
        query: searchParams.query || '',
        filters: {
          file_hash: searchParams.fileHash,
          ip_addresses: searchParams.ipAddresses,
          domains: searchParams.domains,
          severity_min: searchParams.severityMin,
          threat_score_min: searchParams.threatScoreMin,
          has_malware: searchParams.hasMalware,
          has_patterns: searchParams.hasPatterns,
          rule_matches: searchParams.ruleMatches
        },
        date_range: {
          start: searchParams.startDate,
          end: searchParams.endDate
        },
        limit: searchParams.limit || 50
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get history statistics
   * @param {Object} params - Statistics parameters
   * @returns {Promise} History statistics
   */
  async getStatistics(params = {}) {
    try {
      const queryParams = new URLSearchParams({
        period: params.period || '30d',
        group_by: params.groupBy || 'day'
      });

      const response = await api.get(`/history/statistics?${queryParams}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get related analyses
   * @param {string} analysisId - Analysis ID
   * @returns {Promise} Related analyses
   */
  async getRelatedAnalyses(analysisId) {
    try {
      const response = await api.get(`/history/${analysisId}/related`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Archive analysis
   * @param {string} id - Analysis ID
   * @returns {Promise} Archive result
   */
  async archiveAnalysis(id) {
    try {
      const response = await api.post(`/history/${id}/archive`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Restore archived analysis
   * @param {string} id - Analysis ID
   * @returns {Promise} Restore result
   */
  async restoreAnalysis(id) {
    try {
      const response = await api.post(`/history/${id}/restore`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get user's favorite analyses
   * @returns {Promise} Favorite analyses list
   */
  async getFavorites() {
    try {
      const response = await api.get('/history/favorites');
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Toggle favorite status
   * @param {string} id - Analysis ID
   * @returns {Promise} Updated favorite status
   */
  async toggleFavorite(id) {
    try {
      const response = await api.post(`/history/${id}/favorite`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get history summary for dashboard
   * @returns {Promise} Summary data
   */
  async getDashboardSummary() {
    try {
      const response = await api.get('/history/summary');
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Clean up old history entries
   * @param {Object} params - Cleanup parameters
   * @returns {Promise} Cleanup result
   */
  async cleanupHistory(params = {}) {
    try {
      const response = await api.post('/history/cleanup', {
        older_than_days: params.olderThanDays || 90,
        keep_favorites: params.keepFavorites !== false,
        keep_tagged: params.keepTagged !== false
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Handle and format errors
   * @param {Error} error - The error to handle
   * @returns {Error} Formatted error
   */
  handleError(error) {
    if (error.response) {
      const message = error.response.data?.message || error.response.data?.error || 'History operation failed';
      const err = new Error(message);
      err.status = error.response.status;
      err.details = error.response.data;
      return err;
    } else if (error.request) {
      return new Error('No response from server. Please check your connection.');
    } else {
      return error;
    }
  }
}

// Create and export a singleton instance
const historyService = new HistoryService();
export { historyService };