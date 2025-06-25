import api from './api';

class RulesService {
  /**
   * Get rules with filtering and pagination
   * @param {Object} params - Query parameters
   * @returns {Promise} Paginated rules
   */
  async getRules(params = {}) {
    try {
      const queryParams = new URLSearchParams({
        page: params.page || 1,
        limit: params.limit || 50,
        type: params.type || '',
        severity: params.severity || '',
        enabled: params.enabled !== undefined ? params.enabled : '',
        search: params.search || '',
        tags: params.tags ? params.tags.join(',') : '',
        sort_by: params.sortBy || 'updated_at',
        sort_order: params.sortOrder || 'desc'
      });

      // Remove empty parameters
      for (const [key, value] of queryParams.entries()) {
        if (value === '') {
          queryParams.delete(key);
        }
      }

      const response = await api.get(`/rules?${queryParams}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get single rule by ID
   * @param {string} id - Rule ID
   * @returns {Promise} Rule details
   */
  async getRule(id) {
    try {
      const response = await api.get(`/rules/${id}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Create new rule
   * @param {Object} ruleData - Rule data
   * @returns {Promise} Created rule
   */
  async createRule(ruleData) {
    try {
      const response = await api.post('/rules/', {
        name: ruleData.name,
        description: ruleData.description,
        type: ruleData.type,
        severity: ruleData.severity,
        content: ruleData.content,
        enabled: ruleData.enabled !== false,
        tags: ruleData.tags || [],
        metadata: ruleData.metadata || {}
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Update existing rule
   * @param {string} id - Rule ID
   * @param {Object} updates - Rule updates
   * @returns {Promise} Updated rule
   */
  async updateRule(id, updates) {
    try {
      const response = await api.put(`/rules/${id}`, updates);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Delete rule
   * @param {string} id - Rule ID
   * @returns {Promise} Deletion result
   */
  async deleteRule(id) {
    try {
      const response = await api.delete(`/rules/${id}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Validate rule syntax
   * @param {Object} ruleData - Rule content to validate
   * @returns {Promise} Validation result
   */
  async validateRule(ruleData) {
    try {
      const response = await api.post('/rules/validate', {
        type: ruleData.type,
        content: ruleData.content
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Test rule against sample data
   * @param {string} id - Rule ID
   * @param {Object} testData - Test data
   * @returns {Promise} Test results
   */
  async testRule(id, testData) {
    try {
      const response = await api.post(`/rules/${id}/test`, {
        test_data: testData.data,
        test_type: testData.type || 'raw',
        timeout: testData.timeout || 30
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Import rules from file
   * @param {File} file - Rules file
   * @param {Object} options - Import options
   * @returns {Promise} Import results
   */
  async importRules(file, options = {}) {
    try {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('overwrite', options.overwrite || false);
      formData.append('validate', options.validate !== false);
      formData.append('enable_imported', options.enableImported || false);

      const response = await api.post('/rules/import', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        }
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Export rules
   * @param {Object} params - Export parameters
   * @returns {Promise} Export data
   */
  async exportRules(params = {}) {
    try {
      const queryParams = new URLSearchParams({
        format: params.format || 'json',
        rule_ids: params.ruleIds ? params.ruleIds.join(',') : '',
        types: params.types ? params.types.join(',') : '',
        include_disabled: params.includeDisabled || false
      });

      const response = await api.get(`/rules/export?${queryParams}`, {
        responseType: params.format === 'zip' ? 'blob' : 'json'
      });

      if (params.format === 'zip') {
        // Create download link for ZIP
        const blob = new Blob([response.data], { type: 'application/zip' });
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `rules-export-${new Date().toISOString().split('T')[0]}.zip`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        window.URL.revokeObjectURL(url);
        return { success: true, format: 'zip' };
      }

      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Bulk update rules
   * @param {string[]} ids - Rule IDs
   * @param {Object} updates - Updates to apply
   * @returns {Promise} Bulk update result
   */
  async bulkUpdate(ids, updates) {
    try {
      const response = await api.post('/rules/bulk-update', {
        rule_ids: ids,
        updates: {
          enabled: updates.enabled,
          severity: updates.severity,
          tags: updates.tags
        }
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Clone existing rule
   * @param {string} id - Rule ID to clone
   * @param {Object} options - Clone options
   * @returns {Promise} Cloned rule
   */
  async cloneRule(id, options = {}) {
    try {
      const response = await api.post(`/rules/${id}/clone`, {
        name: options.name,
        enabled: options.enabled || false
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get rule templates
   * @param {string} type - Rule type (yara, sigma, custom)
   * @returns {Promise} Available templates
   */
  async getTemplates(type) {
    try {
      const response = await api.get(`/rules/templates/${type}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get rule performance metrics
   * @param {string} id - Rule ID
   * @param {Object} params - Query parameters
   * @returns {Promise} Performance metrics
   */
  async getPerformanceMetrics(id, params = {}) {
    try {
      const queryParams = new URLSearchParams({
        period: params.period || '7d',
        granularity: params.granularity || 'day'
      });

      const response = await api.get(`/rules/${id}/performance?${queryParams}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get rule execution history
   * @param {string} id - Rule ID
   * @param {Object} params - Query parameters
   * @returns {Promise} Execution history
   */
  async getExecutionHistory(id, params = {}) {
    try {
      const queryParams = new URLSearchParams({
        limit: params.limit || 100,
        include_matches: params.includeMatches || false
      });

      const response = await api.get(`/rules/${id}/history?${queryParams}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Update rule pack
   * @param {string} packName - Rule pack name
   * @returns {Promise} Update result
   */
  async updateRulePack(packName) {
    try {
      const response = await api.post(`/rules/packs/${packName}/update`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get available rule packs
   * @returns {Promise} Available rule packs
   */
  async getRulePacks() {
    try {
      const response = await api.get('/rules/packs');
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Sync rules with remote repository
   * @param {Object} options - Sync options
   * @returns {Promise} Sync result
   */
  async syncRules(options = {}) {
    try {
      const response = await api.post('/rules/sync', {
        source: options.source || 'github',
        repository: options.repository,
        branch: options.branch || 'main',
        overwrite: options.overwrite || false
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
      const message = error.response.data?.message || error.response.data?.error || 'Rule operation failed';
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
const rulesService = new RulesService();
export { rulesService };