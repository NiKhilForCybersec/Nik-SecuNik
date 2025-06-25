import api, { apiHelpers } from './api';
import { API_ENDPOINTS } from '@/utils/constants';

class RulesService {
  /**
   * Get all rules with filters
   */
  async getRules(params = {}) {
    const queryString = apiHelpers.buildQueryString(params);
    const response = await api.get(`${API_ENDPOINTS.RULES}${queryString}`);
    return response.data;
  }

  /**
   * Get rule by ID
   */
  async getRule(id) {
    const response = await api.get(`${API_ENDPOINTS.RULES}/${id}`);
    return response.data;
  }

  /**
   * Create new rule
   */
  async createRule(ruleData) {
    const response = await api.post(API_ENDPOINTS.RULES, ruleData);
    return response.data;
  }

  /**
   * Update rule
   */
  async updateRule(id, ruleData) {
    const response = await api.put(`${API_ENDPOINTS.RULES}/${id}`, ruleData);
    return response.data;
  }

  /**
   * Delete rule
   */
  async deleteRule(id) {
    const response = await api.delete(`${API_ENDPOINTS.RULES}/${id}`);
    return response.data;
  }

  /**
   * Delete multiple rules
   */
  async deleteRules(ids) {
    const response = await api.post(`${API_ENDPOINTS.RULES}/delete-batch`, { ids });
    return response.data;
  }

  /**
   * Import rules from file
   */
  async importRules(file, options = {}) {
    const formData = new FormData();
    formData.append('file', file);
    Object.entries(options).forEach(([key, value]) => {
      formData.append(key, value);
    });

    const response = await api.post(API_ENDPOINTS.RULES_IMPORT, formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  }

  /**
   * Export rules
   */
  async exportRules(format = 'json', filters = {}) {
    const queryString = apiHelpers.buildQueryString({ format, ...filters });
    await apiHelpers.downloadFile(
      `${API_ENDPOINTS.RULES_EXPORT}${queryString}`,
      `rules_export_${Date.now()}.${format}`
    );
  }

  /**
   * Test rule against sample data
   */
  async testRule(ruleId, testData) {
    const response = await api.post(`${API_ENDPOINTS.RULES_TEST}/${ruleId}`, testData);
    return response.data;
  }

  /**
   * Sync rules from repository
   */
  async syncRules(syncConfig) {
    const response = await api.post(API_ENDPOINTS.RULES_SYNC, syncConfig);
    return response.data;
  }

  /**
   * Get rule statistics
   */
  async getRuleStats() {
    const response = await api.get(`${API_ENDPOINTS.RULES}/stats`);
    return response.data;
  }

  /**
   * Enable/disable rule
   */
  async toggleRule(id, enabled) {
    const response = await api.patch(`${API_ENDPOINTS.RULES}/${id}/toggle`, { enabled });
    return response.data;
  }

  /**
   * Validate rule syntax
   */
  async validateRule(ruleContent, ruleType) {
    const response = await api.post(`${API_ENDPOINTS.RULES}/validate`, {
      content: ruleContent,
      type: ruleType,
    });
    return response.data;
  }
}

// Create and export singleton instance
const rulesService = new RulesService();
export { rulesService };