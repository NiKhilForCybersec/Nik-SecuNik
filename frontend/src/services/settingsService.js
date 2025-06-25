import api from './api';

class SettingsService {
  /**
   * Get all settings
   */
  async getSettings() {
    const response = await api.get('/settings');
    return response.data;
  }

  /**
   * Update general settings
   */
  async updateGeneralSettings(settings) {
    const response = await api.put('/settings/general', settings);
    return response.data;
  }

  /**
   * Update API keys
   */
  async updateApiKeys(keys) {
    const response = await api.put('/settings/api-keys', keys);
    return response.data;
  }

  /**
   * Update notification preferences
   */
  async updateNotificationSettings(settings) {
    const response = await api.put('/settings/notifications', settings);
    return response.data;
  }

  /**
   * Update security settings
   */
  async updateSecuritySettings(settings) {
    const response = await api.put('/settings/security', settings);
    return response.data;
  }

  /**
   * Test API connection
   */
  async testApiConnection(service, apiKey) {
    const response = await api.post('/settings/test-connection', {
      service,
      api_key: apiKey,
    });
    return response.data;
  }

  /**
   * Get system info
   */
  async getSystemInfo() {
    const response = await api.get('/settings/system-info');
    return response.data;
  }

  /**
   * Export settings
   */
  async exportSettings() {
    const response = await api.get('/settings/export');
    return response.data;
  }

  /**
   * Import settings
   */
  async importSettings(settingsData) {
    const response = await api.post('/settings/import', settingsData);
    return response.data;
  }

  /**
   * Reset settings to defaults
   */
  async resetSettings(category) {
    const response = await api.post('/settings/reset', { category });
    return response.data;
  }

  /**
   * Update theme settings
   */
  async updateThemeSettings(themeData) {
    const response = await api.put('/settings/theme', themeData);
    return response.data;
  }
}

// Create and export singleton instance
const settingsService = new SettingsService();
export { settingsService };