import api from './api';

class SettingsService {
  /**
   * Get all settings
   * @returns {Promise} Current settings
   */
  async getSettings() {
    try {
      const response = await api.get('/settings/');
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Update settings
   * @param {Object} settings - Settings to update
   * @returns {Promise} Updated settings
   */
  async updateSettings(settings) {
    try {
      const response = await api.put('/settings/', settings);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get specific setting category
   * @param {string} category - Setting category
   * @returns {Promise} Category settings
   */
  async getSettingCategory(category) {
    try {
      const response = await api.get(`/settings/${category}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Update specific setting category
   * @param {string} category - Setting category
   * @param {Object} settings - Category settings
   * @returns {Promise} Updated category settings
   */
  async updateSettingCategory(category, settings) {
    try {
      const response = await api.put(`/settings/${category}`, settings);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Test webhook URL
   * @param {string} url - Webhook URL to test
   * @returns {Promise} Test result
   */
  async testWebhook(url) {
    try {
      const response = await api.post('/settings/test-webhook', { url });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Clear storage
   * @param {Object} options - Clear options
   * @returns {Promise} Clear result
   */
  async clearStorage(options = {}) {
    try {
      const response = await api.post('/settings/clear-storage', {
        clear_uploads: options.clearUploads || false,
        clear_analysis: options.clearAnalysis || false,
        clear_temp: options.clearTemp !== false,
        older_than_days: options.olderThanDays || 0
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Export user data
   * @returns {Promise} Export data
   */
  async exportUserData() {
    try {
      const response = await api.get('/settings/export-data', {
        responseType: 'blob'
      });

      // Create download link
      const blob = new Blob([response.data], { type: 'application/zip' });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `secunik-data-export-${new Date().toISOString().split('T')[0]}.zip`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);

      return { success: true };
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get storage statistics
   * @returns {Promise} Storage stats
   */
  async getStorageStats() {
    try {
      const response = await api.get('/settings/storage-stats');
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Validate API key
   * @param {string} service - Service name (virustotal, openai, etc.)
   * @param {string} apiKey - API key to validate
   * @returns {Promise} Validation result
   */
  async validateApiKey(service, apiKey) {
    try {
      const response = await api.post('/settings/validate-api-key', {
        service,
        api_key: apiKey
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get system information
   * @returns {Promise} System info
   */
  async getSystemInfo() {
    try {
      const response = await api.get('/settings/system-info');
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Reset settings to default
   * @param {string} category - Category to reset (optional)
   * @returns {Promise} Reset result
   */
  async resetSettings(category = null) {
    try {
      const response = await api.post('/settings/reset', { category });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get notification preferences
   * @returns {Promise} Notification settings
   */
  async getNotificationPreferences() {
    try {
      const response = await api.get('/settings/notifications');
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Update notification preferences
   * @param {Object} preferences - Notification preferences
   * @returns {Promise} Updated preferences
   */
  async updateNotificationPreferences(preferences) {
    try {
      const response = await api.put('/settings/notifications', preferences);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get theme settings
   * @returns {Promise} Theme settings
   */
  async getThemeSettings() {
    try {
      const response = await api.get('/settings/theme');
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Update theme settings
   * @param {Object} theme - Theme settings
   * @returns {Promise} Updated theme
   */
  async updateThemeSettings(theme) {
    try {
      const response = await api.put('/settings/theme', theme);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get user profile
   * @returns {Promise} User profile
   */
  async getUserProfile() {
    try {
      const response = await api.get('/settings/profile');
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Update user profile
   * @param {Object} profile - Profile data
   * @returns {Promise} Updated profile
   */
  async updateUserProfile(profile) {
    try {
      const response = await api.put('/settings/profile', profile);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Change password
   * @param {Object} passwords - Current and new passwords
   * @returns {Promise} Change result
   */
  async changePassword(passwords) {
    try {
      const response = await api.post('/settings/change-password', {
        current_password: passwords.currentPassword,
        new_password: passwords.newPassword
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get backup settings
   * @returns {Promise} Backup configuration
   */
  async getBackupSettings() {
    try {
      const response = await api.get('/settings/backup');
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Update backup settings
   * @param {Object} backupConfig - Backup configuration
   * @returns {Promise} Updated configuration
   */
  async updateBackupSettings(backupConfig) {
    try {
      const response = await api.put('/settings/backup', backupConfig);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Trigger manual backup
   * @returns {Promise} Backup result
   */
  async triggerBackup() {
    try {
      const response = await api.post('/settings/backup/trigger');
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get activity logs
   * @param {Object} params - Query parameters
   * @returns {Promise} Activity logs
   */
  async getActivityLogs(params = {}) {
    try {
      const queryParams = new URLSearchParams({
        page: params.page || 1,
        limit: params.limit || 50,
        start_date: params.startDate || '',
        end_date: params.endDate || '',
        action_type: params.actionType || ''
      });

      const response = await api.get(`/settings/activity-logs?${queryParams}`);
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
      const message = error.response.data?.message || error.response.data?.error || 'Settings operation failed';
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
const settingsService = new SettingsService();
export { settingsService };