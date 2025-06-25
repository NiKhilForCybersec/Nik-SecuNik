import api, { apiHelpers } from './api';
import { API_ENDPOINTS } from '@/utils/constants';

class HistoryService {
  /**
   * Get analysis history with filters
   */
  async getHistory(params = {}) {
    const queryString = apiHelpers.buildQueryString(params);
    const response = await api.get(`${API_ENDPOINTS.HISTORY}${queryString}`);
    return response.data;
  }

  /**
   * Search history
   */
  async searchHistory(searchParams) {
    const response = await api.post(API_ENDPOINTS.HISTORY_SEARCH, searchParams);
    return response.data;
  }

  /**
   * Get history item details
   */
  async getHistoryItem(id) {
    const response = await api.get(`${API_ENDPOINTS.HISTORY}/${id}`);
    return response.data;
  }

  /**
   * Delete history items
   */
  async deleteHistoryItems(ids) {
    const response = await api.post(API_ENDPOINTS.HISTORY_DELETE, { ids });
    return response.data;
  }

  /**
   * Export history to CSV
   */
  async exportHistory(filters = {}) {
    const queryString = apiHelpers.buildQueryString(filters);
    await apiHelpers.exportToCsv(
      `${API_ENDPOINTS.HISTORY}/export${queryString}`,
      `history_export_${Date.now()}.csv`
    );
  }

  /**
   * Get history statistics
   */
  async getHistoryStats(timeRange = '30d') {
    const response = await api.get(`${API_ENDPOINTS.HISTORY}/stats?range=${timeRange}`);
    return response.data;
  }

  /**
   * Add tags to history item
   */
  async addTags(historyId, tags) {
    const response = await api.post(`${API_ENDPOINTS.HISTORY}/${historyId}/tags`, { tags });
    return response.data;
  }

  /**
   * Add comment to history item
   */
  async addComment(historyId, comment) {
    const response = await api.post(`${API_ENDPOINTS.HISTORY}/${historyId}/comments`, { comment });
    return response.data;
  }
}

// Create and export singleton instance
const historyService = new HistoryService();
export { historyService };