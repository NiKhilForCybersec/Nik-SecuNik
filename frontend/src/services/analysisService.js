import api, { apiHelpers } from './api';
import { API_ENDPOINTS } from '@/utils/constants';

class AnalysisService {
  /**
   * Start a new analysis
   */
  async startAnalysis(fileHash, options = {}) {
    const response = await api.post(API_ENDPOINTS.ANALYSIS_START, {
      file_hash: fileHash,
      ...options,
    });
    return response.data;
  }

  /**
   * Get analysis status
   */
  async getAnalysisStatus(analysisId) {
    const response = await api.get(`${API_ENDPOINTS.ANALYSIS_STATUS}/${analysisId}`);
    return response.data;
  }

  /**
   * Get analysis results
   */
  async getAnalysisResults(analysisId) {
    const response = await api.get(`${API_ENDPOINTS.ANALYSIS_RESULTS}/${analysisId}`);
    return response.data;
  }

  /**
   * Export analysis results
   */
  async exportAnalysis(analysisId, format = 'pdf') {
    const filename = `analysis_${analysisId}_${Date.now()}.${format}`;
    await apiHelpers.downloadFile(
      `${API_ENDPOINTS.ANALYSIS_EXPORT}/${analysisId}?format=${format}`,
      filename
    );
  }

  /**
   * Get analysis by file hash
   */
  async getAnalysisByHash(fileHash) {
    const response = await api.get(`${API_ENDPOINTS.ANALYSIS}/hash/${fileHash}`);
    return response.data;
  }

  /**
   * Cancel running analysis
   */
  async cancelAnalysis(analysisId) {
    const response = await api.post(`${API_ENDPOINTS.ANALYSIS}/${analysisId}/cancel`);
    return response.data;
  }

  /**
   * Re-run analysis
   */
  async rerunAnalysis(analysisId, options = {}) {
    const response = await api.post(`${API_ENDPOINTS.ANALYSIS}/${analysisId}/rerun`, options);
    return response.data;
  }

  /**
   * Get analysis statistics
   */
  async getAnalysisStats(timeRange = '7d') {
    const response = await api.get(`${API_ENDPOINTS.ANALYSIS}/stats?range=${timeRange}`);
    return response.data;
  }
}

// Create and export singleton instance
const analysisService = new AnalysisService();
export { analysisService };