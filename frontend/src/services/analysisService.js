import api from './api';

class AnalysisService {
  /**
   * Start analysis for an uploaded file
   * @param {string} fileHash - SHA256 hash of the file
   * @param {Object} options - Analysis options
   * @returns {Promise} Analysis task info
   */
  async startAnalysis(fileHash, options = {}) {
    try {
      const response = await api.post(`/analyze/${fileHash}`, {
        priority: options.priority || 'normal',
        rules: options.rules || 'all',
        deep_scan: options.deepScan || false,
        extract_iocs: options.extractIOCs !== false,
        run_yara: options.runYara !== false,
        run_sigma: options.runSigma !== false,
        ai_analysis: options.aiAnalysis || false,
        custom_rules: options.customRules || []
      });
      
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get analysis status
   * @param {string} analysisId - Analysis ID
   * @returns {Promise} Current status
   */
  async getStatus(analysisId) {
    try {
      const response = await api.get(`/analyze/status/${analysisId}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get complete analysis result
   * @param {string} analysisId - Analysis ID
   * @returns {Promise} Analysis results
   */
  async getResult(analysisId) {
    try {
      const response = await api.get(`/analyze/result/${analysisId}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Export analysis results in specified format
   * @param {string} analysisId - Analysis ID
   * @param {string} format - Export format (json, pdf, csv)
   * @param {Object} options - Export options
   * @returns {Promise} Export data or download URL
   */
  async exportResult(analysisId, format = 'json', options = {}) {
    try {
      const params = new URLSearchParams({
        format,
        include_raw: options.includeRaw || false,
        include_timeline: options.includeTimeline !== false,
        include_iocs: options.includeIOCs !== false,
        include_patterns: options.includePatterns !== false,
        include_anomalies: options.includeAnomalies !== false
      });

      const response = await api.get(`/analyze/export/${analysisId}?${params}`, {
        responseType: format === 'pdf' ? 'blob' : 'json'
      });

      if (format === 'pdf') {
        // Create download link for PDF
        const blob = new Blob([response.data], { type: 'application/pdf' });
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `analysis-${analysisId}.pdf`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        window.URL.revokeObjectURL(url);
        return { success: true, format: 'pdf' };
      }

      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Cancel ongoing analysis
   * @param {string} analysisId - Analysis ID to cancel
   * @returns {Promise} Cancellation result
   */
  async cancelAnalysis(analysisId) {
    try {
      const response = await api.delete(`/analyze/cancel/${analysisId}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Re-run analysis with different options
   * @param {string} analysisId - Original analysis ID
   * @param {Object} newOptions - New analysis options
   * @returns {Promise} New analysis task info
   */
  async rerunAnalysis(analysisId, newOptions = {}) {
    try {
      const response = await api.post(`/analyze/rerun/${analysisId}`, newOptions);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get analysis statistics
   * @param {Object} params - Query parameters
   * @returns {Promise} Analysis statistics
   */
  async getStatistics(params = {}) {
    try {
      const queryParams = new URLSearchParams({
        start_date: params.startDate || '',
        end_date: params.endDate || '',
        group_by: params.groupBy || 'day'
      });

      const response = await api.get(`/analyze/statistics?${queryParams}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Compare multiple analyses
   * @param {string[]} analysisIds - Array of analysis IDs to compare
   * @returns {Promise} Comparison results
   */
  async compareAnalyses(analysisIds) {
    try {
      const response = await api.post('/analyze/compare', { analysis_ids: analysisIds });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get recommended actions based on analysis
   * @param {string} analysisId - Analysis ID
   * @returns {Promise} Recommended actions
   */
  async getRecommendations(analysisId) {
    try {
      const response = await api.get(`/analyze/recommendations/${analysisId}`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Add comment to analysis
   * @param {string} analysisId - Analysis ID
   * @param {string} comment - Comment text
   * @returns {Promise} Updated analysis
   */
  async addComment(analysisId, comment) {
    try {
      const response = await api.post(`/analyze/${analysisId}/comment`, { comment });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Tag analysis
   * @param {string} analysisId - Analysis ID
   * @param {string[]} tags - Tags to add
   * @returns {Promise} Updated analysis
   */
  async addTags(analysisId, tags) {
    try {
      const response = await api.post(`/analyze/${analysisId}/tags`, { tags });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get analysis by file hash
   * @param {string} fileHash - File SHA256 hash
   * @returns {Promise} Analysis data if exists
   */
  async getByFileHash(fileHash) {
    try {
      const response = await api.get(`/analyze/file/${fileHash}`);
      return response.data;
    } catch (error) {
      if (error.response?.status === 404) {
        return null;
      }
      throw this.handleError(error);
    }
  }

  /**
   * Get threat score breakdown
   * @param {string} analysisId - Analysis ID
   * @returns {Promise} Detailed threat score calculation
   */
  async getThreatScoreDetails(analysisId) {
    try {
      const response = await api.get(`/analyze/${analysisId}/threat-score`);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Submit feedback on analysis accuracy
   * @param {string} analysisId - Analysis ID
   * @param {Object} feedback - Feedback data
   * @returns {Promise} Feedback submission result
   */
  async submitFeedback(analysisId, feedback) {
    try {
      const response = await api.post(`/analyze/${analysisId}/feedback`, {
        accuracy: feedback.accuracy, // 1-5 rating
        false_positives: feedback.falsePositives || [],
        missed_threats: feedback.missedThreats || [],
        comments: feedback.comments || ''
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
      const message = error.response.data?.message || error.response.data?.error || 'Analysis operation failed';
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
const analysisService = new AnalysisService();
export { analysisService };