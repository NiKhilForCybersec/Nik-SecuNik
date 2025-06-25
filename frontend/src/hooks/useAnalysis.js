import { useState, useCallback, useEffect, useRef } from 'react';
import { analysisService } from '../services/analysisService';
import { useAnalysisSubscription } from './useWebSocket';
import { ANALYSIS_STATUS } from '../utils/constants';

/**
 * Hook for managing analysis state and operations
 * @param {string} analysisId - Analysis ID to track
 * @param {Object} options - Hook options
 */
export const useAnalysis = (analysisId, options = {}) => {
  const [analysis, setAnalysis] = useState(null);
  const [status, setStatus] = useState(null);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [results, setResults] = useState(null);
  const pollIntervalRef = useRef(null);

  // Use WebSocket subscription for real-time updates
  const { 
    progress: wsProgress, 
    status: wsStatus, 
    result: wsResult,
    error: wsError 
  } = useAnalysisSubscription(analysisId, {
    onProgress: (data) => {
      if (options.onProgress) {
        options.onProgress(data);
      }
    },
    onComplete: (data) => {
      if (options.onComplete) {
        options.onComplete(data);
      }
      stopPolling();
    },
    onError: (data) => {
      if (options.onError) {
        options.onError(data);
      }
      stopPolling();
    }
  });

  // Update state from WebSocket
  useEffect(() => {
    if (wsProgress !== null) setProgress(wsProgress);
    if (wsStatus) setStatus(wsStatus);
    if (wsResult) setResults(wsResult);
    if (wsError) setError(wsError);
  }, [wsProgress, wsStatus, wsResult, wsError]);

  // Load initial analysis data
  useEffect(() => {
    if (analysisId && options.loadOnMount !== false) {
      loadAnalysis();
    }
  }, [analysisId]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      stopPolling();
    };
  }, []);

  /**
   * Load analysis data
   */
  const loadAnalysis = useCallback(async () => {
    if (!analysisId) return;

    setIsLoading(true);
    setError(null);

    try {
      const data = await analysisService.getResult(analysisId);
      setAnalysis(data);
      setStatus(data.status);
      setProgress(data.progress || 0);
      
      if (data.status === ANALYSIS_STATUS.COMPLETED) {
        setResults(data.results);
      }
      
      // Start polling if analysis is in progress
      if (
        data.status === ANALYSIS_STATUS.PROCESSING || 
        data.status === ANALYSIS_STATUS.QUEUED
      ) {
        startPolling();
      }
    } catch (err) {
      setError(err.message || 'Failed to load analysis');
    } finally {
      setIsLoading(false);
    }
  }, [analysisId]);

  /**
   * Start polling for updates (fallback for WebSocket)
   */
  const startPolling = useCallback(() => {
    if (pollIntervalRef.current) return;

    pollIntervalRef.current = setInterval(async () => {
      try {
        const statusData = await analysisService.getStatus(analysisId);
        setStatus(statusData.status);
        setProgress(statusData.progress || 0);

        if (
          statusData.status === ANALYSIS_STATUS.COMPLETED ||
          statusData.status === ANALYSIS_STATUS.ERROR ||
          statusData.status === ANALYSIS_STATUS.CANCELLED
        ) {
          stopPolling();
          loadAnalysis();
        }
      } catch (err) {
        console.error('Polling error:', err);
      }
    }, options.pollInterval || 2000);
  }, [analysisId, loadAnalysis]);

  /**
   * Stop polling
   */
  const stopPolling = useCallback(() => {
    if (pollIntervalRef.current) {
      clearInterval(pollIntervalRef.current);
      pollIntervalRef.current = null;
    }
  }, []);

  /**
   * Cancel analysis
   */
  const cancelAnalysis = useCallback(async () => {
    if (!analysisId) return;

    try {
      await analysisService.cancelAnalysis(analysisId);
      setStatus(ANALYSIS_STATUS.CANCELLED);
      stopPolling();
      
      if (options.onCancel) {
        options.onCancel();
      }
    } catch (err) {
      setError(err.message || 'Failed to cancel analysis');
    }
  }, [analysisId]);

  /**
   * Rerun analysis with new options
   */
  const rerunAnalysis = useCallback(async (newOptions = {}) => {
    if (!analysisId) return;

    setIsLoading(true);
    setError(null);

    try {
      const data = await analysisService.rerunAnalysis(analysisId, newOptions);
      return data;
    } catch (err) {
      setError(err.message || 'Failed to rerun analysis');
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [analysisId]);

  /**
   * Export analysis results
   */
  const exportAnalysis = useCallback(async (format = 'json', exportOptions = {}) => {
    if (!analysisId) return;

    try {
      const data = await analysisService.exportResult(analysisId, format, exportOptions);
      return data;
    } catch (err) {
      setError(err.message || 'Failed to export analysis');
      throw err;
    }
  }, [analysisId]);

  /**
   * Add comment to analysis
   */
  const addComment = useCallback(async (comment) => {
    if (!analysisId) return;

    try {
      const data = await analysisService.addComment(analysisId, comment);
      setAnalysis(data);
      return data;
    } catch (err) {
      setError(err.message || 'Failed to add comment');
      throw err;
    }
  }, [analysisId]);

  /**
   * Add tags to analysis
   */
  const addTags = useCallback(async (tags) => {
    if (!analysisId) return;

    try {
      const data = await analysisService.addTags(analysisId, tags);
      setAnalysis(data);
      return data;
    } catch (err) {
      setError(err.message || 'Failed to add tags');
      throw err;
    }
  }, [analysisId]);

  return {
    // State
    analysis,
    status,
    progress,
    error,
    isLoading,
    results,
    
    // Methods
    loadAnalysis,
    cancelAnalysis,
    rerunAnalysis,
    exportAnalysis,
    addComment,
    addTags,
    
    // Computed
    isComplete: status === ANALYSIS_STATUS.COMPLETED,
    isProcessing: status === ANALYSIS_STATUS.PROCESSING,
    isQueued: status === ANALYSIS_STATUS.QUEUED,
    hasError: status === ANALYSIS_STATUS.ERROR,
    isCancelled: status === ANALYSIS_STATUS.CANCELLED
  };
};

/**
 * Hook for starting new analyses
 */
export const useStartAnalysis = () => {
  const [isStarting, setIsStarting] = useState(false);
  const [error, setError] = useState(null);

  const startAnalysis = useCallback(async (fileHash, options = {}) => {
    setIsStarting(true);
    setError(null);

    try {
      const data = await analysisService.startAnalysis(fileHash, options);
      return data;
    } catch (err) {
      setError(err.message || 'Failed to start analysis');
      throw err;
    } finally {
      setIsStarting(false);
    }
  }, []);

  const checkExistingAnalysis = useCallback(async (fileHash) => {
    try {
      const existing = await analysisService.getByFileHash(fileHash);
      return existing;
    } catch (err) {
      // Not found is expected
      return null;
    }
  }, []);

  return {
    startAnalysis,
    checkExistingAnalysis,
    isStarting,
    error
  };
};

/**
 * Hook for analysis comparison
 */
export const useAnalysisComparison = (analysisIds = []) => {
  const [comparison, setComparison] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  const compareAnalyses = useCallback(async () => {
    if (analysisIds.length < 2) {
      setError('At least 2 analyses required for comparison');
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const data = await analysisService.compareAnalyses(analysisIds);
      setComparison(data);
      return data;
    } catch (err) {
      setError(err.message || 'Failed to compare analyses');
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [analysisIds]);

  useEffect(() => {
    if (analysisIds.length >= 2) {
      compareAnalyses();
    }
  }, [analysisIds]);

  return {
    comparison,
    isLoading,
    error,
    refresh: compareAnalyses
  };
};

/**
 * Hook for analysis recommendations
 */
export const useAnalysisRecommendations = (analysisId) => {
  const [recommendations, setRecommendations] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  const loadRecommendations = useCallback(async () => {
    if (!analysisId) return;

    setIsLoading(true);
    setError(null);

    try {
      const data = await analysisService.getRecommendations(analysisId);
      setRecommendations(data);
      return data;
    } catch (err) {
      setError(err.message || 'Failed to load recommendations');
    } finally {
      setIsLoading(false);
    }
  }, [analysisId]);

  useEffect(() => {
    loadRecommendations();
  }, [analysisId]);

  return {
    recommendations,
    isLoading,
    error,
    refresh: loadRecommendations
  };
};