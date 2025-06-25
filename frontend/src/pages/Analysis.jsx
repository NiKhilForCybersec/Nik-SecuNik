import React, { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ChartBarIcon,
  ClockIcon,
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  BeakerIcon,
  DocumentTextIcon,
  ArrowDownTrayIcon,
  ArrowPathIcon,
  CheckCircleIcon
} from '@heroicons/react/24/outline';
import { toast } from 'react-hot-toast';
import Card from '@/components/common/Card';
import Button from '@/components/common/Button';
import EventsTimeline from '@/components/analysis/EventsTimeline';
import IOCsTable from '@/components/analysis/IOCsTable';
import AnalysisOverview from '@/components/analysis/AnalysisOverview';
import { analysisService } from '@/services/analysisService';
import { useWebSocket } from '@/hooks/useWebSocket';
import { formatDateTime, formatDuration } from '@/utils/formatters';

const ANALYSIS_STAGES = [
  { id: 'upload', label: 'File Uploaded', icon: CheckCircleIcon },
  { id: 'parsing', label: 'Parsing', icon: DocumentTextIcon },
  { id: 'analyzing', label: 'Analyzing', icon: BeakerIcon },
  { id: 'enriching', label: 'Threat Intel', icon: ShieldCheckIcon },
  { id: 'complete', label: 'Complete', icon: CheckCircleIcon }
];

const TABS = [
  { id: 'overview', label: 'Overview', icon: ChartBarIcon },
  { id: 'timeline', label: 'Events Timeline', icon: ClockIcon },
  { id: 'iocs', label: 'IOCs', icon: ShieldCheckIcon },
  { id: 'patterns', label: 'Patterns', icon: ExclamationTriangleIcon },
  { id: 'anomalies', label: 'Anomalies', icon: ExclamationTriangleIcon },
  { id: 'raw', label: 'Raw Data', icon: DocumentTextIcon }
];

export default function Analysis() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [refreshing, setRefreshing] = useState(false);
  const [progress, setProgress] = useState(0);
  const [currentStage, setCurrentStage] = useState('upload');

  // WebSocket connection for real-time updates
  const { isConnected, lastMessage } = useWebSocket(
    analysis?.status === 'processing' ? `/ws/analysis/${id}` : null,
    {
      onMessage: (data) => {
        if (data.type === 'progress') {
          setProgress(data.progress);
          setCurrentStage(data.stage);
        } else if (data.type === 'complete') {
          loadAnalysisResult();
        } else if (data.type === 'error') {
          setError(data.message);
          toast.error('Analysis failed: ' + data.message);
        }
      }
    }
  );

  // Load initial analysis data
  const loadAnalysisResult = useCallback(async () => {
    try {
      setLoading(true);
      const result = await analysisService.getResult(id);
      setAnalysis(result);
      setError(null);
      
      if (result.status === 'completed') {
        setProgress(100);
        setCurrentStage('complete');
      }
    } catch (err) {
      setError(err.message || 'Failed to load analysis');
      toast.error('Failed to load analysis');
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    loadAnalysisResult();
  }, [loadAnalysisResult]);

  // Handle refresh
  const handleRefresh = async () => {
    setRefreshing(true);
    await loadAnalysisResult();
    setRefreshing(false);
    toast.success('Analysis refreshed');
  };

  // Handle export
  const handleExport = async (format = 'json') => {
    try {
      const blob = await analysisService.exportResult(id, format);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `analysis-${id}.${format}`;
      a.click();
      window.URL.revokeObjectURL(url);
      toast.success(`Exported as ${format.toUpperCase()}`);
    } catch (err) {
      toast.error('Export failed');
    }
  };

  // Calculate threat score color
  const getThreatScoreColor = (score) => {
    if (score >= 80) return 'text-red-500 border-red-500';
    if (score >= 60) return 'text-orange-500 border-orange-500';
    if (score >= 40) return 'text-yellow-500 border-yellow-500';
    return 'text-green-500 border-green-500';
  };

  // Get stage index
  const getStageIndex = (stageId) => {
    return ANALYSIS_STAGES.findIndex(s => s.id === stageId);
  };

  const currentStageIndex = getStageIndex(currentStage);

  if (loading && !analysis) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyber-blue mx-auto mb-4" />
          <p className="text-gray-400">Loading analysis...</p>
        </div>
      </div>
    );
  }

  if (error && !analysis) {
    return (
      <Card className="bg-gray-800/50">
        <div className="text-center py-12">
          <ExclamationTriangleIcon className="h-12 w-12 text-red-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-white mb-2">Analysis Error</h3>
          <p className="text-gray-400 mb-6">{error}</p>
          <Button onClick={() => navigate('/upload')}>
            Upload New File
          </Button>
        </div>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-gray-800/50 backdrop-blur border border-gray-700 rounded-lg p-6">
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white mb-2">
              Analysis Results
            </h1>
            <div className="space-y-1 text-sm text-gray-400">
              <p>File: <span className="text-white">{analysis?.filename}</span></p>
              <p>Hash: <span className="text-gray-300 font-mono">{analysis?.file_hash}</span></p>
              <p>Started: {formatDateTime(analysis?.created_at)}</p>
              {analysis?.status === 'completed' && (
                <p>Duration: {formatDuration(analysis?.processing_time)}</p>
              )}
            </div>
          </div>

          {/* Actions */}
          <div className="flex items-center space-x-3">
            <Button
              variant="ghost"
              size="sm"
              icon={ArrowPathIcon}
              onClick={handleRefresh}
              loading={refreshing}
            >
              Refresh
            </Button>
            <div className="relative group">
              <Button
                variant="secondary"
                size="sm"
                icon={ArrowDownTrayIcon}
                onClick={() => handleExport('json')}
              >
                Export
              </Button>
              <div className="absolute right-0 mt-1 w-32 bg-gray-800 border border-gray-700 rounded-lg shadow-xl opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 z-10">
                <button
                  onClick={() => handleExport('json')}
                  className="block w-full text-left px-4 py-2 text-sm text-gray-300 hover:bg-gray-700 hover:text-white"
                >
                  Export JSON
                </button>
                <button
                  onClick={() => handleExport('pdf')}
                  className="block w-full text-left px-4 py-2 text-sm text-gray-300 hover:bg-gray-700 hover:text-white"
                >
                  Export PDF
                </button>
                <button
                  onClick={() => handleExport('csv')}
                  className="block w-full text-left px-4 py-2 text-sm text-gray-300 hover:bg-gray-700 hover:text-white"
                >
                  Export CSV
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Progress Bar (if processing) */}
      {analysis?.status === 'processing' && (
        <Card className="bg-gray-800/50">
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-medium text-white">Analysis Progress</h3>
              <span className="text-sm text-gray-400">{progress}%</span>
            </div>

            {/* Progress Bar */}
            <div className="relative">
              <div className="h-2 bg-gray-700 rounded-full overflow-hidden">
                <motion.div
                  className="h-full bg-gradient-to-r from-cyber-blue to-cyber-purple"
                  initial={{ width: 0 }}
                  animate={{ width: `${progress}%` }}
                  transition={{ duration: 0.5 }}
                />
              </div>
            </div>

            {/* Stages */}
            <div className="flex items-center justify-between">
              {ANALYSIS_STAGES.map((stage, index) => {
                const Icon = stage.icon;
                const isActive = index === currentStageIndex;
                const isComplete = index < currentStageIndex;
                
                return (
                  <div key={stage.id} className="flex flex-col items-center">
                    <div className={`
                      w-10 h-10 rounded-full flex items-center justify-center
                      ${isComplete ? 'bg-green-500/20 text-green-400' : 
                        isActive ? 'bg-cyber-blue/20 text-cyber-blue animate-pulse' : 
                        'bg-gray-700 text-gray-500'}
                    `}>
                      <Icon className="h-5 w-5" />
                    </div>
                    <span className={`text-xs mt-1 ${isActive ? 'text-white' : 'text-gray-500'}`}>
                      {stage.label}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </Card>
      )}

      {/* Threat Score (if completed) */}
      {analysis?.status === 'completed' && analysis?.threat_score !== undefined && (
        <Card className="bg-gray-800/50">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-lg font-medium text-white mb-1">Threat Assessment</h3>
              <p className="text-sm text-gray-400">
                Based on {analysis?.total_events || 0} events and {analysis?.iocs?.length || 0} IOCs
              </p>
            </div>
            <div className={`text-center p-6 border-4 rounded-full ${getThreatScoreColor(analysis.threat_score)}`}>
              <div className="text-3xl font-bold">{analysis.threat_score}</div>
              <div className="text-xs uppercase">Score</div>
            </div>
          </div>

          {/* Summary */}
          {analysis?.summary && (
            <div className="mt-4 p-4 bg-gray-900/50 rounded-lg">
              <p className="text-gray-300">{analysis.summary}</p>
            </div>
          )}
        </Card>
      )}

      {/* Tabs */}
      {analysis?.status === 'completed' && (
        <Card className="bg-gray-800/50">
          {/* Tab Navigation */}
          <div className="border-b border-gray-700 -mx-6 px-6 mb-6">
            <nav className="flex space-x-8">
              {TABS.map(tab => {
                const Icon = tab.icon;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={`
                      flex items-center space-x-2 py-3 border-b-2 transition-colors
                      ${activeTab === tab.id
                        ? 'border-cyber-blue text-cyber-blue'
                        : 'border-transparent text-gray-400 hover:text-white hover:border-gray-600'
                      }
                    `}
                  >
                    <Icon className="h-5 w-5" />
                    <span className="font-medium">{tab.label}</span>
                  </button>
                );
              })}
            </nav>
          </div>

          {/* Tab Content */}
          <AnimatePresence mode="wait">
            <motion.div
              key={activeTab}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              transition={{ duration: 0.2 }}
            >
              {activeTab === 'overview' && (
                <AnalysisOverview analysis={analysis} />
              )}

              {activeTab === 'timeline' && (
                <EventsTimeline events={analysis.events || []} />
              )}

              {activeTab === 'iocs' && (
                <IOCsTable iocs={analysis.iocs || []} analysisId={id} />
              )}

              {activeTab === 'patterns' && (
                <div className="space-y-4">
                  {analysis.patterns?.map((pattern, index) => (
                    <div key={index} className="bg-gray-900/50 rounded-lg p-4">
                      <h4 className="font-medium text-white mb-2">{pattern.name}</h4>
                      <p className="text-sm text-gray-400 mb-2">{pattern.description}</p>
                      <div className="flex items-center space-x-4 text-sm">
                        <span className="text-gray-500">Confidence: {pattern.confidence}%</span>
                        <span className="text-gray-500">Occurrences: {pattern.count}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {activeTab === 'anomalies' && (
                <div className="space-y-4">
                  {analysis.anomalies?.map((anomaly, index) => (
                    <div key={index} className="bg-gray-900/50 rounded-lg p-4 border-l-4 border-orange-500">
                      <h4 className="font-medium text-white mb-2">{anomaly.type}</h4>
                      <p className="text-sm text-gray-400">{anomaly.description}</p>
                      <div className="mt-2 text-xs text-gray-500">
                        Detected at: {formatDateTime(anomaly.timestamp)}
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {activeTab === 'raw' && (
                <div className="bg-gray-900 rounded-lg p-4 overflow-auto max-h-96">
                  <pre className="text-xs text-gray-300">
                    {JSON.stringify(analysis, null, 2)}
                  </pre>
                </div>
              )}
            </motion.div>
          </AnimatePresence>
        </Card>
      )}
    </div>
  );
}