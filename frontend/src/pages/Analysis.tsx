import React, { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import {
  Search,
  Filter,
  Download,
  Share,
  AlertTriangle,
  Shield,
  Eye,
  Clock,
  FileText,
  Network,
  Bug,
  Zap,
  TrendingUp,
  Activity,
  ArrowLeft
} from 'lucide-react'
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell
} from 'recharts'
import { analysisService } from '../services/analysisService'
import { historyService } from '../services/historyService'
import { useAnalysisById } from '../hooks/useAnalysis'
import toast from 'react-hot-toast'

const Analysis: React.FC = () => {
  const { id } = useParams()
  const navigate = useNavigate()
  const [activeTab, setActiveTab] = useState('overview')
  const [analysisData, setAnalysisData] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Use WebSocket hook for real-time updates if analysis is in progress
  const liveAnalysis = useAnalysisById(id)

  useEffect(() => {
    if (id) {
      loadAnalysisData(id)
    }
  }, [id])

  const loadAnalysisData = async (analysisId: string) => {
    try {
      setLoading(true)
      setError(null)

      // Try to get from history first
      const historyData = await historyService.getAnalysisDetails(analysisId)
      if (historyData) {
        setAnalysisData(historyData)
      } else {
        // If not in history, try to get current analysis results
        const results = await analysisService.getAnalysisResults(analysisId)
        setAnalysisData(results)
      }
    } catch (error: any) {
      console.error('Failed to load analysis data:', error)
      setError(error.message || 'Failed to load analysis data')
      toast.error('Failed to load analysis data')
    } finally {
      setLoading(false)
    }
  }

  const exportAnalysis = async (format: string) => {
    if (!id) return
    
    try {
      const data = await analysisService.exportAnalysis(id, format)
      
      // Create download link
      const blob = new Blob([JSON.stringify(data, null, 2)], { 
        type: format === 'json' ? 'application/json' : 'text/csv' 
      })
      const url = window.URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `analysis_${id}.${format}`
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      window.URL.revokeObjectURL(url)
      
      toast.success(`Analysis exported as ${format.toUpperCase()}`)
    } catch (error: any) {
      console.error('Export failed:', error)
      toast.error('Failed to export analysis')
    }
  }

  const tabs = [
    { id: 'overview', label: 'Overview', icon: Activity },
    { id: 'events', label: 'Events Timeline', icon: Clock },
    { id: 'iocs', label: 'IOCs & Threats', icon: AlertTriangle },
    { id: 'patterns', label: 'Patterns', icon: Search },
    { id: 'yara', label: 'YARA Results', icon: Shield },
    { id: 'sigma', label: 'Sigma Results', icon: Bug },
    { id: 'mitre', label: 'MITRE ATT&CK', icon: Network },
    { id: 'ai', label: 'AI Insights', icon: Zap },
  ]

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'text-red-400 bg-red-900/30'
      case 'high':
        return 'text-orange-400 bg-orange-900/30'
      case 'medium':
        return 'text-yellow-400 bg-yellow-900/30'
      case 'low':
        return 'text-green-400 bg-green-900/30'
      default:
        return 'text-gray-400 bg-gray-900/30'
    }
  }

  const getThreatLevelColor = (level: string) => {
    switch (level) {
      case 'critical':
        return 'text-red-400 bg-red-900/30'
      case 'high':
        return 'text-orange-400 bg-orange-900/30'
      case 'medium':
        return 'text-yellow-400 bg-yellow-900/30'
      case 'low':
        return 'text-green-400 bg-green-900/30'
      default:
        return 'text-gray-400 bg-gray-900/30'
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-500"></div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="text-center py-12">
        <AlertTriangle className="w-12 h-12 text-red-400 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-gray-300 mb-2">Analysis Error</h3>
        <p className="text-gray-400 mb-4">{error}</p>
        <button
          onClick={() => navigate('/history')}
          className="flex items-center space-x-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors mx-auto"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to History</span>
        </button>
      </div>
    )
  }

  if (!analysisData) {
    return (
      <div className="text-center py-12">
        <AlertTriangle className="w-12 h-12 text-gray-400 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-gray-300 mb-2">Analysis not found</h3>
        <p className="text-gray-400">The requested analysis could not be found.</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <button
            onClick={() => navigate('/history')}
            className="p-2 text-gray-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
          >
            <ArrowLeft className="w-5 h-5" />
          </button>
          <div>
            <h1 className="text-3xl font-bold text-white">Analysis Results</h1>
            <div className="flex items-center space-x-4 mt-2 text-sm text-gray-400">
              <span>File: {analysisData.file_info?.filename || 'Unknown'}</span>
              {analysisData.file_info?.file_size && (
                <>
                  <span>•</span>
                  <span>Size: {(analysisData.file_info.file_size / 1024 / 1024).toFixed(2)} MB</span>
                </>
              )}
            </div>
          </div>
        </div>
        <div className="flex items-center space-x-3">
          {analysisData.severity && (
            <div className={`px-3 py-1 rounded-lg text-sm font-medium ${getThreatLevelColor(analysisData.severity)}`}>
              Threat Level: {analysisData.severity.toUpperCase()}
            </div>
          )}
          <button 
            onClick={() => exportAnalysis('json')}
            className="flex items-center space-x-2 px-4 py-2 bg-slate-800 text-white rounded-lg hover:bg-slate-700 transition-colors"
          >
            <Download className="w-4 h-4" />
            <span>Export</span>
          </button>
          <button className="flex items-center space-x-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors">
            <Share className="w-4 h-4" />
            <span>Share</span>
          </button>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        {[
          { 
            title: 'Threat Score', 
            value: analysisData.threat_score?.toString() || '0', 
            icon: Activity, 
            color: 'text-blue-400' 
          },
          { 
            title: 'IOCs Found', 
            value: analysisData.iocs?.length?.toString() || '0', 
            icon: Eye, 
            color: 'text-yellow-400' 
          },
          { 
            title: 'YARA Matches', 
            value: analysisData.yara_results?.length?.toString() || '0', 
            icon: Shield, 
            color: 'text-green-400' 
          },
          { 
            title: 'Sigma Matches', 
            value: analysisData.sigma_results?.length?.toString() || '0', 
            icon: Bug, 
            color: 'text-purple-400' 
          },
          { 
            title: 'MITRE Techniques', 
            value: analysisData.mitre_results?.techniques?.length?.toString() || '0', 
            icon: Network, 
            color: 'text-red-400' 
          },
        ].map((stat, index) => {
          const Icon = stat.icon
          return (
            <motion.div
              key={stat.title}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
              className="bg-slate-900/50 rounded-lg p-4 border border-slate-800"
            >
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-400">{stat.title}</p>
                  <p className="text-xl font-bold text-white mt-1">{stat.value}</p>
                </div>
                <Icon className={`w-6 h-6 ${stat.color}`} />
              </div>
            </motion.div>
          )
        })}
      </div>

      {/* Tabs */}
      <div className="bg-slate-900/50 rounded-lg border border-slate-800">
        <div className="border-b border-slate-700">
          <nav className="flex space-x-8 px-6 overflow-x-auto">
            {tabs.map((tab) => {
              const Icon = tab.icon
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center space-x-2 py-4 px-1 border-b-2 font-medium text-sm transition-colors whitespace-nowrap ${
                    activeTab === tab.id
                      ? 'border-primary-500 text-primary-400'
                      : 'border-transparent text-gray-400 hover:text-gray-300'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  <span>{tab.label}</span>
                </button>
              )
            })}
          </nav>
        </div>

        <div className="p-6">
          {/* Overview Tab */}
          {activeTab === 'overview' && (
            <div className="space-y-6">
              {/* Summary */}
              {analysisData.summary && (
                <div className="bg-slate-800/50 rounded-lg p-4">
                  <h3 className="text-lg font-semibold text-white mb-2">Analysis Summary</h3>
                  <p className="text-gray-300">{analysisData.summary}</p>
                </div>
              )}

              {/* AI Insights */}
              {analysisData.ai_insights && (
                <div className="bg-slate-800/50 rounded-lg p-4">
                  <h3 className="text-lg font-semibold text-white mb-4">AI Insights</h3>
                  <div className="space-y-4">
                    {analysisData.ai_insights.analysis && (
                      <div>
                        <h4 className="text-sm font-medium text-primary-400 mb-2">Analysis</h4>
                        <p className="text-gray-300 text-sm">{analysisData.ai_insights.analysis}</p>
                      </div>
                    )}
                    
                    {analysisData.ai_insights.key_findings && analysisData.ai_insights.key_findings.length > 0 && (
                      <div>
                        <h4 className="text-sm font-medium text-primary-400 mb-2">Key Findings</h4>
                        <ul className="list-disc list-inside space-y-1">
                          {analysisData.ai_insights.key_findings.map((finding: string, index: number) => (
                            <li key={index} className="text-gray-300 text-sm">{finding}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                    
                    {analysisData.ai_insights.recommendations && analysisData.ai_insights.recommendations.length > 0 && (
                      <div>
                        <h4 className="text-sm font-medium text-primary-400 mb-2">Recommendations</h4>
                        <ul className="list-disc list-inside space-y-1">
                          {analysisData.ai_insights.recommendations.map((rec: string, index: number) => (
                            <li key={index} className="text-gray-300 text-sm">{rec}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* IOCs Tab */}
          {activeTab === 'iocs' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-semibold text-white">Indicators of Compromise (IOCs)</h3>
              </div>

              {analysisData.iocs && analysisData.iocs.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-slate-700">
                        <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                          Type
                        </th>
                        <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                          Value
                        </th>
                        <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                          Context
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-700">
                      {analysisData.iocs.map((ioc: any, index: number) => (
                        <tr key={index} className="hover:bg-slate-800/50 transition-colors">
                          <td className="px-4 py-4">
                            <span className="px-2 py-1 bg-primary-900/30 text-primary-300 text-xs rounded">
                              {ioc.type}
                            </span>
                          </td>
                          <td className="px-4 py-4">
                            <span className="text-sm text-white font-mono">{ioc.value}</span>
                          </td>
                          <td className="px-4 py-4">
                            <span className="text-sm text-gray-300">{ioc.context || 'N/A'}</span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="text-center py-8">
                  <Eye className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                  <p className="text-gray-400">No IOCs found in this analysis</p>
                </div>
              )}
            </div>
          )}

          {/* YARA Results Tab */}
          {activeTab === 'yara' && (
            <div className="space-y-6">
              <h3 className="text-lg font-semibold text-white">YARA Rule Matches</h3>
              
              {analysisData.yara_results && analysisData.yara_results.length > 0 ? (
                <div className="space-y-4">
                  {analysisData.yara_results.map((result: any, index: number) => (
                    <div key={index} className="bg-slate-800/50 rounded-lg p-4">
                      <div className="flex items-center justify-between mb-2">
                        <h4 className="text-sm font-medium text-white">{result.rule}</h4>
                        <span className={`px-2 py-1 text-xs rounded ${getSeverityColor(result.severity || 'medium')}`}>
                          {result.severity?.toUpperCase() || 'MEDIUM'}
                        </span>
                      </div>
                      {result.meta?.description && (
                        <p className="text-sm text-gray-300 mb-2">{result.meta.description}</p>
                      )}
                      <div className="flex items-center space-x-4 text-xs text-gray-400">
                        <span>Matches: {result.matches || 1}</span>
                        {result.meta?.author && <span>Author: {result.meta.author}</span>}
                        {result.tags && result.tags.length > 0 && (
                          <div className="flex space-x-1">
                            {result.tags.map((tag: string, tagIndex: number) => (
                              <span key={tagIndex} className="px-1 py-0.5 bg-slate-700 rounded text-xs">
                                {tag}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8">
                  <Shield className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                  <p className="text-gray-400">No YARA rule matches found</p>
                </div>
              )}
            </div>
          )}

          {/* MITRE ATT&CK Tab */}
          {activeTab === 'mitre' && (
            <div className="space-y-6">
              <h3 className="text-lg font-semibold text-white">MITRE ATT&CK Techniques</h3>
              
              {analysisData.mitre_results?.techniques && analysisData.mitre_results.techniques.length > 0 ? (
                <div className="space-y-4">
                  {analysisData.mitre_results.techniques.map((technique: any, index: number) => (
                    <div key={index} className="bg-slate-800/50 rounded-lg p-4">
                      <div className="flex items-center justify-between mb-2">
                        <h4 className="text-sm font-medium text-white">
                          {technique.technique_id}: {technique.technique_name}
                        </h4>
                        <div className="flex items-center space-x-2">
                          <span className="text-xs text-gray-400">
                            Confidence: {Math.round((technique.confidence || 0) * 100)}%
                          </span>
                          <span className="px-2 py-1 bg-blue-900/30 text-blue-300 text-xs rounded">
                            {technique.tactic}
                          </span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8">
                  <Network className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                  <p className="text-gray-400">No MITRE ATT&CK techniques identified</p>
                </div>
              )}
            </div>
          )}

          {/* Other tabs would show "No data available" or implement based on available data */}
          {!['overview', 'iocs', 'yara', 'mitre'].includes(activeTab) && (
            <div className="text-center py-12">
              <FileText className="w-12 h-12 text-gray-400 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-gray-300 mb-2">
                {tabs.find(t => t.id === activeTab)?.label} Analysis
              </h3>
              <p className="text-gray-400">
                Detailed {activeTab} analysis results will be displayed here.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default Analysis