import React, { useState, useEffect } from 'react'
import { useParams } from 'react-router-dom'
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
  Activity
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

interface AnalysisData {
  id: string
  fileName: string
  fileType: string
  fileSize: string
  uploadTime: Date
  analysisTime: Date
  status: 'completed' | 'processing' | 'failed'
  threatLevel: 'low' | 'medium' | 'high' | 'critical'
  summary: {
    totalEvents: number
    threatsDetected: number
    iocsFound: number
    patternsMatched: number
    anomaliesDetected: number
  }
}

const Analysis: React.FC = () => {
  const { id } = useParams()
  const [activeTab, setActiveTab] = useState('overview')
  const [analysisData, setAnalysisData] = useState<AnalysisData | null>(null)
  const [loading, setLoading] = useState(true)

  // Mock data - replace with actual API call
  useEffect(() => {
    setTimeout(() => {
      setAnalysisData({
        id: id || 'sample_analysis',
        fileName: 'system_logs_2024.log',
        fileType: 'System Log',
        fileSize: '2.4 MB',
        uploadTime: new Date('2024-01-15T10:30:00'),
        analysisTime: new Date('2024-01-15T10:32:15'),
        status: 'completed',
        threatLevel: 'medium',
        summary: {
          totalEvents: 15847,
          threatsDetected: 23,
          iocsFound: 12,
          patternsMatched: 156,
          anomaliesDetected: 8
        }
      })
      setLoading(false)
    }, 1000)
  }, [id])

  const tabs = [
    { id: 'overview', label: 'Overview', icon: Activity },
    { id: 'events', label: 'Events Timeline', icon: Clock },
    { id: 'iocs', label: 'IOCs & Threats', icon: AlertTriangle },
    { id: 'patterns', label: 'Patterns', icon: Search },
    { id: 'anomalies', label: 'Anomalies', icon: Bug },
    { id: 'network', label: 'Network Analysis', icon: Network },
  ]

  const eventTimelineData = [
    { time: '00:00', events: 45, threats: 2 },
    { time: '04:00', events: 23, threats: 1 },
    { time: '08:00', events: 156, threats: 8 },
    { time: '12:00', events: 234, threats: 5 },
    { time: '16:00', events: 189, threats: 4 },
    { time: '20:00', events: 98, threats: 3 },
  ]

  const threatDistribution = [
    { name: 'Malware', value: 35, color: '#ef4444' },
    { name: 'Suspicious Activity', value: 28, color: '#f59e0b' },
    { name: 'Network Anomaly', value: 20, color: '#3b82f6' },
    { name: 'Policy Violation', value: 17, color: '#8b5cf6' },
  ]

  const recentEvents = [
    {
      id: 1,
      timestamp: '2024-01-15 10:45:23',
      severity: 'high',
      type: 'Malware Detection',
      description: 'Suspicious executable detected in system32 directory',
      source: 'YARA Rule: Win32_Trojan_Generic',
      details: 'File: svchost.exe, Hash: a1b2c3d4e5f6...'
    },
    {
      id: 2,
      timestamp: '2024-01-15 10:42:15',
      severity: 'medium',
      type: 'Network Anomaly',
      description: 'Unusual outbound connection to suspicious domain',
      source: 'Network Monitor',
      details: 'Destination: malicious-domain.com:443'
    },
    {
      id: 3,
      timestamp: '2024-01-15 10:38:47',
      severity: 'low',
      type: 'Authentication',
      description: 'Multiple failed login attempts detected',
      source: 'Sigma Rule: Auth_Bruteforce',
      details: 'User: admin, Source IP: 192.168.1.100'
    }
  ]

  const iocData = [
    {
      type: 'IP Address',
      value: '192.168.1.100',
      threat: 'Brute Force Attack',
      confidence: 85,
      vtDetections: 12,
      firstSeen: '2024-01-15 08:30:00'
    },
    {
      type: 'Domain',
      value: 'malicious-domain.com',
      threat: 'C&C Server',
      confidence: 92,
      vtDetections: 28,
      firstSeen: '2024-01-15 09:15:00'
    },
    {
      type: 'File Hash',
      value: 'a1b2c3d4e5f6789...',
      threat: 'Trojan',
      confidence: 98,
      vtDetections: 45,
      firstSeen: '2024-01-15 10:45:00'
    }
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
        <div>
          <h1 className="text-3xl font-bold text-white">Analysis Results</h1>
          <div className="flex items-center space-x-4 mt-2 text-sm text-gray-400">
            <span>File: {analysisData.fileName}</span>
            <span>•</span>
            <span>Type: {analysisData.fileType}</span>
            <span>•</span>
            <span>Size: {analysisData.fileSize}</span>
          </div>
        </div>
        <div className="flex items-center space-x-3">
          <div className={`px-3 py-1 rounded-lg text-sm font-medium ${getThreatLevelColor(analysisData.threatLevel)}`}>
            Threat Level: {analysisData.threatLevel.toUpperCase()}
          </div>
          <button className="flex items-center space-x-2 px-4 py-2 bg-slate-800 text-white rounded-lg hover:bg-slate-700 transition-colors">
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
          { title: 'Total Events', value: analysisData.summary.totalEvents.toLocaleString(), icon: Activity, color: 'text-blue-400' },
          { title: 'Threats Detected', value: analysisData.summary.threatsDetected.toString(), icon: AlertTriangle, color: 'text-red-400' },
          { title: 'IOCs Found', value: analysisData.summary.iocsFound.toString(), icon: Eye, color: 'text-yellow-400' },
          { title: 'Patterns Matched', value: analysisData.summary.patternsMatched.toString(), icon: Search, color: 'text-green-400' },
          { title: 'Anomalies', value: analysisData.summary.anomaliesDetected.toString(), icon: Bug, color: 'text-purple-400' },
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
          <nav className="flex space-x-8 px-6">
            {tabs.map((tab) => {
              const Icon = tab.icon
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center space-x-2 py-4 px-1 border-b-2 font-medium text-sm transition-colors ${
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
              {/* Charts Row */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Event Timeline */}
                <div>
                  <h3 className="text-lg font-semibold text-white mb-4">Event Timeline</h3>
                  <ResponsiveContainer width="100%" height={300}>
                    <AreaChart data={eventTimelineData}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                      <XAxis dataKey="time" stroke="#9ca3af" />
                      <YAxis stroke="#9ca3af" />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#1f2937',
                          border: '1px solid #374151',
                          borderRadius: '8px',
                          color: '#fff'
                        }}
                      />
                      <Area
                        type="monotone"
                        dataKey="events"
                        stroke="#3b82f6"
                        fill="#3b82f6"
                        fillOpacity={0.3}
                      />
                      <Area
                        type="monotone"
                        dataKey="threats"
                        stroke="#ef4444"
                        fill="#ef4444"
                        fillOpacity={0.3}
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>

                {/* Threat Distribution */}
                <div>
                  <h3 className="text-lg font-semibold text-white mb-4">Threat Distribution</h3>
                  <ResponsiveContainer width="100%" height={300}>
                    <PieChart>
                      <Pie
                        data={threatDistribution}
                        cx="50%"
                        cy="50%"
                        innerRadius={60}
                        outerRadius={120}
                        paddingAngle={5}
                        dataKey="value"
                      >
                        {threatDistribution.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#1f2937',
                          border: '1px solid #374151',
                          borderRadius: '8px',
                          color: '#fff'
                        }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Recent Events */}
              <div>
                <h3 className="text-lg font-semibold text-white mb-4">Recent Critical Events</h3>
                <div className="space-y-3">
                  {recentEvents.map((event) => (
                    <div
                      key={event.id}
                      className={`p-4 rounded-lg border-l-4 ${
                        event.severity === 'high' ? 'border-l-red-500 bg-red-900/10' :
                        event.severity === 'medium' ? 'border-l-yellow-500 bg-yellow-900/10' :
                        'border-l-blue-500 bg-blue-900/10'
                      }`}
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center space-x-3">
                            <span className={`px-2 py-1 text-xs rounded-full ${getSeverityColor(event.severity)}`}>
                              {event.severity.toUpperCase()}
                            </span>
                            <span className="text-sm font-medium text-white">{event.type}</span>
                            <span className="text-xs text-gray-400">{event.timestamp}</span>
                          </div>
                          <p className="text-sm text-gray-300 mt-2">{event.description}</p>
                          <div className="flex items-center justify-between mt-2">
                            <span className="text-xs text-gray-500">{event.source}</span>
                            <span className="text-xs text-gray-500">{event.details}</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* IOCs Tab */}
          {activeTab === 'iocs' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-semibold text-white">Indicators of Compromise (IOCs)</h3>
                <div className="flex items-center space-x-3">
                  <button className="flex items-center space-x-2 px-3 py-2 bg-slate-800 text-white rounded-lg hover:bg-slate-700 transition-colors">
                    <Filter className="w-4 h-4" />
                    <span>Filter</span>
                  </button>
                  <button className="flex items-center space-x-2 px-3 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors">
                    <Download className="w-4 h-4" />
                    <span>Export IOCs</span>
                  </button>
                </div>
              </div>

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
                        Threat
                      </th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                        Confidence
                      </th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                        VT Detections
                      </th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                        First Seen
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-700">
                    {iocData.map((ioc, index) => (
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
                          <span className="text-sm text-white">{ioc.threat}</span>
                        </td>
                        <td className="px-4 py-4">
                          <div className="flex items-center space-x-2">
                            <div className="w-16 bg-slate-700 rounded-full h-2">
                              <div
                                className="bg-primary-500 h-2 rounded-full"
                                style={{ width: `${ioc.confidence}%` }}
                              />
                            </div>
                            <span className="text-sm text-white">{ioc.confidence}%</span>
                          </div>
                        </td>
                        <td className="px-4 py-4">
                          <span className={`px-2 py-1 text-xs rounded ${
                            ioc.vtDetections > 20 ? 'bg-red-900/30 text-red-300' :
                            ioc.vtDetections > 10 ? 'bg-yellow-900/30 text-yellow-300' :
                            'bg-green-900/30 text-green-300'
                          }`}>
                            {ioc.vtDetections}/70
                          </span>
                        </td>
                        <td className="px-4 py-4">
                          <span className="text-sm text-gray-400">{ioc.firstSeen}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Other tabs would be implemented similarly */}
          {activeTab !== 'overview' && activeTab !== 'iocs' && (
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