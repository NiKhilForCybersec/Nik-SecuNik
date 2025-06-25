import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import {
  Shield,
  AlertTriangle,
  Activity,
  FileText,
  TrendingUp,
  Clock,
  Eye,
  Zap,
  Users,
  Server,
  Database,
  Wifi,
  RefreshCw
} from 'lucide-react'
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend
} from 'recharts'
import { historyService } from '../services/historyService'
import { uploadService } from '../services/uploadService'
import { wsManager } from '../services/websocket'
import toast from 'react-hot-toast'
import { format } from 'date-fns'

interface DashboardStats {
  total_analyses: number
  by_severity: Record<string, number>
  by_file_type: Record<string, number>
  by_date: Array<{ date: string; count: number }>
  top_techniques: Array<{ technique: string; count: number }>
  total_iocs: number
  threat_score_avg: number
}

interface SystemService {
  name: string
  status: 'online' | 'warning' | 'offline'
  icon: React.ElementType
  latency?: number
}

const Dashboard: React.FC = () => {
  const [threatLevel, setThreatLevel] = useState<'low' | 'medium' | 'high' | 'critical'>('low')
  const [historyStats, setHistoryStats] = useState<DashboardStats | null>(null)
  const [recentUploads, setRecentUploads] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [systemServices, setSystemServices] = useState<SystemService[]>([
    { name: 'API Server', status: 'online', icon: Server },
    { name: 'WebSocket', status: 'offline', icon: Wifi },
    { name: 'Database', status: 'online', icon: Database },
    { name: 'Analysis Engine', status: 'online', icon: Zap }
  ])

  useEffect(() => {
    loadDashboardData()
    
    // Subscribe to system status updates
    const unsubscribe = wsManager.subscribe('system_status', (message) => {
      handleSystemStatusUpdate(message.data)
    })
    
    // Update WebSocket status based on connection
    updateWebSocketStatus()
    
    // Set up auto-refresh every 30 seconds
    const refreshInterval = setInterval(() => {
      loadDashboardData(true)
    }, 30000)
    
    return () => {
      unsubscribe()
      clearInterval(refreshInterval)
    }
  }, [])

  const updateWebSocketStatus = () => {
    setSystemServices(prev => prev.map(service => 
      service.name === 'WebSocket' 
        ? { ...service, status: wsManager.isConnected() ? 'online' : 'offline' }
        : service
    ))
  }

  const handleSystemStatusUpdate = (status: any) => {
    if (status.services) {
      setSystemServices(prev => prev.map(service => {
        const updatedService = status.services.find((s: any) => s.name === service.name)
        return updatedService ? { ...service, ...updatedService } : service
      }))
    }
  }

  const loadDashboardData = async (isRefresh = false) => {
    try {
      if (isRefresh) {
        setRefreshing(true)
      } else {
        setLoading(true)
      }
      setError(null)
      
      // Load data in parallel
      const [historyData, uploadsData] = await Promise.all([
        historyService.getHistoryStats(30),
        uploadService.listUploads({ limit: 10 })
      ])
      
      setHistoryStats(historyData)
      setRecentUploads(uploadsData.uploads || [])
      
      // Determine threat level
      determineThreatLevel(historyData)
      
    } catch (error: any) {
      console.error('Failed to load dashboard data:', error)
      setError(error.message || 'Failed to load dashboard data')
      if (!isRefresh) {
        toast.error('Failed to load dashboard data')
      }
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }

  const determineThreatLevel = (stats: DashboardStats) => {
    if (!stats.by_severity) return
    
    const { critical = 0, high = 0, medium = 0 } = stats.by_severity
    
    if (critical > 0) {
      setThreatLevel('critical')
    } else if (high > 5 || (high > 0 && medium > 10)) {
      setThreatLevel('high')
    } else if (high > 0 || medium > 5) {
      setThreatLevel('medium')
    } else {
      setThreatLevel('low')
    }
  }

  const getAlertColor = (level: string) => {
    const colors = {
      critical: 'border-l-red-500 bg-red-900/10',
      high: 'border-l-orange-500 bg-orange-900/10',
      medium: 'border-l-yellow-500 bg-yellow-900/10',
      low: 'border-l-blue-500 bg-blue-900/10'
    }
    return colors[level as keyof typeof colors] || colors.low
  }

  const getThreatLevelColor = (level: string) => {
    const colors = {
      critical: 'text-red-400 bg-red-900/30',
      high: 'text-orange-400 bg-orange-900/30',
      medium: 'text-yellow-400 bg-yellow-900/30',
      low: 'text-green-400 bg-green-900/30'
    }
    return colors[level as keyof typeof colors] || colors.low
  }

  const formatNumber = (num: number): string => {
    if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`
    if (num >= 1000) return `${(num / 1000).toFixed(1)}K`
    return num.toString()
  }

  if (loading && !refreshing) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-500 mx-auto mb-4"></div>
          <p className="text-gray-400">Loading dashboard data...</p>
        </div>
      </div>
    )
  }

  if (error && !historyStats) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <AlertTriangle className="w-12 h-12 text-red-500 mx-auto mb-4" />
          <p className="text-red-400 mb-4">{error}</p>
          <button
            onClick={() => loadDashboardData()}
            className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700"
          >
            Retry
          </button>
        </div>
      </div>
    )
  }

  const statsData = historyStats ? [
    {
      title: 'Total Analyses',
      value: formatNumber(historyStats.total_analyses),
      icon: Activity,
      color: 'text-blue-400',
      change: '+12%'
    },
    {
      title: 'Threats Detected',
      value: formatNumber(
        (historyStats.by_severity?.critical || 0) + 
        (historyStats.by_severity?.high || 0)
      ),
      icon: AlertTriangle,
      color: 'text-red-400',
      change: '-5%'
    },
    {
      title: 'IOCs Extracted',
      value: formatNumber(historyStats.total_iocs || 0),
      icon: Eye,
      color: 'text-purple-400',
      change: '+23%'
    },
    {
      title: 'Avg Threat Score',
      value: `${(historyStats.threat_score_avg || 0).toFixed(1)}%`,
      icon: TrendingUp,
      color: 'text-green-400',
      change: '+3%'
    }
  ] : []

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">Security Dashboard</h1>
          <p className="text-gray-400 mt-2">
            Real-time security monitoring and analysis overview
          </p>
        </div>
        <div className="flex items-center space-x-4">
          <button
            onClick={() => loadDashboardData(true)}
            disabled={refreshing}
            className="flex items-center space-x-2 px-4 py-2 bg-slate-800 text-white rounded-lg hover:bg-slate-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
          <div className={`px-4 py-2 rounded-lg ${getThreatLevelColor(threatLevel)}`}>
            <span className="font-semibold">Threat Level: {threatLevel.toUpperCase()}</span>
          </div>
        </div>
      </div>

      {/* System Status */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="grid grid-cols-1 md:grid-cols-4 gap-4"
      >
        {systemServices.map((service, index) => {
          const Icon = service.icon
          return (
            <motion.div
              key={service.name}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
              className="bg-slate-900/50 rounded-lg p-4 border border-slate-800"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <Icon className="w-5 h-5 text-gray-400" />
                  <div>
                    <p className="text-sm font-medium text-white">{service.name}</p>
                    <div className="flex items-center space-x-2 mt-1">
                      <div className={`status-indicator ${
                        service.status === 'online' 
                          ? 'status-online' 
                          : service.status === 'warning'
                          ? 'status-warning'
                          : 'status-offline'
                      }`}></div>
                      <span className={`text-xs ${
                        service.status === 'online' 
                          ? 'text-green-400' 
                          : service.status === 'warning'
                          ? 'text-yellow-400'
                          : 'text-red-400'
                      }`}>
                        {service.status}
                      </span>
                    </div>
                  </div>
                </div>
                {service.latency && (
                  <span className="text-xs text-gray-500">{service.latency}ms</span>
                )}
              </div>
            </motion.div>
          )
        })}
      </motion.div>

      {/* Stats Overview */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {statsData.map((stat, index) => {
          const Icon = stat.icon
          return (
            <motion.div
              key={stat.title}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 + index * 0.1 }}
              className="bg-slate-900/50 rounded-lg p-6 border border-slate-800 hover:border-slate-700 transition-colors"
            >
              <div className="flex items-center justify-between mb-4">
                <Icon className={`w-8 h-8 ${stat.color}`} />
                <span className={`text-xs ${
                  stat.change.startsWith('+') ? 'text-green-400' : 'text-red-400'
                }`}>
                  {stat.change}
                </span>
              </div>
              <h3 className="text-sm font-medium text-gray-400">{stat.title}</h3>
              <p className="text-2xl font-bold text-white mt-1">{stat.value}</p>
            </motion.div>
          )
        })}
      </div>

      {/* Charts */}
      {historyStats && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Timeline Chart */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className="bg-slate-900/50 rounded-lg p-6 border border-slate-800"
          >
            <h3 className="text-lg font-semibold text-white mb-6">Analysis Timeline</h3>
            {historyStats.by_date && historyStats.by_date.length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <AreaChart data={historyStats.by_date}>
                  <defs>
                    <linearGradient id="colorAnalyses" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.8}/>
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis 
                    dataKey="date" 
                    stroke="#9ca3af"
                    tickFormatter={(date) => format(new Date(date), 'MMM dd')}
                  />
                  <YAxis stroke="#9ca3af" />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#1f2937',
                      border: '1px solid #374151',
                      borderRadius: '8px',
                      color: '#fff'
                    }}
                    labelFormatter={(date) => format(new Date(date), 'PPP')}
                  />
                  <Area
                    type="monotone"
                    dataKey="count"
                    stroke="#3b82f6"
                    fillOpacity={1}
                    fill="url(#colorAnalyses)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-[300px] flex items-center justify-center">
                <p className="text-gray-400">No timeline data available</p>
              </div>
            )}
          </motion.div>

          {/* File Type Distribution */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4 }}
            className="bg-slate-900/50 rounded-lg p-6 border border-slate-800"
          >
            <h3 className="text-lg font-semibold text-white mb-6">File Type Distribution</h3>
            {historyStats.by_file_type && Object.keys(historyStats.by_file_type).length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={Object.entries(historyStats.by_file_type).map(([key, value]) => ({
                      name: key.charAt(0).toUpperCase() + key.slice(1),
                      value: value as number,
                      color: ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6'][
                        Object.keys(historyStats.by_file_type).indexOf(key) % 5
                      ]
                    }))}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={100}
                    paddingAngle={5}
                    dataKey="value"
                  >
                    {Object.entries(historyStats.by_file_type).map((entry, index) => (
                      <Cell 
                        key={`cell-${index}`} 
                        fill={['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6'][index % 5]} 
                      />
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
                  <Legend 
                    verticalAlign="middle" 
                    align="right"
                    layout="vertical"
                    wrapperStyle={{
                      paddingLeft: '20px',
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-[300px] flex items-center justify-center">
                <p className="text-gray-400">No file type data available</p>
              </div>
            )}
          </motion.div>
        </div>
      )}

      {/* Recent Uploads */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.5 }}
        className="bg-slate-900/50 rounded-lg p-6 border border-slate-800"
      >
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-lg font-semibold text-white">Recent Uploads</h3>
          <a 
            href="/history" 
            className="text-sm text-primary-400 hover:text-primary-300 transition-colors"
          >
            View all →
          </a>
        </div>
        {recentUploads.length > 0 ? (
          <div className="space-y-4">
            {recentUploads.slice(0, 5).map((upload) => (
              <div
                key={upload.id}
                className="flex items-center justify-between p-4 bg-slate-800/50 rounded-lg hover:bg-slate-800/70 transition-colors"
              >
                <div className="flex items-center space-x-3">
                  <FileText className="w-5 h-5 text-primary-400" />
                  <div>
                    <h4 className="text-sm font-medium text-white">{upload.filename}</h4>
                    <p className="text-xs text-gray-400">
                      {format(new Date(upload.upload_time), 'PPp')} • {upload.status}
                    </p>
                  </div>
                </div>
                <div className="flex items-center space-x-2">
                  <span className="text-xs text-gray-400">
                    {(upload.file_size / 1024 / 1024).toFixed(2)} MB
                  </span>
                  {upload.status === 'parsed' && (
                    <button
                      onClick={() => window.location.href = `/upload`}
                      className="p-1 text-gray-400 hover:text-white transition-colors"
                    >
                      <Eye className="w-4 h-4" />
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-8">
            <FileText className="w-12 h-12 text-gray-400 mx-auto mb-4" />
            <p className="text-gray-400">No recent uploads</p>
            <button
              onClick={() => window.location.href = '/upload'}
              className="mt-4 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors"
            >
              Upload Files
            </button>
          </div>
        )}
      </motion.div>

      {/* Top MITRE Techniques */}
      {historyStats?.top_techniques && historyStats.top_techniques.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.6 }}
          className="bg-slate-900/50 rounded-lg p-6 border border-slate-800"
        >
          <h3 className="text-lg font-semibold text-white mb-6">Top MITRE ATT&CK Techniques</h3>
          <div className="space-y-3">
            {historyStats.top_techniques.slice(0, 5).map((technique, index) => (
              <div key={technique.technique} className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <span className="text-sm font-mono text-primary-400">
                    {technique.technique}
                  </span>
                </div>
                <div className="flex items-center space-x-2">
                  <div className="w-32 bg-slate-700 rounded-full h-2">
                    <div
                      className="bg-primary-500 h-2 rounded-full transition-all duration-500"
                      style={{
                        width: `${(technique.count / historyStats.top_techniques[0].count) * 100}%`
                      }}
                    />
                  </div>
                  <span className="text-sm text-gray-400 w-10 text-right">
                    {technique.count}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </motion.div>
      )}
    </div>
  )
}

export default Dashboard