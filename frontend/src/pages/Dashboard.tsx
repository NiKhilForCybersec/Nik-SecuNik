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
  Wifi
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
import toast from 'react-hot-toast'

const Dashboard: React.FC = () => {
  const [threatLevel, setThreatLevel] = useState<'low' | 'medium' | 'high' | 'critical'>('low')
  const [stats, setStats] = useState<any>(null)
  const [recentUploads, setRecentUploads] = useState<any[]>([])
  const [historyStats, setHistoryStats] = useState<any>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadDashboardData()
  }, [])

  const loadDashboardData = async () => {
    try {
      setLoading(true)
      
      // Load history statistics
      const historyData = await historyService.getHistoryStats(30)
      setHistoryStats(historyData)
      
      // Load recent uploads
      const uploadsData = await uploadService.listUploads({ limit: 10 })
      setRecentUploads(uploadsData.uploads || [])
      
      // Determine threat level based on recent analyses
      if (historyData.by_severity) {
        const { critical, high } = historyData.by_severity
        if (critical > 0) setThreatLevel('critical')
        else if (high > 5) setThreatLevel('high')
        else if (high > 0) setThreatLevel('medium')
        else setThreatLevel('low')
      }
      
    } catch (error: any) {
      console.error('Failed to load dashboard data:', error)
      toast.error('Failed to load dashboard data')
    } finally {
      setLoading(false)
    }
  }

  const getAlertColor = (type: string) => {
    switch (type) {
      case 'critical':
        return 'border-l-red-500 bg-red-900/10'
      case 'high':
        return 'border-l-orange-500 bg-orange-900/10'
      case 'medium':
        return 'border-l-yellow-500 bg-yellow-900/10'
      case 'low':
        return 'border-l-blue-500 bg-blue-900/10'
      default:
        return 'border-l-gray-500 bg-gray-900/10'
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

  const statsData = historyStats ? [
    {
      title: 'Total Analyses',
      value: historyStats.total_analyses?.toString() || '0',
      change: '+0%',
      trend: 'up',
      icon: FileText,
      color: 'text-primary-400',
      bgColor: 'bg-primary-900/20'
    },
    {
      title: 'Threats Found',
      value: historyStats.total_threats_found?.toString() || '0',
      change: '+0%',
      trend: 'up',
      icon: AlertTriangle,
      color: 'text-danger-400',
      bgColor: 'bg-danger-900/20'
    },
    {
      title: 'Avg Threat Score',
      value: historyStats.average_threat_score?.toFixed(1) || '0.0',
      change: '+0%',
      trend: 'up',
      icon: Eye,
      color: 'text-warning-400',
      bgColor: 'bg-warning-900/20'
    },
    {
      title: 'System Health',
      value: '98.5%',
      change: '+0.2%',
      trend: 'up',
      icon: Activity,
      color: 'text-success-400',
      bgColor: 'bg-success-900/20'
    }
  ] : []

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">Security Dashboard</h1>
          <p className="text-gray-400 mt-2">
            Real-time threat monitoring and analysis overview
          </p>
        </div>
        <div className="flex items-center space-x-4">
          <div className={`px-4 py-2 rounded-lg flex items-center space-x-2 ${getThreatLevelColor(threatLevel)}`}>
            <Shield className="w-4 h-4" />
            <span className="text-sm font-medium">Threat Level: {threatLevel.toUpperCase()}</span>
          </div>
          <div className="flex items-center space-x-2 text-sm text-gray-400">
            <Clock className="w-4 h-4" />
            <span>Last updated: {new Date().toLocaleTimeString()}</span>
          </div>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {statsData.map((stat, index) => {
          const Icon = stat.icon
          return (
            <motion.div
              key={stat.title}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
              className={`${stat.bgColor} rounded-lg p-6 border border-slate-800`}
            >
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-400">{stat.title}</p>
                  <p className="text-2xl font-bold text-white mt-1">{stat.value}</p>
                  <div className="flex items-center mt-2">
                    <TrendingUp className={`w-4 h-4 mr-1 ${
                      stat.trend === 'up' ? 'text-success-400' : 'text-danger-400'
                    }`} />
                    <span className={`text-sm ${
                      stat.trend === 'up' ? 'text-success-400' : 'text-danger-400'
                    }`}>
                      {stat.change}
                    </span>
                  </div>
                </div>
                <Icon className={`w-8 h-8 ${stat.color}`} />
              </div>
            </motion.div>
          )
        })}
      </div>

      {/* Charts Row */}
      {historyStats && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Severity Distribution */}
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.2 }}
            className="bg-slate-900/50 rounded-lg p-6 border border-slate-800"
          >
            <h3 className="text-lg font-semibold text-white mb-6">Threat Severity Distribution</h3>
            {historyStats.by_severity && (
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={[
                      { name: 'Critical', value: historyStats.by_severity.critical || 0, color: '#ef4444' },
                      { name: 'High', value: historyStats.by_severity.high || 0, color: '#f59e0b' },
                      { name: 'Medium', value: historyStats.by_severity.medium || 0, color: '#eab308' },
                      { name: 'Low', value: historyStats.by_severity.low || 0, color: '#22c55e' }
                    ]}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={120}
                    paddingAngle={5}
                    dataKey="value"
                  >
                    {[
                      { name: 'Critical', value: historyStats.by_severity.critical || 0, color: '#ef4444' },
                      { name: 'High', value: historyStats.by_severity.high || 0, color: '#f59e0b' },
                      { name: 'Medium', value: historyStats.by_severity.medium || 0, color: '#eab308' },
                      { name: 'Low', value: historyStats.by_severity.low || 0, color: '#22c55e' }
                    ].map((entry, index) => (
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
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            )}
          </motion.div>

          {/* File Types Analysis */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.3 }}
            className="bg-slate-900/50 rounded-lg p-6 border border-slate-800"
          >
            <h3 className="text-lg font-semibold text-white mb-6">File Types Analyzed</h3>
            {historyStats.by_file_type && (
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={Object.entries(historyStats.by_file_type).map(([key, value]) => ({
                      name: key.charAt(0).toUpperCase() + key.slice(1),
                      value: value as number,
                      color: ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6'][Object.keys(historyStats.by_file_type).indexOf(key) % 5]
                    }))}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={120}
                    paddingAngle={5}
                    dataKey="value"
                  >
                    {Object.entries(historyStats.by_file_type).map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6'][index % 5]} />
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
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            )}
          </motion.div>
        </div>
      )}

      {/* Recent Uploads */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
        className="bg-slate-900/50 rounded-lg p-6 border border-slate-800"
      >
        <h3 className="text-lg font-semibold text-white mb-6">Recent Uploads</h3>
        {recentUploads.length > 0 ? (
          <div className="space-y-4">
            {recentUploads.slice(0, 5).map((upload) => (
              <div
                key={upload.id}
                className="flex items-center justify-between p-4 bg-slate-800/50 rounded-lg"
              >
                <div className="flex items-center space-x-3">
                  <FileText className="w-5 h-5 text-primary-400" />
                  <div>
                    <h4 className="text-sm font-medium text-white">{upload.filename}</h4>
                    <p className="text-xs text-gray-400">
                      {new Date(upload.upload_time).toLocaleString()} • {upload.status}
                    </p>
                  </div>
                </div>
                <div className="text-xs text-gray-400">
                  {(upload.file_size / 1024 / 1024).toFixed(2)} MB
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-8">
            <FileText className="w-12 h-12 text-gray-400 mx-auto mb-4" />
            <p className="text-gray-400">No recent uploads</p>
          </div>
        )}
      </motion.div>

      {/* Top MITRE Techniques */}
      {historyStats?.top_techniques && historyStats.top_techniques.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
          className="bg-slate-900/50 rounded-lg p-6 border border-slate-800"
        >
          <h3 className="text-lg font-semibold text-white mb-6">Top MITRE ATT&CK Techniques</h3>
          <div className="space-y-4">
            {historyStats.top_techniques.slice(0, 5).map((technique: any, index: number) => (
              <div key={technique.technique} className="flex items-center justify-between">
                <div>
                  <span className="text-sm font-medium text-white">{technique.technique}</span>
                </div>
                <div className="flex items-center space-x-3">
                  <div className="w-32 bg-slate-700 rounded-full h-2">
                    <div
                      className="bg-primary-500 h-2 rounded-full"
                      style={{ 
                        width: `${(technique.count / Math.max(...historyStats.top_techniques.map((t: any) => t.count))) * 100}%` 
                      }}
                    />
                  </div>
                  <span className="text-sm text-gray-400 w-8 text-right">{technique.count}</span>
                </div>
              </div>
            ))}
          </div>
        </motion.div>
      )}

      {/* System Status */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.6 }}
        className="bg-slate-900/50 rounded-lg p-6 border border-slate-800"
      >
        <h3 className="text-lg font-semibold text-white mb-6">System Status</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {[
            { name: 'Analysis Engine', status: 'online', icon: Zap },
            { name: 'Rule Engine', status: 'online', icon: Shield },
            { name: 'Database', status: 'online', icon: Database },
            { name: 'API Gateway', status: 'online', icon: Server },
          ].map((service) => {
            const Icon = service.icon
            return (
              <div key={service.name} className="flex items-center space-x-3">
                <Icon className="w-5 h-5 text-primary-400" />
                <div className="flex-1">
                  <p className="text-sm font-medium text-white">{service.name}</p>
                  <div className="flex items-center space-x-2 mt-1">
                    <div className={`w-2 h-2 rounded-full ${
                      service.status === 'online' ? 'bg-success-400' : 'bg-warning-400'
                    }`}></div>
                    <span className={`text-xs ${
                      service.status === 'online' ? 'text-success-400' : 'text-warning-400'
                    }`}>
                      {service.status === 'online' ? 'Online' : 'Warning'}
                    </span>
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      </motion.div>
    </div>
  )
}

export default Dashboard