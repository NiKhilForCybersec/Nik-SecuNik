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

const Dashboard: React.FC = () => {
  const [threatLevel, setThreatLevel] = useState<'low' | 'medium' | 'high' | 'critical'>('low')
  const [realtimeData, setRealtimeData] = useState<any[]>([])

  // Mock real-time data simulation
  useEffect(() => {
    const interval = setInterval(() => {
      const newData = {
        time: new Date().toLocaleTimeString(),
        threats: Math.floor(Math.random() * 10),
        events: Math.floor(Math.random() * 100) + 50,
        anomalies: Math.floor(Math.random() * 5)
      }
      setRealtimeData(prev => [...prev.slice(-19), newData])
    }, 2000)

    return () => clearInterval(interval)
  }, [])

  const stats = [
    {
      title: 'Active Threats',
      value: '23',
      change: '+12%',
      trend: 'up',
      icon: AlertTriangle,
      color: 'text-danger-400',
      bgColor: 'bg-danger-900/20'
    },
    {
      title: 'Files Analyzed',
      value: '1,247',
      change: '+8%',
      trend: 'up',
      icon: FileText,
      color: 'text-primary-400',
      bgColor: 'bg-primary-900/20'
    },
    {
      title: 'IOCs Detected',
      value: '89',
      change: '-3%',
      trend: 'down',
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
  ]

  const threatData = [
    { name: 'Jan', threats: 45, resolved: 42 },
    { name: 'Feb', threats: 52, resolved: 48 },
    { name: 'Mar', threats: 38, resolved: 35 },
    { name: 'Apr', threats: 67, resolved: 61 },
    { name: 'May', threats: 43, resolved: 40 },
    { name: 'Jun', threats: 58, resolved: 54 },
  ]

  const fileTypeData = [
    { name: 'Logs', value: 45, color: '#3b82f6' },
    { name: 'Network', value: 25, color: '#10b981' },
    { name: 'System', value: 15, color: '#f59e0b' },
    { name: 'Email', value: 10, color: '#ef4444' },
    { name: 'Other', value: 5, color: '#8b5cf6' },
  ]

  const recentAlerts = [
    {
      id: 1,
      type: 'critical',
      title: 'Ransomware Pattern Detected',
      description: 'Suspicious file encryption activity detected in network logs',
      time: '2 minutes ago',
      source: 'YARA Rule: Ransomware_Generic'
    },
    {
      id: 2,
      type: 'high',
      title: 'Multiple Failed Login Attempts',
      description: 'Brute force attack detected from IP 192.168.1.100',
      time: '5 minutes ago',
      source: 'Sigma Rule: Auth_Bruteforce'
    },
    {
      id: 3,
      type: 'medium',
      title: 'Unusual Network Traffic',
      description: 'Anomalous data transfer patterns detected',
      time: '12 minutes ago',
      source: 'AI Analyzer: Traffic_Anomaly'
    },
    {
      id: 4,
      type: 'low',
      title: 'New IOC Identified',
      description: 'Suspicious domain added to threat intelligence feed',
      time: '18 minutes ago',
      source: 'VirusTotal Integration'
    }
  ]

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
        {stats.map((stat, index) => {
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
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Threat Trends */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.2 }}
          className="bg-slate-900/50 rounded-lg p-6 border border-slate-800"
        >
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-lg font-semibold text-white">Threat Trends</h3>
            <div className="flex items-center space-x-4 text-sm">
              <div className="flex items-center space-x-2">
                <div className="w-3 h-3 bg-danger-400 rounded-full"></div>
                <span className="text-gray-400">Threats</span>
              </div>
              <div className="flex items-center space-x-2">
                <div className="w-3 h-3 bg-success-400 rounded-full"></div>
                <span className="text-gray-400">Resolved</span>
              </div>
            </div>
          </div>
          <ResponsiveContainer width="100%" height={300}>
            <AreaChart data={threatData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="name" stroke="#9ca3af" />
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
                dataKey="threats"
                stackId="1"
                stroke="#ef4444"
                fill="#ef4444"
                fillOpacity={0.3}
              />
              <Area
                type="monotone"
                dataKey="resolved"
                stackId="2"
                stroke="#22c55e"
                fill="#22c55e"
                fillOpacity={0.3}
              />
            </AreaChart>
          </ResponsiveContainer>
        </motion.div>

        {/* File Types Analysis */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.3 }}
          className="bg-slate-900/50 rounded-lg p-6 border border-slate-800"
        >
          <h3 className="text-lg font-semibold text-white mb-6">File Types Analyzed</h3>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={fileTypeData}
                cx="50%"
                cy="50%"
                innerRadius={60}
                outerRadius={120}
                paddingAngle={5}
                dataKey="value"
              >
                {fileTypeData.map((entry, index) => (
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
        </motion.div>
      </div>

      {/* Real-time Activity & Recent Alerts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Real-time Activity */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="lg:col-span-2 bg-slate-900/50 rounded-lg p-6 border border-slate-800"
        >
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-lg font-semibold text-white">Real-time Activity</h3>
            <div className="flex items-center space-x-2">
              <div className="w-2 h-2 bg-success-400 rounded-full animate-pulse"></div>
              <span className="text-sm text-gray-400">Live</span>
            </div>
          </div>
          <ResponsiveContainer width="100%" height={250}>
            <LineChart data={realtimeData}>
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
              <Line
                type="monotone"
                dataKey="events"
                stroke="#3b82f6"
                strokeWidth={2}
                dot={false}
              />
              <Line
                type="monotone"
                dataKey="threats"
                stroke="#ef4444"
                strokeWidth={2}
                dot={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </motion.div>

        {/* Recent Alerts */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
          className="bg-slate-900/50 rounded-lg p-6 border border-slate-800"
        >
          <h3 className="text-lg font-semibold text-white mb-6">Recent Alerts</h3>
          <div className="space-y-4">
            {recentAlerts.map((alert) => (
              <div
                key={alert.id}
                className={`p-4 rounded-lg border-l-4 ${getAlertColor(alert.type)}`}
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <h4 className="text-sm font-medium text-white">{alert.title}</h4>
                    <p className="text-xs text-gray-400 mt-1">{alert.description}</p>
                    <div className="flex items-center justify-between mt-2">
                      <span className="text-xs text-gray-500">{alert.source}</span>
                      <span className="text-xs text-gray-500">{alert.time}</span>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </motion.div>
      </div>

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
            { name: 'API Gateway', status: 'warning', icon: Server },
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