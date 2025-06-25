import React, { useState } from 'react'
import { motion } from 'framer-motion'
import { useNavigate } from 'react-router-dom'
import {
  Search,
  Filter,
  Download,
  Eye,
  Trash2,
  Calendar,
  FileText,
  AlertTriangle,
  Clock,
  CheckCircle,
  XCircle
} from 'lucide-react'

interface AnalysisHistory {
  id: string
  fileName: string
  fileType: string
  fileSize: string
  uploadTime: Date
  analysisTime: Date
  status: 'completed' | 'processing' | 'failed'
  threatLevel: 'low' | 'medium' | 'high' | 'critical'
  threatsFound: number
  iocsDetected: number
  duration: string
}

const History: React.FC = () => {
  const navigate = useNavigate()
  const [searchTerm, setSearchTerm] = useState('')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [threatFilter, setThreatFilter] = useState<string>('all')

  // Mock data - replace with actual API call
  const historyData: AnalysisHistory[] = [
    {
      id: 'analysis_001',
      fileName: 'system_logs_2024.log',
      fileType: 'System Log',
      fileSize: '2.4 MB',
      uploadTime: new Date('2024-01-15T10:30:00'),
      analysisTime: new Date('2024-01-15T10:32:15'),
      status: 'completed',
      threatLevel: 'medium',
      threatsFound: 23,
      iocsDetected: 12,
      duration: '2m 15s'
    },
    {
      id: 'analysis_002',
      fileName: 'network_capture.pcap',
      fileType: 'Network Capture',
      fileSize: '15.7 MB',
      uploadTime: new Date('2024-01-15T09:15:00'),
      analysisTime: new Date('2024-01-15T09:18:45'),
      status: 'completed',
      threatLevel: 'high',
      threatsFound: 45,
      iocsDetected: 28,
      duration: '3m 45s'
    },
    {
      id: 'analysis_003',
      fileName: 'email_archive.mbox',
      fileType: 'Email Archive',
      fileSize: '8.2 MB',
      uploadTime: new Date('2024-01-15T08:45:00'),
      analysisTime: new Date('2024-01-15T08:47:30'),
      status: 'completed',
      threatLevel: 'low',
      threatsFound: 3,
      iocsDetected: 1,
      duration: '2m 30s'
    },
    {
      id: 'analysis_004',
      fileName: 'suspicious_binary.exe',
      fileType: 'Executable',
      fileSize: '1.2 MB',
      uploadTime: new Date('2024-01-15T07:20:00'),
      analysisTime: new Date('2024-01-15T07:25:15'),
      status: 'completed',
      threatLevel: 'critical',
      threatsFound: 67,
      iocsDetected: 34,
      duration: '5m 15s'
    },
    {
      id: 'analysis_005',
      fileName: 'large_dataset.zip',
      fileType: 'Archive',
      fileSize: '45.8 MB',
      uploadTime: new Date('2024-01-15T06:30:00'),
      analysisTime: new Date('2024-01-15T06:30:00'),
      status: 'processing',
      threatLevel: 'low',
      threatsFound: 0,
      iocsDetected: 0,
      duration: '15m 30s'
    },
    {
      id: 'analysis_006',
      fileName: 'corrupted_file.dat',
      fileType: 'Unknown',
      fileSize: '0.5 MB',
      uploadTime: new Date('2024-01-15T05:45:00'),
      analysisTime: new Date('2024-01-15T05:45:30'),
      status: 'failed',
      threatLevel: 'low',
      threatsFound: 0,
      iocsDetected: 0,
      duration: '30s'
    }
  ]

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="w-5 h-5 text-success-400" />
      case 'processing':
        return <Clock className="w-5 h-5 text-warning-400 animate-spin" />
      case 'failed':
        return <XCircle className="w-5 h-5 text-danger-400" />
      default:
        return <Clock className="w-5 h-5 text-gray-400" />
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

  const formatDate = (date: Date) => {
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString()
  }

  const filteredData = historyData.filter(item => {
    const matchesSearch = item.fileName.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         item.fileType.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesStatus = statusFilter === 'all' || item.status === statusFilter
    const matchesThreat = threatFilter === 'all' || item.threatLevel === threatFilter
    return matchesSearch && matchesStatus && matchesThreat
  })

  const stats = [
    {
      title: 'Total Analyses',
      value: historyData.length.toString(),
      icon: FileText,
      color: 'text-primary-400'
    },
    {
      title: 'Completed',
      value: historyData.filter(h => h.status === 'completed').length.toString(),
      icon: CheckCircle,
      color: 'text-success-400'
    },
    {
      title: 'High Risk Files',
      value: historyData.filter(h => h.threatLevel === 'high' || h.threatLevel === 'critical').length.toString(),
      icon: AlertTriangle,
      color: 'text-danger-400'
    },
    {
      title: 'Total Threats',
      value: historyData.reduce((sum, h) => sum + h.threatsFound, 0).toString(),
      icon: Eye,
      color: 'text-warning-400'
    }
  ]

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">Analysis History</h1>
          <p className="text-gray-400 mt-2">
            View and manage your file analysis history and results
          </p>
        </div>
        <div className="flex items-center space-x-3">
          <button className="flex items-center space-x-2 px-4 py-2 bg-slate-800 text-white rounded-lg hover:bg-slate-700 transition-colors">
            <Download className="w-4 h-4" />
            <span>Export History</span>
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {stats.map((stat, index) => {
          const Icon = stat.icon
          return (
            <motion.div
              key={stat.title}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
              className="bg-slate-900/50 rounded-lg p-6 border border-slate-800"
            >
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-400">{stat.title}</p>
                  <p className="text-2xl font-bold text-white mt-1">{stat.value}</p>
                </div>
                <Icon className={`w-8 h-8 ${stat.color}`} />
              </div>
            </motion.div>
          )
        })}
      </div>

      {/* Filters */}
      <div className="bg-slate-900/50 rounded-lg p-6 border border-slate-800">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div className="flex items-center space-x-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
              <input
                type="text"
                placeholder="Search files..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10 pr-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent w-64"
              />
            </div>
            
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary-500"
            >
              <option value="all">All Status</option>
              <option value="completed">Completed</option>
              <option value="processing">Processing</option>
              <option value="failed">Failed</option>
            </select>
            
            <select
              value={threatFilter}
              onChange={(e) => setThreatFilter(e.target.value)}
              className="px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary-500"
            >
              <option value="all">All Threat Levels</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
          
          <div className="flex items-center space-x-2">
            <Calendar className="w-4 h-4 text-gray-400" />
            <span className="text-sm text-gray-400">Last 30 days</span>
          </div>
        </div>
      </div>

      {/* History Table */}
      <div className="bg-slate-900/50 rounded-lg border border-slate-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-slate-700 bg-slate-800/50">
                <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  File
                </th>
                <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Status
                </th>
                <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Threat Level
                </th>
                <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Threats
                </th>
                <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  IOCs
                </th>
                <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Duration
                </th>
                <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Date
                </th>
                <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700">
              {filteredData.map((item, index) => (
                <motion.tr
                  key={item.id}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: index * 0.1 }}
                  className="hover:bg-slate-800/50 transition-colors"
                >
                  <td className="px-6 py-4">
                    <div>
                      <div className="text-sm font-medium text-white">{item.fileName}</div>
                      <div className="text-sm text-gray-400">{item.fileType} • {item.fileSize}</div>
                    </div>
                  </td>
                  
                  <td className="px-6 py-4">
                    <div className="flex items-center space-x-2">
                      {getStatusIcon(item.status)}
                      <span className="text-sm text-white capitalize">{item.status}</span>
                    </div>
                  </td>
                  
                  <td className="px-6 py-4">
                    <span className={`px-2 py-1 text-xs rounded-full ${getThreatLevelColor(item.threatLevel)}`}>
                      {item.threatLevel.toUpperCase()}
                    </span>
                  </td>
                  
                  <td className="px-6 py-4">
                    <span className="text-sm text-white">{item.threatsFound}</span>
                  </td>
                  
                  <td className="px-6 py-4">
                    <span className="text-sm text-white">{item.iocsDetected}</span>
                  </td>
                  
                  <td className="px-6 py-4">
                    <span className="text-sm text-gray-400">{item.duration}</span>
                  </td>
                  
                  <td className="px-6 py-4">
                    <div className="text-sm text-gray-400">
                      {formatDate(item.uploadTime)}
                    </div>
                  </td>
                  
                  <td className="px-6 py-4">
                    <div className="flex items-center space-x-2">
                      {item.status === 'completed' && (
                        <button
                          onClick={() => navigate(`/analysis/${item.id}`)}
                          className="text-primary-400 hover:text-primary-300 transition-colors"
                        >
                          <Eye className="w-4 h-4" />
                        </button>
                      )}
                      <button className="text-gray-400 hover:text-white transition-colors">
                        <Download className="w-4 h-4" />
                      </button>
                      <button className="text-gray-400 hover:text-red-400 transition-colors">
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </td>
                </motion.tr>
              ))}
            </tbody>
          </table>
        </div>

        {filteredData.length === 0 && (
          <div className="text-center py-12">
            <FileText className="w-12 h-12 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-300 mb-2">No analyses found</h3>
            <p className="text-gray-400">
              {searchTerm || statusFilter !== 'all' || threatFilter !== 'all'
                ? 'Try adjusting your search or filter criteria.'
                : 'Upload your first file to start analyzing.'
              }
            </p>
          </div>
        )}
      </div>
    </div>
  )
}

export default History