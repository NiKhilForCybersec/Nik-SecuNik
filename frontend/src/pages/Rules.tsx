import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import {
  Shield,
  Plus,
  Search,
  Filter,
  Download,
  Upload,
  Edit,
  Trash2,
  Play,
  Eye,
  FileText,
  Code,
  AlertTriangle,
  CheckCircle,
  XCircle,
  RefreshCw
} from 'lucide-react'
import { rulesService } from '../services/rulesService'
import toast from 'react-hot-toast'

const Rules: React.FC = () => {
  const [activeTab, setActiveTab] = useState('all')
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedRule, setSelectedRule] = useState<any>(null)
  const [showEditor, setShowEditor] = useState(false)
  const [rules, setRules] = useState<any[]>([])
  const [stats, setStats] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [pagination, setPagination] = useState({
    limit: 50,
    offset: 0,
    total: 0
  })

  useEffect(() => {
    loadRules()
    loadStats()
  }, [])

  useEffect(() => {
    loadRules()
  }, [activeTab, searchTerm, pagination.offset])

  const loadRules = async () => {
    try {
      setLoading(true)
      
      const filters: any = {
        limit: pagination.limit,
        offset: pagination.offset
      }
      
      if (activeTab !== 'all') filters.type = activeTab
      if (searchTerm) filters.search = searchTerm
      
      const response = await rulesService.getRules(filters)
      
      setRules(response.rules || [])
      setPagination(prev => ({
        ...prev,
        total: response.total || 0
      }))
      
    } catch (error: any) {
      console.error('Failed to load rules:', error)
      toast.error('Failed to load rules')
    } finally {
      setLoading(false)
    }
  }

  const loadStats = async () => {
    try {
      const statsData = await rulesService.getRuleStats()
      setStats(statsData)
    } catch (error: any) {
      console.error('Failed to load rule stats:', error)
    }
  }

  const deleteRule = async (ruleId: string) => {
    if (!confirm('Are you sure you want to delete this rule?')) return
    
    try {
      await rulesService.deleteRule(ruleId)
      toast.success('Rule deleted successfully')
      loadRules()
    } catch (error: any) {
      console.error('Failed to delete rule:', error)
      toast.error('Failed to delete rule')
    }
  }

  const toggleRule = async (ruleId: string, currentEnabled: boolean) => {
    try {
      await rulesService.updateRule(ruleId, { enabled: !currentEnabled })
      toast.success(`Rule ${!currentEnabled ? 'enabled' : 'disabled'}`)
      loadRules()
    } catch (error: any) {
      console.error('Failed to toggle rule:', error)
      toast.error('Failed to update rule')
    }
  }

  const exportRules = async () => {
    try {
      const data = await rulesService.exportRules('json')
      
      // Create download link
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
      const url = window.URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `rules_export_${new Date().toISOString().split('T')[0]}.json`
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      window.URL.revokeObjectURL(url)
      
      toast.success('Rules exported successfully')
    } catch (error: any) {
      console.error('Export failed:', error)
      toast.error('Failed to export rules')
    }
  }

  const tabs = [
    { id: 'all', label: 'All Rules', count: rules.length },
    { id: 'yara', label: 'YARA', count: rules.filter(r => r.type === 'yara').length },
    { id: 'sigma', label: 'Sigma', count: rules.filter(r => r.type === 'sigma').length },
    { id: 'custom', label: 'Custom', count: rules.filter(r => r.type === 'custom').length },
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
        return 'text-blue-400 bg-blue-900/30'
    }
  }

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'yara':
        return <FileText className="w-4 h-4" />
      case 'sigma':
        return <Shield className="w-4 h-4" />
      case 'custom':
        return <Code className="w-4 h-4" />
      default:
        return <FileText className="w-4 h-4" />
    }
  }

  const formatDate = (date: string) => {
    return new Date(date).toLocaleDateString() + ' ' + new Date(date).toLocaleTimeString()
  }

  const filteredRules = rules.filter(rule => {
    const matchesSearch = rule.name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         rule.description?.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         rule.tags?.some((tag: string) => tag.toLowerCase().includes(searchTerm.toLowerCase()))
    const matchesTab = activeTab === 'all' || rule.type === activeTab
    return matchesSearch && matchesTab
  })

  const statsData = stats ? [
    {
      title: 'Total Rules',
      value: stats.total_rules?.toString() || rules.length.toString(),
      icon: Shield,
      color: 'text-primary-400'
    },
    {
      title: 'Active Rules',
      value: rules.filter(r => r.enabled).length.toString(),
      icon: CheckCircle,
      color: 'text-success-400'
    },
    {
      title: 'High Severity',
      value: rules.filter(r => r.severity === 'high' || r.severity === 'critical').length.toString(),
      icon: AlertTriangle,
      color: 'text-danger-400'
    },
    {
      title: 'YARA Rules',
      value: rules.filter(r => r.type === 'yara').length.toString(),
      icon: FileText,
      color: 'text-warning-400'
    }
  ] : []

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">Detection Rules</h1>
          <p className="text-gray-400 mt-2">
            Manage YARA, Sigma, and custom detection rules for comprehensive threat detection
          </p>
        </div>
        <div className="flex items-center space-x-3">
          <button 
            onClick={loadRules}
            className="flex items-center space-x-2 px-4 py-2 bg-slate-800 text-white rounded-lg hover:bg-slate-700 transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            <span>Refresh</span>
          </button>
          <button 
            onClick={exportRules}
            className="flex items-center space-x-2 px-4 py-2 bg-slate-800 text-white rounded-lg hover:bg-slate-700 transition-colors"
          >
            <Download className="w-4 h-4" />
            <span>Export Rules</span>
          </button>
          <button className="flex items-center space-x-2 px-4 py-2 bg-slate-800 text-white rounded-lg hover:bg-slate-700 transition-colors">
            <Upload className="w-4 h-4" />
            <span>Import Rules</span>
          </button>
          <button
            onClick={() => setShowEditor(true)}
            className="flex items-center space-x-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors"
          >
            <Plus className="w-4 h-4" />
            <span>New Rule</span>
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {statsData.map((stat, index) => {
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

      {/* Rules Management */}
      <div className="bg-slate-900/50 rounded-lg p-6 border border-slate-800">
        {/* Filters */}
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 mb-6">
          <div className="flex items-center space-x-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
              <input
                type="text"
                placeholder="Search rules..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10 pr-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent w-64"
              />
            </div>
            <button className="flex items-center space-x-2 px-3 py-2 bg-slate-800 text-white rounded-lg hover:bg-slate-700 transition-colors">
              <Filter className="w-4 h-4" />
              <span>Advanced Filters</span>
            </button>
          </div>
        </div>

        {/* Tabs */}
        <div className="border-b border-slate-700 mb-6">
          <nav className="flex space-x-8">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`py-2 px-1 border-b-2 font-medium text-sm transition-colors ${
                  activeTab === tab.id
                    ? 'border-primary-500 text-primary-400'
                    : 'border-transparent text-gray-400 hover:text-gray-300'
                }`}
              >
                {tab.label} ({tab.count})
              </button>
            ))}
          </nav>
        </div>

        {/* Rules Table */}
        {loading ? (
          <div className="flex items-center justify-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500"></div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-700">
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Rule
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Type
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Severity
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Modified
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700">
                {filteredRules.map((rule, index) => (
                  <motion.tr
                    key={rule.id}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: index * 0.1 }}
                    className="hover:bg-slate-800/50 transition-colors"
                  >
                    <td className="px-4 py-4">
                      <div>
                        <div className="text-sm font-medium text-white">{rule.name}</div>
                        <div className="text-sm text-gray-400 mt-1">{rule.description}</div>
                        {rule.tags && rule.tags.length > 0 && (
                          <div className="flex items-center space-x-2 mt-2">
                            {rule.tags.slice(0, 3).map((tag: string) => (
                              <span
                                key={tag}
                                className="px-2 py-1 bg-primary-900/30 text-primary-300 text-xs rounded"
                              >
                                {tag}
                              </span>
                            ))}
                            {rule.tags.length > 3 && (
                              <span className="text-xs text-gray-400">+{rule.tags.length - 3} more</span>
                            )}
                          </div>
                        )}
                      </div>
                    </td>
                    
                    <td className="px-4 py-4">
                      <div className="flex items-center">
                        {getTypeIcon(rule.type)}
                        <span className="ml-2 text-sm text-white capitalize">{rule.type}</span>
                      </div>
                    </td>
                    
                    <td className="px-4 py-4">
                      <span className={`px-2 py-1 text-xs rounded-full ${getSeverityColor(rule.severity)}`}>
                        {rule.severity?.toUpperCase() || 'MEDIUM'}
                      </span>
                    </td>
                    
                    <td className="px-4 py-4">
                      <div className="flex items-center">
                        <div className={`w-2 h-2 rounded-full mr-2 ${
                          rule.enabled ? 'bg-success-400' : 'bg-gray-400'
                        }`} />
                        <span className={`text-sm ${
                          rule.enabled ? 'text-success-400' : 'text-gray-400'
                        }`}>
                          {rule.enabled ? 'Active' : 'Disabled'}
                        </span>
                      </div>
                    </td>
                    
                    <td className="px-4 py-4">
                      <div className="text-sm text-gray-400">
                        {rule.updated_at ? formatDate(rule.updated_at) : 'N/A'}
                      </div>
                    </td>
                    
                    <td className="px-4 py-4">
                      <div className="flex items-center space-x-2">
                        <button
                          onClick={() => setSelectedRule(rule)}
                          className="text-primary-400 hover:text-primary-300 transition-colors"
                        >
                          <Eye className="w-4 h-4" />
                        </button>
                        <button 
                          onClick={() => toggleRule(rule.id, rule.enabled)}
                          className="text-gray-400 hover:text-white transition-colors"
                        >
                          <Play className="w-4 h-4" />
                        </button>
                        <button className="text-gray-400 hover:text-white transition-colors">
                          <Edit className="w-4 h-4" />
                        </button>
                        <button 
                          onClick={() => deleteRule(rule.id)}
                          className="text-gray-400 hover:text-red-400 transition-colors"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {!loading && filteredRules.length === 0 && (
          <div className="text-center py-12">
            <Shield className="w-12 h-12 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-300 mb-2">No rules found</h3>
            <p className="text-gray-400">
              {searchTerm 
                ? 'Try adjusting your search terms.'
                : 'Create your first detection rule to get started.'
              }
            </p>
          </div>
        )}
      </div>

      {/* Rule Viewer Modal */}
      {selectedRule && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="bg-slate-900 rounded-lg border border-slate-700 max-w-4xl w-full max-h-[80vh] overflow-hidden"
          >
            <div className="flex items-center justify-between p-6 border-b border-slate-700">
              <div>
                <h3 className="text-lg font-semibold text-white">{selectedRule.name}</h3>
                <p className="text-sm text-gray-400 mt-1">{selectedRule.description}</p>
              </div>
              <button
                onClick={() => setSelectedRule(null)}
                className="text-gray-400 hover:text-white transition-colors"
              >
                <XCircle className="w-6 h-6" />
              </button>
            </div>
            
            <div className="p-6 overflow-y-auto max-h-96">
              {selectedRule.content ? (
                <pre className="bg-slate-800 p-4 rounded-lg text-sm text-gray-300 font-mono overflow-x-auto">
                  {selectedRule.content}
                </pre>
              ) : (
                <div className="text-center py-8">
                  <Code className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                  <p className="text-gray-400">Rule content not available</p>
                </div>
              )}
            </div>
          </motion.div>
        </div>
      )}
    </div>
  )
}

export default Rules