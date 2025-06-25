import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  MagnifyingGlassIcon,
  FunnelIcon,
  ArrowDownTrayIcon,
  TrashIcon,
  ChartBarIcon,
  CalendarIcon,
  ClockIcon,
  DocumentTextIcon,
  ExclamationTriangleIcon,
  ShieldCheckIcon,
  CheckCircleIcon,
  XCircleIcon
} from '@heroicons/react/24/outline';
import { toast } from 'react-hot-toast';
import Card from '@/components/common/Card';
import Button from '@/components/common/Button';
import { historyService } from '@/services/historyService';
import { formatDateTime, formatBytes, getFileIcon } from '@/utils/formatters';

const SEVERITY_COLORS = {
  critical: 'text-red-500 bg-red-500/10',
  high: 'text-orange-500 bg-orange-500/10',
  medium: 'text-yellow-500 bg-yellow-500/10',
  low: 'text-green-500 bg-green-500/10',
  info: 'text-blue-500 bg-blue-500/10'
};

const QUICK_FILTERS = [
  { id: 'all', label: 'All Time', value: null },
  { id: '24h', label: 'Last 24 Hours', value: 24 },
  { id: '7d', label: 'Last 7 Days', value: 24 * 7 },
  { id: '30d', label: 'Last 30 Days', value: 24 * 30 }
];

const PAGE_SIZES = [20, 50, 100];

export default function History() {
  const navigate = useNavigate();
  const [analyses, setAnalyses] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [quickFilter, setQuickFilter] = useState('all');
  const [showFilters, setShowFilters] = useState(false);
  const [selectedItems, setSelectedItems] = useState([]);
  const [pagination, setPagination] = useState({
    page: 1,
    limit: 20,
    total: 0,
    totalPages: 0
  });
  const [filters, setFilters] = useState({
    status: '',
    severity: '',
    fileType: '',
    dateFrom: '',
    dateTo: ''
  });
  const [viewMode, setViewMode] = useState('table'); // table or timeline

  // Load history data
  const loadHistory = useCallback(async () => {
    try {
      setLoading(true);
      
      // Build query params
      const params = {
        page: pagination.page,
        limit: pagination.limit,
        search: searchTerm,
        ...filters
      };

      // Apply quick filter
      if (quickFilter !== 'all') {
        const hours = QUICK_FILTERS.find(f => f.id === quickFilter)?.value;
        if (hours) {
          const date = new Date();
          date.setHours(date.getHours() - hours);
          params.dateFrom = date.toISOString();
        }
      }

      const response = await historyService.getHistory(params);
      setAnalyses(response.items);
      setPagination({
        ...pagination,
        total: response.total,
        totalPages: response.totalPages
      });
    } catch (error) {
      toast.error('Failed to load history');
      console.error(error);
    } finally {
      setLoading(false);
    }
  }, [pagination.page, pagination.limit, searchTerm, filters, quickFilter]);

  useEffect(() => {
    loadHistory();
  }, [loadHistory]);

  // Handle search
  const handleSearch = (e) => {
    setSearchTerm(e.target.value);
    setPagination(prev => ({ ...prev, page: 1 }));
  };

  // Handle filter change
  const handleFilterChange = (key, value) => {
    setFilters(prev => ({ ...prev, [key]: value }));
    setPagination(prev => ({ ...prev, page: 1 }));
  };

  // Handle quick filter
  const handleQuickFilter = (filterId) => {
    setQuickFilter(filterId);
    setPagination(prev => ({ ...prev, page: 1 }));
  };

  // Handle selection
  const handleSelectItem = (id) => {
    setSelectedItems(prev => 
      prev.includes(id) 
        ? prev.filter(item => item !== id)
        : [...prev, id]
    );
  };

  const handleSelectAll = () => {
    if (selectedItems.length === analyses.length) {
      setSelectedItems([]);
    } else {
      setSelectedItems(analyses.map(a => a.id));
    }
  };

  // Handle bulk delete
  const handleBulkDelete = async () => {
    if (selectedItems.length === 0) return;

    if (!confirm(`Delete ${selectedItems.length} analyses? This cannot be undone.`)) {
      return;
    }

    try {
      await historyService.bulkDelete(selectedItems);
      toast.success(`Deleted ${selectedItems.length} analyses`);
      setSelectedItems([]);
      loadHistory();
    } catch (error) {
      toast.error('Failed to delete analyses');
    }
  };

  // Handle export
  const handleExport = async (format = 'csv') => {
    try {
      const blob = await historyService.exportHistory({
        format,
        ids: selectedItems.length > 0 ? selectedItems : undefined,
        ...filters
      });
      
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `analysis-history-${new Date().toISOString()}.${format}`;
      a.click();
      window.URL.revokeObjectURL(url);
      
      toast.success(`Exported ${selectedItems.length || 'all'} records`);
    } catch (error) {
      toast.error('Export failed');
    }
  };

  // Get status icon
  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed':
        return <CheckCircleIcon className="h-5 w-5 text-green-400" />;
      case 'processing':
        return <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-cyber-blue" />;
      case 'failed':
        return <XCircleIcon className="h-5 w-5 text-red-400" />;
      default:
        return <ClockIcon className="h-5 w-5 text-gray-400" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-gray-800/50 backdrop-blur border border-gray-700 rounded-lg p-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white mb-2">Analysis History</h1>
            <p className="text-gray-400">
              Browse and manage your previous file analyses
            </p>
          </div>
          
          {/* View Mode Toggle */}
          <div className="flex items-center space-x-2 bg-gray-900/50 rounded-lg p-1">
            <button
              onClick={() => setViewMode('table')}
              className={`px-3 py-1.5 rounded text-sm font-medium transition-colors ${
                viewMode === 'table' 
                  ? 'bg-cyber-blue text-white' 
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              Table
            </button>
            <button
              onClick={() => setViewMode('timeline')}
              className={`px-3 py-1.5 rounded text-sm font-medium transition-colors ${
                viewMode === 'timeline' 
                  ? 'bg-cyber-blue text-white' 
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              Timeline
            </button>
          </div>
        </div>
      </div>

      {/* Controls */}
      <Card className="bg-gray-800/50">
        <div className="space-y-4">
          {/* Search and Quick Filters */}
          <div className="flex flex-col lg:flex-row gap-4">
            {/* Search */}
            <div className="flex-1">
              <div className="relative">
                <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search by filename, hash, or content..."
                  value={searchTerm}
                  onChange={handleSearch}
                  className="w-full pl-10 pr-4 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-cyber-blue"
                />
              </div>
            </div>

            {/* Quick Filters */}
            <div className="flex items-center space-x-2">
              {QUICK_FILTERS.map(filter => (
                <button
                  key={filter.id}
                  onClick={() => handleQuickFilter(filter.id)}
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                    quickFilter === filter.id
                      ? 'bg-cyber-blue text-white'
                      : 'bg-gray-900/50 text-gray-400 hover:text-white'
                  }`}
                >
                  {filter.label}
                </button>
              ))}
            </div>

            {/* Filter Toggle */}
            <Button
              variant="secondary"
              size="sm"
              icon={FunnelIcon}
              onClick={() => setShowFilters(!showFilters)}
            >
              Filters
            </Button>
          </div>

          {/* Advanced Filters */}
          {showFilters && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-4 pt-4 border-t border-gray-700"
            >
              <select
                value={filters.status}
                onChange={(e) => handleFilterChange('status', e.target.value)}
                className="px-3 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white"
              >
                <option value="">All Statuses</option>
                <option value="completed">Completed</option>
                <option value="processing">Processing</option>
                <option value="failed">Failed</option>
              </select>

              <select
                value={filters.severity}
                onChange={(e) => handleFilterChange('severity', e.target.value)}
                className="px-3 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white"
              >
                <option value="">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>

              <select
                value={filters.fileType}
                onChange={(e) => handleFilterChange('fileType', e.target.value)}
                className="px-3 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white"
              >
                <option value="">All File Types</option>
                <option value="log">Logs</option>
                <option value="pcap">Network Captures</option>
                <option value="document">Documents</option>
                <option value="archive">Archives</option>
                <option value="other">Other</option>
              </select>

              <input
                type="date"
                value={filters.dateFrom}
                onChange={(e) => handleFilterChange('dateFrom', e.target.value)}
                className="px-3 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white"
                placeholder="From Date"
              />

              <input
                type="date"
                value={filters.dateTo}
                onChange={(e) => handleFilterChange('dateTo', e.target.value)}
                className="px-3 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white"
                placeholder="To Date"
              />
            </motion.div>
          )}

          {/* Actions Bar */}
          {selectedItems.length > 0 && (
            <div className="flex items-center justify-between p-4 bg-cyber-blue/10 border border-cyber-blue/30 rounded-lg">
              <span className="text-sm text-white">
                {selectedItems.length} item{selectedItems.length > 1 ? 's' : ''} selected
              </span>
              <div className="flex items-center space-x-3">
                <Button
                  variant="ghost"
                  size="sm"
                  icon={ArrowDownTrayIcon}
                  onClick={() => handleExport('csv')}
                >
                  Export
                </Button>
                <Button
                  variant="danger"
                  size="sm"
                  icon={TrashIcon}
                  onClick={handleBulkDelete}
                >
                  Delete
                </Button>
              </div>
            </div>
          )}
        </div>
      </Card>

      {/* Results */}
      {loading ? (
        <Card className="bg-gray-800/50">
          <div className="flex items-center justify-center h-64">
            <div className="text-center">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyber-blue mx-auto mb-4" />
              <p className="text-gray-400">Loading history...</p>
            </div>
          </div>
        </Card>
      ) : viewMode === 'table' ? (
        <Card className="bg-gray-800/50">
          {/* Table */}
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-700">
                  <th className="px-4 py-3 text-left">
                    <input
                      type="checkbox"
                      checked={selectedItems.length === analyses.length && analyses.length > 0}
                      onChange={handleSelectAll}
                      className="rounded border-gray-600 bg-gray-800 text-cyber-blue focus:ring-cyber-blue"
                    />
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    File
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Severity
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Events
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Date
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700">
                {analyses.map((analysis) => (
                  <tr key={analysis.id} className="hover:bg-gray-800/50 transition-colors">
                    <td className="px-4 py-3">
                      <input
                        type="checkbox"
                        checked={selectedItems.includes(analysis.id)}
                        onChange={() => handleSelectItem(analysis.id)}
                        className="rounded border-gray-600 bg-gray-800 text-cyber-blue focus:ring-cyber-blue"
                      />
                    </td>
                    <td className="px-4 py-3">
                      {getStatusIcon(analysis.status)}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center space-x-3">
                        <DocumentTextIcon className="h-5 w-5 text-gray-400" />
                        <div>
                          <p className="text-sm font-medium text-white truncate max-w-xs">
                            {analysis.filename}
                          </p>
                          <p className="text-xs text-gray-400">
                            {formatBytes(analysis.file_size)}
                          </p>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      {analysis.max_severity && (
                        <span className={`px-2 py-1 text-xs font-medium rounded-full ${SEVERITY_COLORS[analysis.max_severity]}`}>
                          {analysis.max_severity.toUpperCase()}
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <div className="text-sm text-gray-300">
                        {analysis.total_events || 0}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="text-sm text-gray-300">
                        {formatDateTime(analysis.created_at)}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => navigate(`/analysis/${analysis.id}`)}
                      >
                        View
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div className="mt-6 flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <span className="text-sm text-gray-400">Show</span>
              <select
                value={pagination.limit}
                onChange={(e) => setPagination(prev => ({ ...prev, limit: parseInt(e.target.value), page: 1 }))}
                className="px-3 py-1 bg-gray-900/50 border border-gray-700 rounded text-white text-sm"
              >
                {PAGE_SIZES.map(size => (
                  <option key={size} value={size}>{size}</option>
                ))}
              </select>
              <span className="text-sm text-gray-400">per page</span>
            </div>

            <div className="flex items-center space-x-2">
              <Button
                variant="ghost"
                size="sm"
                disabled={pagination.page === 1}
                onClick={() => setPagination(prev => ({ ...prev, page: prev.page - 1 }))}
              >
                Previous
              </Button>
              
              <span className="text-sm text-gray-400">
                Page {pagination.page} of {pagination.totalPages}
              </span>

              <Button
                variant="ghost"
                size="sm"
                disabled={pagination.page === pagination.totalPages}
                onClick={() => setPagination(prev => ({ ...prev, page: prev.page + 1 }))}
              >
                Next
              </Button>
            </div>
          </div>
        </Card>
      ) : (
        <Card className="bg-gray-800/50">
          {/* Timeline View */}
          <div className="relative">
            <div className="absolute left-8 top-0 bottom-0 w-0.5 bg-gray-700"></div>
            
            {analyses.map((analysis, index) => (
              <motion.div
                key={analysis.id}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: index * 0.1 }}
                className="relative flex items-start mb-8"
              >
                <div className="absolute left-8 w-4 h-4 bg-gray-800 border-2 border-cyber-blue rounded-full -translate-x-1/2"></div>
                
                <div className="ml-16 flex-1">
                  <div className="bg-gray-900/50 rounded-lg p-4 hover:bg-gray-800/50 transition-colors cursor-pointer"
                       onClick={() => navigate(`/analysis/${analysis.id}`)}>
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center space-x-3 mb-2">
                          {getStatusIcon(analysis.status)}
                          <h3 className="font-medium text-white">{analysis.filename}</h3>
                          {analysis.max_severity && (
                            <span className={`px-2 py-1 text-xs font-medium rounded-full ${SEVERITY_COLORS[analysis.max_severity]}`}>
                              {analysis.max_severity.toUpperCase()}
                            </span>
                          )}
                        </div>
                        <p className="text-sm text-gray-400 mb-2">
                          {analysis.total_events || 0} events • {formatBytes(analysis.file_size)}
                        </p>
                        {analysis.summary && (
                          <p className="text-sm text-gray-300">{analysis.summary}</p>
                        )}
                      </div>
                      <div className="text-sm text-gray-500">
                        {formatDateTime(analysis.created_at)}
                      </div>
                    </div>
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}