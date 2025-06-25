import React, { useState } from 'react';
import { 
  Edit, Trash2, Play, Pause, Copy, MoreVertical, 
  ChevronUp, ChevronDown, Clock, Zap, CheckCircle, 
  AlertCircle, Shield 
} from 'lucide-react';
import Button from '../common/Button';
import { formatDateTime } from '../../utils/formatters';

const RuleList = ({ 
  rules = [], 
  onEdit, 
  onDelete, 
  onToggle, 
  onTest, 
  onClone,
  onBulkAction,
  totalCount,
  currentPage,
  onPageChange,
  itemsPerPage = 20
}) => {
  const [selectedRules, setSelectedRules] = useState(new Set());
  const [sortField, setSortField] = useState('updated_at');
  const [sortDirection, setSortDirection] = useState('desc');
  const [expandedRows, setExpandedRows] = useState(new Set());
  const [showBulkActions, setShowBulkActions] = useState(false);

  const handleSelectAll = (e) => {
    if (e.target.checked) {
      setSelectedRules(new Set(rules.map(r => r.id)));
    } else {
      setSelectedRules(new Set());
    }
    setShowBulkActions(e.target.checked);
  };

  const handleSelectRule = (ruleId) => {
    const newSelected = new Set(selectedRules);
    if (newSelected.has(ruleId)) {
      newSelected.delete(ruleId);
    } else {
      newSelected.add(ruleId);
    }
    setSelectedRules(newSelected);
    setShowBulkActions(newSelected.size > 0);
  };

  const handleSort = (field) => {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('asc');
    }
  };

  const toggleRowExpansion = (ruleId) => {
    const newExpanded = new Set(expandedRows);
    if (newExpanded.has(ruleId)) {
      newExpanded.delete(ruleId);
    } else {
      newExpanded.add(ruleId);
    }
    setExpandedRows(newExpanded);
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: 'text-red-500 bg-red-500/10',
      high: 'text-orange-500 bg-orange-500/10',
      medium: 'text-yellow-500 bg-yellow-500/10',
      low: 'text-green-500 bg-green-500/10'
    };
    return colors[severity] || colors.low;
  };

  const getTypeIcon = (type) => {
    const icons = {
      yara: '🛡️',
      sigma: '🎯',
      custom: '⚡'
    };
    return icons[type] || '📋';
  };

  const SortIcon = ({ field }) => {
    if (sortField !== field) {
      return <ChevronUp className="w-4 h-4 text-gray-600" />;
    }
    return sortDirection === 'asc' 
      ? <ChevronUp className="w-4 h-4 text-cyan-400" />
      : <ChevronDown className="w-4 h-4 text-cyan-400" />;
  };

  const PerformanceMetrics = ({ metrics }) => {
    if (!metrics) return null;

    return (
      <div className="grid grid-cols-3 gap-4 mt-2 p-3 bg-gray-800 rounded-lg">
        <div>
          <div className="text-xs text-gray-400">Avg. Time</div>
          <div className="text-sm font-semibold text-white">
            {metrics.avg_time_ms?.toFixed(2) || 0}ms
          </div>
        </div>
        <div>
          <div className="text-xs text-gray-400">Matches</div>
          <div className="text-sm font-semibold text-cyan-400">
            {metrics.total_matches || 0}
          </div>
        </div>
        <div>
          <div className="text-xs text-gray-400">False Positives</div>
          <div className="text-sm font-semibold text-orange-400">
            {metrics.false_positives || 0}
          </div>
        </div>
      </div>
    );
  };

  const totalPages = Math.ceil(totalCount / itemsPerPage);

  return (
    <div className="space-y-4">
      {/* Bulk Actions */}
      {showBulkActions && (
        <div className="flex items-center space-x-4 p-4 bg-gray-800 rounded-lg">
          <span className="text-sm text-gray-300">
            {selectedRules.size} rule{selectedRules.size !== 1 ? 's' : ''} selected
          </span>
          <div className="flex items-center space-x-2">
            <Button
              size="sm"
              variant="secondary"
              onClick={() => onBulkAction('enable', Array.from(selectedRules))}
              leftIcon={<Play className="w-4 h-4" />}
            >
              Enable
            </Button>
            <Button
              size="sm"
              variant="secondary"
              onClick={() => onBulkAction('disable', Array.from(selectedRules))}
              leftIcon={<Pause className="w-4 h-4" />}
            >
              Disable
            </Button>
            <Button
              size="sm"
              variant="danger"
              onClick={() => {
                if (confirm(`Delete ${selectedRules.size} rules?`)) {
                  onBulkAction('delete', Array.from(selectedRules));
                  setSelectedRules(new Set());
                  setShowBulkActions(false);
                }
              }}
              leftIcon={<Trash2 className="w-4 h-4" />}
            >
              Delete
            </Button>
          </div>
        </div>
      )}

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-800">
              <th className="p-4 text-left">
                <input
                  type="checkbox"
                  checked={selectedRules.size === rules.length && rules.length > 0}
                  onChange={handleSelectAll}
                  className="w-4 h-4 rounded border-gray-700 bg-gray-800 text-cyan-500"
                />
              </th>
              <th 
                className="p-4 text-left text-sm font-medium text-gray-300 cursor-pointer hover:text-white"
                onClick={() => handleSort('name')}
              >
                <div className="flex items-center space-x-1">
                  <span>Rule Name</span>
                  <SortIcon field="name" />
                </div>
              </th>
              <th 
                className="p-4 text-left text-sm font-medium text-gray-300 cursor-pointer hover:text-white"
                onClick={() => handleSort('type')}
              >
                <div className="flex items-center space-x-1">
                  <span>Type</span>
                  <SortIcon field="type" />
                </div>
              </th>
              <th 
                className="p-4 text-left text-sm font-medium text-gray-300 cursor-pointer hover:text-white"
                onClick={() => handleSort('severity')}
              >
                <div className="flex items-center space-x-1">
                  <span>Severity</span>
                  <SortIcon field="severity" />
                </div>
              </th>
              <th className="p-4 text-left text-sm font-medium text-gray-300">
                Status
              </th>
              <th 
                className="p-4 text-left text-sm font-medium text-gray-300 cursor-pointer hover:text-white"
                onClick={() => handleSort('updated_at')}
              >
                <div className="flex items-center space-x-1">
                  <span>Last Updated</span>
                  <SortIcon field="updated_at" />
                </div>
              </th>
              <th className="p-4 text-left text-sm font-medium text-gray-300">
                Performance
              </th>
              <th className="p-4 text-right text-sm font-medium text-gray-300">
                Actions
              </th>
            </tr>
          </thead>
          <tbody>
            {rules.map((rule) => {
              const isExpanded = expandedRows.has(rule.id);
              const isSelected = selectedRules.has(rule.id);

              return (
                <React.Fragment key={rule.id}>
                  <tr className={`
                    border-b border-gray-800 hover:bg-gray-800/50 transition-colors
                    ${isSelected ? 'bg-cyan-500/5' : ''}
                  `}>
                    <td className="p-4">
                      <input
                        type="checkbox"
                        checked={isSelected}
                        onChange={() => handleSelectRule(rule.id)}
                        className="w-4 h-4 rounded border-gray-700 bg-gray-800 text-cyan-500"
                      />
                    </td>
                    <td className="p-4">
                      <button
                        onClick={() => toggleRowExpansion(rule.id)}
                        className="flex items-start space-x-3 text-left hover:text-cyan-400 transition-colors"
                      >
                        <span className="text-2xl">{getTypeIcon(rule.type)}</span>
                        <div>
                          <div className="font-medium text-white">{rule.name}</div>
                          <div className="text-sm text-gray-400 mt-1">
                            {rule.description}
                          </div>
                          {rule.tags && rule.tags.length > 0 && (
                            <div className="flex flex-wrap gap-1 mt-2">
                              {rule.tags.map((tag, idx) => (
                                <span 
                                  key={idx}
                                  className="px-2 py-0.5 text-xs bg-gray-700 text-gray-300 rounded"
                                >
                                  {tag}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                      </button>
                    </td>
                    <td className="p-4">
                      <span className="px-2 py-1 text-xs font-medium bg-gray-700 text-gray-300 rounded">
                        {rule.type.toUpperCase()}
                      </span>
                    </td>
                    <td className="p-4">
                      <span className={`
                        px-2 py-1 text-xs font-medium rounded
                        ${getSeverityColor(rule.severity)}
                      `}>
                        {rule.severity.toUpperCase()}
                      </span>
                    </td>
                    <td className="p-4">
                      <button
                        onClick={() => onToggle(rule.id, !rule.enabled)}
                        className={`
                          flex items-center space-x-2 px-3 py-1 rounded-full text-xs font-medium
                          transition-colors
                          ${rule.enabled 
                            ? 'bg-green-500/20 text-green-400 hover:bg-green-500/30' 
                            : 'bg-gray-700 text-gray-400 hover:bg-gray-600'
                          }
                        `}
                      >
                        {rule.enabled ? (
                          <>
                            <CheckCircle className="w-3 h-3" />
                            <span>Enabled</span>
                          </>
                        ) : (
                          <>
                            <AlertCircle className="w-3 h-3" />
                            <span>Disabled</span>
                          </>
                        )}
                      </button>
                    </td>
                    <td className="p-4">
                      <div className="flex items-center space-x-2 text-sm text-gray-400">
                        <Clock className="w-4 h-4" />
                        <span>{formatDateTime(rule.updated_at)}</span>
                      </div>
                    </td>
                    <td className="p-4">
                      {rule.performance_metrics ? (
                        <div className="flex items-center space-x-2">
                          <Zap className={`w-4 h-4 ${
                            rule.performance_metrics.avg_time_ms < 50 
                              ? 'text-green-400' 
                              : rule.performance_metrics.avg_time_ms < 200 
                              ? 'text-yellow-400'
                              : 'text-red-400'
                          }`} />
                          <span className="text-sm text-gray-300">
                            {rule.performance_metrics.avg_time_ms.toFixed(0)}ms
                          </span>
                        </div>
                      ) : (
                        <span className="text-sm text-gray-500">No data</span>
                      )}
                    </td>
                    <td className="p-4">
                      <div className="flex items-center justify-end space-x-2">
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => onTest(rule.id)}
                          leftIcon={<Play className="w-4 h-4" />}
                        >
                          Test
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => onEdit(rule)}
                          leftIcon={<Edit className="w-4 h-4" />}
                        >
                          Edit
                        </Button>
                        <div className="relative group">
                          <button className="p-1 hover:bg-gray-700 rounded transition-colors">
                            <MoreVertical className="w-4 h-4 text-gray-400" />
                          </button>
                          <div className="
                            absolute right-0 mt-2 w-48 bg-gray-800 rounded-lg shadow-lg 
                            border border-gray-700 opacity-0 invisible group-hover:opacity-100 
                            group-hover:visible transition-all z-10
                          ">
                            <button
                              onClick={() => onClone(rule)}
                              className="
                                w-full px-4 py-2 text-left text-sm text-gray-300 
                                hover:bg-gray-700 hover:text-white transition-colors
                                flex items-center space-x-2
                              "
                            >
                              <Copy className="w-4 h-4" />
                              <span>Clone Rule</span>
                            </button>
                            <button
                              onClick={() => {
                                if (confirm('Delete this rule?')) {
                                  onDelete(rule.id);
                                }
                              }}
                              className="
                                w-full px-4 py-2 text-left text-sm text-red-400 
                                hover:bg-gray-700 hover:text-red-300 transition-colors
                                flex items-center space-x-2
                              "
                            >
                              <Trash2 className="w-4 h-4" />
                              <span>Delete Rule</span>
                            </button>
                          </div>
                        </div>
                      </div>
                    </td>
                  </tr>
                  {isExpanded && (
                    <tr>
                      <td colSpan={8} className="p-4 bg-gray-900/50">
                        <div className="space-y-4">
                          <div className="p-4 bg-gray-800 rounded-lg">
                            <h4 className="text-sm font-semibold text-gray-300 mb-2">
                              Rule Content Preview
                            </h4>
                            <pre className="text-xs text-gray-400 font-mono overflow-x-auto">
                              {rule.content.slice(0, 500)}
                              {rule.content.length > 500 && '...'}
                            </pre>
                          </div>
                          {rule.performance_metrics && (
                            <PerformanceMetrics metrics={rule.performance_metrics} />
                          )}
                          {rule.last_matched && (
                            <div className="flex items-center space-x-2 text-sm text-gray-400">
                              <Shield className="w-4 h-4" />
                              <span>
                                Last matched: {formatDateTime(rule.last_matched)}
                              </span>
                            </div>
                          )}
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <div className="text-sm text-gray-400">
            Showing {((currentPage - 1) * itemsPerPage) + 1} to{' '}
            {Math.min(currentPage * itemsPerPage, totalCount)} of {totalCount} rules
          </div>
          <div className="flex items-center space-x-2">
            <Button
              size="sm"
              variant="secondary"
              onClick={() => onPageChange(currentPage - 1)}
              disabled={currentPage === 1}
            >
              Previous
            </Button>
            <div className="flex items-center space-x-1">
              {[...Array(totalPages)].map((_, i) => {
                const page = i + 1;
                if (
                  page === 1 || 
                  page === totalPages || 
                  (page >= currentPage - 1 && page <= currentPage + 1)
                ) {
                  return (
                    <Button
                      key={page}
                      size="sm"
                      variant={page === currentPage ? 'primary' : 'ghost'}
                      onClick={() => onPageChange(page)}
                    >
                      {page}
                    </Button>
                  );
                } else if (
                  page === currentPage - 2 || 
                  page === currentPage + 2
                ) {
                  return <span key={page} className="text-gray-500">...</span>;
                }
                return null;
              })}
            </div>
            <Button
              size="sm"
              variant="secondary"
              onClick={() => onPageChange(currentPage + 1)}
              disabled={currentPage === totalPages}
            >
              Next
            </Button>
          </div>
        </div>
      )}
    </div>
  );
};

export default RuleList;