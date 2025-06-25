import React, { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  PlusIcon,
  MagnifyingGlassIcon,
  FunnelIcon,
  ArrowUpTrayIcon,
  ArrowDownTrayIcon,
  TrashIcon,
  PencilIcon,
  PlayIcon,
  CheckCircleIcon,
  XCircleIcon,
  ShieldCheckIcon,
  BeakerIcon,
  DocumentTextIcon,
  ExclamationTriangleIcon
} from '@heroicons/react/24/outline';
import { toast } from 'react-hot-toast';
import Card from '@/components/common/Card';
import Button from '@/components/common/Button';
import RuleEditor from '@/components/rules/RuleEditor';
import RuleList from '@/components/rules/RuleList';
import { rulesService } from '@/services/rulesService';
import { formatDateTime } from '@/utils/formatters';

const RULE_TYPES = [
  { id: 'yara', label: 'YARA', icon: ShieldCheckIcon, color: 'text-blue-400' },
  { id: 'sigma', label: 'Sigma', icon: BeakerIcon, color: 'text-purple-400' },
  { id: 'custom', label: 'Custom', icon: DocumentTextIcon, color: 'text-green-400' }
];

const RULE_CATEGORIES = [
  'malware',
  'exploits',
  'suspicious',
  'network',
  'persistence',
  'privilege_escalation',
  'defense_evasion',
  'credential_access',
  'discovery',
  'lateral_movement',
  'collection',
  'exfiltration',
  'command_control'
];

export default function Rules() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedType, setSelectedType] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('');
  const [selectedRules, setSelectedRules] = useState([]);
  const [showEditor, setShowEditor] = useState(false);
  const [editingRule, setEditingRule] = useState(null);
  const [showImport, setShowImport] = useState(false);
  const [testResults, setTestResults] = useState({});
  const [stats, setStats] = useState({
    total: 0,
    enabled: 0,
    yara: 0,
    sigma: 0,
    custom: 0,
    lastUpdate: null
  });
  const [pagination, setPagination] = useState({
    page: 1,
    limit: 50,
    total: 0,
    totalPages: 0
  });

  // Load rules
  const loadRules = useCallback(async () => {
    try {
      setLoading(true);
      
      const params = {
        page: pagination.page,
        limit: pagination.limit,
        search: searchTerm,
        type: selectedType,
        category: selectedCategory
      };

      const response = await rulesService.getRules(params);
      setRules(response.items);
      setPagination({
        ...pagination,
        total: response.total,
        totalPages: response.totalPages
      });

      // Calculate stats
      const enabledCount = response.items.filter(r => r.enabled).length;
      const typeCount = response.items.reduce((acc, rule) => {
        acc[rule.type] = (acc[rule.type] || 0) + 1;
        return acc;
      }, {});

      setStats({
        total: response.total,
        enabled: enabledCount,
        yara: typeCount.yara || 0,
        sigma: typeCount.sigma || 0,
        custom: typeCount.custom || 0,
        lastUpdate: response.items[0]?.updated_at || null
      });

    } catch (error) {
      toast.error('Failed to load rules');
      console.error(error);
    } finally {
      setLoading(false);
    }
  }, [pagination.page, pagination.limit, searchTerm, selectedType, selectedCategory]);

  useEffect(() => {
    loadRules();
  }, [loadRules]);

  // Handle rule creation/update
  const handleSaveRule = async (ruleData) => {
    try {
      if (editingRule) {
        await rulesService.updateRule(editingRule.id, ruleData);
        toast.success('Rule updated successfully');
      } else {
        await rulesService.createRule(ruleData);
        toast.success('Rule created successfully');
      }
      
      setShowEditor(false);
      setEditingRule(null);
      loadRules();
    } catch (error) {
      toast.error('Failed to save rule');
      throw error;
    }
  };

  // Handle rule deletion
  const handleDeleteRule = async (ruleId) => {
    if (!confirm('Are you sure you want to delete this rule?')) return;

    try {
      await rulesService.deleteRule(ruleId);
      toast.success('Rule deleted');
      loadRules();
    } catch (error) {
      toast.error('Failed to delete rule');
    }
  };

  // Handle bulk actions
  const handleBulkDelete = async () => {
    if (selectedRules.length === 0) return;

    if (!confirm(`Delete ${selectedRules.length} rules? This cannot be undone.`)) {
      return;
    }

    try {
      await rulesService.bulkDelete(selectedRules);
      toast.success(`Deleted ${selectedRules.length} rules`);
      setSelectedRules([]);
      loadRules();
    } catch (error) {
      toast.error('Failed to delete rules');
    }
  };

  const handleBulkEnable = async (enable = true) => {
    if (selectedRules.length === 0) return;

    try {
      await rulesService.bulkUpdate(selectedRules, { enabled: enable });
      toast.success(`${enable ? 'Enabled' : 'Disabled'} ${selectedRules.length} rules`);
      setSelectedRules([]);
      loadRules();
    } catch (error) {
      toast.error(`Failed to ${enable ? 'enable' : 'disable'} rules`);
    }
  };

  // Handle rule testing
  const handleTestRule = async (ruleId) => {
    try {
      setTestResults(prev => ({ ...prev, [ruleId]: 'testing' }));
      const result = await rulesService.testRule(ruleId);
      setTestResults(prev => ({ ...prev, [ruleId]: result }));
      toast.success('Rule test completed');
    } catch (error) {
      setTestResults(prev => ({ ...prev, [ruleId]: 'error' }));
      toast.error('Rule test failed');
    }
  };

  // Handle import
  const handleImport = async (file) => {
    try {
      const result = await rulesService.importRules(file);
      toast.success(`Imported ${result.imported} rules`);
      if (result.errors.length > 0) {
        toast.error(`${result.errors.length} rules failed to import`);
      }
      setShowImport(false);
      loadRules();
    } catch (error) {
      toast.error('Import failed');
    }
  };

  // Handle export
  const handleExport = async (format = 'json') => {
    try {
      const blob = await rulesService.exportRules({
        format,
        ids: selectedRules.length > 0 ? selectedRules : undefined
      });
      
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `rules-${new Date().toISOString()}.${format}`;
      a.click();
      window.URL.revokeObjectURL(url);
      
      toast.success(`Exported ${selectedRules.length || 'all'} rules`);
    } catch (error) {
      toast.error('Export failed');
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-gray-800/50 backdrop-blur border border-gray-700 rounded-lg p-6">
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white mb-2">Detection Rules</h1>
            <p className="text-gray-400">
              Manage YARA, Sigma, and custom detection rules for file analysis
            </p>
          </div>
          
          <div className="flex items-center space-x-3">
            <Button
              variant="secondary"
              icon={ArrowUpTrayIcon}
              onClick={() => setShowImport(true)}
            >
              Import
            </Button>
            <Button
              icon={PlusIcon}
              onClick={() => {
                setEditingRule(null);
                setShowEditor(true);
              }}
            >
              Create Rule
            </Button>
          </div>
        </div>
      </div>

      {/* Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        <Card className="bg-gray-800/50 p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-2xl font-bold text-white">{stats.total}</p>
              <p className="text-sm text-gray-400">Total Rules</p>
            </div>
            <ShieldCheckIcon className="h-8 w-8 text-gray-600" />
          </div>
        </Card>

        <Card className="bg-gray-800/50 p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-2xl font-bold text-green-400">{stats.enabled}</p>
              <p className="text-sm text-gray-400">Active Rules</p>
            </div>
            <CheckCircleIcon className="h-8 w-8 text-green-600" />
          </div>
        </Card>

        {RULE_TYPES.map(type => {
          const Icon = type.icon;
          return (
            <Card key={type.id} className="bg-gray-800/50 p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className={`text-2xl font-bold ${type.color}`}>
                    {stats[type.id] || 0}
                  </p>
                  <p className="text-sm text-gray-400">{type.label} Rules</p>
                </div>
                <Icon className={`h-8 w-8 ${type.color} opacity-50`} />
              </div>
            </Card>
          );
        })}
      </div>

      {/* Filters */}
      <Card className="bg-gray-800/50">
        <div className="flex flex-col lg:flex-row gap-4">
          {/* Search */}
          <div className="flex-1">
            <div className="relative">
              <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
              <input
                type="text"
                placeholder="Search rules by name, description, or content..."
                value={searchTerm}
                onChange={(e) => {
                  setSearchTerm(e.target.value);
                  setPagination(prev => ({ ...prev, page: 1 }));
                }}
                className="w-full pl-10 pr-4 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-cyber-blue"
              />
            </div>
          </div>

          {/* Type Filter */}
          <select
            value={selectedType}
            onChange={(e) => {
              setSelectedType(e.target.value);
              setPagination(prev => ({ ...prev, page: 1 }));
            }}
            className="px-4 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white"
          >
            <option value="">All Types</option>
            {RULE_TYPES.map(type => (
              <option key={type.id} value={type.id}>{type.label}</option>
            ))}
          </select>

          {/* Category Filter */}
          <select
            value={selectedCategory}
            onChange={(e) => {
              setSelectedCategory(e.target.value);
              setPagination(prev => ({ ...prev, page: 1 }));
            }}
            className="px-4 py-2 bg-gray-900/50 border border-gray-700 rounded-lg text-white"
          >
            <option value="">All Categories</option>
            {RULE_CATEGORIES.map(cat => (
              <option key={cat} value={cat}>
                {cat.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
              </option>
            ))}
          </select>
        </div>

        {/* Bulk Actions */}
        {selectedRules.length > 0 && (
          <div className="mt-4 flex items-center justify-between p-4 bg-cyber-blue/10 border border-cyber-blue/30 rounded-lg">
            <span className="text-sm text-white">
              {selectedRules.length} rule{selectedRules.length > 1 ? 's' : ''} selected
            </span>
            <div className="flex items-center space-x-3">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => handleBulkEnable(true)}
              >
                Enable
              </Button>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => handleBulkEnable(false)}
              >
                Disable
              </Button>
              <Button
                variant="ghost"
                size="sm"
                icon={ArrowDownTrayIcon}
                onClick={() => handleExport('json')}
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
      </Card>

      {/* Rules List */}
      <RuleList
        rules={rules}
        loading={loading}
        selectedRules={selectedRules}
        onSelectRule={(id) => {
          setSelectedRules(prev => 
            prev.includes(id) 
              ? prev.filter(r => r !== id)
              : [...prev, id]
          );
        }}
        onSelectAll={() => {
          if (selectedRules.length === rules.length) {
            setSelectedRules([]);
          } else {
            setSelectedRules(rules.map(r => r.id));
          }
        }}
        onEditRule={(rule) => {
          setEditingRule(rule);
          setShowEditor(true);
        }}
        onDeleteRule={handleDeleteRule}
        onTestRule={handleTestRule}
        onToggleRule={async (ruleId, enabled) => {
          try {
            await rulesService.updateRule(ruleId, { enabled });
            loadRules();
          } catch (error) {
            toast.error('Failed to toggle rule');
          }
        }}
        testResults={testResults}
        pagination={pagination}
        onPageChange={(page) => setPagination(prev => ({ ...prev, page }))}
      />

      {/* Rule Editor Modal */}
      <AnimatePresence>
        {showEditor && (
          <RuleEditor
            rule={editingRule}
            onSave={handleSaveRule}
            onClose={() => {
              setShowEditor(false);
              setEditingRule(null);
            }}
          />
        )}
      </AnimatePresence>

      {/* Import Modal */}
      <AnimatePresence>
        {showImport && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4"
            onClick={() => setShowImport(false)}
          >
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              onClick={(e) => e.stopPropagation()}
              className="bg-gray-800 border border-gray-700 rounded-lg shadow-xl max-w-md w-full p-6"
            >
              <h3 className="text-lg font-medium text-white mb-4">Import Rules</h3>
              
              <div className="space-y-4">
                <div className="border-2 border-dashed border-gray-700 rounded-lg p-8 text-center">
                  <ArrowUpTrayIcon className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                  <p className="text-gray-400 mb-2">Drop rule files here or click to browse</p>
                  <p className="text-sm text-gray-500">Supports YARA, Sigma, and JSON formats</p>
                  
                  <input
                    type="file"
                    accept=".yar,.yara,.yml,.yaml,.json"
                    onChange={(e) => {
                      if (e.target.files?.[0]) {
                        handleImport(e.target.files[0]);
                      }
                    }}
                    className="hidden"
                    id="rule-import"
                  />
                  <label
                    htmlFor="rule-import"
                    className="inline-block mt-4 px-4 py-2 bg-cyber-blue text-white rounded-lg cursor-pointer hover:bg-cyber-blue/80 transition-colors"
                  >
                    Select Files
                  </label>
                </div>

                <div className="flex justify-end space-x-3">
                  <Button
                    variant="ghost"
                    onClick={() => setShowImport(false)}
                  >
                    Cancel
                  </Button>
                </div>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}