import React, { useState, useCallback } from 'react';
import { Upload, FileText, AlertCircle, CheckCircle, Download, RefreshCw } from 'lucide-react';
import { useDropzone } from 'react-dropzone';
import Modal from '../common/Modal';
import Button from '../common/Button';
import Table from '../common/Table';
import { rulesService } from '../../services/rulesService';
import { formatDateTime } from '../../utils/formatters';

const RuleImporter = ({ isOpen, onClose, onImportComplete }) => {
  const [importedFile, setImportedFile] = useState(null);
  const [importResults, setImportResults] = useState(null);
  const [isImporting, setIsImporting] = useState(false);
  const [error, setError] = useState(null);
  const [importOptions, setImportOptions] = useState({
    overwrite: false,
    validate: true,
    enableImported: false
  });

  const onDrop = useCallback((acceptedFiles) => {
    const file = acceptedFiles[0];
    if (file) {
      setImportedFile(file);
      setError(null);
      setImportResults(null);
    }
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'application/json': ['.json'],
      'text/yaml': ['.yml', '.yaml'],
      'text/plain': ['.yar', '.yara']
    },
    maxFiles: 1,
    maxSize: 10 * 1024 * 1024 // 10MB
  });

  const handleImport = async () => {
    if (!importedFile) return;

    setIsImporting(true);
    setError(null);

    try {
      const results = await rulesService.importRules(importedFile, importOptions);
      setImportResults(results);
      
      if (results.success && results.imported > 0) {
        onImportComplete?.(results);
      }
    } catch (err) {
      setError(err.message || 'Import failed');
    } finally {
      setIsImporting(false);
    }
  };

  const downloadSamplePack = () => {
    // This would download a sample rule pack
    const link = document.createElement('a');
    link.href = '/api/rules/sample-pack';
    link.download = 'sample-rules.json';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const syncWithRepository = async () => {
    setIsImporting(true);
    setError(null);

    try {
      const results = await rulesService.syncRules({
        source: 'github',
        repository: 'sigma-rules/sigma',
        branch: 'main'
      });
      setImportResults(results);
      
      if (results.success) {
        onImportComplete?.(results);
      }
    } catch (err) {
      setError(err.message || 'Sync failed');
    } finally {
      setIsImporting(false);
    }
  };

  const renderImportResults = () => {
    if (!importResults) return null;

    const columns = [
      {
        key: 'name',
        label: 'Rule Name',
        render: (value) => (
          <span className="font-medium text-white">{value}</span>
        )
      },
      {
        key: 'type',
        label: 'Type',
        render: (value) => (
          <span className="px-2 py-1 text-xs bg-gray-700 rounded">
            {value.toUpperCase()}
          </span>
        )
      },
      {
        key: 'status',
        label: 'Status',
        render: (value) => {
          const statusConfig = {
            imported: { color: 'text-green-400', icon: CheckCircle },
            updated: { color: 'text-blue-400', icon: RefreshCw },
            skipped: { color: 'text-yellow-400', icon: AlertCircle },
            failed: { color: 'text-red-400', icon: AlertCircle }
          };
          
          const config = statusConfig[value] || statusConfig.failed;
          const Icon = config.icon;
          
          return (
            <div className={`flex items-center space-x-2 ${config.color}`}>
              <Icon className="w-4 h-4" />
              <span className="capitalize">{value}</span>
            </div>
          );
        }
      },
      {
        key: 'message',
        label: 'Details',
        render: (value) => (
          <span className="text-sm text-gray-400">{value || '-'}</span>
        )
      }
    ];

    return (
      <div className="mt-6">
        <div className="mb-4 p-4 bg-gray-800 rounded-lg">
          <h4 className="text-sm font-semibold text-white mb-2">Import Summary</h4>
          <div className="grid grid-cols-4 gap-4 text-sm">
            <div>
              <span className="text-gray-400">Total Rules:</span>
              <span className="ml-2 text-white font-medium">{importResults.total}</span>
            </div>
            <div>
              <span className="text-gray-400">Imported:</span>
              <span className="ml-2 text-green-400 font-medium">{importResults.imported}</span>
            </div>
            <div>
              <span className="text-gray-400">Updated:</span>
              <span className="ml-2 text-blue-400 font-medium">{importResults.updated || 0}</span>
            </div>
            <div>
              <span className="text-gray-400">Failed:</span>
              <span className="ml-2 text-red-400 font-medium">{importResults.failed}</span>
            </div>
          </div>
        </div>

        {importResults.rules && importResults.rules.length > 0 && (
          <Table
            data={importResults.rules}
            columns={columns}
            compact
            pageSize={10}
          />
        )}
      </div>
    );
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Import Rules"
      size="lg"
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant="primary"
            onClick={handleImport}
            disabled={!importedFile || isImporting}
            loading={isImporting}
          >
            Import Rules
          </Button>
        </>
      }
    >
      <div className="space-y-6">
        {/* Quick Actions */}
        <div className="flex space-x-4">
          <Button
            variant="secondary"
            size="sm"
            onClick={downloadSamplePack}
            leftIcon={<Download className="w-4 h-4" />}
          >
            Download Sample Pack
          </Button>
          <Button
            variant="secondary"
            size="sm"
            onClick={syncWithRepository}
            leftIcon={<RefreshCw className="w-4 h-4" />}
            loading={isImporting}
          >
            Sync from Repository
          </Button>
        </div>

        {/* File Upload */}
        {!importResults && (
          <>
            <div
              {...getRootProps()}
              className={`
                border-2 border-dashed rounded-lg p-8 text-center cursor-pointer
                transition-all duration-200
                ${isDragActive 
                  ? 'border-cyan-500 bg-cyan-500/10' 
                  : 'border-gray-700 hover:border-gray-600'
                }
              `}
            >
              <input {...getInputProps()} />
              <Upload className="w-12 h-12 text-gray-500 mx-auto mb-4" />
              {importedFile ? (
                <div className="space-y-2">
                  <p className="text-white font-medium">{importedFile.name}</p>
                  <p className="text-sm text-gray-400">
                    {(importedFile.size / 1024).toFixed(2)} KB
                  </p>
                </div>
              ) : (
                <>
                  <p className="text-gray-300 mb-2">
                    {isDragActive
                      ? 'Drop the file here...'
                      : 'Drag & drop rule file here, or click to browse'
                    }
                  </p>
                  <p className="text-sm text-gray-500">
                    Supports JSON, YAML, and YARA files (max 10MB)
                  </p>
                </>
              )}
            </div>

            {/* Import Options */}
            <div className="space-y-3">
              <h4 className="text-sm font-semibold text-gray-300">Import Options</h4>
              
              <label className="flex items-center space-x-3">
                <input
                  type="checkbox"
                  checked={importOptions.overwrite}
                  onChange={(e) => setImportOptions(prev => ({
                    ...prev,
                    overwrite: e.target.checked
                  }))}
                  className="w-4 h-4 rounded border-gray-600 bg-gray-700 text-cyan-500"
                />
                <span className="text-sm text-gray-300">
                  Overwrite existing rules with same name
                </span>
              </label>

              <label className="flex items-center space-x-3">
                <input
                  type="checkbox"
                  checked={importOptions.validate}
                  onChange={(e) => setImportOptions(prev => ({
                    ...prev,
                    validate: e.target.checked
                  }))}
                  className="w-4 h-4 rounded border-gray-600 bg-gray-700 text-cyan-500"
                />
                <span className="text-sm text-gray-300">
                  Validate rules before importing
                </span>
              </label>

              <label className="flex items-center space-x-3">
                <input
                  type="checkbox"
                  checked={importOptions.enableImported}
                  onChange={(e) => setImportOptions(prev => ({
                    ...prev,
                    enableImported: e.target.checked
                  }))}
                  className="w-4 h-4 rounded border-gray-600 bg-gray-700 text-cyan-500"
                />
                <span className="text-sm text-gray-300">
                  Enable imported rules immediately
                </span>
              </label>
            </div>
          </>
        )}

        {/* Error Display */}
        {error && (
          <div className="p-4 bg-red-500/10 border border-red-500/50 rounded-lg">
            <div className="flex items-start space-x-3">
              <AlertCircle className="w-5 h-5 text-red-500 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-red-400 font-medium">Import Error</p>
                <p className="text-sm text-gray-300 mt-1">{error}</p>
              </div>
            </div>
          </div>
        )}

        {/* Import Results */}
        {renderImportResults()}
      </div>
    </Modal>
  );
};

export default RuleImporter;