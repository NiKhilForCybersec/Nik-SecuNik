import React from 'react';
import { 
  X, CheckCircle, AlertCircle, Clock, Upload, 
  FileText, Hash, Calendar, HardDrive 
} from 'lucide-react';
import Card from '../common/Card';
import Button from '../common/Button';
import { ProgressLoader } from '../common/LoadingSpinner';
import { formatBytes, formatDateTime, getFileIcon } from '../../utils/formatters';

const FileList = ({ 
  files = [], 
  onRemove, 
  onRetry,
  onAnalyze,
  showActions = true 
}) => {
  if (files.length === 0) {
    return null;
  }

  const getStatusIcon = (status) => {
    switch (status) {
      case 'uploading':
        return <Upload className="w-5 h-5 text-blue-500 animate-pulse" />;
      case 'processing':
        return <Clock className="w-5 h-5 text-yellow-500 animate-spin" />;
      case 'completed':
        return <CheckCircle className="w-5 h-5 text-green-500" />;
      case 'error':
        return <AlertCircle className="w-5 h-5 text-red-500" />;
      default:
        return <Clock className="w-5 h-5 text-gray-500" />;
    }
  };

  const getStatusText = (status) => {
    switch (status) {
      case 'uploading':
        return 'Uploading...';
      case 'processing':
        return 'Processing...';
      case 'completed':
        return 'Ready for analysis';
      case 'error':
        return 'Upload failed';
      default:
        return 'Pending';
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'uploading':
        return 'text-blue-400';
      case 'processing':
        return 'text-yellow-400';
      case 'completed':
        return 'text-green-400';
      case 'error':
        return 'text-red-400';
      default:
        return 'text-gray-400';
    }
  };

  return (
    <Card title={`Uploaded Files (${files.length})`}>
      <div className="space-y-3">
        {files.map((file, index) => (
          <div
            key={file.id || index}
            className={`
              p-4 bg-gray-800 rounded-lg border transition-all duration-200
              ${file.status === 'error' 
                ? 'border-red-500/50' 
                : 'border-gray-700 hover:border-gray-600'
              }
            `}
          >
            <div className="flex items-start justify-between">
              {/* File Info */}
              <div className="flex items-start space-x-4 flex-1">
                <div className="text-3xl">{getFileIcon(file.name)}</div>
                
                <div className="flex-1 min-w-0">
                  <div className="flex items-center space-x-3">
                    <h4 className="font-medium text-white truncate">
                      {file.name}
                    </h4>
                    {getStatusIcon(file.status)}
                  </div>
                  
                  <div className="mt-2 flex flex-wrap items-center gap-4 text-sm text-gray-400">
                    <div className="flex items-center space-x-1">
                      <HardDrive className="w-4 h-4" />
                      <span>{formatBytes(file.size)}</span>
                    </div>
                    
                    {file.hash && (
                      <div className="flex items-center space-x-1">
                        <Hash className="w-4 h-4" />
                        <span className="font-mono text-xs">
                          {file.hash.substring(0, 8)}...
                        </span>
                      </div>
                    )}
                    
                    {file.uploadedAt && (
                      <div className="flex items-center space-x-1">
                        <Calendar className="w-4 h-4" />
                        <span>{formatDateTime(file.uploadedAt, { relative: true })}</span>
                      </div>
                    )}
                  </div>

                  {/* Status Text */}
                  <div className={`mt-2 text-sm ${getStatusColor(file.status)}`}>
                    {getStatusText(file.status)}
                  </div>

                  {/* Progress Bar */}
                  {file.progress !== undefined && file.progress < 100 && (
                    <div className="mt-3">
                      <ProgressLoader 
                        progress={file.progress} 
                        color={file.status === 'error' ? 'red' : 'cyan'}
                      />
                    </div>
                  )}

                  {/* Error Message */}
                  {file.error && (
                    <div className="mt-2 text-sm text-red-400">
                      {file.error}
                    </div>
                  )}

                  {/* File Details */}
                  {file.details && (
                    <div className="mt-3 grid grid-cols-2 gap-3 text-sm">
                      {file.details.type && (
                        <div>
                          <span className="text-gray-500">Type:</span>
                          <span className="ml-2 text-gray-300">{file.details.type}</span>
                        </div>
                      )}
                      {file.details.parsedEvents && (
                        <div>
                          <span className="text-gray-500">Events:</span>
                          <span className="ml-2 text-gray-300">
                            {file.details.parsedEvents.toLocaleString()}
                          </span>
                        </div>
                      )}
                      {file.details.encoding && (
                        <div>
                          <span className="text-gray-500">Encoding:</span>
                          <span className="ml-2 text-gray-300">{file.details.encoding}</span>
                        </div>
                      )}
                      {file.details.compressed && (
                        <div>
                          <span className="text-gray-500">Compressed:</span>
                          <span className="ml-2 text-gray-300">Yes</span>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>

              {/* Actions */}
              {showActions && (
                <div className="flex items-start space-x-2 ml-4">
                  {file.status === 'completed' && onAnalyze && (
                    <Button
                      size="sm"
                      variant="primary"
                      onClick={() => onAnalyze(file)}
                    >
                      Analyze
                    </Button>
                  )}
                  
                  {file.status === 'error' && onRetry && (
                    <Button
                      size="sm"
                      variant="secondary"
                      onClick={() => onRetry(file)}
                    >
                      Retry
                    </Button>
                  )}
                  
                  {onRemove && (
                    <button
                      onClick={() => onRemove(file)}
                      className="p-1.5 hover:bg-gray-700 rounded transition-colors"
                      title="Remove file"
                    >
                      <X className="w-4 h-4 text-gray-400" />
                    </button>
                  )}
                </div>
              )}
            </div>

            {/* Additional Metadata */}
            {file.metadata && (
              <div className="mt-3 pt-3 border-t border-gray-700">
                <div className="flex flex-wrap gap-2">
                  {Object.entries(file.metadata).map(([key, value]) => (
                    <span
                      key={key}
                      className="px-2 py-1 bg-gray-700 rounded text-xs text-gray-300"
                    >
                      {key}: {value}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </Card>
  );
};

export default FileList;