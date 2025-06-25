import React, { useMemo } from 'react';
import { Upload, CheckCircle, AlertCircle, X } from 'lucide-react';
import { formatBytes, formatDuration } from '../../utils/formatters';

const UploadProgress = ({ 
  uploads = [], 
  onCancel,
  onDismiss,
  compact = false 
}) => {
  // Calculate overall progress
  const overallProgress = useMemo(() => {
    if (uploads.length === 0) return 0;
    
    const totalProgress = uploads.reduce((sum, upload) => sum + (upload.progress || 0), 0);
    return Math.round(totalProgress / uploads.length);
  }, [uploads]);

  // Count uploads by status
  const statusCounts = useMemo(() => {
    return uploads.reduce((counts, upload) => {
      const status = upload.status || 'pending';
      counts[status] = (counts[status] || 0) + 1;
      return counts;
    }, {});
  }, [uploads]);

  // Calculate upload speed
  const calculateSpeed = (upload) => {
    if (!upload.startTime || !upload.loaded || upload.status !== 'uploading') {
      return null;
    }
    
    const elapsedSeconds = (Date.now() - upload.startTime) / 1000;
    const bytesPerSecond = upload.loaded / elapsedSeconds;
    return bytesPerSecond;
  };

  // Estimate time remaining
  const estimateTimeRemaining = (upload) => {
    const speed = calculateSpeed(upload);
    if (!speed || !upload.total) return null;
    
    const remaining = upload.total - upload.loaded;
    const secondsRemaining = remaining / speed;
    return secondsRemaining;
  };

  if (uploads.length === 0) return null;

  // Compact view for single upload
  if (compact && uploads.length === 1) {
    const upload = uploads[0];
    return (
      <div className="fixed bottom-4 right-4 w-80 bg-gray-900 border border-gray-700 rounded-lg shadow-lg p-4 z-50">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center space-x-2">
            <Upload className="w-4 h-4 text-cyan-400" />
            <span className="text-sm font-medium text-white">Uploading</span>
          </div>
          {onDismiss && upload.status === 'completed' && (
            <button
              onClick={() => onDismiss(upload)}
              className="p-1 hover:bg-gray-800 rounded"
            >
              <X className="w-3 h-3 text-gray-400" />
            </button>
          )}
        </div>
        
        <div className="space-y-2">
          <div className="text-sm text-gray-300 truncate">{upload.name}</div>
          <div className="w-full h-2 bg-gray-700 rounded-full overflow-hidden">
            <div 
              className="h-full bg-cyan-500 transition-all duration-300"
              style={{ width: `${upload.progress || 0}%` }}
            />
          </div>
          <div className="flex justify-between text-xs text-gray-400">
            <span>{upload.progress || 0}%</span>
            <span>{formatBytes(upload.loaded || 0)} / {formatBytes(upload.total || 0)}</span>
          </div>
        </div>
      </div>
    );
  }

  // Full view
  return (
    <div className="fixed bottom-4 right-4 w-96 max-h-96 bg-gray-900 border border-gray-700 rounded-lg shadow-lg z-50">
      {/* Header */}
      <div className="p-4 border-b border-gray-700">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="font-medium text-white">Upload Progress</h3>
            <p className="text-sm text-gray-400 mt-1">
              {statusCounts.uploading || 0} uploading, {statusCounts.completed || 0} completed
            </p>
          </div>
          {onDismiss && statusCounts.uploading === 0 && (
            <button
              onClick={() => onDismiss()}
              className="p-1 hover:bg-gray-800 rounded"
            >
              <X className="w-4 h-4 text-gray-400" />
            </button>
          )}
        </div>

        {/* Overall Progress */}
        <div className="mt-3">
          <div className="flex justify-between text-sm mb-1">
            <span className="text-gray-400">Overall Progress</span>
            <span className="text-white">{overallProgress}%</span>
          </div>
          <div className="w-full h-2 bg-gray-700 rounded-full overflow-hidden">
            <div 
              className="h-full bg-cyan-500 transition-all duration-300"
              style={{ width: `${overallProgress}%` }}
            />
          </div>
        </div>
      </div>

      {/* Upload List */}
      <div className="max-h-64 overflow-y-auto">
        {uploads.map((upload, index) => {
          const speed = calculateSpeed(upload);
          const timeRemaining = estimateTimeRemaining(upload);
          
          return (
            <div
              key={upload.id || index}
              className="p-4 border-b border-gray-800 hover:bg-gray-800/50 transition-colors"
            >
              <div className="flex items-start justify-between">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center space-x-2">
                    {upload.status === 'completed' ? (
                      <CheckCircle className="w-4 h-4 text-green-500 flex-shrink-0" />
                    ) : upload.status === 'error' ? (
                      <AlertCircle className="w-4 h-4 text-red-500 flex-shrink-0" />
                    ) : (
                      <Upload className="w-4 h-4 text-blue-500 animate-pulse flex-shrink-0" />
                    )}
                    <span className="text-sm text-white truncate">{upload.name}</span>
                  </div>

                  {upload.status === 'uploading' && (
                    <>
                      <div className="mt-2 w-full h-1.5 bg-gray-700 rounded-full overflow-hidden">
                        <div 
                          className="h-full bg-cyan-500 transition-all duration-300"
                          style={{ width: `${upload.progress || 0}%` }}
                        />
                      </div>
                      
                      <div className="mt-1 flex items-center justify-between text-xs text-gray-400">
                        <div className="flex items-center space-x-3">
                          <span>{upload.progress || 0}%</span>
                          {speed && (
                            <span>{formatBytes(speed)}/s</span>
                          )}
                        </div>
                        <div className="flex items-center space-x-3">
                          {timeRemaining && (
                            <span>{formatDuration(timeRemaining)} left</span>
                          )}
                          <span>
                            {formatBytes(upload.loaded || 0)} / {formatBytes(upload.total || 0)}
                          </span>
                        </div>
                      </div>
                    </>
                  )}

                  {upload.status === 'completed' && (
                    <div className="mt-1 text-xs text-green-400">
                      Upload complete
                    </div>
                  )}

                  {upload.status === 'error' && (
                    <div className="mt-1 text-xs text-red-400">
                      {upload.error || 'Upload failed'}
                    </div>
                  )}
                </div>

                {/* Cancel button */}
                {upload.status === 'uploading' && onCancel && (
                  <button
                    onClick={() => onCancel(upload)}
                    className="ml-2 p-1 hover:bg-gray-700 rounded"
                    title="Cancel upload"
                  >
                    <X className="w-4 h-4 text-gray-400" />
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Footer Actions */}
      {statusCounts.uploading > 0 && onCancel && (
        <div className="p-4 border-t border-gray-700">
          <button
            onClick={() => uploads.forEach(u => u.status === 'uploading' && onCancel(u))}
            className="w-full px-3 py-1.5 bg-red-500/10 hover:bg-red-500/20 text-red-400 rounded transition-colors text-sm"
          >
            Cancel All Uploads
          </button>
        </div>
      )}
    </div>
  );
};

// Mini progress indicator for navbar/header
export const UploadProgressMini = ({ uploads = [] }) => {
  const activeUploads = uploads.filter(u => u.status === 'uploading');
  
  if (activeUploads.length === 0) return null;

  const totalProgress = activeUploads.reduce((sum, u) => sum + (u.progress || 0), 0);
  const averageProgress = Math.round(totalProgress / activeUploads.length);

  return (
    <div className="flex items-center space-x-2 px-3 py-1 bg-gray-800 rounded-lg">
      <Upload className="w-4 h-4 text-cyan-400 animate-pulse" />
      <div className="w-24 h-1.5 bg-gray-700 rounded-full overflow-hidden">
        <div 
          className="h-full bg-cyan-500 transition-all duration-300"
          style={{ width: `${averageProgress}%` }}
        />
      </div>
      <span className="text-xs text-gray-400">{activeUploads.length}</span>
    </div>
  );
};

export default UploadProgress;