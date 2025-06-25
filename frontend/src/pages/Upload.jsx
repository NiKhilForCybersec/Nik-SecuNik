import React, { useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  CloudUploadIcon, 
  DocumentIcon, 
  ExclamationCircleIcon,
  CheckCircleIcon,
  XCircleIcon,
  InformationCircleIcon
} from '@heroicons/react/24/outline';
import { toast } from 'react-hot-toast';
import FileDropzone from '@/components/upload/FileDropzone';
import Button from '@/components/common/Button';
import Card from '@/components/common/Card';
import { uploadService } from '@/services/uploadService';
import { formatBytes, getFileIcon } from '@/utils/formatters';

const SUPPORTED_FORMATS = {
  'Logs': ['.log', '.txt', '.syslog', '.evtx', '.evt'],
  'Network': ['.pcap', '.pcapng', '.cap', '.netflow'],
  'Archives': ['.zip', '.rar', '.7z', '.tar', '.gz'],
  'Documents': ['.pdf', '.doc', '.docx', '.xls', '.xlsx'],
  'Email': ['.eml', '.msg', '.mbox', '.pst'],
  'Forensics': ['.dd', '.e01', '.vmdk', '.vhd'],
  'Structured': ['.json', '.xml', '.csv', '.yaml'],
  'Mobile': ['.logcat', '.ips'],
  'Cloud': ['.cloudtrail', '.azurelog']
};

export default function Upload() {
  const navigate = useNavigate();
  const [files, setFiles] = useState([]);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState({});
  const [supportedFormats, setSupportedFormats] = useState(SUPPORTED_FORMATS);

  // Fetch supported formats on mount
  React.useEffect(() => {
    uploadService.getSupportedFormats()
      .then(formats => {
        if (formats) setSupportedFormats(formats);
      })
      .catch(err => console.error('Failed to fetch formats:', err));
  }, []);

  const handleFilesSelected = useCallback((newFiles) => {
    // Validate file count
    const totalFiles = files.length + newFiles.length;
    if (totalFiles > 10) {
      toast.error('Maximum 10 files allowed at once');
      return;
    }

    // Add files with metadata
    const filesWithMeta = newFiles.map(file => ({
      id: `${file.name}-${Date.now()}-${Math.random()}`,
      file,
      name: file.name,
      size: file.size,
      type: file.type || 'unknown',
      status: 'pending',
      progress: 0,
      error: null
    }));

    setFiles(prev => [...prev, ...filesWithMeta]);
  }, [files.length]);

  const removeFile = useCallback((fileId) => {
    setFiles(prev => prev.filter(f => f.id !== fileId));
    setUploadProgress(prev => {
      const newProgress = { ...prev };
      delete newProgress[fileId];
      return newProgress;
    });
  }, []);

  const handleUpload = async () => {
    if (files.length === 0) {
      toast.error('Please select files to upload');
      return;
    }

    setUploading(true);
    const results = [];

    for (const fileItem of files) {
      try {
        // Update file status
        setFiles(prev => prev.map(f => 
          f.id === fileItem.id ? { ...f, status: 'uploading' } : f
        ));

        // Upload with progress tracking
        const result = await uploadService.uploadFile(
          fileItem.file,
          (progress) => {
            setUploadProgress(prev => ({
              ...prev,
              [fileItem.id]: progress
            }));
          }
        );

        // Update file status to success
        setFiles(prev => prev.map(f => 
          f.id === fileItem.id ? { 
            ...f, 
            status: 'success',
            hash: result.hash,
            analysisId: result.analysisId
          } : f
        ));

        results.push(result);
        toast.success(`${fileItem.name} uploaded successfully`);

      } catch (error) {
        // Update file status to error
        setFiles(prev => prev.map(f => 
          f.id === fileItem.id ? { 
            ...f, 
            status: 'error',
            error: error.message || 'Upload failed'
          } : f
        ));

        toast.error(`Failed to upload ${fileItem.name}`);
      }
    }

    setUploading(false);

    // If any files uploaded successfully, offer to analyze
    const successfulUploads = results.filter(r => r.analysisId);
    if (successfulUploads.length > 0) {
      if (successfulUploads.length === 1) {
        // Single file - go directly to analysis
        navigate(`/analysis/${successfulUploads[0].analysisId}`);
      } else {
        // Multiple files - show options
        toast((t) => (
          <div className="flex items-center space-x-3">
            <CheckCircleIcon className="h-5 w-5 text-green-400" />
            <span>{successfulUploads.length} files ready for analysis</span>
            <Button
              size="sm"
              onClick={() => {
                toast.dismiss(t.id);
                navigate('/history');
              }}
            >
              View All
            </Button>
          </div>
        ), { duration: 5000 });
      }
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'uploading':
        return <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-cyber-blue" />;
      case 'success':
        return <CheckCircleIcon className="h-5 w-5 text-green-400" />;
      case 'error':
        return <XCircleIcon className="h-5 w-5 text-red-400" />;
      default:
        return <DocumentIcon className="h-5 w-5 text-gray-400" />;
    }
  };

  const canUpload = files.length > 0 && !uploading && 
    files.every(f => f.status === 'pending' || f.status === 'error');

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-gray-800/50 backdrop-blur border border-gray-700 rounded-lg p-6">
        <h1 className="text-2xl font-bold text-white mb-2">Upload Files for Analysis</h1>
        <p className="text-gray-400">
          Upload log files, network captures, forensic images, and other security artifacts for comprehensive analysis.
          Maximum 10 files at once, up to 500MB each.
        </p>
      </div>

      {/* Upload Area */}
      <Card title="Select Files" className="bg-gray-800/50">
        <FileDropzone 
          onFilesSelected={handleFilesSelected}
          maxFiles={10 - files.length}
          disabled={uploading}
        />

        {/* File List */}
        {files.length > 0 && (
          <div className="mt-6 space-y-3">
            <h3 className="text-sm font-medium text-gray-300">
              Selected Files ({files.length}/10)
            </h3>
            
            <AnimatePresence>
              {files.map((fileItem) => (
                <motion.div
                  key={fileItem.id}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, x: -100 }}
                  className="bg-gray-900/50 border border-gray-700 rounded-lg p-4"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3 flex-1">
                      {getStatusIcon(fileItem.status)}
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium text-white truncate">
                          {fileItem.name}
                        </p>
                        <p className="text-xs text-gray-400">
                          {formatBytes(fileItem.size)}
                        </p>
                      </div>
                    </div>

                    {/* Progress or Actions */}
                    <div className="flex items-center space-x-3">
                      {fileItem.status === 'uploading' && (
                        <div className="w-32">
                          <div className="bg-gray-700 rounded-full h-2">
                            <div 
                              className="bg-cyber-blue h-2 rounded-full transition-all duration-300"
                              style={{ width: `${uploadProgress[fileItem.id] || 0}%` }}
                            />
                          </div>
                          <p className="text-xs text-gray-400 mt-1 text-center">
                            {uploadProgress[fileItem.id] || 0}%
                          </p>
                        </div>
                      )}

                      {fileItem.status === 'error' && (
                        <p className="text-xs text-red-400">{fileItem.error}</p>
                      )}

                      {fileItem.status === 'success' && fileItem.analysisId && (
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => navigate(`/analysis/${fileItem.analysisId}`)}
                        >
                          View Analysis
                        </Button>
                      )}

                      {(fileItem.status === 'pending' || fileItem.status === 'error') && !uploading && (
                        <button
                          onClick={() => removeFile(fileItem.id)}
                          className="text-gray-400 hover:text-red-400 transition-colors"
                        >
                          <XCircleIcon className="h-5 w-5" />
                        </button>
                      )}
                    </div>
                  </div>
                </motion.div>
              ))}
            </AnimatePresence>
          </div>
        )}

        {/* Upload Button */}
        {files.length > 0 && (
          <div className="mt-6 flex justify-end">
            <Button
              size="lg"
              loading={uploading}
              disabled={!canUpload}
              onClick={handleUpload}
              icon={CloudUploadIcon}
            >
              {uploading ? 'Uploading...' : `Upload ${files.length} File${files.length > 1 ? 's' : ''}`}
            </Button>
          </div>
        )}
      </Card>

      {/* Supported Formats */}
      <Card 
        title="Supported File Formats" 
        collapsible 
        defaultExpanded={false}
        className="bg-gray-800/50"
      >
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {Object.entries(supportedFormats).map(([category, extensions]) => (
            <div key={category} className="space-y-2">
              <h4 className="text-sm font-medium text-cyber-blue">{category}</h4>
              <div className="flex flex-wrap gap-2">
                {extensions.map(ext => (
                  <span 
                    key={ext}
                    className="px-2 py-1 bg-gray-900/50 border border-gray-700 rounded text-xs text-gray-300"
                  >
                    {ext}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>

        <div className="mt-4 p-4 bg-blue-900/20 border border-blue-800/50 rounded-lg">
          <div className="flex items-start space-x-2">
            <InformationCircleIcon className="h-5 w-5 text-blue-400 flex-shrink-0 mt-0.5" />
            <p className="text-sm text-blue-300">
              Don't see your file format? The system will attempt to parse any file type. 
              Listed formats have optimized parsers for best results.
            </p>
          </div>
        </div>
      </Card>
    </div>
  );
}