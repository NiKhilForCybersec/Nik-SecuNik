import React, { useCallback, useState } from 'react';
import { useDropzone } from 'react-dropzone';
import { motion, AnimatePresence } from 'framer-motion';
import {
  CloudUpload,
  FileText,
  AlertCircle,
  FolderOpen
} from 'lucide-react';
import { formatBytes } from '@/utils/formatters';

const MAX_FILE_SIZE = 500 * 1024 * 1024; // 500MB

export default function FileDropzone({ 
  onFilesSelected, 
  maxFiles = 10, 
  disabled = false,
  acceptedFormats = null 
}) {
  const [errors, setErrors] = useState([]);

  const onDrop = useCallback((acceptedFiles, rejectedFiles) => {
    // Clear previous errors
    setErrors([]);

    // Process accepted files
    if (acceptedFiles.length > 0) {
      onFilesSelected(acceptedFiles);
    }

    // Process rejected files
    if (rejectedFiles.length > 0) {
      const newErrors = rejectedFiles.map(rejection => {
        const error = rejection.errors[0];
        let message = `${rejection.file.name}: `;
        
        if (error.code === 'file-too-large') {
          message += `File too large (max ${formatBytes(MAX_FILE_SIZE)})`;
        } else if (error.code === 'too-many-files') {
          message += `Too many files (max ${maxFiles})`;
        } else if (error.code === 'file-invalid-type') {
          message += 'Invalid file type';
        } else {
          message += error.message;
        }
        
        return message;
      });
      
      setErrors(newErrors);
      
      // Clear errors after 5 seconds
      setTimeout(() => setErrors([]), 5000);
    }
  }, [onFilesSelected, maxFiles]);

  const {
    getRootProps,
    getInputProps,
    isDragActive,
    isDragAccept,
    isDragReject
  } = useDropzone({
    onDrop,
    maxSize: MAX_FILE_SIZE,
    maxFiles,
    disabled,
    accept: acceptedFormats
  });

  // Determine border color based on drag state
  const getBorderColor = () => {
    if (isDragReject) return 'border-red-500';
    if (isDragAccept) return 'border-green-500';
    if (isDragActive) return 'border-cyber-500';
    return 'border-gray-700';
  };

  // Determine background color based on drag state
  const getBackgroundColor = () => {
    if (isDragReject) return 'bg-red-500/10';
    if (isDragAccept) return 'bg-green-500/10';
    if (isDragActive) return 'bg-cyber-500/10';
    return 'bg-gray-900/50';
  };

  return (
    <div className="space-y-4">
      <div
        {...getRootProps()}
        className={`
          relative overflow-hidden rounded-lg border-2 border-dashed p-12 text-center 
          transition-all duration-200 cursor-pointer
          ${getBorderColor()} ${getBackgroundColor()}
          ${disabled ? 'opacity-50 cursor-not-allowed' : 'hover:border-cyber-500/50'}
        `}
      >
        <input {...getInputProps()} />

        {/* Background Pattern */}
        <div className="absolute inset-0 opacity-5">
          <div className="absolute inset-0" 
               style={{
                 backgroundImage: `repeating-linear-gradient(
                   45deg,
                   transparent,
                   transparent 10px,
                   rgba(0, 255, 255, 0.1) 10px,
                   rgba(0, 255, 255, 0.1) 20px
                 )`
               }}
          />
        </div>

        {/* Content */}
        <div className="relative z-10">
          <AnimatePresence mode="wait">
            {isDragReject ? (
              <motion.div
                key="reject"
                initial={{ opacity: 0, scale: 0.8 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.8 }}
                className="flex flex-col items-center"
              >
                <AlertCircle className="h-16 w-16 text-red-500 mb-4" />
                <p className="text-lg font-medium text-red-500">Invalid file type or size</p>
                <p className="text-sm text-gray-400 mt-2">
                  Please check file requirements
                </p>
              </motion.div>
            ) : isDragActive ? (
              <motion.div
                key="active"
                initial={{ opacity: 0, scale: 0.8 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.8 }}
                className="flex flex-col items-center"
              >
                <FolderOpen className="h-16 w-16 text-cyber-500 mb-4 animate-pulse" />
                <p className="text-lg font-medium text-cyber-500">Drop files here</p>
                <p className="text-sm text-gray-400 mt-2">
                  Release to upload
                </p>
              </motion.div>
            ) : (
              <motion.div
                key="default"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="flex flex-col items-center"
              >
                <CloudUpload className="h-16 w-16 text-gray-500 mb-4" />
                <p className="text-lg font-medium text-gray-300">
                  Drag & drop files here
                </p>
                <p className="text-sm text-gray-500 mt-2">
                  or click to browse
                </p>
                <div className="mt-4 space-y-1">
                  <p className="text-xs text-gray-600">
                    Maximum {maxFiles} files • Up to {formatBytes(MAX_FILE_SIZE)} each
                  </p>
                  {acceptedFormats && (
                    <p className="text-xs text-gray-600">
                      Accepted formats: {Object.keys(acceptedFormats).join(', ')}
                    </p>
                  )}
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Cyber Effects */}
        {isDragActive && (
          <>
            {/* Corner Brackets */}
            <div className="absolute top-0 left-0 w-8 h-8 border-t-2 border-l-2 border-cyber-500" />
            <div className="absolute top-0 right-0 w-8 h-8 border-t-2 border-r-2 border-cyber-500" />
            <div className="absolute bottom-0 left-0 w-8 h-8 border-b-2 border-l-2 border-cyber-500" />
            <div className="absolute bottom-0 right-0 w-8 h-8 border-b-2 border-r-2 border-cyber-500" />
            
            {/* Scanning Line */}
            <motion.div
              className="absolute left-0 right-0 h-0.5 bg-gradient-to-r from-transparent via-cyber-500 to-transparent"
              initial={{ top: 0 }}
              animate={{ top: '100%' }}
              transition={{ duration: 1.5, repeat: Infinity }}
            />
          </>
        )}
      </div>

      {/* Error Messages */}
      <AnimatePresence>
        {errors.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="space-y-2"
          >
            {errors.map((error, index) => (
              <div
                key={index}
                className="flex items-center space-x-2 p-3 bg-red-500/10 border border-red-500/30 rounded-lg"
              >
                <AlertCircle className="h-5 w-5 text-red-500 flex-shrink-0" />
                <p className="text-sm text-red-400">{error}</p>
              </div>
            ))}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Quick Actions */}
      {!disabled && (
        <div className="grid grid-cols-2 gap-3">
          <button
            onClick={() => document.querySelector('input[type="file"]')?.click()}
            className="flex items-center justify-center space-x-2 px-4 py-2 bg-gray-800/50 hover:bg-gray-700/50 border border-gray-700 rounded-lg transition-colors"
          >
            <FileText className="h-5 w-5 text-gray-400" />
            <span className="text-sm text-gray-300">Browse Files</span>
          </button>
          
          <button
            onClick={() => {
              // Could implement folder selection if needed
              document.querySelector('input[type="file"]')?.click();
            }}
            className="flex items-center justify-center space-x-2 px-4 py-2 bg-gray-800/50 hover:bg-gray-700/50 border border-gray-700 rounded-lg transition-colors"
          >
            <FolderOpen className="h-5 w-5 text-gray-400" />
            <span className="text-sm text-gray-300">Select Folder</span>
          </button>
        </div>
      )}
    </div>
  );
}