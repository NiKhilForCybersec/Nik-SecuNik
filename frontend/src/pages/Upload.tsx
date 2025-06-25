import React, { useState, useCallback } from 'react'
import { motion } from 'framer-motion'
import { useDropzone } from 'react-dropzone'
import { useNavigate } from 'react-router-dom'
import {
  Upload as UploadIcon,
  File,
  X,
  CheckCircle,
  AlertCircle,
  Clock,
  FileText,
  Image,
  Archive,
  Database,
  Code,
  Wifi,
  Mail,
  Shield,
  Play
} from 'lucide-react'
import toast from 'react-hot-toast'
import { uploadService } from '../services/uploadService'
import { analysisService } from '../services/analysisService'

interface UploadedFile {
  id: string
  file: File
  status: 'uploading' | 'uploaded' | 'parsing' | 'parsed' | 'analyzing' | 'completed' | 'error'
  progress: number
  uploadResult?: any
  analysisId?: string
  error?: string
}

const Upload: React.FC = () => {
  const navigate = useNavigate()
  const [uploadedFiles, setUploadedFiles] = useState<UploadedFile[]>([])
  const [dragActive, setDragActive] = useState(false)

  const getFileIcon = (fileName: string) => {
    const extension = fileName.split('.').pop()?.toLowerCase()
    
    switch (extension) {
      case 'log':
      case 'txt':
        return <FileText className="w-8 h-8 text-blue-400" />
      case 'pcap':
      case 'pcapng':
        return <Wifi className="w-8 h-8 text-green-400" />
      case 'zip':
      case 'rar':
      case '7z':
        return <Archive className="w-8 h-8 text-yellow-400" />
      case 'eml':
      case 'msg':
        return <Mail className="w-8 h-8 text-purple-400" />
      case 'exe':
      case 'dll':
        return <Shield className="w-8 h-8 text-red-400" />
      case 'sql':
      case 'db':
        return <Database className="w-8 h-8 text-indigo-400" />
      case 'js':
      case 'py':
      case 'sh':
        return <Code className="w-8 h-8 text-orange-400" />
      case 'jpg':
      case 'png':
      case 'gif':
        return <Image className="w-8 h-8 text-pink-400" />
      default:
        return <File className="w-8 h-8 text-gray-400" />
    }
  }

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes'
    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  const getFileType = (fileName: string): string => {
    const extension = fileName.split('.').pop()?.toLowerCase()
    
    const typeMap: { [key: string]: string } = {
      'log': 'System Log',
      'txt': 'Text File',
      'pcap': 'Network Capture',
      'pcapng': 'Network Capture',
      'zip': 'Archive',
      'rar': 'Archive',
      '7z': 'Archive',
      'eml': 'Email',
      'msg': 'Email',
      'exe': 'Executable',
      'dll': 'Library',
      'sql': 'Database',
      'db': 'Database',
      'js': 'JavaScript',
      'py': 'Python',
      'sh': 'Shell Script',
      'jpg': 'Image',
      'png': 'Image',
      'gif': 'Image'
    }
    
    return typeMap[extension || ''] || 'Unknown'
  }

  const uploadAndAnalyzeFile = async (fileId: string) => {
    const fileIndex = uploadedFiles.findIndex(f => f.id === fileId)
    if (fileIndex === -1) return

    const uploadedFile = uploadedFiles[fileIndex]
    
    try {
      // Upload file
      setUploadedFiles(prev => prev.map(f => 
        f.id === fileId 
          ? { ...f, status: 'uploading', progress: 0 }
          : f
      ))

      const uploadResult = await uploadService.uploadFile(uploadedFile.file, {
        autoAnalyze: false,
        tags: ['frontend-upload'],
        onProgress: (progress) => {
          setUploadedFiles(prev => prev.map(f => 
            f.id === fileId 
              ? { ...f, progress }
              : f
          ))
        }
      })

      // Update with upload result
      setUploadedFiles(prev => prev.map(f => 
        f.id === fileId 
          ? { ...f, status: 'uploaded', progress: 100, uploadResult }
          : f
      ))

      // Wait for parsing if needed
      if (uploadResult.status === 'parsing') {
        setUploadedFiles(prev => prev.map(f => 
          f.id === fileId 
            ? { ...f, status: 'parsing' }
            : f
        ))

        // Poll for parsing completion
        let parseComplete = false
        while (!parseComplete) {
          await new Promise(resolve => setTimeout(resolve, 1000))
          const status = await uploadService.getUploadStatus(uploadResult.id)
          
          if (status.status === 'parsed') {
            parseComplete = true
            setUploadedFiles(prev => prev.map(f => 
              f.id === fileId 
                ? { ...f, status: 'parsed' }
                : f
            ))
          } else if (status.status === 'failed') {
            throw new Error(status.message || 'Parsing failed')
          }
        }
      }

      // Start analysis
      setUploadedFiles(prev => prev.map(f => 
        f.id === fileId 
          ? { ...f, status: 'analyzing' }
          : f
      ))

      const analysisResult = await analysisService.startAnalysis(uploadResult.id, {
        analyzers: ['yara', 'sigma', 'mitre', 'ai', 'patterns'],
        deepScan: true,
        extractIocs: true,
        checkVirusTotal: true
      })

      setUploadedFiles(prev => prev.map(f => 
        f.id === fileId 
          ? { ...f, analysisId: analysisResult.analysis_id }
          : f
      ))

      toast.success('File uploaded and analysis started!')

    } catch (error: any) {
      console.error('Upload/Analysis error:', error)
      setUploadedFiles(prev => prev.map(f => 
        f.id === fileId 
          ? { ...f, status: 'error', error: error.message }
          : f
      ))
      toast.error(error.message || 'Upload failed')
    }
  }

  const onDrop = useCallback((acceptedFiles: File[]) => {
    const newFiles: UploadedFile[] = acceptedFiles.map(file => ({
      id: `${Date.now()}_${Math.random()}`,
      file,
      status: 'uploading',
      progress: 0
    }))

    setUploadedFiles(prev => [...prev, ...newFiles])
    
    // Start upload and analysis for each file
    newFiles.forEach(file => {
      uploadAndAnalyzeFile(file.id)
    })

    toast.success(`${acceptedFiles.length} file(s) queued for upload and analysis!`)
  }, [])

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    multiple: true,
    maxSize: 1073741824, // 1GB
    onDragEnter: () => setDragActive(true),
    onDragLeave: () => setDragActive(false),
  })

  const removeFile = (fileId: string) => {
    setUploadedFiles(prev => prev.filter(f => f.id !== fileId))
    toast.success('File removed')
  }

  const viewAnalysis = (analysisId: string) => {
    navigate(`/analysis/${analysisId}`)
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'uploading':
        return <Clock className="w-5 h-5 text-blue-400 animate-spin" />
      case 'uploaded':
        return <CheckCircle className="w-5 h-5 text-green-400" />
      case 'parsing':
        return <Clock className="w-5 h-5 text-yellow-400 animate-spin" />
      case 'parsed':
        return <CheckCircle className="w-5 h-5 text-green-400" />
      case 'analyzing':
        return <Clock className="w-5 h-5 text-purple-400 animate-spin" />
      case 'completed':
        return <CheckCircle className="w-5 h-5 text-green-400" />
      case 'error':
        return <AlertCircle className="w-5 h-5 text-red-400" />
      default:
        return <Clock className="w-5 h-5 text-gray-400" />
    }
  }

  const getStatusText = (status: string) => {
    switch (status) {
      case 'uploading':
        return 'Uploading...'
      case 'uploaded':
        return 'Uploaded'
      case 'parsing':
        return 'Parsing...'
      case 'parsed':
        return 'Parsed'
      case 'analyzing':
        return 'Analyzing...'
      case 'completed':
        return 'Analysis Complete'
      case 'error':
        return 'Error'
      default:
        return 'Unknown'
    }
  }

  const supportedFormats = [
    { category: 'Log Files', formats: ['*.log', '*.txt', '*.syslog'] },
    { category: 'Network Captures', formats: ['*.pcap', '*.pcapng', '*.cap'] },
    { category: 'Archives', formats: ['*.zip', '*.rar', '*.7z', '*.tar'] },
    { category: 'Email Files', formats: ['*.eml', '*.msg', '*.mbox'] },
    { category: 'System Files', formats: ['*.evt', '*.evtx', '*.reg'] },
    { category: 'Database Files', formats: ['*.sql', '*.db', '*.sqlite'] },
  ]

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-white">Upload Files</h1>
        <p className="text-gray-400 mt-2">
          Upload files for comprehensive cybersecurity analysis using SecuNik LogX
        </p>
      </div>

      {/* Upload Area */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="bg-slate-900/50 rounded-lg border-2 border-dashed border-slate-700 p-12 text-center hover:border-primary-500 transition-colors"
        {...getRootProps()}
      >
        <input {...getInputProps()} />
        <motion.div
          animate={{ scale: isDragActive ? 1.1 : 1 }}
          transition={{ type: "spring", stiffness: 300, damping: 30 }}
        >
          <UploadIcon className="w-16 h-16 text-primary-400 mx-auto mb-4" />
          <h3 className="text-xl font-semibold text-white mb-2">
            {isDragActive ? 'Drop files here' : 'Drag & drop files here'}
          </h3>
          <p className="text-gray-400 mb-4">
            or click to browse and select files for analysis
          </p>
          <div className="inline-flex items-center px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors">
            <UploadIcon className="w-4 h-4 mr-2" />
            Choose Files
          </div>
        </motion.div>
      </motion.div>

      {/* Supported Formats */}
      <div className="bg-slate-900/50 rounded-lg p-6 border border-slate-800">
        <h3 className="text-lg font-semibold text-white mb-4">Supported File Formats</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {supportedFormats.map((category) => (
            <div key={category.category} className="space-y-2">
              <h4 className="text-sm font-medium text-primary-400">{category.category}</h4>
              <div className="flex flex-wrap gap-1">
                {category.formats.map((format) => (
                  <span
                    key={format}
                    className="px-2 py-1 bg-slate-800 text-gray-300 text-xs rounded"
                  >
                    {format}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Uploaded Files */}
      {uploadedFiles.length > 0 && (
        <div className="bg-slate-900/50 rounded-lg p-6 border border-slate-800">
          <h3 className="text-lg font-semibold text-white mb-4">
            Uploaded Files ({uploadedFiles.length})
          </h3>
          <div className="space-y-4">
            {uploadedFiles.map((uploadedFile, index) => (
              <motion.div
                key={uploadedFile.id}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: index * 0.1 }}
                className="flex items-center space-x-4 p-4 bg-slate-800/50 rounded-lg"
              >
                {getFileIcon(uploadedFile.file.name)}
                
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between">
                    <h4 className="text-sm font-medium text-white truncate">
                      {uploadedFile.file.name}
                    </h4>
                    <div className="flex items-center space-x-2">
                      {uploadedFile.analysisId && uploadedFile.status === 'completed' && (
                        <button
                          onClick={() => viewAnalysis(uploadedFile.analysisId!)}
                          className="flex items-center space-x-1 px-2 py-1 bg-primary-600 text-white text-xs rounded hover:bg-primary-700 transition-colors"
                        >
                          <Play className="w-3 h-3" />
                          <span>View Analysis</span>
                        </button>
                      )}
                      <button
                        onClick={() => removeFile(uploadedFile.id)}
                        className="text-gray-400 hover:text-red-400 transition-colors"
                      >
                        <X className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                  
                  <div className="flex items-center space-x-4 mt-1">
                    <span className="text-xs text-gray-400">{getFileType(uploadedFile.file.name)}</span>
                    <span className="text-xs text-gray-400">{formatFileSize(uploadedFile.file.size)}</span>
                  </div>
                  
                  <div className="flex items-center space-x-3 mt-2">
                    {getStatusIcon(uploadedFile.status)}
                    <span className="text-xs text-gray-400">
                      {getStatusText(uploadedFile.status)}
                    </span>
                    
                    {uploadedFile.status === 'uploading' && (
                      <div className="flex-1 bg-slate-700 rounded-full h-2">
                        <motion.div
                          className="bg-primary-500 h-2 rounded-full"
                          initial={{ width: 0 }}
                          animate={{ width: `${uploadedFile.progress}%` }}
                          transition={{ duration: 0.3 }}
                        />
                      </div>
                    )}
                    
                    {uploadedFile.error && (
                      <span className="text-xs text-red-400">{uploadedFile.error}</span>
                    )}
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      )}

      {/* Upload Guidelines */}
      <div className="bg-slate-900/50 rounded-lg p-6 border border-slate-800">
        <h3 className="text-lg font-semibold text-white mb-4">Upload Guidelines</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <h4 className="text-sm font-medium text-primary-400 mb-2">File Requirements</h4>
            <ul className="text-sm text-gray-400 space-y-1">
              <li>• Maximum file size: 1GB</li>
              <li>• Multiple files supported</li>
              <li>• Compressed archives will be extracted</li>
              <li>• Binary files will be analyzed for malware</li>
            </ul>
          </div>
          <div>
            <h4 className="text-sm font-medium text-primary-400 mb-2">Analysis Features</h4>
            <ul className="text-sm text-gray-400 space-y-1">
              <li>• YARA rule matching</li>
              <li>• Sigma rule detection</li>
              <li>• MITRE ATT&CK mapping</li>
              <li>• AI-powered analysis</li>
              <li>• IOC extraction</li>
              <li>• VirusTotal integration</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Upload