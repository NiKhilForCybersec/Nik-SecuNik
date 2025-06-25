import React, { useState, useCallback, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
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
  Play,
  Pause,
  RotateCcw,
  Info,
  Activity
} from 'lucide-react'
import toast from 'react-hot-toast'
import { uploadService } from '../services/uploadService'
import { analysisService } from '../services/analysisService'
import { API_CONFIG } from '../utils/constants'
import { format } from 'date-fns'

interface UploadedFile {
  id: string
  file: File
  status: 'queued' | 'uploading' | 'uploaded' | 'parsing' | 'parsed' | 'analyzing' | 'completed' | 'error' | 'cancelled'
  progress: number
  uploadResult?: any
  analysisId?: string
  error?: string
  startTime: Date
  endTime?: Date
  chunks?: {
    total: number
    completed: number
  }
}

const Upload: React.FC = () => {
  const navigate = useNavigate()
  const [uploadedFiles, setUploadedFiles] = useState<UploadedFile[]>([])
  const [dragActive, setDragActive] = useState(false)
  const [isUploading, setIsUploading] = useState(false)
  const uploadQueueRef = useRef<string[]>([])
  const maxConcurrentUploads = 3

  const getFileIcon = (fileName: string) => {
    const extension = fileName.split('.').pop()?.toLowerCase()
    const iconMap: Record<string, JSX.Element> = {
      log: <FileText className="w-8 h-8 text-blue-400" />,
      txt: <FileText className="w-8 h-8 text-blue-400" />,
      pcap: <Wifi className="w-8 h-8 text-green-400" />,
      pcapng: <Wifi className="w-8 h-8 text-green-400" />,
      zip: <Archive className="w-8 h-8 text-yellow-400" />,
      rar: <Archive className="w-8 h-8 text-yellow-400" />,
      '7z': <Archive className="w-8 h-8 text-yellow-400" />,
      eml: <Mail className="w-8 h-8 text-purple-400" />,
      msg: <Mail className="w-8 h-8 text-purple-400" />,
      exe: <Shield className="w-8 h-8 text-red-400" />,
      dll: <Shield className="w-8 h-8 text-red-400" />,
      sql: <Database className="w-8 h-8 text-indigo-400" />,
      db: <Database className="w-8 h-8 text-indigo-400" />,
      js: <Code className="w-8 h-8 text-orange-400" />,
      py: <Code className="w-8 h-8 text-orange-400" />,
      sh: <Code className="w-8 h-8 text-orange-400" />,
      jpg: <Image className="w-8 h-8 text-pink-400" />,
      png: <Image className="w-8 h-8 text-pink-400" />,
      gif: <Image className="w-8 h-8 text-pink-400" />
    }
    
    return iconMap[extension || ''] || <File className="w-8 h-8 text-gray-400" />
  }

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes'
    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  const getFileType = (fileName: string): string => {
    const extension = fileName.split('.').pop()?.toLowerCase() || ''
    const typeMap: Record<string, string> = {
      log: 'System Log',
      txt: 'Text File',
      pcap: 'Network Capture',
      pcapng: 'Network Capture',
      zip: 'Archive',
      rar: 'Archive',
      '7z': 'Archive',
      eml: 'Email',
      msg: 'Email',
      exe: 'Executable',
      dll: 'Library',
      sql: 'Database',
      db: 'Database',
      js: 'JavaScript',
      py: 'Python',
      sh: 'Shell Script',
      jpg: 'Image',
      png: 'Image',
      gif: 'Image'
    }
    
    return typeMap[extension] || 'Unknown'
  }

  const processUploadQueue = async () => {
    const activeUploads = uploadedFiles.filter(f => f.status === 'uploading').length
    if (activeUploads >= maxConcurrentUploads) return

    const nextFileId = uploadQueueRef.current.shift()
    if (!nextFileId) {
      setIsUploading(false)
      return
    }

    await uploadAndAnalyzeFile(nextFileId)
    processUploadQueue() // Process next in queue
  }

  const uploadAndAnalyzeFile = async (fileId: string) => {
    const fileIndex = uploadedFiles.findIndex(f => f.id === fileId)
    if (fileIndex === -1) return

    const uploadedFile = uploadedFiles[fileIndex]
    
    try {
      // Update status to uploading
      setUploadedFiles(prev => prev.map(f => 
        f.id === fileId 
          ? { ...f, status: 'uploading', progress: 0 }
          : f
      ))

      // Upload file with progress tracking
      const uploadResult = await uploadService.uploadFile(uploadedFile.file, {
        autoAnalyze: false,
        tags: ['frontend-upload', `uploaded-${format(new Date(), 'yyyy-MM-dd')}`],
        priority: 'normal',
        onProgress: (progress) => {
          setUploadedFiles(prev => prev.map(f => 
            f.id === fileId 
              ? { ...f, progress }
              : f
          ))
        },
        onChunkComplete: (completed, total) => {
          setUploadedFiles(prev => prev.map(f => 
            f.id === fileId 
              ? { ...f, chunks: { completed, total } }
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

        // Poll for parsing completion with exponential backoff
        let parseComplete = false
        let pollDelay = 1000
        let attempts = 0
        const maxAttempts = 30

        while (!parseComplete && attempts < maxAttempts) {
          await new Promise(resolve => setTimeout(resolve, pollDelay))
          
          try {
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
          } catch (error) {
            console.error('Error checking parse status:', error)
          }
          
          attempts++
          pollDelay = Math.min(pollDelay * 1.5, 5000) // Cap at 5 seconds
        }

        if (!parseComplete) {
          throw new Error('Parsing timeout')
        }
      }

      // Start analysis
      setUploadedFiles(prev => prev.map(f => 
        f.id === fileId 
          ? { ...f, status: 'analyzing' }
          : f
      ))

      const analysisResult = await analysisService.startAnalysis(uploadResult.id, {
        analyzers: ['yara', 'sigma', 'mitre', 'ai', 'patterns', 'ioc'],
        deepScan: true,
        extractIocs: true,
        checkVirusTotal: true,
        priority: 'normal'
      })

      setUploadedFiles(prev => prev.map(f => 
        f.id === fileId 
          ? { 
              ...f, 
              status: 'completed',
              analysisId: analysisResult.analysis_id,
              endTime: new Date()
            }
          : f
      ))

      toast.success(`${uploadedFile.file.name} uploaded and analysis started!`)

    } catch (error: any) {
      console.error('Upload/Analysis error:', error)
      setUploadedFiles(prev => prev.map(f => 
        f.id === fileId 
          ? { 
              ...f, 
              status: 'error', 
              error: error.message || 'Upload failed',
              endTime: new Date()
            }
          : f
      ))
      toast.error(error.message || 'Upload failed')
    }
  }

  const onDrop = useCallback((acceptedFiles: File[], rejectedFiles: any[]) => {
    // Handle rejected files
    rejectedFiles.forEach(({ file, errors }) => {
      errors.forEach((error: any) => {
        if (error.code === 'file-too-large') {
          toast.error(`${file.name} is too large. Max size is ${formatFileSize(API_CONFIG.MAX_FILE_SIZE)}`)
        } else if (error.code === 'file-invalid-type') {
          toast.error(`${file.name} is not a supported file type`)
        } else {
          toast.error(`${file.name}: ${error.message}`)
        }
      })
    })

    if (acceptedFiles.length === 0) return

    const newFiles: UploadedFile[] = acceptedFiles.map(file => ({
      id: `${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      file,
      status: 'queued',
      progress: 0,
      startTime: new Date()
    }))

    setUploadedFiles(prev => [...prev, ...newFiles])
    
    // Add to upload queue
    uploadQueueRef.current.push(...newFiles.map(f => f.id))
    
    if (!isUploading) {
      setIsUploading(true)
      processUploadQueue()
    }

    toast.success(`${acceptedFiles.length} file(s) queued for upload`)
  }, [isUploading])

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    multiple: true,
    maxSize: API_CONFIG.MAX_FILE_SIZE,
    accept: API_CONFIG.ALLOWED_FILE_TYPES.reduce((acc, ext) => {
      const mimeTypes: Record<string, string[]> = {
        '.log': ['text/plain', 'text/x-log'],
        '.txt': ['text/plain'],
        '.json': ['application/json'],
        '.xml': ['application/xml', 'text/xml'],
        '.pcap': ['application/vnd.tcpdump.pcap', 'application/x-pcap'],
        '.pcapng': ['application/x-pcapng'],
        '.zip': ['application/zip', 'application/x-zip-compressed'],
        '.rar': ['application/x-rar-compressed', 'application/vnd.rar'],
        '.7z': ['application/x-7z-compressed'],
        '.eml': ['message/rfc822'],
        '.msg': ['application/vnd.ms-outlook'],
        '.csv': ['text/csv'],
        '.pdf': ['application/pdf'],
        '.exe': ['application/x-msdownload', 'application/x-executable'],
        '.dll': ['application/x-msdownload'],
        '.sql': ['application/sql', 'text/plain'],
        '.db': ['application/x-sqlite3'],
        '.py': ['text/x-python', 'application/x-python'],
        '.js': ['text/javascript', 'application/javascript'],
        '.sh': ['application/x-sh', 'text/x-shellscript']
      }
      
      const types = mimeTypes[ext]
      if (types) {
        types.forEach(type => {
          if (!acc[type]) acc[type] = []
          acc[type].push(ext)
        })
      }
      return acc
    }, {} as Record<string, string[]>),
    onDragEnter: () => setDragActive(true),
    onDragLeave: () => setDragActive(false),
    onDropAccepted: () => setDragActive(false),
    onDropRejected: () => setDragActive(false),
  })

  const removeFile = (fileId: string) => {
    const file = uploadedFiles.find(f => f.id === fileId)
    if (file && ['uploading', 'parsing', 'analyzing'].includes(file.status)) {
      uploadService.cancelUpload(fileId).catch(console.error)
    }
    
    setUploadedFiles(prev => prev.filter(f => f.id !== fileId))
    uploadQueueRef.current = uploadQueueRef.current.filter(id => id !== fileId)
    toast.success('File removed')
  }

  const retryUpload = (fileId: string) => {
    setUploadedFiles(prev => prev.map(f => 
      f.id === fileId 
        ? { ...f, status: 'queued', progress: 0, error: undefined }
        : f
    ))
    
    uploadQueueRef.current.push(fileId)
    
    if (!isUploading) {
      setIsUploading(true)
      processUploadQueue()
    }
  }

  const viewAnalysis = (analysisId: string) => {
    navigate(`/analysis/${analysisId}`)
  }

  const getStatusIcon = (status: string) => {
    const icons: Record<string, JSX.Element> = {
      queued: <Clock className="w-5 h-5 text-gray-400" />,
      uploading: <Clock className="w-5 h-5 text-blue-400 animate-spin" />,
      uploaded: <CheckCircle className="w-5 h-5 text-green-400" />,
      parsing: <Clock className="w-5 h-5 text-yellow-400 animate-spin" />,
      parsed: <CheckCircle className="w-5 h-5 text-green-400" />,
      analyzing: <Clock className="w-5 h-5 text-purple-400 animate-spin" />,
      completed: <CheckCircle className="w-5 h-5 text-green-400" />,
      error: <AlertCircle className="w-5 h-5 text-red-400" />,
      cancelled: <X className="w-5 h-5 text-gray-400" />
    }
    
    return icons[status] || <Clock className="w-5 h-5 text-gray-400" />
  }

  const getStatusText = (status: string): string => {
    const statusMap: Record<string, string> = {
      queued: 'Queued',
      uploading: 'Uploading...',
      uploaded: 'Uploaded',
      parsing: 'Parsing...',
      parsed: 'Parsed',
      analyzing: 'Analyzing...',
      completed: 'Analysis Complete',
      error: 'Error',
      cancelled: 'Cancelled'
    }
    
    return statusMap[status] || 'Unknown'
  }

  const clearCompleted = () => {
    setUploadedFiles(prev => prev.filter(f => 
      !['completed', 'error', 'cancelled'].includes(f.status)
    ))
    toast.success('Completed files cleared')
  }

  const supportedFormats = [
    { category: 'Log Files', formats: ['*.log', '*.txt', '*.syslog', '*.json', '*.xml'] },
    { category: 'Network Captures', formats: ['*.pcap', '*.pcapng', '*.cap'] },
    { category: 'Archives', formats: ['*.zip', '*.rar', '*.7z', '*.tar', '*.gz'] },
    { category: 'Email Files', formats: ['*.eml', '*.msg', '*.mbox', '*.pst'] },
    { category: 'System Files', formats: ['*.evt', '*.evtx', '*.reg', '*.dmp'] },
    { category: 'Database Files', formats: ['*.sql', '*.db', '*.sqlite'] },
    { category: 'Documents', formats: ['*.pdf', '*.doc', '*.docx', '*.xls', '*.xlsx'] },
    { category: 'Code Files', formats: ['*.js', '*.py', '*.sh', '*.ps1', '*.bat'] },
  ]

  const activeUploads = uploadedFiles.filter(f => 
    ['queued', 'uploading', 'parsing', 'analyzing'].includes(f.status)
  ).length

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">Upload Files</h1>
          <p className="text-gray-400 mt-2">
            Upload files for comprehensive cybersecurity analysis
          </p>
        </div>
        {uploadedFiles.length > 0 && (
          <button
            onClick={clearCompleted}
            className="px-4 py-2 bg-slate-800 text-white rounded-lg hover:bg-slate-700 transition-colors"
          >
            Clear Completed
          </button>
        )}
      </div>

      {/* Upload Area */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className={`bg-slate-900/50 rounded-lg border-2 border-dashed p-12 text-center transition-all ${
          isDragActive 
            ? 'border-primary-500 bg-primary-500/10' 
            : 'border-slate-700 hover:border-primary-500/50'
        }`}
        {...getRootProps()}
      >
        <input {...getInputProps()} />
        <motion.div
          animate={{ scale: isDragActive ? 1.05 : 1 }}
          transition={{ type: "spring", stiffness: 300, damping: 30 }}
        >
          <UploadIcon className={`w-16 h-16 mx-auto mb-4 ${
            isDragActive ? 'text-primary-400' : 'text-gray-400'
          }`} />
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
          <p className="text-xs text-gray-500 mt-4">
            Max file size: {formatFileSize(API_CONFIG.MAX_FILE_SIZE)} • 
            Multiple files supported
          </p>
        </motion.div>
      </motion.div>

      {/* Active Uploads Counter */}
      {activeUploads > 0 && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-blue-900/20 border border-blue-500/30 rounded-lg p-4"
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Activity className="w-5 h-5 text-blue-400 animate-pulse" />
              <span className="text-blue-300">
                {activeUploads} active {activeUploads === 1 ? 'upload' : 'uploads'}
              </span>
            </div>
            <span className="text-xs text-blue-400">
              Max concurrent: {maxConcurrentUploads}
            </span>
          </div>
        </motion.div>
      )}

      {/* Uploaded Files */}
      {uploadedFiles.length > 0 && (
        <div className="bg-slate-900/50 rounded-lg p-6 border border-slate-800">
          <h3 className="text-lg font-semibold text-white mb-4">
            Files ({uploadedFiles.length})
          </h3>
          <div className="space-y-4 max-h-96 overflow-y-auto">
            <AnimatePresence>
              {uploadedFiles.map((uploadedFile, index) => (
                <motion.div
                  key={uploadedFile.id}
                  layout
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: 20 }}
                  transition={{ delay: index * 0.05 }}
                  className="flex items-center space-x-4 p-4 bg-slate-800/50 rounded-lg"
                >
                  {getFileIcon(uploadedFile.file.name)}
                  
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between mb-1">
                      <h4 className="text-sm font-medium text-white truncate pr-2">
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
                        {uploadedFile.status === 'error' && (
                          <button
                            onClick={() => retryUpload(uploadedFile.id)}
                            className="p-1 text-gray-400 hover:text-white transition-colors"
                            title="Retry upload"
                          >
                            <RotateCcw className="w-4 h-4" />
                          </button>
                        )}
                        <button
                          onClick={() => removeFile(uploadedFile.id)}
                          className="p-1 text-gray-400 hover:text-red-400 transition-colors"
                          title="Remove file"
                        >
                          <X className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                    
                    <div className="flex items-center space-x-4 text-xs text-gray-400">
                      <span>{getFileType(uploadedFile.file.name)}</span>
                      <span>{formatFileSize(uploadedFile.file.size)}</span>
                      {uploadedFile.endTime && (
                        <span>
                          Duration: {Math.round(
                            (uploadedFile.endTime.getTime() - uploadedFile.startTime.getTime()) / 1000
                          )}s
                        </span>
                      )}
                    </div>
                    
                    <div className="flex items-center space-x-3 mt-2">
                      {getStatusIcon(uploadedFile.status)}
                      <span className="text-xs text-gray-400">
                        {getStatusText(uploadedFile.status)}
                      </span>
                      
                      {uploadedFile.status === 'uploading' && (
                        <div className="flex-1 flex items-center space-x-2">
                          <div className="flex-1 bg-slate-700 rounded-full h-2">
                            <motion.div
                              className="bg-primary-500 h-2 rounded-full"
                              initial={{ width: 0 }}
                              animate={{ width: `${uploadedFile.progress}%` }}
                              transition={{ duration: 0.3 }}
                            />
                          </div>
                          <span className="text-xs text-gray-400 w-12 text-right">
                            {uploadedFile.progress}%
                          </span>
                        </div>
                      )}
                      
                      {uploadedFile.chunks && uploadedFile.status === 'uploading' && (
                        <span className="text-xs text-gray-500">
                          Chunk {uploadedFile.chunks.completed}/{uploadedFile.chunks.total}
                        </span>
                      )}
                      
                      {uploadedFile.error && (
                        <span className="text-xs text-red-400 flex items-center space-x-1">
                          <Info className="w-3 h-3" />
                          <span>{uploadedFile.error}</span>
                        </span>
                      )}
                    </div>
                  </div>
                </motion.div>
              ))}
            </AnimatePresence>
          </div>
        </div>
      )}

      {/* Supported Formats */}
      <div className="bg-slate-900/50 rounded-lg p-6 border border-slate-800">
        <h3 className="text-lg font-semibold text-white mb-4">Supported File Formats</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
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

      {/* Upload Guidelines */}
      <div className="bg-slate-900/50 rounded-lg p-6 border border-slate-800">
        <h3 className="text-lg font-semibold text-white mb-4">Upload Guidelines</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <h4 className="text-sm font-medium text-primary-400 mb-2">File Requirements</h4>
            <ul className="text-sm text-gray-400 space-y-1">
              <li className="flex items-start">
                <span className="mr-2">•</span>
                <span>Maximum file size: {formatFileSize(API_CONFIG.MAX_FILE_SIZE)}</span>
              </li>
              <li className="flex items-start">
                <span className="mr-2">•</span>
                <span>Multiple files can be uploaded simultaneously</span>
              </li>
              <li className="flex items-start">
                <span className="mr-2">•</span>
                <span>Large files are automatically chunked for reliable upload</span>
              </li>
              <li className="flex items-start">
                <span className="mr-2">•</span>
                <span>Compressed archives will be extracted and analyzed</span>
              </li>
              <li className="flex items-start">
                <span className="mr-2">•</span>
                <span>Binary files undergo malware analysis</span>
              </li>
            </ul>
          </div>
          <div>
            <h4 className="text-sm font-medium text-primary-400 mb-2">Analysis Features</h4>
            <ul className="text-sm text-gray-400 space-y-1">
              <li className="flex items-start">
                <span className="mr-2">•</span>
                <span>YARA rule matching for malware detection</span>
              </li>
              <li className="flex items-start">
                <span className="mr-2">•</span>
                <span>Sigma rule detection for security events</span>
              </li>
              <li className="flex items-start">
                <span className="mr-2">•</span>
                <span>MITRE ATT&CK technique mapping</span>
              </li>
              <li className="flex items-start">
                <span className="mr-2">•</span>
                <span>AI-powered behavioral analysis</span>
              </li>
              <li className="flex items-start">
                <span className="mr-2">•</span>
                <span>Automated IOC extraction</span>
              </li>
              <li className="flex items-start">
                <span className="mr-2">•</span>
                <span>VirusTotal integration for threat intelligence</span>
              </li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Upload