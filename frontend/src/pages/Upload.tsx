import React, { useState, useCallback } from 'react'
import { motion } from 'framer-motion'
import { useDropzone } from 'react-dropzone'
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
  Shield
} from 'lucide-react'
import toast from 'react-hot-toast'

interface UploadedFile {
  id: string
  file: File
  status: 'uploading' | 'analyzing' | 'completed' | 'error'
  progress: number
  type: string
  size: string
  analysisId?: string
  error?: string
}

const Upload: React.FC = () => {
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

  const simulateUploadAndAnalysis = (fileId: string) => {
    // Simulate upload progress
    let progress = 0
    const uploadInterval = setInterval(() => {
      progress += Math.random() * 20
      if (progress >= 100) {
        progress = 100
        clearInterval(uploadInterval)
        
        // Start analysis phase
        setUploadedFiles(prev => prev.map(f => 
          f.id === fileId 
            ? { ...f, status: 'analyzing', progress: 0 }
            : f
        ))
        
        // Simulate analysis
        let analysisProgress = 0
        const analysisInterval = setInterval(() => {
          analysisProgress += Math.random() * 15
          if (analysisProgress >= 100) {
            analysisProgress = 100
            clearInterval(analysisInterval)
            
            // Complete analysis
            setUploadedFiles(prev => prev.map(f => 
              f.id === fileId 
                ? { 
                    ...f, 
                    status: 'completed', 
                    progress: 100,
                    analysisId: `analysis_${Date.now()}`
                  }
                : f
            ))
            
            toast.success('File analysis completed!')
          } else {
            setUploadedFiles(prev => prev.map(f => 
              f.id === fileId 
                ? { ...f, progress: analysisProgress }
                : f
            ))
          }
        }, 500)
      } else {
        setUploadedFiles(prev => prev.map(f => 
          f.id === fileId 
            ? { ...f, progress }
            : f
        ))
      }
    }, 300)
  }

  const onDrop = useCallback((acceptedFiles: File[]) => {
    const newFiles: UploadedFile[] = acceptedFiles.map(file => ({
      id: `${Date.now()}_${Math.random()}`,
      file,
      status: 'uploading',
      progress: 0,
      type: getFileType(file.name),
      size: formatFileSize(file.size)
    }))

    setUploadedFiles(prev => [...prev, ...newFiles])
    
    // Start upload simulation for each file
    newFiles.forEach(file => {
      simulateUploadAndAnalysis(file.id)
    })

    toast.success(`${acceptedFiles.length} file(s) uploaded successfully!`)
  }, [])

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    multiple: true,
    maxSize: 100 * 1024 * 1024, // 100MB
    onDragEnter: () => setDragActive(true),
    onDragLeave: () => setDragActive(false),
  })

  const removeFile = (fileId: string) => {
    setUploadedFiles(prev => prev.filter(f => f.id !== fileId))
    toast.success('File removed')
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'uploading':
        return <Clock className="w-5 h-5 text-blue-400 animate-spin" />
      case 'analyzing':
        return <Clock className="w-5 h-5 text-yellow-400 animate-spin" />
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
      case 'analyzing':
        return 'Analyzing...'
      case 'completed':
        return 'Completed'
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
          Upload files for comprehensive cybersecurity analysis and threat detection
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
            or click to browse and select files
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
                    <button
                      onClick={() => removeFile(uploadedFile.id)}
                      className="text-gray-400 hover:text-red-400 transition-colors"
                    >
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                  
                  <div className="flex items-center space-x-4 mt-1">
                    <span className="text-xs text-gray-400">{uploadedFile.type}</span>
                    <span className="text-xs text-gray-400">{uploadedFile.size}</span>
                  </div>
                  
                  <div className="flex items-center space-x-3 mt-2">
                    {getStatusIcon(uploadedFile.status)}
                    <span className="text-xs text-gray-400">
                      {getStatusText(uploadedFile.status)}
                    </span>
                    
                    {uploadedFile.status !== 'completed' && (
                      <div className="flex-1 bg-slate-700 rounded-full h-2">
                        <motion.div
                          className="bg-primary-500 h-2 rounded-full"
                          initial={{ width: 0 }}
                          animate={{ width: `${uploadedFile.progress}%` }}
                          transition={{ duration: 0.3 }}
                        />
                      </div>
                    )}
                    
                    {uploadedFile.status === 'completed' && uploadedFile.analysisId && (
                      <button className="text-xs text-primary-400 hover:text-primary-300 transition-colors">
                        View Analysis →
                      </button>
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
              <li>• Maximum file size: 100MB</li>
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
              <li>• IOC extraction</li>
              <li>• VirusTotal integration</li>
              <li>• AI-powered analysis</li>
              <li>• Pattern recognition</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Upload