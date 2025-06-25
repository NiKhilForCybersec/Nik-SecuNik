import axios from 'axios';
import api from './api';

class UploadService {
  constructor() {
    this.uploadControllers = new Map();
  }

  /**
   * Upload a single file with progress tracking
   * @param {File} file - The file to upload
   * @param {Function} onProgress - Progress callback (percentage)
   * @returns {Promise} Upload result with file hash
   */
  async uploadFile(file, onProgress) {
    const formData = new FormData();
    formData.append('file', file);

    // Create a cancel token for this upload
    const source = axios.CancelToken.source();
    const uploadId = `${file.name}-${Date.now()}`;
    this.uploadControllers.set(uploadId, source);

    try {
      const response = await api.post('/upload/file', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
        cancelToken: source.token,
        onUploadProgress: (progressEvent) => {
          if (progressEvent.lengthComputable) {
            const percentCompleted = Math.round(
              (progressEvent.loaded * 100) / progressEvent.total
            );
            if (onProgress) {
              onProgress(percentCompleted);
            }
          }
        },
      });

      // Clean up controller after successful upload
      this.uploadControllers.delete(uploadId);

      return {
        success: true,
        data: response.data,
        uploadId
      };
    } catch (error) {
      // Clean up controller on error
      this.uploadControllers.delete(uploadId);

      if (axios.isCancel(error)) {
        throw new Error('Upload cancelled');
      }

      throw this.handleError(error);
    }
  }

  /**
   * Upload multiple files with individual progress tracking
   * @param {File[]} files - Array of files to upload
   * @param {Function} onProgress - Progress callback ({ [filename]: percentage })
   * @returns {Promise} Array of upload results
   */
  async uploadMultiple(files, onProgress) {
    const progressMap = {};
    const uploadPromises = files.map(file => {
      return this.uploadFile(file, (progress) => {
        progressMap[file.name] = progress;
        if (onProgress) {
          onProgress({ ...progressMap });
        }
      });
    });

    try {
      const results = await Promise.allSettled(uploadPromises);
      
      return results.map((result, index) => ({
        file: files[index].name,
        success: result.status === 'fulfilled',
        data: result.status === 'fulfilled' ? result.value.data : null,
        error: result.status === 'rejected' ? result.reason.message : null
      }));
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get list of supported file formats
   * @returns {Promise} Supported formats data
   */
  async getSupportedFormats() {
    try {
      const response = await api.get('/upload/supported-formats');
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Validate file before upload
   * @param {File} file - File to validate
   * @returns {Object} Validation result
   */
  validateFile(file) {
    const MAX_FILE_SIZE = 500 * 1024 * 1024; // 500MB
    const result = {
      valid: true,
      errors: []
    };

    // Check file size
    if (file.size > MAX_FILE_SIZE) {
      result.valid = false;
      result.errors.push(`File size exceeds 500MB limit (${(file.size / 1024 / 1024).toFixed(2)}MB)`);
    }

    // Check if file is empty
    if (file.size === 0) {
      result.valid = false;
      result.errors.push('File is empty');
    }

    // Check filename
    if (!file.name || file.name.trim() === '') {
      result.valid = false;
      result.errors.push('Invalid filename');
    }

    // Check for potentially dangerous file extensions (optional)
    const dangerousExtensions = ['.exe', '.dll', '.scr', '.vbs', '.js'];
    const fileExtension = file.name.toLowerCase().substring(file.name.lastIndexOf('.'));
    if (dangerousExtensions.includes(fileExtension)) {
      result.warnings = result.warnings || [];
      result.warnings.push(`Potentially dangerous file type: ${fileExtension}`);
    }

    return result;
  }

  /**
   * Cancel an ongoing upload
   * @param {string} uploadId - The upload ID to cancel
   */
  cancelUpload(uploadId) {
    const controller = this.uploadControllers.get(uploadId);
    if (controller) {
      controller.cancel('Upload cancelled by user');
      this.uploadControllers.delete(uploadId);
    }
  }

  /**
   * Cancel all ongoing uploads
   */
  cancelAllUploads() {
    for (const [uploadId, controller] of this.uploadControllers) {
      controller.cancel('All uploads cancelled');
    }
    this.uploadControllers.clear();
  }

  /**
   * Check if a file has already been uploaded
   * @param {string} fileHash - SHA256 hash of the file
   * @returns {Promise} Upload status
   */
  async checkFileExists(fileHash) {
    try {
      const response = await api.get(`/upload/check/${fileHash}`);
      return response.data;
    } catch (error) {
      if (error.response?.status === 404) {
        return { exists: false };
      }
      throw this.handleError(error);
    }
  }

  /**
   * Get upload statistics
   * @returns {Promise} Upload statistics
   */
  async getUploadStats() {
    try {
      const response = await api.get('/upload/stats');
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Resume an interrupted upload (if supported by backend)
   * @param {string} uploadId - Previous upload ID
   * @param {File} file - File to resume uploading
   * @param {number} startByte - Byte position to resume from
   * @param {Function} onProgress - Progress callback
   * @returns {Promise} Upload result
   */
  async resumeUpload(uploadId, file, startByte, onProgress) {
    const formData = new FormData();
    formData.append('file', file.slice(startByte));
    formData.append('uploadId', uploadId);
    formData.append('startByte', startByte);

    const source = axios.CancelToken.source();
    this.uploadControllers.set(uploadId, source);

    try {
      const response = await api.post('/upload/resume', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
        cancelToken: source.token,
        onUploadProgress: (progressEvent) => {
          if (progressEvent.lengthComputable) {
            const totalUploaded = startByte + progressEvent.loaded;
            const percentCompleted = Math.round(
              (totalUploaded * 100) / file.size
            );
            if (onProgress) {
              onProgress(percentCompleted);
            }
          }
        },
      });

      this.uploadControllers.delete(uploadId);
      return response.data;
    } catch (error) {
      this.uploadControllers.delete(uploadId);
      throw this.handleError(error);
    }
  }

  /**
   * Handle and format errors
   * @param {Error} error - The error to handle
   * @returns {Error} Formatted error
   */
  handleError(error) {
    if (error.response) {
      // Server responded with error
      const message = error.response.data?.message || error.response.data?.error || 'Upload failed';
      const err = new Error(message);
      err.status = error.response.status;
      err.details = error.response.data;
      return err;
    } else if (error.request) {
      // Request made but no response
      return new Error('No response from server. Please check your connection.');
    } else {
      // Something else happened
      return error;
    }
  }
}

// Create and export a singleton instance
const uploadService = new UploadService();
export { uploadService };