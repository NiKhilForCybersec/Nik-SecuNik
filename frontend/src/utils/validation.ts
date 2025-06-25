import { API_CONFIG } from './constants'

export const validateFile = (file: File): { valid: boolean; error?: string } => {
  // Check file size
  if (file.size > API_CONFIG.MAX_FILE_SIZE) {
    return {
      valid: false,
      error: `File size exceeds maximum allowed size of ${API_CONFIG.MAX_FILE_SIZE / 1024 / 1024}MB`
    }
  }

  // Check file extension
  const extension = '.' + file.name.split('.').pop()?.toLowerCase()
  if (!API_CONFIG.ALLOWED_FILE_TYPES.includes(extension)) {
    return {
      valid: false,
      error: `File type ${extension} is not supported`
    }
  }

  // Check file name for invalid characters
  if (!/^[\w\-. ]+$/.test(file.name)) {
    return {
      valid: false,
      error: 'File name contains invalid characters'
    }
  }

  return { valid: true }
}

export const sanitizeInput = (input: string): string => {
  // Remove any potential XSS vectors
  return input
    .replace(/[<>]/g, '')
    .replace(/javascript:/gi, '')
    .replace(/on\w+\s*=/gi, '')
    .trim()
}

export const validateEmail = (email: string): boolean => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  return emailRegex.test(email)
}

export const validateUrl = (url: string): boolean => {
  try {
    new URL(url)
    return true
  } catch {
    return false
  }
}

export const validateIPAddress = (ip: string): boolean => {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/
  const ipv6Regex = /^([\da-f]{1,4}:){7}[\da-f]{1,4}$/i
  
  if (ipv4Regex.test(ip)) {
    const parts = ip.split('.')
    return parts.every(part => {
      const num = parseInt(part, 10)
      return num >= 0 && num <= 255
    })
  }
  
  return ipv6Regex.test(ip)
}

export const validateHash = (hash: string): { valid: boolean; type?: string } => {
  const hashPatterns = {
    md5: /^[a-f0-9]{32}$/i,
    sha1: /^[a-f0-9]{40}$/i,
    sha256: /^[a-f0-9]{64}$/i,
    sha512: /^[a-f0-9]{128}$/i
  }

  for (const [type, pattern] of Object.entries(hashPatterns)) {
    if (pattern.test(hash)) {
      return { valid: true, type }
    }
  }

  return { valid: false }
}