import { format, formatDistance, formatRelative } from 'date-fns';
import {
  DocumentTextIcon,
  DocumentIcon,
  ArchiveBoxIcon,
  GlobeAltIcon,
  EnvelopeIcon,
  ServerIcon,
  CodeBracketIcon,
  PhoneIcon,
  CloudIcon,
} from '@heroicons/react/24/outline';

/**
 * Format bytes to human readable format
 */
export const formatBytes = (bytes, decimals = 2) => {
  if (bytes === 0) return '0 Bytes';

  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];

  const i = Math.floor(Math.log(bytes) / Math.log(k));

  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
};

/**
 * Format date to various formats
 */
export const formatDateTime = (date, formatStr = 'PPpp') => {
  return format(new Date(date), formatStr);
};

export const formatDate = (date) => {
  return format(new Date(date), 'PP');
};

export const formatTime = (date) => {
  return format(new Date(date), 'p');
};

export const formatRelativeTime = (date) => {
  return formatDistance(new Date(date), new Date(), { addSuffix: true });
};

/**
 * Format duration in seconds to human readable format
 */
export const formatDuration = (seconds) => {
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = seconds % 60;

  const parts = [];
  if (hours > 0) parts.push(`${hours}h`);
  if (minutes > 0) parts.push(`${minutes}m`);
  if (secs > 0 || parts.length === 0) parts.push(`${secs}s`);

  return parts.join(' ');
};

/**
 * Format number with commas
 */
export const formatNumber = (num) => {
  return new Intl.NumberFormat().format(num);
};

/**
 * Format percentage
 */
export const formatPercentage = (value, decimals = 1) => {
  return `${(value * 100).toFixed(decimals)}%`;
};

/**
 * Truncate text with ellipsis
 */
export const truncateText = (text, maxLength) => {
  if (text.length <= maxLength) return text;
  return text.substr(0, maxLength - 3) + '...';
};

/**
 * Get file icon based on file type
 */
export const getFileIcon = (filename) => {
  const ext = filename.split('.').pop().toLowerCase();
  
  const iconMap = {
    // Logs
    log: DocumentTextIcon,
    txt: DocumentTextIcon,
    syslog: DocumentTextIcon,
    evtx: DocumentTextIcon,
    evt: DocumentTextIcon,
    
    // Network
    pcap: GlobeAltIcon,
    pcapng: GlobeAltIcon,
    cap: GlobeAltIcon,
    netflow: GlobeAltIcon,
    
    // Archives
    zip: ArchiveBoxIcon,
    rar: ArchiveBoxIcon,
    '7z': ArchiveBoxIcon,
    tar: ArchiveBoxIcon,
    gz: ArchiveBoxIcon,
    
    // Documents
    pdf: DocumentIcon,
    doc: DocumentIcon,
    docx: DocumentIcon,
    xls: DocumentIcon,
    xlsx: DocumentIcon,
    
    // Email
    eml: EnvelopeIcon,
    msg: EnvelopeIcon,
    mbox: EnvelopeIcon,
    pst: EnvelopeIcon,
    
    // System
    dd: ServerIcon,
    e01: ServerIcon,
    vmdk: ServerIcon,
    vhd: ServerIcon,
    
    // Code
    json: CodeBracketIcon,
    xml: CodeBracketIcon,
    csv: CodeBracketIcon,
    yaml: CodeBracketIcon,
    
    // Mobile
    logcat: PhoneIcon,
    ips: PhoneIcon,
    
    // Cloud
    cloudtrail: CloudIcon,
    azurelog: CloudIcon,
  };

  return iconMap[ext] || DocumentIcon;
};

/**
 * Get severity color class
 */
export const getSeverityColor = (severity) => {
  const colors = {
    critical: 'text-red-500 bg-red-500/10',
    high: 'text-orange-500 bg-orange-500/10',
    medium: 'text-yellow-500 bg-yellow-500/10',
    low: 'text-green-500 bg-green-500/10',
    info: 'text-blue-500 bg-blue-500/10',
  };

  return colors[severity.toLowerCase()] || colors.info;
};

/**
 * Format threat score
 */
export const formatThreatScore = (score) => {
  if (score >= 90) return { text: 'Critical', color: 'text-red-500' };
  if (score >= 70) return { text: 'High', color: 'text-orange-500' };
  if (score >= 50) return { text: 'Medium', color: 'text-yellow-500' };
  if (score >= 30) return { text: 'Low', color: 'text-green-500' };
  return { text: 'Info', color: 'text-blue-500' };
};