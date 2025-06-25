"""
ZIP Archive Parser
Parses ZIP archives and analyzes contained files
"""

import zipfile
import os
from typing import Optional, AsyncIterator, Dict, Any, List
from datetime import datetime
import asyncio
import aiofiles
import tempfile
import shutil
from pathlib import Path

from parsers.base_parser import BaseParser, ParsedEntry
from core.file_identifier import FileIdentifier

class ZipParser(BaseParser):
    """Parser for ZIP archive files"""
    
    @property
    def parser_name(self) -> str:
        return "zip"
    
    @property
    def supported_extensions(self) -> list:
        return ['.zip', '.zipx']
    
    def __init__(self, file_path, config=None):
        super().__init__(file_path, config)
        
        # Configuration
        self.extract_nested = config.get('extract_nested', True) if config else True
        self.max_extraction_size = config.get('max_extraction_size', 500 * 1024 * 1024) if config else 500 * 1024 * 1024  # 500MB
        self.analyze_contents = config.get('analyze_contents', True) if config else True
        
        # Archive info
        self.archive_info = {
            'total_files': 0,
            'total_size': 0,
            'compressed_size': 0,
            'file_types': {},
            'suspicious_files': []
        }
        
        # Suspicious patterns
        self.suspicious_extensions = {
            '.exe', '.dll', '.scr', '.bat', '.cmd', '.com', '.pif',
            '.vbs', '.js', '.jar', '.ps1', '.psm1', '.app', '.dmg'
        }
        
        self.suspicious_names = [
            'password', 'passwd', 'crack', 'hack', 'exploit',
            'payload', 'malware', 'virus', 'trojan', 'backdoor'
        ]
        
        # Temporary directory for extraction
        self.temp_dir = None
        self.file_identifier = FileIdentifier()
    
    async def _parse_content(self) -> AsyncIterator[Optional[ParsedEntry]]:
        """Parse ZIP archive content"""
        try:
            # Create temporary directory
            self.temp_dir = tempfile.mkdtemp(prefix='zipparser_')
            
            # Analyze archive
            async for entry in self._analyze_archive():
                yield entry
                
        finally:
            # Cleanup temporary directory
            if self.temp_dir and os.path.exists(self.temp_dir):
                try:
                    shutil.rmtree(self.temp_dir)
                except:
                    pass
    
    async def _analyze_archive(self) -> AsyncIterator[Optional[ParsedEntry]]:
        """Analyze ZIP archive contents"""
        try:
            with zipfile.ZipFile(self.file_path, 'r') as zip_file:
                # Check if encrypted
                if self._is_encrypted(zip_file):
                    yield self._create_encrypted_entry()
                    return
                
                # Get file list
                file_list = zip_file.namelist()
                self.archive_info['total_files'] = len(file_list)
                
                # Analyze each file
                for file_info in zip_file.infolist():
                    # Create entry for archived file
                    entry = await self._analyze_archived_file(zip_file, file_info)
                    if entry:
                        yield entry
                    
                    # Yield control
                    if self._total_count % 50 == 0:
                        await asyncio.sleep(0)
                
                # Create summary entry
                yield self._create_summary_entry()
                
        except zipfile.BadZipFile as e:
            self.errors.append(f"Invalid ZIP file: {str(e)}")
            yield self._create_error_entry(f"Invalid ZIP file: {str(e)}")
        except Exception as e:
            self.errors.append(f"Error analyzing archive: {str(e)}")
            yield self._create_error_entry(f"Error analyzing archive: {str(e)}")
    
    async def _analyze_archived_file(self, zip_file: zipfile.ZipFile, file_info: zipfile.ZipInfo) -> Optional[ParsedEntry]:
        """Analyze a single file in the archive"""
        try:
            # Extract file info
            filename = file_info.filename
            file_size = file_info.file_size
            compressed_size = file_info.compress_size
            
            self.archive_info['total_size'] += file_size
            self.archive_info['compressed_size'] += compressed_size
            
            # Get timestamp
            timestamp = datetime(*file_info.date_time).isoformat()
            
            # Determine file type
            file_ext = Path(filename).suffix.lower()
            file_type = self.file_identifier.identify(filename) or 'unknown'
            
            # Update file type statistics
            self.archive_info['file_types'][file_type] = \
                self.archive_info['file_types'].get(file_type, 0) + 1
            
            # Check for suspicious indicators
            is_suspicious = self._check_suspicious(filename, file_info)
            severity = 'high' if is_suspicious else 'info'
            
            # Build metadata
            metadata = {
                'archived_file': filename,
                'file_size': file_size,
                'compressed_size': compressed_size,
                'compression_ratio': round(1 - (compressed_size / file_size), 2) if file_size > 0 else 0,
                'file_type': file_type,
                'crc32': format(file_info.CRC, '08x'),
                'compress_type': self._get_compression_method(file_info.compress_type)
            }
            
            # Extract and analyze content if configured
            if self.analyze_contents and file_size < self.max_extraction_size:
                content_info = await self._extract_and_analyze(zip_file, file_info)
                if content_info:
                    metadata.update(content_info)
            
            # Add suspicious indicators
            if is_suspicious:
                metadata['suspicious_indicators'] = self._get_suspicious_indicators(filename, file_info)
                self.archive_info['suspicious_files'].append(filename)
            
            # Extract IOCs from filename
            self._extract_iocs_from_filename(filename)
            
            # Build message
            message = f"Archived file: {filename} ({file_size} bytes, {file_type})"
            if is_suspicious:
                message += " [SUSPICIOUS]"
            
            return ParsedEntry(
                timestamp=timestamp,
                source=self.file_path.name,
                event_type='archive_content',
                severity=severity,
                message=message,
                raw_data=filename,
                metadata=metadata
            )
            
        except Exception as e:
            self.warnings.append(f"Failed to analyze file {file_info.filename}: {str(e)}")
            return None
    
    def _check_suspicious(self, filename: str, file_info: zipfile.ZipInfo) -> bool:
        """Check if file is suspicious"""
        filename_lower = filename.lower()
        
        # Check extension
        ext = Path(filename).suffix.lower()
        if ext in self.suspicious_extensions:
            return True
        
        # Check filename patterns
        if any(pattern in filename_lower for pattern in self.suspicious_names):
            return True
        
        # Check for double extensions
        parts = filename.split('.')
        if len(parts) > 2 and parts[-2].lower() in ['jpg', 'png', 'pdf', 'doc', 'txt']:
            return True
        
        # Check for hidden files
        if os.path.basename(filename).startswith('.'):
            return True
        
        # Check for unusual compression ratio
        if file_info.file_size > 0:
            ratio = file_info.compress_size / file_info.file_size
            if ratio < 0.01:  # Over 99% compression
                return True
        
        return False
    
    def _get_suspicious_indicators(self, filename: str, file_info: zipfile.ZipInfo) -> List[str]:
        """Get list of suspicious indicators"""
        indicators = []
        
        ext = Path(filename).suffix.lower()
        if ext in self.suspicious_extensions:
            indicators.append(f"Executable extension: {ext}")
        
        filename_lower = filename.lower()
        for pattern in self.suspicious_names:
            if pattern in filename_lower:
                indicators.append(f"Suspicious name pattern: {pattern}")
        
        parts = filename.split('.')
        if len(parts) > 2 and parts[-2].lower() in ['jpg', 'png', 'pdf', 'doc', 'txt']:
            indicators.append(f"Double extension: {parts[-2]}.{parts[-1]}")
        
        if os.path.basename(filename).startswith('.'):
            indicators.append("Hidden file")
        
        if file_info.file_size > 0:
            ratio = file_info.compress_size / file_info.file_size
            if ratio < 0.01:
                indicators.append(f"Unusual compression ratio: {ratio:.2%}")
        
        return indicators
    
    async def _extract_and_analyze(self, zip_file: zipfile.ZipFile, file_info: zipfile.ZipInfo) -> Dict[str, Any]:
        """Extract and analyze file content"""
        content_info = {}
        
        try:
            # Extract to temporary location
            temp_path = os.path.join(self.temp_dir, os.path.basename(file_info.filename))
            zip_file.extract(file_info, self.temp_dir)
            
            # Calculate hash
            if os.path.exists(temp_path):
                import hashlib
                sha256 = hashlib.sha256()
                
                with open(temp_path, 'rb') as f:
                    while chunk := f.read(8192):
                        sha256.update(chunk)
                
                content_info['file_hash'] = sha256.hexdigest()
                self.iocs['hashes'].append(content_info['file_hash'])
                
                # Check for nested archives
                if self.extract_nested and temp_path.lower().endswith(('.zip', '.rar', '.7z', '.tar', '.gz')):
                    content_info['nested_archive'] = True
                
                # Cleanup
                try:
                    os.remove(temp_path)
                except:
                    pass
                    
        except Exception as e:
            self.warnings.append(f"Failed to extract {file_info.filename}: {str(e)}")
        
        return content_info
    
    def _get_compression_method(self, compress_type: int) -> str:
        """Get compression method name"""
        methods = {
            zipfile.ZIP_STORED: 'Stored (no compression)',
            zipfile.ZIP_DEFLATED: 'Deflated',
            zipfile.ZIP_BZIP2: 'BZIP2',
            zipfile.ZIP_LZMA: 'LZMA'
        }
        return methods.get(compress_type, f'Unknown ({compress_type})')
    
    def _is_encrypted(self, zip_file: zipfile.ZipFile) -> bool:
        """Check if archive is encrypted"""
        for file_info in zip_file.infolist():
            if file_info.flag_bits & 0x1:
                return True
        return False
    
    def _create_encrypted_entry(self) -> ParsedEntry:
        """Create entry for encrypted archive"""
        return ParsedEntry(
            timestamp=datetime.now().isoformat(),
            source=self.file_path.name,
            event_type='archive_encrypted',
            severity='medium',
            message=f"Encrypted ZIP archive: {self.file_path.name}",
            raw_data='',
            metadata={
                'encrypted': True,
                'archive_name': self.file_path.name
            }
        )
    
    def _create_summary_entry(self) -> ParsedEntry:
        """Create summary entry for the archive"""
        # Sort file types by count
        sorted_types = sorted(
            self.archive_info['file_types'].items(), 
            key=lambda x: x[1], 
            reverse=True
        )
        
        metadata = {
            'total_files': self.archive_info['total_files'],
            'total_size': self.archive_info['total_size'],
            'compressed_size': self.archive_info['compressed_size'],
            'compression_ratio': round(
                1 - (self.archive_info['compressed_size'] / self.archive_info['total_size']), 2
            ) if self.archive_info['total_size'] > 0 else 0,
            'file_types': dict(sorted_types[:10]),  # Top 10 file types
            'suspicious_files_count': len(self.archive_info['suspicious_files'])
        }
        
        if self.archive_info['suspicious_files']:
            metadata['suspicious_files'] = self.archive_info['suspicious_files'][:20]  # First 20
        
        severity = 'high' if self.archive_info['suspicious_files'] else 'info'
        
        message = (
            f"ZIP Archive Summary: {self.archive_info['total_files']} files, "
            f"{self.archive_info['total_size']} bytes total"
        )
        
        if self.archive_info['suspicious_files']:
            message += f", {len(self.archive_info['suspicious_files'])} suspicious files"
        
        return ParsedEntry(
            timestamp=datetime.now().isoformat(),
            source=self.file_path.name,
            event_type='archive_summary',
            severity=severity,
            message=message,
            raw_data='',
            metadata=metadata
        )
    
    def _create_error_entry(self, error_message: str) -> ParsedEntry:
        """Create error entry"""
        return ParsedEntry(
            timestamp=datetime.now().isoformat(),
            source=self.file_path.name,
            event_type='archive_error',
            severity='high',
            message=error_message,
            raw_data='',
            metadata={
                'error': True,
                'error_message': error_message
            }
        )
    
    def _extract_iocs_from_filename(self, filename: str) -> None:
        """Extract IOCs from filename"""
        # Look for hashes in filename
        import re
        
        # MD5
        md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        md5_matches = re.findall(md5_pattern, filename)
        self.iocs['hashes'].extend(md5_matches)
        
        # SHA1
        sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
        sha1_matches = re.findall(sha1_pattern, filename)
        self.iocs['hashes'].extend(sha1_matches)
        
        # SHA256
        sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
        sha256_matches = re.findall(sha256_pattern, filename)
        self.iocs['hashes'].extend(sha256_matches)
        
        # IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ip_matches = re.findall(ip_pattern, filename)
        self.iocs['ips'].extend(ip_matches)
        
        # Email addresses
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        email_matches = re.findall(email_pattern, filename)
        self.iocs['emails'].extend(email_matches)
    
    async def _extract_file_metadata(self) -> None:
        """Extract ZIP-specific metadata"""
        await super()._extract_file_metadata()
        
        self.metadata['archive_type'] = 'zip'
        self.metadata['parser_version'] = '1.0'
        
        # Try to get ZIP comment
        try:
            with zipfile.ZipFile(self.file_path, 'r') as zip_file:
                if zip_file.comment:
                    self.metadata['archive_comment'] = zip_file.comment.decode('utf-8', errors='replace')
        except:
            pass