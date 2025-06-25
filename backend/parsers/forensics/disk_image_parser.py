"""
Disk Image Parser for SecuNik LogX
Parses disk images (DD, E01) for forensic analysis
Extracts file system artifacts, deleted files, and security indicators
"""

import struct
import asyncio
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set, AsyncGenerator, Tuple
from pathlib import Path
from collections import defaultdict
import hashlib
import re
import json

from ..base_parser import BaseParser, ParseResult, ParsedEntry, FileMetadata, IOCs


class DiskImageParser(BaseParser):
    """Parser for disk image files (DD, E01 formats)"""
    
    name = "disk_image"
    description = "Parses disk images for forensic artifacts"
    supported_extensions = ['.dd', '.raw', '.img', '.e01', '.aff', '.001']
    
    # Common file signatures (magic bytes)
    FILE_SIGNATURES = {
        b'\x4D\x5A': ('exe', 'Windows Executable'),
        b'\x50\x4B\x03\x04': ('zip', 'ZIP Archive'),
        b'\x89\x50\x4E\x47': ('png', 'PNG Image'),
        b'\xFF\xD8\xFF': ('jpg', 'JPEG Image'),
        b'\x25\x50\x44\x46': ('pdf', 'PDF Document'),
        b'\x37\x7A\xBC\xAF\x27\x1C': ('7z', '7-Zip Archive'),
        b'\x52\x61\x72\x21': ('rar', 'RAR Archive'),
        b'\x00\x00\x00\x20\x66\x74\x79\x70': ('mp4', 'MP4 Video'),
        b'\x49\x44\x33': ('mp3', 'MP3 Audio'),
        b'\x4F\x67\x67\x53': ('ogg', 'OGG Media'),
        b'\x38\x42\x50\x53': ('psd', 'Photoshop Document'),
        b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1': ('doc', 'MS Office Document'),
        b'\x50\x4B\x05\x06': ('docx', 'MS Office Open XML'),
        b'\x7B\x5C\x72\x74\x66': ('rtf', 'Rich Text Format'),
        b'\xFE\xED\xFA': ('macho', 'Mac Executable'),
        b'\x7F\x45\x4C\x46': ('elf', 'Linux Executable'),
        b'#!/': ('script', 'Shell Script'),
        b'#!': ('script', 'Script File'),
        b'MZ': ('dos', 'DOS Executable')
    }
    
    # MBR/GPT structures
    MBR_SIGNATURE = b'\x55\xAA'
    GPT_SIGNATURE = b'EFI PART'
    
    # File system signatures
    FS_SIGNATURES = {
        b'NTFS': 'NTFS',
        b'FAT32': 'FAT32',
        b'FAT16': 'FAT16',
        b'FAT12': 'FAT12',
        b'\x53\xEF': 'ext2/3/4',
        b'_BHR': 'HFS+',
        b'XFSB': 'XFS',
        b'_BTree': 'Btrfs'
    }
    
    # Security artifacts to search for
    SECURITY_ARTIFACTS = {
        'shadow_copies': rb'\\System Volume Information\\',
        'recycle_bin': rb'\$Recycle\.Bin|\$RECYCLE\.BIN',
        'browser_data': rb'\\AppData\\.*\\(Chrome|Firefox|Edge)\\',
        'registry': rb'\\Windows\\System32\\config\\(SAM|SYSTEM|SOFTWARE|SECURITY)',
        'event_logs': rb'\\Windows\\System32\\winevt\\Logs\\',
        'prefetch': rb'\\Windows\\Prefetch\\.*\.pf',
        'temp_files': rb'\\(Windows\\Temp|Users\\.*\\AppData\\Local\\Temp)\\',
        'ssh_keys': rb'\.ssh\\(id_rsa|id_dsa|authorized_keys)',
        'password_files': rb'(shadow|passwd|SAM|SYSTEM)$',
        'history_files': rb'\.(bash_history|zsh_history|history)$'
    }
    
    # Suspicious patterns
    SUSPICIOUS_PATTERNS = {
        'encrypted_files': rb'\.(encrypted|locked|enc|aes|gpg)$',
        'ransomware_notes': rb'(README|DECRYPT|RECOVER|RESTORE).*\.(txt|html|hta)$',
        'malware_artifacts': rb'\\(System32|SysWOW64)\\.*\.(tmp|dat|log)$',
        'hidden_files': rb'/\.[^/]+$|\\\..*',
        'suspicious_scripts': rb'\.(ps1|vbs|js|jse|wsf|wsh|bat|cmd)$',
        'packed_executables': rb'UPX[0-9]|ASPack|PECompact|Themida',
        'rootkit_files': rb'\\(drivers|system32\\drivers)\\.*\.sys$',
        'keylogger_logs': rb'(keylog|keys|typed|keyboard).*\.(txt|log|dat)$'
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.partitions = []
        self.file_artifacts = []
        self.deleted_files = []
        self.suspicious_artifacts = []
        self.security_findings = []
        self.carved_files = []
        
    async def parse(self) -> ParseResult:
        """Parse disk image file"""
        result = ParseResult(
            file_path=str(self.file_path),
            file_type="disk_image",
            parser_name=self.name
        )
        
        try:
            # Get file metadata
            result.metadata = await self._get_file_metadata()
            
            # Detect image format
            image_format = await self._detect_image_format()
            result.metadata.additional["image_format"] = image_format
            
            # Parse based on format
            if image_format == "e01":
                await self._parse_e01_image(result)
            else:
                await self._parse_raw_image(result)
                
            # Add findings to results
            for finding in self.security_findings[:100]:  # Limit findings
                result.entries.append(finding)
                
            # Add suspicious artifacts
            for artifact in self.suspicious_artifacts[:50]:
                result.entries.append(artifact)
                
            # Extract IOCs from all findings
            for entry in result.entries:
                result.iocs.merge(self._extract_image_iocs(entry))
                
            # Add summary
            result.metadata.additional.update({
                "partition_count": len(self.partitions),
                "total_artifacts": len(self.file_artifacts),
                "deleted_files": len(self.deleted_files),
                "suspicious_artifacts": len(self.suspicious_artifacts),
                "carved_files": len(self.carved_files),
                "security_findings": len(self.security_findings),
                "file_systems": self._get_file_systems(),
                "artifact_summary": self._summarize_artifacts(),
                "threat_indicators": self._get_threat_indicators()
            })
            
            self.logger.info(f"Parsed disk image with {len(self.partitions)} partitions")
            
        except Exception as e:
            self.logger.error(f"Error parsing disk image: {e}")
            result.errors.append(f"Parse error: {str(e)}")
            
        return result
        
    async def _detect_image_format(self) -> str:
        """Detect disk image format"""
        async with self._open_file('rb') as f:
            header = await f.read(512)
            
        # Check for E01 (Expert Witness Format)
        if header.startswith(b'EVF\x09\x0D\x0A\xFF\x00'):
            return "e01"
            
        # Check for AFF
        if header.startswith(b'AFF'):
            return "aff"
            
        # Default to raw/dd
        return "raw"
        
    async def _parse_raw_image(self, result: ParseResult):
        """Parse raw disk image (DD format)"""
        # Create main entry
        image_entry = ParsedEntry(
            timestamp=datetime.now(),
            source="disk_image",
            event_type="forensic_image",
            severity="info",
            message=f"Disk image: {self.file_path.name}",
            raw_data={'format': 'raw', 'size': result.metadata.size}
        )
        result.entries.append(image_entry)
        
        # Parse partition table
        await self._parse_partitions()
        
        # Scan for file artifacts
        await self._scan_artifacts()
        
        # Carve for deleted files
        await self._carve_files()
        
        # Analyze security artifacts
        await self._analyze_security_artifacts()
        
    async def _parse_e01_image(self, result: ParseResult):
        """Parse E01 (Expert Witness) format"""
        # E01 has header, volume, sections, etc.
        # This is a simplified implementation
        
        async with self._open_file('rb') as f:
            # Read E01 header
            header = await f.read(13)
            if header != b'EVF\x09\x0D\x0A\xFF\x00':
                result.errors.append("Invalid E01 header")
                return
                
            # Read header section
            header_section = await f.read(76)
            
            # Create E01 entry
            e01_entry = ParsedEntry(
                timestamp=datetime.now(),
                source="disk_image",
                event_type="forensic_image",
                severity="info",
                message=f"E01 disk image: {self.file_path.name}",
                raw_data={
                    'format': 'e01',
                    'header': self._parse_e01_header(header_section)
                }
            )
            result.entries.append(e01_entry)
            
        # For now, we'll do basic scanning
        await self._scan_artifacts()
        
    def _parse_e01_header(self, header_data: bytes) -> Dict:
        """Parse E01 header section"""
        # Simplified E01 header parsing
        return {
            'type': 'e01_header',
            'size': len(header_data),
            'parsed': False  # Would need full E01 implementation
        }
        
    async def _parse_partitions(self):
        """Parse partition table (MBR/GPT)"""
        async with self._open_file('rb') as f:
            # Check for MBR
            f.seek(510)
            signature = await f.read(2)
            
            if signature == self.MBR_SIGNATURE:
                # Parse MBR
                f.seek(446)
                for i in range(4):
                    partition_entry = await f.read(16)
                    partition = self._parse_mbr_entry(partition_entry, i)
                    if partition['type'] != 0:
                        self.partitions.append(partition)
                        
            # Check for GPT
            f.seek(512)
            gpt_header = await f.read(8)
            if gpt_header == self.GPT_SIGNATURE:
                # Parse GPT
                await self._parse_gpt(f)
                
    def _parse_mbr_entry(self, entry: bytes, index: int) -> Dict:
        """Parse MBR partition entry"""
        if len(entry) < 16:
            return {'type': 0}
            
        return {
            'index': index,
            'bootable': entry[0] == 0x80,
            'type': entry[4],
            'start_lba': struct.unpack('<I', entry[8:12])[0],
            'size_lba': struct.unpack('<I', entry[12:16])[0]
        }
        
    async def _parse_gpt(self, f):
        """Parse GPT partition table"""
        # Simplified GPT parsing
        f.seek(512)
        header = await f.read(92)
        
        if header[:8] == self.GPT_SIGNATURE:
            # Read partition entries
            f.seek(1024)  # GPT partition entries usually start here
            
            for i in range(128):  # Max 128 partitions
                entry = await f.read(128)
                if entry[:16] == b'\x00' * 16:
                    break
                    
                partition = {
                    'index': i,
                    'type': 'gpt',
                    'guid': entry[:16].hex(),
                    'start_lba': struct.unpack('<Q', entry[32:40])[0],
                    'end_lba': struct.unpack('<Q', entry[40:48])[0]
                }
                self.partitions.append(partition)
                
    async def _scan_artifacts(self):
        """Scan for file artifacts and security indicators"""
        chunk_size = 1024 * 1024  # 1MB chunks
        offset = 0
        
        async with self._open_file('rb') as f:
            while True:
                chunk = await f.read(chunk_size)
                if not chunk:
                    break
                    
                # Yield control periodically
                if offset % (10 * chunk_size) == 0:
                    await asyncio.sleep(0)
                    
                # Scan for file signatures
                await self._scan_file_signatures(chunk, offset)
                
                # Scan for security artifacts
                await self._scan_security_artifacts(chunk, offset)
                
                # Scan for suspicious patterns
                await self._scan_suspicious_patterns(chunk, offset)
                
                offset += len(chunk)
                
    async def _scan_file_signatures(self, chunk: bytes, offset: int):
        """Scan chunk for file signatures"""
        for signature, (ext, description) in self.FILE_SIGNATURES.items():
            # Find all occurrences of signature
            start = 0
            while True:
                pos = chunk.find(signature, start)
                if pos == -1:
                    break
                    
                file_offset = offset + pos
                
                # Create artifact entry
                artifact = {
                    'offset': file_offset,
                    'type': ext,
                    'description': description,
                    'signature': signature.hex()
                }
                
                self.file_artifacts.append(artifact)
                
                # If it's an executable, flag it
                if ext in ['exe', 'elf', 'macho', 'script']:
                    finding = ParsedEntry(
                        timestamp=datetime.now(),
                        source=f"offset_{file_offset}",
                        event_type="file_artifact",
                        severity="warning",
                        message=f"Executable found at offset {file_offset}: {description}",
                        raw_data=artifact
                    )
                    finding.tags = ["executable", ext]
                    self.security_findings.append(finding)
                    
                start = pos + 1
                
    async def _scan_security_artifacts(self, chunk: bytes, offset: int):
        """Scan for security-relevant artifacts"""
        for artifact_type, pattern in self.SECURITY_ARTIFACTS.items():
            matches = list(re.finditer(pattern, chunk, re.IGNORECASE))
            
            for match in matches:
                file_offset = offset + match.start()
                
                finding = ParsedEntry(
                    timestamp=datetime.now(),
                    source=f"offset_{file_offset}",
                    event_type="security_artifact",
                    severity="warning",
                    message=f"{artifact_type} artifact found at offset {file_offset}",
                    raw_data={
                        'type': artifact_type,
                        'offset': file_offset,
                        'pattern': match.group(0).decode('utf-8', errors='ignore')
                    }
                )
                finding.tags = ["security_artifact", artifact_type]
                
                # Higher severity for certain artifacts
                if artifact_type in ['password_files', 'ssh_keys', 'registry']:
                    finding.severity = "critical"
                    finding.tags.append("sensitive_data")
                    
                self.security_findings.append(finding)
                
    async def _scan_suspicious_patterns(self, chunk: bytes, offset: int):
        """Scan for suspicious patterns"""
        for pattern_type, pattern in self.SUSPICIOUS_PATTERNS.items():
            matches = list(re.finditer(pattern, chunk, re.IGNORECASE))
            
            for match in matches:
                file_offset = offset + match.start()
                matched_text = match.group(0).decode('utf-8', errors='ignore')
                
                # Create suspicious finding
                suspicious = ParsedEntry(
                    timestamp=datetime.now(),
                    source=f"offset_{file_offset}",
                    event_type="security_alert",
                    severity="warning",
                    message=f"Suspicious pattern '{pattern_type}' at offset {file_offset}",
                    raw_data={
                        'pattern_type': pattern_type,
                        'offset': file_offset,
                        'matched': matched_text
                    }
                )
                suspicious.tags = ["suspicious", pattern_type]
                
                # Increase severity for certain patterns
                if pattern_type in ['ransomware_notes', 'rootkit_files', 'keylogger_logs']:
                    suspicious.severity = "critical"
                    suspicious.tags.append("malware")
                    
                self.suspicious_artifacts.append(suspicious)
                
    async def _carve_files(self):
        """Carve for deleted files"""
        # Simplified file carving - look for file headers not in allocated space
        chunk_size = 1024 * 1024
        offset = 0
        
        async with self._open_file('rb') as f:
            while offset < 100 * 1024 * 1024:  # Limit to first 100MB for performance
                chunk = await f.read(chunk_size)
                if not chunk:
                    break
                    
                # Look for file headers
                for signature, (ext, description) in self.FILE_SIGNATURES.items():
                    pos = chunk.find(signature)
                    if pos != -1:
                        file_offset = offset + pos
                        
                        # Try to carve file
                        carved = await self._carve_file(f, file_offset, ext)
                        if carved:
                            self.carved_files.append(carved)
                            
                            # Create entry for carved file
                            carved_entry = ParsedEntry(
                                timestamp=datetime.now(),
                                source=f"carved_{file_offset}",
                                event_type="carved_file",
                                severity="info",
                                message=f"Carved {ext} file at offset {file_offset}",
                                raw_data=carved
                            )
                            carved_entry.tags = ["file_carving", "deleted_file", ext]
                            
                            # Check if carved file is suspicious
                            if ext in ['exe', 'script', 'zip', 'rar']:
                                carved_entry.severity = "warning"
                                carved_entry.tags.append("suspicious_carved")
                                
                            self.deleted_files.append(carved_entry)
                            
                offset += len(chunk)
                
                # Yield control
                await asyncio.sleep(0)
                
    async def _carve_file(self, f, offset: int, file_type: str) -> Optional[Dict]:
        """Attempt to carve a file starting at offset"""
        max_size = 10 * 1024 * 1024  # Max 10MB per carved file
        
        # Save current position
        current_pos = f.tell()
        
        try:
            f.seek(offset)
            
            # Read file header
            header = await f.read(1024)
            
            # Try to determine file size
            # This is simplified - real carving is more complex
            file_size = min(max_size, 1024 * 1024)  # Default 1MB
            
            # Read file data
            f.seek(offset)
            file_data = await f.read(file_size)
            
            # Calculate hash
            file_hash = hashlib.md5(file_data).hexdigest()
            
            carved_info = {
                'offset': offset,
                'type': file_type,
                'size': len(file_data),
                'hash': file_hash,
                'header': header[:32].hex()
            }
            
            return carved_info
            
        finally:
            # Restore position
            f.seek(current_pos)
            
        return None
        
    async def _analyze_security_artifacts(self):
        """Analyze found artifacts for security implications"""
        # Group artifacts by type
        artifact_groups = defaultdict(list)
        
        for artifact in self.file_artifacts:
            artifact_groups[artifact['type']].append(artifact)
            
        # Check for malware indicators
        if 'exe' in artifact_groups:
            exe_count = len(artifact_groups['exe'])
            if exe_count > 50:
                alert = ParsedEntry(
                    timestamp=datetime.now(),
                    source="artifact_analysis",
                    event_type="security_alert",
                    severity="warning",
                    message=f"High number of executables found: {exe_count}",
                    raw_data={'executable_count': exe_count}
                )
                alert.tags = ["anomaly", "many_executables"]
                self.security_findings.append(alert)
                
        # Check for encrypted files
        encrypted_count = sum(1 for a in self.suspicious_artifacts 
                            if 'encrypted_files' in a.tags)
        if encrypted_count > 10:
            alert = ParsedEntry(
                timestamp=datetime.now(),
                source="artifact_analysis",
                event_type="security_alert",
                severity="critical",
                message=f"Multiple encrypted files detected: {encrypted_count}",
                raw_data={'encrypted_count': encrypted_count}
            )
            alert.tags = ["ransomware", "encryption"]
            self.security_findings.append(alert)
            
    def _extract_image_iocs(self, entry: ParsedEntry) -> IOCs:
        """Extract IOCs from disk image artifacts"""
        iocs = IOCs()
        
        # Extract from raw data
        raw_str = json.dumps(entry.raw_data)
        
        # Extract file paths
        paths = re.findall(r'[A-Za-z]:\\[^\\/:*?"<>|\r\n]+(?:\\[^\\/:*?"<>|\r\n]+)*', raw_str)
        for path in paths:
            iocs.file_paths.add(path)
            
        # Extract potential malware names
        if 'pattern' in entry.raw_data:
            pattern = entry.raw_data['pattern']
            # Check for executable names
            exe_match = re.search(r'\\([^\\]+\.(exe|dll|sys|bat|ps1))', pattern, re.IGNORECASE)
            if exe_match:
                iocs.file_paths.add(exe_match.group(1))
                
        # Extract hashes
        if 'hash' in entry.raw_data:
            iocs.hashes.add(entry.raw_data['hash'])
            
        return iocs
        
    def _get_file_systems(self) -> List[str]:
        """Get detected file systems"""
        fs_list = []
        
        for partition in self.partitions:
            # Map partition type to file system
            if partition.get('type') == 0x07:
                fs_list.append('NTFS')
            elif partition.get('type') == 0x0C:
                fs_list.append('FAT32')
            elif partition.get('type') == 0x83:
                fs_list.append('Linux')
                
        return list(set(fs_list))
        
    def _summarize_artifacts(self) -> Dict[str, int]:
        """Summarize found artifacts by type"""
        summary = defaultdict(int)
        
        for artifact in self.file_artifacts:
            summary[artifact['type']] += 1
            
        return dict(summary)
        
    def _get_threat_indicators(self) -> List[str]:
        """Get list of threat indicators found"""
        indicators = []
        
        # Check for ransomware
        if any('ransomware' in a.tags for a in self.suspicious_artifacts):
            indicators.append("Ransomware indicators")
            
        # Check for rootkits
        if any('rootkit' in a.tags for a in self.suspicious_artifacts):
            indicators.append("Rootkit artifacts")
            
        # Check for data theft
        if any('keylogger' in a.tags for a in self.suspicious_artifacts):
            indicators.append("Keylogger artifacts")
            
        # Check for sensitive data exposure
        if any('sensitive_data' in a.tags for a in self.security_findings):
            indicators.append("Sensitive data exposure")
            
        return indicators