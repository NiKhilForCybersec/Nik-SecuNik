"""
Windows Registry Parser for SecuNik LogX
Parses Windows Registry hive files for security analysis
Detects malware persistence, suspicious entries, and IoCs
"""

import struct
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Set, AsyncGenerator, Tuple
from pathlib import Path
from collections import defaultdict
import re
import json
import base64

from ..base_parser import BaseParser, ParseResult, ParsedEntry, FileMetadata, IOCs


class RegistryParser(BaseParser):
    """Parser for Windows Registry hive files"""
    
    name = "registry"
    description = "Parses Windows Registry hives for security analysis"
    supported_extensions = ['.hive', '.reg', '.dat', '.log', '.log1', '.log2']
    
    # Registry hive signatures
    HIVE_SIGNATURES = {
        b'regf': 'Registry Hive',
        b'CRMF': 'Registry Transaction Log',
        b'DIRT': 'Registry Transaction Log'
    }
    
    # Registry paths for persistence mechanisms
    PERSISTENCE_KEYS = {
        # Run keys
        r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run': 'User Run',
        r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce': 'User RunOnce',
        r'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run': 'User Run (32-bit)',
        r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices': 'RunServices',
        r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce': 'RunServicesOnce',
        
        # System run keys
        r'SYSTEM\CurrentControlSet\Services': 'Services',
        r'SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute': 'BootExecute',
        
        # Explorer keys
        r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders': 'Shell Folders',
        r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders': 'User Shell Folders',
        r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects': 'Browser Helper Objects',
        
        # Security providers
        r'SYSTEM\CurrentControlSet\Control\SecurityProviders': 'Security Providers',
        r'SYSTEM\CurrentControlSet\Control\Lsa': 'LSA',
        
        # Network providers
        r'SYSTEM\CurrentControlSet\Control\NetworkProvider\Order': 'Network Providers',
        
        # Winlogon
        r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon': 'Winlogon',
        r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify': 'Winlogon Notify',
        
        # AppInit
        r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs': 'AppInit DLLs',
        r'SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs': 'AppInit DLLs (32-bit)',
        
        # Image File Execution Options
        r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options': 'IFEO',
        
        # File associations
        r'SOFTWARE\Classes': 'File Associations',
        
        # Scheduled tasks
        r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache': 'Scheduled Tasks'
    }
    
    # Suspicious value patterns
    SUSPICIOUS_PATTERNS = {
        'powershell': re.compile(r'(?i)powershell.*(-enc|-e\s|iex|downloadstring)', re.IGNORECASE),
        'wscript': re.compile(r'(?i)(wscript|cscript).*\.(js|jse|vbs|vbe|wsf)', re.IGNORECASE),
        'mshta': re.compile(r'(?i)mshta.*http', re.IGNORECASE),
        'regsvr32': re.compile(r'(?i)regsvr32.*/s.*(/u\s|/i:|scrobj)', re.IGNORECASE),
        'rundll32': re.compile(r'(?i)rundll32.*javascript:|shell32', re.IGNORECASE),
        'encoded_command': re.compile(r'(?i)(-enc|-e\s+)[a-z0-9+/=]{20,}', re.IGNORECASE),
        'temp_path': re.compile(r'(?i)(%temp%|\\temp\\|\\tmp\\)', re.IGNORECASE),
        'http_download': re.compile(r'(?i)(http|ftp)s?://[^\s]+\.(exe|dll|scr|bat|cmd|ps1)', re.IGNORECASE),
        'suspicious_extension': re.compile(r'(?i)\.(scr|pif|cpl|hta|jar|vb[se]?|ws[fh]?)$', re.IGNORECASE)
    }
    
    # Common malware registry indicators
    MALWARE_INDICATORS = {
        'mutex_pattern': re.compile(r'(?i)(mutex|global\\)', re.IGNORECASE),
        'service_dll': re.compile(r'(?i)servicedll.*\.dll$', re.IGNORECASE),
        'svchost': re.compile(r'(?i)svchost.*-k\s+[^\s]+$', re.IGNORECASE),
        'clsid': re.compile(r'\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}', re.IGNORECASE)
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.suspicious_entries = []
        self.persistence_mechanisms = []
        self.registry_iocs = defaultdict(set)
        self.value_cache = {}
        
    async def parse(self) -> ParseResult:
        """Parse Windows Registry file"""
        result = ParseResult(
            file_path=str(self.file_path),
            file_type="registry",
            parser_name=self.name
        )
        
        try:
            # Get file metadata
            result.metadata = await self._get_file_metadata()
            
            # Detect registry file type
            file_type = await self._detect_registry_type()
            if not file_type:
                result.errors.append("Unable to detect registry file type")
                return result
                
            result.metadata.additional["registry_type"] = file_type
            
            # Parse based on file type
            if file_type == "hive":
                async for entry in self._parse_hive():
                    result.entries.append(entry)
                    result.iocs.merge(self._extract_registry_iocs(entry))
            else:  # .reg text file
                async for entry in self._parse_reg_file():
                    result.entries.append(entry)
                    result.iocs.merge(self._extract_registry_iocs(entry))
                    
            # Add suspicious findings
            for suspicious in self.suspicious_entries[:200]:  # Limit findings
                result.entries.append(suspicious)
                
            # Add persistence mechanisms
            for persistence in self.persistence_mechanisms[:100]:
                result.entries.append(persistence)
                
            # Generate summary
            result.metadata.additional.update({
                "total_keys": len(result.entries),
                "suspicious_entries": len(self.suspicious_entries),
                "persistence_mechanisms": len(self.persistence_mechanisms),
                "registry_iocs": {k: list(v) for k, v in self.registry_iocs.items()},
                "top_suspicious_keys": self._get_top_suspicious_keys(),
                "malware_indicators": self._summarize_malware_indicators()
            })
            
            self.logger.info(f"Parsed {len(result.entries)} registry entries")
            
        except Exception as e:
            self.logger.error(f"Error parsing registry file: {e}")
            result.errors.append(f"Parse error: {str(e)}")
            
        return result
        
    async def _detect_registry_type(self) -> Optional[str]:
        """Detect registry file type"""
        # Check for binary hive
        async with self._open_file('rb') as f:
            header = await f.read(4)
            
            if header in self.HIVE_SIGNATURES:
                return "hive"
                
        # Check for text .reg file
        async with self._open_file('r', encoding='utf-16-le', errors='ignore') as f:
            first_line = await f.readline()
            if first_line.strip().startswith('Windows Registry Editor'):
                return "reg"
                
        # Try UTF-8
        async with self._open_file('r', encoding='utf-8', errors='ignore') as f:
            first_line = await f.readline()
            if first_line.strip().startswith('Windows Registry Editor'):
                return "reg"
                
        return None
        
    async def _parse_hive(self) -> AsyncGenerator[ParsedEntry, None]:
        """Parse binary registry hive file"""
        entry_count = 0
        
        async with self._open_file('rb') as f:
            # Read hive header
            header = await f.read(4096)
            if len(header) < 4096:
                return
                
            hive_info = self._parse_hive_header(header)
            
            # Note: Full binary hive parsing is complex
            # This is a simplified implementation focusing on key structures
            
            # Parse hive bins
            while True:
                bin_header = await f.read(32)
                if len(bin_header) < 32:
                    break
                    
                if bin_header[:4] != b'hbin':
                    continue
                    
                bin_size = struct.unpack('<I', bin_header[8:12])[0]
                
                # Read bin data
                bin_data = await f.read(bin_size - 32)
                
                # Parse cells in bin
                offset = 0
                while offset < len(bin_data):
                    cell_size = struct.unpack('<i', bin_data[offset:offset+4])[0]
                    if cell_size == 0:
                        break
                        
                    cell_size = abs(cell_size)
                    if offset + cell_size > len(bin_data):
                        break
                        
                    # Parse cell based on signature
                    cell_data = bin_data[offset+4:offset+cell_size]
                    
                    if len(cell_data) >= 2:
                        signature = cell_data[:2]
                        
                        if signature == b'nk':  # Key node
                            key_entry = self._parse_key_node(cell_data, entry_count)
                            if key_entry:
                                entry_count += 1
                                
                                # Yield control periodically
                                if entry_count % 100 == 0:
                                    await asyncio.sleep(0)
                                    
                                # Check for suspicious content
                                await self._analyze_registry_entry(key_entry)
                                
                                yield key_entry
                                
                        elif signature == b'vk':  # Value node
                            value_entry = self._parse_value_node(cell_data, entry_count)
                            if value_entry:
                                self.value_cache[entry_count] = value_entry
                                
                    offset += cell_size
                    
    async def _parse_reg_file(self) -> AsyncGenerator[ParsedEntry, None]:
        """Parse text .reg registry file"""
        current_key = None
        entry_count = 0
        
        # Try different encodings
        for encoding in ['utf-16-le', 'utf-8', 'latin-1']:
            try:
                async with self._open_file('r', encoding=encoding) as f:
                    async for line in f:
                        line = line.strip()
                        
                        if not line or line.startswith(';'):
                            continue
                            
                        # New key
                        if line.startswith('[') and line.endswith(']'):
                            current_key = line[1:-1]
                            
                            # Handle key deletion
                            if current_key.startswith('-'):
                                current_key = current_key[1:]
                                event_type = "registry_delete"
                            else:
                                event_type = "registry_key"
                                
                            entry = ParsedEntry(
                                timestamp=datetime.now(),
                                source="registry",
                                event_type=event_type,
                                severity="info",
                                message=f"Registry key: {current_key}",
                                raw_data={'key': current_key}
                            )
                            
                            entry.parsed_data = {
                                'key_path': current_key,
                                'action': 'delete' if event_type == "registry_delete" else 'create'
                            }
                            
                            entry_count += 1
                            
                            # Yield control periodically
                            if entry_count % 100 == 0:
                                await asyncio.sleep(0)
                                
                            # Analyze key
                            await self._analyze_registry_entry(entry)
                            
                            yield entry
                            
                        # Value assignment
                        elif '=' in line and current_key:
                            # Parse value
                            name, value = line.split('=', 1)
                            name = name.strip('"@')
                            
                            # Handle different value types
                            parsed_value = self._parse_reg_value(value)
                            
                            entry = ParsedEntry(
                                timestamp=datetime.now(),
                                source="registry",
                                event_type="registry_value",
                                severity="info",
                                message=f"Registry value: {current_key}\\{name}",
                                raw_data={
                                    'key': current_key,
                                    'name': name,
                                    'value': parsed_value
                                }
                            )
                            
                            entry.parsed_data = {
                                'key_path': current_key,
                                'value_name': name,
                                'value_data': parsed_value,
                                'action': 'set'
                            }
                            
                            entry_count += 1
                            
                            # Analyze value
                            await self._analyze_registry_entry(entry)
                            
                            yield entry
                            
                break  # Successfully parsed with this encoding
                
            except UnicodeDecodeError:
                continue  # Try next encoding
                
    def _parse_hive_header(self, header: bytes) -> Dict:
        """Parse registry hive header"""
        if header[:4] != b'regf':
            return {}
            
        return {
            'signature': header[:4],
            'sequence1': struct.unpack('<I', header[4:8])[0],
            'sequence2': struct.unpack('<I', header[8:12])[0],
            'timestamp': self._filetime_to_datetime(struct.unpack('<Q', header[12:20])[0]),
            'major_version': struct.unpack('<I', header[20:24])[0],
            'minor_version': struct.unpack('<I', header[24:28])[0],
            'file_type': struct.unpack('<I', header[28:32])[0],
            'root_key_offset': struct.unpack('<I', header[36:40])[0],
            'hive_name': header[48:112].decode('utf-16-le', errors='ignore').rstrip('\x00')
        }
        
    def _parse_key_node(self, data: bytes, entry_num: int) -> Optional[ParsedEntry]:
        """Parse registry key node"""
        if len(data) < 76:
            return None
            
        try:
            # Parse key node structure
            flags = struct.unpack('<H', data[2:4])[0]
            timestamp = self._filetime_to_datetime(struct.unpack('<Q', data[4:12])[0])
            parent_offset = struct.unpack('<I', data[16:20])[0]
            subkey_count = struct.unpack('<I', data[20:24])[0]
            value_count = struct.unpack('<I', data[28:32])[0]
            key_name_length = struct.unpack('<H', data[72:74])[0]
            class_name_length = struct.unpack('<H', data[74:76])[0]
            
            # Extract key name
            key_name = data[76:76+key_name_length].decode('ascii', errors='ignore')
            
            entry = ParsedEntry(
                timestamp=timestamp,
                source="registry",
                event_type="registry_key",
                severity="info",
                message=f"Registry key: {key_name}",
                raw_data={
                    'key_name': key_name,
                    'flags': flags,
                    'subkeys': subkey_count,
                    'values': value_count
                }
            )
            
            entry.parsed_data = {
                'key_path': key_name,
                'subkey_count': subkey_count,
                'value_count': value_count,
                'is_volatile': bool(flags & 0x0001),
                'is_symlink': bool(flags & 0x0010)
            }
            
            return entry
            
        except Exception as e:
            self.logger.debug(f"Error parsing key node: {e}")
            return None
            
    def _parse_value_node(self, data: bytes, entry_num: int) -> Optional[Dict]:
        """Parse registry value node"""
        if len(data) < 20:
            return None
            
        try:
            name_length = struct.unpack('<H', data[2:4])[0]
            data_size = struct.unpack('<I', data[4:8])[0]
            data_offset = struct.unpack('<I', data[8:12])[0]
            data_type = struct.unpack('<I', data[12:16])[0]
            flags = struct.unpack('<H', data[16:18])[0]
            
            # Extract value name
            value_name = data[20:20+name_length].decode('utf-16-le', errors='ignore')
            
            return {
                'name': value_name,
                'type': self._get_value_type_name(data_type),
                'size': data_size & 0x7FFFFFFF,  # Remove inline flag
                'is_inline': bool(data_size & 0x80000000)
            }
            
        except Exception as e:
            self.logger.debug(f"Error parsing value node: {e}")
            return None
            
    def _parse_reg_value(self, value_str: str) -> Any:
        """Parse registry value from .reg file format"""
        value_str = value_str.strip()
        
        # String value
        if value_str.startswith('"') and value_str.endswith('"'):
            return value_str[1:-1].replace('\\\\', '\\').replace('\\"', '"')
            
        # DWORD
        if value_str.startswith('dword:'):
            try:
                return int(value_str[6:], 16)
            except ValueError:
                return value_str
                
        # Binary
        if value_str.startswith('hex:'):
            hex_data = value_str[4:].replace(',', '').replace(' ', '')
            try:
                return bytes.fromhex(hex_data)
            except ValueError:
                return value_str
                
        # Multi-string
        if value_str.startswith('hex(7):'):
            hex_data = value_str[7:].replace(',', '').replace(' ', '')
            try:
                data = bytes.fromhex(hex_data)
                # Decode as UTF-16 multi-string
                strings = data.decode('utf-16-le').split('\x00')
                return [s for s in strings if s]
            except:
                return value_str
                
        return value_str
        
    async def _analyze_registry_entry(self, entry: ParsedEntry):
        """Analyze registry entry for suspicious content"""
        data = entry.parsed_data
        key_path = data.get('key_path', '')
        
        # Check for persistence mechanisms
        for persist_key, description in self.PERSISTENCE_KEYS.items():
            if persist_key.lower() in key_path.lower():
                # Check if it's a value being set
                if entry.event_type == "registry_value":
                    value_data = str(data.get('value_data', ''))
                    
                    # Create persistence alert
                    persist_entry = ParsedEntry(
                        timestamp=entry.timestamp,
                        source="registry",
                        event_type="security_alert",
                        severity="warning",
                        message=f"Persistence mechanism detected in {description}: {value_data[:100]}",
                        raw_data=entry.raw_data
                    )
                    persist_entry.tags = ["persistence", "autostart", description.replace(' ', '_').lower()]
                    persist_entry.parsed_data = {
                        'persistence_type': description,
                        'key_path': key_path,
                        'value_name': data.get('value_name', ''),
                        'value_data': value_data
                    }
                    
                    self.persistence_mechanisms.append(persist_entry)
                    
                    # Check for suspicious patterns in value
                    await self._check_suspicious_value(persist_entry, value_data)
                    
        # Check for suspicious patterns in any value
        if entry.event_type == "registry_value":
            value_data = str(data.get('value_data', ''))
            await self._check_suspicious_value(entry, value_data)
            
        # Check for CLSID hijacking
        if '{' in key_path and '}' in key_path:
            if 'InprocServer32' in key_path or 'LocalServer32' in key_path:
                entry.tags.append("clsid_hijack_risk")
                
        # Check for Image File Execution Options
        if 'Image File Execution Options' in key_path:
            if 'Debugger' in str(data.get('value_name', '')):
                alert = ParsedEntry(
                    timestamp=entry.timestamp,
                    source="registry",
                    event_type="security_alert",
                    severity="critical",
                    message=f"IFEO debugger hijack detected: {key_path}",
                    raw_data=entry.raw_data
                )
                alert.tags = ["ifeo_hijack", "persistence", "malware"]
                self.suspicious_entries.append(alert)
                
    async def _check_suspicious_value(self, entry: ParsedEntry, value_data: str):
        """Check registry value for suspicious patterns"""
        # Check each suspicious pattern
        for pattern_name, pattern in self.SUSPICIOUS_PATTERNS.items():
            if pattern.search(value_data):
                # Create suspicious entry
                suspicious = ParsedEntry(
                    timestamp=entry.timestamp,
                    source="registry",
                    event_type="security_alert",
                    severity="warning" if pattern_name != "encoded_command" else "critical",
                    message=f"Suspicious {pattern_name} detected in registry: {value_data[:100]}",
                    raw_data=entry.raw_data
                )
                suspicious.tags = ["suspicious", pattern_name, "potential_malware"]
                suspicious.parsed_data = entry.parsed_data.copy()
                suspicious.parsed_data['pattern_matched'] = pattern_name
                
                self.suspicious_entries.append(suspicious)
                
                # Add to IOCs if contains URLs or IPs
                if pattern_name == "http_download":
                    urls = re.findall(r'(https?://[^\s]+)', value_data)
                    for url in urls:
                        self.registry_iocs['urls'].add(url)
                        
    def _extract_registry_iocs(self, entry: ParsedEntry) -> IOCs:
        """Extract IOCs from registry entry"""
        iocs = IOCs()
        
        # Extract from value data
        if entry.event_type == "registry_value":
            value_data = str(entry.parsed_data.get('value_data', ''))
            
            # Extract file paths
            file_paths = re.findall(r'([A-Za-z]:\\[^\\/:*?"<>|\r\n]+(?:\\[^\\/:*?"<>|\r\n]+)*)', value_data)
            for path in file_paths:
                if any(path.lower().endswith(ext) for ext in ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs']):
                    iocs.file_paths.add(path)
                    
            # Extract URLs
            urls = re.findall(r'(https?://[^\s]+)', value_data)
            for url in urls:
                iocs.urls.add(url)
                # Extract domain
                domain_match = re.match(r'https?://([^/]+)', url)
                if domain_match:
                    iocs.domains.add(domain_match.group(1))
                    
            # Extract IPs
            ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', value_data)
            for ip in ips:
                iocs.ips.add(ip)
                
            # Extract hashes (MD5, SHA1, SHA256)
            hashes = re.findall(r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b', value_data)
            for hash_val in hashes:
                iocs.hashes.add(hash_val.lower())
                
        return iocs
        
    def _filetime_to_datetime(self, filetime: int) -> datetime:
        """Convert Windows FILETIME to datetime"""
        # Windows FILETIME is 100-nanosecond intervals since 1601-01-01
        if filetime == 0:
            return datetime.now()
            
        try:
            return datetime(1601, 1, 1) + timedelta(microseconds=filetime / 10)
        except:
            return datetime.now()
            
    def _get_value_type_name(self, type_code: int) -> str:
        """Get registry value type name"""
        types = {
            0: "REG_NONE",
            1: "REG_SZ",
            2: "REG_EXPAND_SZ",
            3: "REG_BINARY",
            4: "REG_DWORD",
            5: "REG_DWORD_BIG_ENDIAN",
            6: "REG_LINK",
            7: "REG_MULTI_SZ",
            8: "REG_RESOURCE_LIST",
            9: "REG_FULL_RESOURCE_DESCRIPTOR",
            10: "REG_RESOURCE_REQUIREMENTS_LIST",
            11: "REG_QWORD"
        }
        return types.get(type_code, f"Unknown ({type_code})")
        
    def _get_top_suspicious_keys(self, limit: int = 10) -> List[Dict]:
        """Get most suspicious registry keys"""
        key_scores = defaultdict(lambda: {'score': 0, 'reasons': []})
        
        for entry in self.suspicious_entries:
            key = entry.parsed_data.get('key_path', '')
            if key:
                key_scores[key]['score'] += 1
                key_scores[key]['reasons'].append(entry.parsed_data.get('pattern_matched', 'suspicious'))
                
        # Sort by score
        sorted_keys = sorted(key_scores.items(), key=lambda x: x[1]['score'], reverse=True)
        
        return [
            {
                'key': key,
                'suspicion_score': data['score'],
                'reasons': list(set(data['reasons']))
            }
            for key, data in sorted_keys[:limit]
        ]
        
    def _summarize_malware_indicators(self) -> Dict:
        """Summarize detected malware indicators"""
        summary = {
            'persistence_mechanisms': len(self.persistence_mechanisms),
            'suspicious_patterns': defaultdict(int),
            'risky_keys': []
        }
        
        # Count pattern matches
        for entry in self.suspicious_entries:
            pattern = entry.parsed_data.get('pattern_matched', 'unknown')
            summary['suspicious_patterns'][pattern] += 1
            
        # Identify high-risk keys
        for entry in self.persistence_mechanisms:
            if any(tag in entry.tags for tag in ['ifeo_hijack', 'clsid_hijack', 'encoded_command']):
                summary['risky_keys'].append({
                    'key': entry.parsed_data.get('key_path', ''),
                    'risk_type': entry.tags[0]
                })
                
        summary['suspicious_patterns'] = dict(summary['suspicious_patterns'])
        
        return summary