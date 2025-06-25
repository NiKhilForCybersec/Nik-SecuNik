"""
CSV Parser
Parses CSV files and extracts security-relevant information
"""

import csv
import re
from typing import Optional, AsyncIterator, Dict, Any, List
from datetime import datetime
import asyncio
import aiofiles
from io import StringIO

from parsers.base_parser import BaseParser, ParsedEntry

class CsvParser(BaseParser):
    """Parser for CSV files"""
    
    @property
    def parser_name(self) -> str:
        return "csv"
    
    @property
    def supported_extensions(self) -> list:
        return ['.csv', '.tsv', '.txt']
    
    def __init__(self, file_path, config=None):
        super().__init__(file_path, config)
        
        # Configuration
        self.delimiter = config.get('delimiter') if config else None
        self.has_header = config.get('has_header', True) if config else True
        
        # Column detection patterns
        self.column_patterns = {
            'timestamp': re.compile(r'(time|date|timestamp|datetime|created|modified)', re.I),
            'source': re.compile(r'(source|src|host|hostname|computer|device|origin)', re.I),
            'ip': re.compile(r'(ip|address|addr)(?:_|\.)?(?:v4|v6)?', re.I),
            'user': re.compile(r'(user|usr|account|login|username)', re.I),
            'message': re.compile(r'(message|msg|text|description|details|event)', re.I),
            'severity': re.compile(r'(severity|level|priority|type)', re.I),
            'action': re.compile(r'(action|operation|method|command)', re.I)
        }
        
        self.headers = []
        self.column_mapping = {}
    
    async def _parse_content(self) -> AsyncIterator[Optional[ParsedEntry]]:
        """Parse CSV file content"""
        # Auto-detect delimiter if not specified
        if not self.delimiter:
            self.delimiter = await self._detect_delimiter()
        
        # Read and parse CSV
        async for entry in self._parse_csv():
            yield entry
    
    async def _detect_delimiter(self) -> str:
        """Auto-detect CSV delimiter"""
        # Read sample of file
        sample_lines = []
        async for i, line in enumerate(self.read_file_lines()):
            sample_lines.append(line)
            if i >= 10:  # Sample first 10 lines
                break
        
        if not sample_lines:
            return ','
        
        # Try common delimiters
        delimiters = [',', '\t', '|', ';', ':']
        delimiter_scores = {}
        
        for delimiter in delimiters:
            scores = []
            for line in sample_lines:
                count = line.count(delimiter)
                if count > 0:
                    scores.append(count)
            
            if scores and len(set(scores)) == 1:  # Consistent count
                delimiter_scores[delimiter] = scores[0]
        
        if delimiter_scores:
            # Return delimiter with highest consistent count
            return max(delimiter_scores.items(), key=lambda x: x[1])[0]
        
        return ','  # Default to comma
    
    async def _parse_csv(self) -> AsyncIterator[Optional[ParsedEntry]]:
        """Parse CSV content"""
        first_row = True
        
        async for line_num, line in enumerate(self.read_file_lines()):
            if not line.strip():
                continue
            
            try:
                # Parse CSV line
                reader = csv.reader(StringIO(line), delimiter=self.delimiter)
                row = next(reader)
                
                if first_row and self.has_header:
                    # Process header row
                    self.headers = [col.strip() for col in row]
                    self._analyze_headers()
                    first_row = False
                    continue
                
                # Parse data row
                if not self.headers:
                    # No headers - use column indices
                    self.headers = [f'column_{i}' for i in range(len(row))]
                    self._analyze_headers()
                
                # Create dict from row
                row_dict = {}
                for i, value in enumerate(row):
                    if i < len(self.headers):
                        row_dict[self.headers[i]] = value.strip()
                
                # Parse into entry
                entry = self._parse_csv_row(row_dict, line_num)
                if entry:
                    yield entry
                else:
                    self._failed_count += 1
                    
            except csv.Error as e:
                self.warnings.append(f"CSV parse error on line {line_num}: {str(e)}")
                self._failed_count += 1
            except Exception as e:
                self.warnings.append(f"Error parsing line {line_num}: {str(e)}")
                self._failed_count += 1
            
            # Yield control periodically
            if line_num % 100 == 0:
                await asyncio.sleep(0)
    
    def _analyze_headers(self) -> None:
        """Analyze headers to identify column types"""
        self.column_mapping = {}
        
        for i, header in enumerate(self.headers):
            header_lower = header.lower()
            
            # Check against patterns
            for col_type, pattern in self.column_patterns.items():
                if pattern.search(header):
                    if col_type not in self.column_mapping:
                        self.column_mapping[col_type] = []
                    self.column_mapping[col_type].append(i)
        
        # Log column mapping
        self.metadata['column_mapping'] = {
            k: [self.headers[i] for i in v] 
            for k, v in self.column_mapping.items()
        }
    
    def _parse_csv_row(self, row_dict: Dict[str, str], line_num: int) -> Optional[ParsedEntry]:
        """Parse a single CSV row into ParsedEntry"""
        try:
            # Extract timestamp
            timestamp = self._extract_timestamp(row_dict)
            
            # Extract source
            source = self._extract_source(row_dict)
            
            # Extract message
            message = self._extract_message(row_dict)
            
            # Determine event type
            event_type = self._determine_event_type(row_dict)
            
            # Determine severity
            severity = self._extract_severity(row_dict)
            
            # Build metadata from all columns
            metadata = {
                'csv_line': line_num,
                'csv_columns': len(row_dict)
            }
            
            # Add all column values to metadata
            for header, value in row_dict.items():
                if value:  # Only non-empty values
                    # Sanitize header for metadata key
                    key = re.sub(r'[^a-zA-Z0-9_]', '_', header.lower())
                    metadata[f'csv_{key}'] = value
            
            # Extract IOCs from row
            self._extract_iocs_from_row(row_dict)
            
            # Extract additional security info
            security_info = self._extract_security_info(row_dict)
            if security_info:
                metadata.update(security_info)
            
            return ParsedEntry(
                timestamp=timestamp,
                source=source,
                event_type=event_type,
                severity=severity,
                message=message,
                raw_data=self.delimiter.join(row_dict.values()),
                metadata=metadata
            )
            
        except Exception as e:
            self.warnings.append(f"Failed to parse row {line_num}: {str(e)}")
            return None
    
    def _extract_timestamp(self, row_dict: Dict[str, str]) -> str:
        """Extract timestamp from row"""
        # Check mapped timestamp columns
        if 'timestamp' in self.column_mapping:
            for col_idx in self.column_mapping['timestamp']:
                if col_idx < len(self.headers):
                    value = row_dict.get(self.headers[col_idx], '')
                    if value:
                        normalized = self._normalize_timestamp(value)
                        if normalized:
                            return normalized
        
        # Check all columns for timestamp-like values
        for value in row_dict.values():
            if value and len(value) > 8:  # Minimum length for date
                normalized = self._normalize_timestamp(value)
                if normalized:
                    return normalized
        
        return datetime.now().isoformat()
    
    def _extract_source(self, row_dict: Dict[str, str]) -> str:
        """Extract source from row"""
        # Check mapped source columns
        if 'source' in self.column_mapping:
            for col_idx in self.column_mapping['source']:
                if col_idx < len(self.headers):
                    value = row_dict.get(self.headers[col_idx], '')
                    if value:
                        return value
        
        # Check IP columns
        if 'ip' in self.column_mapping:
            for col_idx in self.column_mapping['ip']:
                if col_idx < len(self.headers):
                    value = row_dict.get(self.headers[col_idx], '')
                    if value and self._is_valid_ip(value):
                        return value
        
        return 'csv_file'
    
    def _extract_message(self, row_dict: Dict[str, str]) -> str:
        """Extract or build message from row"""
        # Check mapped message columns
        if 'message' in self.column_mapping:
            messages = []
            for col_idx in self.column_mapping['message']:
                if col_idx < len(self.headers):
                    value = row_dict.get(self.headers[col_idx], '')
                    if value:
                        messages.append(value)
            
            if messages:
                return ' | '.join(messages)
        
        # Build message from key columns
        key_values = []
        priority_columns = ['action', 'user', 'ip']
        
        # First add priority columns
        for col_type in priority_columns:
            if col_type in self.column_mapping:
                for col_idx in self.column_mapping[col_type]:
                    if col_idx < len(self.headers):
                        header = self.headers[col_idx]
                        value = row_dict.get(header, '')
                        if value:
                            key_values.append(f"{header}={value}")
        
        # Add other non-empty columns (up to 5)
        for header, value in row_dict.items():
            if value and f"{header}=" not in ' '.join(key_values):
                key_values.append(f"{header}={value}")
                if len(key_values) >= 5:
                    break
        
        return ' | '.join(key_values) if key_values else 'CSV row'
    
    def _extract_severity(self, row_dict: Dict[str, str]) -> str:
        """Extract severity from row"""
        # Check mapped severity columns
        if 'severity' in self.column_mapping:
            for col_idx in self.column_mapping['severity']:
                if col_idx < len(self.headers):
                    value = row_dict.get(self.headers[col_idx], '').lower()
                    if value:
                        # Map common severity values
                        if value in ['critical', 'crit', 'fatal', 'emergency']:
                            return 'critical'
                        elif value in ['high', 'error', 'err', 'alert']:
                            return 'high'
                        elif value in ['medium', 'warning', 'warn']:
                            return 'medium'
                        elif value in ['low', 'info', 'information', 'notice']:
                            return 'info'
        
        # Analyze content for severity indicators
        row_text = ' '.join(row_dict.values()).lower()
        if any(term in row_text for term in ['fail', 'error', 'denied', 'invalid']):
            return 'high'
        elif any(term in row_text for term in ['warning', 'warn']):
            return 'medium'
        
        return 'info'
    
    def _determine_event_type(self, row_dict: Dict[str, str]) -> str:
        """Determine event type from row content"""
        # Check action columns
        if 'action' in self.column_mapping:
            for col_idx in self.column_mapping['action']:
                if col_idx < len(self.headers):
                    value = row_dict.get(self.headers[col_idx], '').lower()
                    if value:
                        if any(term in value for term in ['login', 'logon', 'auth']):
                            return 'authentication'
                        elif any(term in value for term in ['create', 'delete', 'modify']):
                            return 'data_modification'
                        elif any(term in value for term in ['connect', 'disconnect']):
                            return 'network'
        
        # Analyze all content
        row_text = ' '.join(row_dict.values()).lower()
        if any(term in row_text for term in ['login', 'password', 'credential']):
            return 'authentication'
        elif any(term in row_text for term in ['network', 'connection', 'port']):
            return 'network'
        elif any(term in row_text for term in ['file', 'directory', 'folder']):
            return 'file_operation'
        
        return 'generic_event'
    
    def _extract_security_info(self, row_dict: Dict[str, str]) -> Dict[str, Any]:
        """Extract security-relevant information"""
        security_info = {}
        
        # Extract user information
        if 'user' in self.column_mapping:
            users = []
            for col_idx in self.column_mapping['user']:
                if col_idx < len(self.headers):
                    value = row_dict.get(self.headers[col_idx], '')
                    if value and value not in users:
                        users.append(value)
            
            if users:
                security_info['users'] = users
        
        # Extract IP information
        if 'ip' in self.column_mapping:
            ips = []
            for col_idx in self.column_mapping['ip']:
                if col_idx < len(self.headers):
                    value = row_dict.get(self.headers[col_idx], '')
                    if value and self._is_valid_ip(value):
                        ips.append(value)
            
            if ips:
                security_info['ip_addresses'] = ips
        
        return security_info
    
    def _extract_iocs_from_row(self, row_dict: Dict[str, str]) -> None:
        """Extract IOCs from CSV row"""
        for value in row_dict.values():
            if not value or len(value) > 500:  # Skip empty or very long values
                continue
            
            # IP addresses
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            ips = re.findall(ip_pattern, value)
            self.iocs['ips'].extend(ips)
            
            # Domain names
            domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
            domains = re.findall(domain_pattern, value)
            self.iocs['domains'].extend(domains)
            
            # URLs
            url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
            urls = re.findall(url_pattern, value)
            self.iocs['urls'].extend(urls)
            
            # Email addresses
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            emails = re.findall(email_pattern, value)
            self.iocs['emails'].extend(emails)
            
            # File hashes
            md5_pattern = r'\b[a-fA-F0-9]{32}\b'
            sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
            sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
            
            hashes = re.findall(md5_pattern, value)
            hashes.extend(re.findall(sha1_pattern, value))
            hashes.extend(re.findall(sha256_pattern, value))
            self.iocs['hashes'].extend(hashes)
    
    def _is_valid_ip(self, value: str) -> bool:
        """Check if value is a valid IP address"""
        parts = value.split('.')
        if len(parts) != 4:
            return False
        
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
    
    def _normalize_timestamp(self, value: str) -> Optional[str]:
        """Normalize timestamp to ISO format"""
        if not value:
            return None
        
        # Common date/time formats
        formats = [
            '%Y-%m-%d %H:%M:%S',
            '%Y/%m/%d %H:%M:%S',
            '%d/%m/%Y %H:%M:%S',
            '%m/%d/%Y %H:%M:%S',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%d',
            '%d-%m-%Y',
            '%m-%d-%Y'
        ]
        
        # Try with and without microseconds
        for fmt in formats:
            try:
                dt = datetime.strptime(value.split('.')[0], fmt)
                return dt.isoformat()
            except ValueError:
                continue
            
            # Try with microseconds
            try:
                dt = datetime.strptime(value, fmt + '.%f')
                return dt.isoformat()
            except ValueError:
                continue
        
        # Try Unix timestamp
        try:
            if value.isdigit() and len(value) >= 10:
                dt = datetime.fromtimestamp(int(value[:10]))
                return dt.isoformat()
        except:
            pass
        
        return None
    
    async def _extract_file_metadata(self) -> None:
        """Extract CSV-specific metadata"""
        await super()._extract_file_metadata()
        
        self.metadata['file_format'] = 'csv'
        self.metadata['parser_version'] = '1.0'
        self.metadata['delimiter'] = self.delimiter
        self.metadata['has_header'] = self.has_header
        self.metadata['columns'] = len(self.headers)
        self.metadata['column_names'] = self.headers