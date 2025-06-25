"""
Generic Text Parser
Parses plain text files and attempts to extract structured information
"""

import re
from typing import Optional, AsyncIterator, Dict, Any, List
from datetime import datetime
import asyncio

from parsers.base_parser import BaseParser, ParsedEntry

class TextParser(BaseParser):
    """Parser for generic text files"""
    
    @property
    def parser_name(self) -> str:
        return "text"
    
    @property
    def supported_extensions(self) -> list:
        return ['.txt', '.log', '.out', '.err', '.info', '']  # Empty for no extension
    
    def __init__(self, file_path, config=None):
        super().__init__(file_path, config)
        
        # Line patterns for common log formats
        self.line_patterns = [
            # ISO timestamp format
            {
                'name': 'iso_timestamp',
                'pattern': re.compile(
                    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+'
                    r'(?P<content>.*)$'
                ),
                'timestamp_group': 'timestamp'
            },
            # Syslog-like format
            {
                'name': 'syslog_like',
                'pattern': re.compile(
                    r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
                    r'(?P<host>\S+)?\s*'
                    r'(?P<content>.*)$'
                ),
                'timestamp_group': 'timestamp'
            },
            # Apache/Nginx access log
            {
                'name': 'access_log',
                'pattern': re.compile(
                    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+'
                    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
                    r'(?P<status>\d+)\s+(?P<size>\S+)'
                ),
                'timestamp_group': 'timestamp'
            },
            # Java stack trace
            {
                'name': 'java_exception',
                'pattern': re.compile(
                    r'^(?P<exception>[\w\.]+Exception(?::|$))\s*(?P<message>.*)?$'
                ),
                'timestamp_group': None
            },
            # Python traceback
            {
                'name': 'python_traceback',
                'pattern': re.compile(
                    r'^Traceback\s+\(most recent call last\):$'
                ),
                'timestamp_group': None
            }
        ]
        
        # Multi-line patterns
        self.multiline_patterns = {
            'java_stacktrace': {
                'start': re.compile(r'^[\w\.]+Exception(?::|$)'),
                'continuation': re.compile(r'^\s+at\s+[\w\.\$]+'),
                'max_lines': 50
            },
            'python_traceback': {
                'start': re.compile(r'^Traceback\s+\(most recent call last\):$'),
                'continuation': re.compile(r'^(?:\s+File\s+"|(?:\s+)?[\w\.]+Error:)'),
                'max_lines': 30
            }
        }
        
        # Security patterns
        self.security_patterns = {
            'auth_failure': re.compile(r'(authentication|login|access)\s+(failed|denied|rejected)', re.I),
            'permission_denied': re.compile(r'permission\s+denied|access\s+denied|unauthorized', re.I),
            'sql_injection': re.compile(r'(union\s+select|drop\s+table|exec\s*\(|script>|<script)', re.I),
            'path_traversal': re.compile(r'\.\.[\\/]|\.\.%2[fF]'),
            'command_injection': re.compile(r';\s*(ls|cat|rm|del|cmd|powershell)', re.I)
        }
        
        # State for multi-line processing
        self.current_multiline = None
        self.multiline_buffer = []
    
    async def _parse_content(self) -> AsyncIterator[Optional[ParsedEntry]]:
        """Parse text file content"""
        line_number = 0
        
        async for line in self.read_file_lines():
            line_number += 1
            
            # Handle multi-line entries
            if self.current_multiline:
                handled = await self._handle_multiline(line, line_number)
                if handled:
                    continue
            
            # Try to parse structured line
            entry = self._parse_line(line, line_number)
            
            if entry:
                yield entry
            else:
                # Check if this starts a multi-line entry
                if self._check_multiline_start(line):
                    self.current_multiline = self._get_multiline_type(line)
                    self.multiline_buffer = [line]
                else:
                    # Create generic entry
                    entry = self._create_generic_entry(line, line_number)
                    if entry:
                        yield entry
            
            # Yield control periodically
            if line_number % 100 == 0:
                await asyncio.sleep(0)
        
        # Handle any remaining multi-line buffer
        if self.multiline_buffer:
            entry = self._process_multiline_buffer(line_number)
            if entry:
                yield entry
    
    def _parse_line(self, line: str, line_number: int) -> Optional[ParsedEntry]:
        """Try to parse line with known patterns"""
        if not line.strip():
            return None
        
        # Try each pattern
        for pattern_info in self.line_patterns:
            match = pattern_info['pattern'].match(line)
            if match:
                return self._process_pattern_match(match, pattern_info, line, line_number)
        
        return None
    
    def _process_pattern_match(self, match, pattern_info: Dict, line: str, line_number: int) -> ParsedEntry:
        """Process a pattern match into ParsedEntry"""
        groups = match.groupdict()
        
        # Extract timestamp
        timestamp = None
        if pattern_info['timestamp_group'] and pattern_info['timestamp_group'] in groups:
            timestamp = self._parse_timestamp_flexible(groups[pattern_info['timestamp_group']])
        
        if not timestamp:
            timestamp = datetime.now().isoformat()
        
        # Build metadata based on pattern type
        metadata = {
            'line_number': line_number,
            'pattern_type': pattern_info['name']
        }
        
        # Pattern-specific processing
        if pattern_info['name'] == 'access_log':
            source = groups.get('ip', 'unknown')
            message = f"{groups.get('method', 'GET')} {groups.get('path', '/')} - {groups.get('status', '200')}"
            event_type = 'web_access'
            severity = 'high' if groups.get('status', '').startswith(('4', '5')) else 'info'
            
            metadata.update({
                'http_method': groups.get('method'),
                'http_path': groups.get('path'),
                'http_status': groups.get('status'),
                'response_size': groups.get('size')
            })
            
            # Add IP to IOCs
            if source != 'unknown':
                self.iocs['ips'].append(source)
                
        elif pattern_info['name'] == 'java_exception':
            source = 'application'
            message = f"{groups.get('exception', 'Exception')}: {groups.get('message', '')}"
            event_type = 'application_error'
            severity = 'high'
            
            metadata['exception_type'] = groups.get('exception')
            
        elif pattern_info['name'] == 'syslog_like':
            source = groups.get('host', 'unknown')
            message = groups.get('content', line)
            event_type = 'system_log'
            severity = self._determine_severity(message)
            
        else:
            source = 'text_file'
            message = groups.get('content', line)
            event_type = 'generic_log'
            severity = self._determine_severity(message)
        
        # Check for security patterns
        security_matches = self._check_security_patterns(line)
        if security_matches:
            severity = 'high'
            metadata['security_indicators'] = security_matches
        
        # Extract IOCs
        self._extract_iocs_from_line(line)
        
        return ParsedEntry(
            timestamp=timestamp,
            source=source,
            event_type=event_type,
            severity=severity,
            message=message,
            raw_data=line,
            metadata=metadata
        )
    
    def _create_generic_entry(self, line: str, line_number: int) -> Optional[ParsedEntry]:
        """Create generic entry for unstructured line"""
        if not line.strip():
            return None
        
        # Try to extract any timestamp
        timestamp = self._extract_any_timestamp(line)
        if not timestamp:
            timestamp = datetime.now().isoformat()
        
        # Check severity
        severity = self._determine_severity(line)
        
        # Check for security patterns
        security_matches = self._check_security_patterns(line)
        if security_matches:
            severity = 'high'
        
        # Determine event type
        event_type = self._guess_event_type(line)
        
        metadata = {
            'line_number': line_number,
            'unstructured': True
        }
        
        if security_matches:
            metadata['security_indicators'] = security_matches
        
        # Extract IOCs
        self._extract_iocs_from_line(line)
        
        return ParsedEntry(
            timestamp=timestamp,
            source='text_file',
            event_type=event_type,
            severity=severity,
            message=line[:200],  # Truncate long lines
            raw_data=line,
            metadata=metadata
        )
    
    async def _handle_multiline(self, line: str, line_number: int) -> bool:
        """Handle multi-line entries"""
        pattern_info = self.multiline_patterns[self.current_multiline]
        
        # Check if line continues the pattern
        if pattern_info['continuation'].match(line):
            self.multiline_buffer.append(line)
            
            # Check max lines
            if len(self.multiline_buffer) >= pattern_info['max_lines']:
                # Process buffer
                entry = self._process_multiline_buffer(line_number)
                if entry:
                    self._parsed_count += 1
                    # Note: We can't yield here, so we store it
                    # This is a limitation of the current design
                
                self.current_multiline = None
                self.multiline_buffer = []
            
            return True
        else:
            # End of multi-line, process buffer
            entry = self._process_multiline_buffer(line_number)
            if entry:
                self._parsed_count += 1
                # Note: Same limitation as above
            
            self.current_multiline = None
            self.multiline_buffer = []
            
            return False
    
    def _process_multiline_buffer(self, line_number: int) -> Optional[ParsedEntry]:
        """Process accumulated multi-line buffer"""
        if not self.multiline_buffer:
            return None
        
        full_text = '\n'.join(self.multiline_buffer)
        first_line = self.multiline_buffer[0]
        
        # Determine type
        if self.current_multiline == 'java_stacktrace':
            event_type = 'java_exception'
            severity = 'high'
            
            # Extract exception type
            match = re.match(r'^([\w\.]+Exception)', first_line)
            exception_type = match.group(1) if match else 'Exception'
            message = f"Java Exception: {exception_type}"
            
            metadata = {
                'exception_type': exception_type,
                'stack_trace_lines': len(self.multiline_buffer)
            }
            
        elif self.current_multiline == 'python_traceback':
            event_type = 'python_exception'
            severity = 'high'
            
            # Find error line
            error_line = None
            for line in reversed(self.multiline_buffer):
                if 'Error:' in line:
                    error_line = line
                    break
            
            message = error_line if error_line else "Python Traceback"
            
            metadata = {
                'traceback_lines': len(self.multiline_buffer)
            }
        else:
            event_type = 'multiline_log'
            severity = 'medium'
            message = f"Multi-line entry ({len(self.multiline_buffer)} lines)"
            metadata = {
                'lines': len(self.multiline_buffer)
            }
        
        return ParsedEntry(
            timestamp=datetime.now().isoformat(),
            source='text_file',
            event_type=event_type,
            severity=severity,
            message=message,
            raw_data=full_text,
            metadata=metadata
        )
    
    def _check_multiline_start(self, line: str) -> bool:
        """Check if line starts a multi-line pattern"""
        for pattern_type, pattern_info in self.multiline_patterns.items():
            if pattern_info['start'].match(line):
                return True
        return False
    
    def _get_multiline_type(self, line: str) -> Optional[str]:
        """Get the type of multi-line pattern"""
        for pattern_type, pattern_info in self.multiline_patterns.items():
            if pattern_info['start'].match(line):
                return pattern_type
        return None
    
    def _parse_timestamp_flexible(self, timestamp_str: str) -> Optional[str]:
        """Parse various timestamp formats flexibly"""
        # Common log timestamp formats
        formats = [
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%dT%H:%M:%S.%f',
            '%d/%b/%Y:%H:%M:%S',  # Apache format
            '%b %d %H:%M:%S',  # Syslog format
            '%Y/%m/%d %H:%M:%S'
        ]
        
        for fmt in formats:
            try:
                # For syslog format, add current year
                if fmt == '%b %d %H:%M:%S':
                    timestamp_str = f"{datetime.now().year} {timestamp_str}"
                    fmt = '%Y ' + fmt
                
                dt = datetime.strptime(timestamp_str.split('+')[0].split('.')[0], fmt)
                return dt.isoformat()
            except ValueError:
                continue
        
        return None
    
    def _extract_any_timestamp(self, line: str) -> Optional[str]:
        """Try to extract any timestamp from line"""
        # ISO format
        iso_pattern = r'\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}'
        match = re.search(iso_pattern, line)
        if match:
            return self._parse_timestamp_flexible(match.group())
        
        # Other common formats
        patterns = [
            r'\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}',
            r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}',
            r'\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                timestamp = self._parse_timestamp_flexible(match.group().strip('[]'))
                if timestamp:
                    return timestamp
        
        return None
    
    def _check_security_patterns(self, line: str) -> List[str]:
        """Check line for security patterns"""
        matches = []
        
        for pattern_name, pattern in self.security_patterns.items():
            if pattern.search(line):
                matches.append(pattern_name)
        
        return matches
    
    def _extract_iocs_from_line(self, line: str) -> None:
        """Extract IOCs from text line"""
        # IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, line)
        self.iocs['ips'].extend(ips)
        
        # URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, line)
        self.iocs['urls'].extend(urls)
        
        # Email addresses
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, line)
        self.iocs['emails'].extend(emails)
        
        # File paths
        path_patterns = [
            r'(?:[A-Za-z]:[\\\/]|[\\\/])[^\s:*?"<>|]+',  # Windows/Unix paths
            r'\.{0,2}[\\\/][\w\-\.]+(?:[\\\/][\w\-\.]+)*'  # Relative paths
        ]
        
        for pattern in path_patterns:
            paths = re.findall(pattern, line)
            self.iocs['files'].extend(paths)
    
    def _guess_event_type(self, line: str) -> str:
        """Guess event type from line content"""
        line_lower = line.lower()
        
        if any(word in line_lower for word in ['error', 'exception', 'failed', 'failure']):
            return 'error'
        elif any(word in line_lower for word in ['warning', 'warn']):
            return 'warning'
        elif any(word in line_lower for word in ['auth', 'login', 'logon', 'logoff']):
            return 'authentication'
        elif any(word in line_lower for word in ['connect', 'disconnect', 'network']):
            return 'network'
        elif any(word in line_lower for word in ['start', 'stop', 'restart', 'boot']):
            return 'system'
        else:
            return 'generic_log'
    
    async def _extract_file_metadata(self) -> None:
        """Extract text file metadata"""
        await super()._extract_file_metadata()
        
        self.metadata['file_format'] = 'text'
        self.metadata['parser_version'] = '1.0'
        
        # Try to detect encoding
        try:
            import chardet
            
            # Read sample for encoding detection
            sample_size = min(10000, self.metadata['file_size'])
            async with aiofiles.open(self.file_path, 'rb') as f:
                sample = await f.read(sample_size)
            
            detection = chardet.detect(sample)
            if detection:
                self.metadata['detected_encoding'] = detection['encoding']
                self.metadata['encoding_confidence'] = detection['confidence']
        except:
            pass