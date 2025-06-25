"""
JSON Parser
Parses JSON formatted files and extracts security-relevant information
"""

import json
import re
from typing import Optional, AsyncIterator, Dict, Any, List, Union
from datetime import datetime
import asyncio
import aiofiles

from parsers.base_parser import BaseParser, ParsedEntry

class JsonParser(BaseParser):
    """Parser for JSON files"""
    
    @property
    def parser_name(self) -> str:
        return "json"
    
    @property
    def supported_extensions(self) -> list:
        return ['.json', '.jsonl', '.ndjson']
    
    def __init__(self, file_path, config=None):
        super().__init__(file_path, config)
        
        # Common timestamp field names
        self.timestamp_fields = [
            'timestamp', 'time', 'datetime', 'date', 'created_at', 'updated_at',
            '@timestamp', 'eventTime', 'event_time', 'log_time', 'occurred_at'
        ]
        
        # Common source field names
        self.source_fields = [
            'source', 'src', 'host', 'hostname', 'computer', 'device',
            'source_ip', 'src_ip', 'client', 'origin', 'sender'
        ]
        
        # Common message field names
        self.message_fields = [
            'message', 'msg', 'text', 'description', 'details', 'content',
            'event', 'action', 'summary', 'log', 'data'
        ]
        
        # Security-relevant field patterns
        self.security_patterns = {
            'ip_fields': re.compile(r'(ip|address|addr|host)(?:_|\.)?(?:v4|v6)?', re.I),
            'user_fields': re.compile(r'(user|usr|account|login|username)', re.I),
            'error_fields': re.compile(r'(error|err|exception|fail|denied)', re.I),
            'auth_fields': re.compile(r'(auth|login|logon|signin|credential)', re.I)
        }
        
        # Common log formats
        self.log_formats = {
            'cloudtrail': self._is_cloudtrail_format,
            'elasticsearch': self._is_elasticsearch_format,
            'splunk': self._is_splunk_format,
            'generic': self._is_generic_log_format
        }
    
    async def _parse_content(self) -> AsyncIterator[Optional[ParsedEntry]]:
        """Parse JSON file content"""
        # Determine file format
        is_jsonl = self.file_path.suffix.lower() in ['.jsonl', '.ndjson']
        
        if is_jsonl:
            async for entry in self._parse_jsonl():
                yield entry
        else:
            async for entry in self._parse_json():
                yield entry
    
    async def _parse_json(self) -> AsyncIterator[Optional[ParsedEntry]]:
        """Parse standard JSON file"""
        try:
            content = await self._read_file_content()
            data = json.loads(content)
            
            # Determine JSON structure
            if isinstance(data, list):
                # Array of objects
                for item in data:
                    if isinstance(item, dict):
                        entry = self._parse_json_object(item)
                        if entry:
                            yield entry
                        else:
                            self._failed_count += 1
                    
                    # Yield control periodically
                    if self._total_count % 100 == 0:
                        await asyncio.sleep(0)
                        
            elif isinstance(data, dict):
                # Single object or nested structure
                # Check if it's a log format with records
                records = self._extract_records(data)
                if records:
                    for record in records:
                        entry = self._parse_json_object(record)
                        if entry:
                            yield entry
                        else:
                            self._failed_count += 1
                            
                        if self._total_count % 100 == 0:
                            await asyncio.sleep(0)
                else:
                    # Parse as single entry
                    entry = self._parse_json_object(data)
                    if entry:
                        yield entry
                    else:
                        self._failed_count += 1
                        
        except json.JSONDecodeError as e:
            self.errors.append(f"JSON decode error: {str(e)}")
        except Exception as e:
            self.errors.append(f"Parse error: {str(e)}")
    
    async def _parse_jsonl(self) -> AsyncIterator[Optional[ParsedEntry]]:
        """Parse JSON Lines format"""
        async for line in self.read_file_lines():
            if not line.strip():
                continue
                
            try:
                data = json.loads(line)
                if isinstance(data, dict):
                    entry = self._parse_json_object(data)
                    if entry:
                        yield entry
                    else:
                        self._failed_count += 1
                else:
                    self.warnings.append(f"Skipping non-object JSON line: {type(data)}")
                    self._failed_count += 1
                    
            except json.JSONDecodeError as e:
                self.warnings.append(f"Failed to parse JSON line: {str(e)}")
                self._failed_count += 1
                
            # Yield control periodically
            if self._total_count % 100 == 0:
                await asyncio.sleep(0)
    
    def _parse_json_object(self, obj: Dict[str, Any]) -> Optional[ParsedEntry]:
        """Parse a single JSON object into ParsedEntry"""
        try:
            # Detect format
            format_type = self._detect_format(obj)
            
            # Use format-specific parser if available
            if format_type == 'cloudtrail':
                return self._parse_cloudtrail_event(obj)
            elif format_type == 'elasticsearch':
                return self._parse_elasticsearch_doc(obj)
            elif format_type == 'splunk':
                return self._parse_splunk_event(obj)
            else:
                return self._parse_generic_json(obj)
                
        except Exception as e:
            self.warnings.append(f"Failed to parse JSON object: {str(e)}")
            return None
    
    def _detect_format(self, obj: Dict[str, Any]) -> str:
        """Detect the format of JSON object"""
        for format_name, check_func in self.log_formats.items():
            if check_func(obj):
                return format_name
        return 'generic'
    
    def _is_cloudtrail_format(self, obj: Dict[str, Any]) -> bool:
        """Check if object is AWS CloudTrail format"""
        return all(field in obj for field in ['eventTime', 'eventName', 'eventSource'])
    
    def _is_elasticsearch_format(self, obj: Dict[str, Any]) -> bool:
        """Check if object is Elasticsearch format"""
        return '_source' in obj or '@timestamp' in obj
    
    def _is_splunk_format(self, obj: Dict[str, Any]) -> bool:
        """Check if object is Splunk format"""
        return '_time' in obj and '_raw' in obj
    
    def _is_generic_log_format(self, obj: Dict[str, Any]) -> bool:
        """Check if object appears to be a log entry"""
        return any(field in obj for field in self.timestamp_fields + self.message_fields)
    
    def _parse_generic_json(self, obj: Dict[str, Any]) -> ParsedEntry:
        """Parse generic JSON object"""
        # Extract timestamp
        timestamp = None
        for field in self.timestamp_fields:
            if field in obj:
                timestamp = self._normalize_timestamp(obj[field])
                if timestamp:
                    break
        
        if not timestamp:
            timestamp = datetime.now().isoformat()
        
        # Extract source
        source = None
        for field in self.source_fields:
            if field in obj:
                source = str(obj[field])
                break
        
        if not source:
            source = 'json_file'
        
        # Extract message
        message = None
        for field in self.message_fields:
            if field in obj:
                message = str(obj[field])
                break
        
        if not message:
            # Build message from key fields
            message = self._build_message_from_object(obj)
        
        # Determine event type
        event_type = self._determine_event_type_from_object(obj)
        
        # Determine severity
        severity = self._determine_severity_from_object(obj)
        
        # Extract security-relevant fields
        metadata = self._extract_metadata(obj)
        
        # Extract IOCs from the entire object
        self._extract_iocs_from_object(obj)
        
        return ParsedEntry(
            timestamp=timestamp,
            source=source,
            event_type=event_type,
            severity=severity,
            message=message,
            raw_data=json.dumps(obj, separators=(',', ':')),
            metadata=metadata
        )
    
    def _parse_cloudtrail_event(self, obj: Dict[str, Any]) -> ParsedEntry:
        """Parse AWS CloudTrail event"""
        timestamp = self._normalize_timestamp(obj.get('eventTime'))
        source = obj.get('eventSource', 'aws')
        event_name = obj.get('eventName', 'Unknown')
        
        # Build message
        user_identity = obj.get('userIdentity', {})
        user = user_identity.get('userName') or user_identity.get('arn', 'Unknown')
        message = f"AWS {event_name} by {user}"
        
        # Determine severity
        severity = 'info'
        if obj.get('errorCode'):
            severity = 'high'
        elif event_name.lower().startswith(('create', 'delete', 'modify')):
            severity = 'medium'
        
        # Extract metadata
        metadata = {
            'aws_event_name': event_name,
            'aws_event_source': source,
            'aws_region': obj.get('awsRegion'),
            'aws_account': user_identity.get('accountId'),
            'user_agent': obj.get('userAgent'),
            'source_ip': obj.get('sourceIPAddress')
        }
        
        if obj.get('errorCode'):
            metadata['error_code'] = obj['errorCode']
            metadata['error_message'] = obj.get('errorMessage')
        
        # Add source IP to IOCs
        if metadata.get('source_ip'):
            self.iocs['ips'].append(metadata['source_ip'])
        
        return ParsedEntry(
            timestamp=timestamp,
            source=source,
            event_type='cloud_audit',
            severity=severity,
            message=message,
            raw_data=json.dumps(obj, separators=(',', ':')),
            metadata=metadata
        )
    
    def _parse_elasticsearch_doc(self, obj: Dict[str, Any]) -> ParsedEntry:
        """Parse Elasticsearch document"""
        # Extract source document
        source = obj.get('_source', obj)
        
        # Use generic parser on the source
        entry = self._parse_generic_json(source)
        
        # Add ES metadata
        if entry:
            entry.metadata.update({
                'es_index': obj.get('_index'),
                'es_type': obj.get('_type'),
                'es_id': obj.get('_id')
            })
        
        return entry
    
    def _parse_splunk_event(self, obj: Dict[str, Any]) -> ParsedEntry:
        """Parse Splunk event"""
        timestamp = self._normalize_timestamp(obj.get('_time'))
        source = obj.get('source', 'splunk')
        raw_message = obj.get('_raw', '')
        
        # Extract message from raw or use it directly
        message = raw_message[:200] if len(raw_message) > 200 else raw_message
        
        metadata = {
            'splunk_source': obj.get('source'),
            'splunk_sourcetype': obj.get('sourcetype'),
            'splunk_host': obj.get('host'),
            'splunk_index': obj.get('index')
        }
        
        # Add any additional fields
        for key, value in obj.items():
            if not key.startswith('_') and key not in metadata:
                metadata[key] = value
        
        return ParsedEntry(
            timestamp=timestamp,
            source=source,
            event_type='log_aggregation',
            severity=self._determine_severity(raw_message),
            message=message,
            raw_data=json.dumps(obj, separators=(',', ':')),
            metadata=metadata
        )
    
    def _normalize_timestamp(self, value: Any) -> Optional[str]:
        """Normalize various timestamp formats to ISO format"""
        if not value:
            return None
            
        if isinstance(value, str):
            # Already ISO format
            if 'T' in value and (value.endswith('Z') or '+' in value or value.count(':') >= 2):
                return value
            
            # Try parsing common formats
            formats = [
                '%Y-%m-%d %H:%M:%S',
                '%Y/%m/%d %H:%M:%S',
                '%d/%m/%Y %H:%M:%S',
                '%Y-%m-%dT%H:%M:%S',
                '%Y-%m-%dT%H:%M:%S.%f'
            ]
            
            for fmt in formats:
                try:
                    dt = datetime.strptime(value.split('.')[0], fmt)
                    return dt.isoformat()
                except:
                    continue
                    
        elif isinstance(value, (int, float)):
            # Unix timestamp
            try:
                dt = datetime.fromtimestamp(value)
                return dt.isoformat()
            except:
                pass
                
        return None
    
    def _build_message_from_object(self, obj: Dict[str, Any]) -> str:
        """Build a message from JSON object fields"""
        # Look for common message-like fields
        important_fields = []
        
        for key, value in obj.items():
            if isinstance(value, (str, int, float, bool)) and not key.startswith('_'):
                # Check if field seems important
                if any(pattern in key.lower() for pattern in ['event', 'action', 'method', 'status', 'result']):
                    important_fields.append(f"{key}={value}")
        
        if important_fields:
            return ' | '.join(important_fields[:5])  # Limit to 5 fields
        else:
            # Just show first few key-value pairs
            items = []
            for key, value in list(obj.items())[:3]:
                if isinstance(value, (str, int, float, bool)):
                    items.append(f"{key}={value}")
            return ' | '.join(items) if items else 'JSON object'
    
    def _determine_event_type_from_object(self, obj: Dict[str, Any]) -> str:
        """Determine event type from object content"""
        # Check for specific patterns
        obj_str = json.dumps(obj).lower()
        
        if any(term in obj_str for term in ['error', 'exception', 'fail']):
            return 'error'
        elif any(term in obj_str for term in ['auth', 'login', 'credential']):
            return 'authentication'
        elif any(term in obj_str for term in ['network', 'connection', 'socket']):
            return 'network'
        elif any(term in obj_str for term in ['file', 'directory', 'path']):
            return 'file_operation'
        elif any(term in obj_str for term in ['process', 'pid', 'command']):
            return 'process'
        else:
            return 'generic_event'
    
    def _determine_severity_from_object(self, obj: Dict[str, Any]) -> str:
        """Determine severity from object content"""
        obj_str = json.dumps(obj).lower()
        
        if any(term in obj_str for term in ['critical', 'fatal', 'emergency']):
            return 'critical'
        elif any(term in obj_str for term in ['error', 'fail', 'denied', 'unauthorized']):
            return 'high'
        elif any(term in obj_str for term in ['warning', 'warn']):
            return 'medium'
        else:
            return 'info'
    
    def _extract_metadata(self, obj: Dict[str, Any]) -> Dict[str, Any]:
        """Extract metadata from JSON object"""
        metadata = {}
        
        # Flatten nested structures (1 level deep)
        for key, value in obj.items():
            if isinstance(value, dict) and len(value) < 10:
                # Flatten small nested objects
                for nested_key, nested_value in value.items():
                    if isinstance(nested_value, (str, int, float, bool, list)):
                        metadata[f"{key}.{nested_key}"] = nested_value
            elif isinstance(value, (str, int, float, bool)):
                metadata[key] = value
            elif isinstance(value, list) and len(value) < 10:
                # Store small lists
                if all(isinstance(item, (str, int, float, bool)) for item in value):
                    metadata[key] = value
        
        return metadata
    
    def _extract_iocs_from_object(self, obj: Dict[str, Any], parent_key: str = '') -> None:
        """Recursively extract IOCs from JSON object"""
        if isinstance(obj, dict):
            for key, value in obj.items():
                full_key = f"{parent_key}.{key}" if parent_key else key
                
                # Check if key indicates IOC type
                if self.security_patterns['ip_fields'].search(key) and isinstance(value, str):
                    # Potential IP address
                    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                    ips = re.findall(ip_pattern, value)
                    self.iocs['ips'].extend(ips)
                
                # Recurse into nested structures
                self._extract_iocs_from_object(value, full_key)
                
        elif isinstance(obj, list):
            for item in obj:
                self._extract_iocs_from_object(item, parent_key)
                
        elif isinstance(obj, str) and len(obj) < 1000:  # Don't process huge strings
            # Extract various IOCs from string values
            # IPs
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            ips = re.findall(ip_pattern, obj)
            self.iocs['ips'].extend(ips)
            
            # URLs
            url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
            urls = re.findall(url_pattern, obj)
            self.iocs['urls'].extend(urls)
            
            # Emails
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            emails = re.findall(email_pattern, obj)
            self.iocs['emails'].extend(emails)
    
    def _extract_records(self, data: Dict[str, Any]) -> Optional[List[Dict]]:
        """Extract records from various JSON structures"""
        # Common patterns for record arrays
        record_fields = ['records', 'events', 'logs', 'data', 'items', 'entries', 'results']
        
        for field in record_fields:
            if field in data and isinstance(data[field], list):
                return data[field]
        
        # Check if it's a wrapped structure
        if len(data) == 1:
            key = list(data.keys())[0]
            if isinstance(data[key], list):
                return data[key]
        
        return None
    
    async def _read_file_content(self) -> str:
        """Read entire file content"""
        async with aiofiles.open(self.file_path, 'r', encoding='utf-8', errors='replace') as f:
            return await f.read()
    
    async def _extract_file_metadata(self) -> None:
        """Extract JSON-specific metadata"""
        await super()._extract_file_metadata()
        
        self.metadata['file_format'] = 'json'
        self.metadata['parser_version'] = '1.0'
        
        # Try to determine JSON structure
        try:
            content = await self._read_file_content()
            if content.strip().startswith('['):
                self.metadata['json_structure'] = 'array'
            elif content.strip().startswith('{'):
                self.metadata['json_structure'] = 'object'
            
            # Check if it's JSON Lines
            if self.file_path.suffix.lower() in ['.jsonl', '.ndjson']:
                self.metadata['json_format'] = 'jsonl'
            else:
                self.metadata['json_format'] = 'standard'
                
        except:
            pass