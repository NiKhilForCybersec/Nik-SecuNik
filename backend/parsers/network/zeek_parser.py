"""
Zeek (formerly Bro) Network Security Monitor Log Parser
Supports multiple Zeek log types with correlation capabilities
"""

import re
import json
import gzip
from datetime import datetime
from typing import Dict, List, Any, Optional, Iterator, Tuple
from pathlib import Path
from ipaddress import ip_address
import base64

from parsers.base_parser import BaseParser
from backend.utils.time_utils import parse_timestamp, unix_to_datetime
from backend.utils.encoding_utils import detect_encoding


class ZeekParser(BaseParser):
    """Parser for Zeek network security monitoring logs"""
    
    # Zeek log types and their expected fields
    ZEEK_LOG_TYPES = {
        'conn': ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
                'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes', 'conn_state',
                'local_orig', 'local_resp', 'missed_bytes', 'history', 'orig_pkts',
                'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes', 'tunnel_parents'],
        'http': ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
                'trans_depth', 'method', 'host', 'uri', 'referrer', 'version',
                'user_agent', 'request_body_len', 'response_body_len', 'status_code',
                'status_msg', 'info_code', 'info_msg', 'tags', 'username', 'password',
                'proxied', 'orig_fuids', 'orig_filenames', 'orig_mime_types',
                'resp_fuids', 'resp_filenames', 'resp_mime_types'],
        'dns': ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
               'proto', 'trans_id', 'rtt', 'query', 'qclass', 'qclass_name',
               'qtype', 'qtype_name', 'rcode', 'rcode_name', 'AA', 'TC', 'RD',
               'RA', 'Z', 'answers', 'TTLs', 'rejected'],
        'ssl': ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
               'version', 'cipher', 'curve', 'server_name', 'resumed', 'last_alert',
               'next_protocol', 'established', 'cert_chain_fuids', 'client_cert_chain_fuids',
               'subject', 'issuer', 'client_subject', 'client_issuer', 'validation_status'],
        'files': ['ts', 'fuid', 'tx_hosts', 'rx_hosts', 'conn_uids', 'source',
                 'depth', 'analyzers', 'mime_type', 'filename', 'duration', 'local_orig',
                 'is_orig', 'seen_bytes', 'total_bytes', 'missing_bytes', 'overflow_bytes',
                 'timedout', 'parent_fuid', 'md5', 'sha1', 'sha256', 'extracted',
                 'extracted_cutoff', 'extracted_size'],
        'notice': ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
                  'fuid', 'file_mime_type', 'file_desc', 'proto', 'note', 'msg', 'sub',
                  'src', 'dst', 'p', 'n', 'peer_descr', 'actions', 'suppress_for',
                  'dropped', 'remote_location.country_code', 'remote_location.region',
                  'remote_location.city', 'remote_location.latitude',
                  'remote_location.longitude']
    }
    
    # Connection states
    CONN_STATES = {
        'S0': 'Connection attempt seen, no reply',
        'S1': 'Connection established, not terminated',
        'SF': 'Normal establishment and termination',
        'REJ': 'Connection attempt rejected',
        'S2': 'Connection established and close attempt by originator seen',
        'S3': 'Connection established and close attempt by responder seen',
        'RSTO': 'Connection established, originator aborted',
        'RSTR': 'Responder sent a RST',
        'RSTOS0': 'Originator sent a SYN then RST',
        'RSTRH': 'Responder sent a RST in response to SYN',
        'SH': 'Originator sent a SYN then FIN',
        'SHR': 'Responder sent a SYN ACK then FIN',
        'OTH': 'No SYN seen, just midstream traffic'
    }
    
    # Suspicious patterns
    SUSPICIOUS_PATTERNS = {
        'sql_injection': re.compile(r'(union|select|insert|update|delete|drop)[\s\+]+', re.I),
        'xss': re.compile(r'<script|javascript:|onerror=|onload=', re.I),
        'path_traversal': re.compile(r'\.\.\/|\.\.\\', re.I),
        'command_injection': re.compile(r';\s*(cat|ls|pwd|whoami|id|uname)', re.I),
        'base64_encoded': re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$'),
        'suspicious_port': re.compile(r'(4444|31337|12345|54321|1337|666|999)')
    }
    
    def __init__(self):
        super().__init__()
        self.file_path = None
        self.log_type = None
        self.field_names = []
        self.field_types = []
        self.encoding = 'utf-8'
        self.is_json = False
    
    def can_parse(self, file_path: str) -> bool:
        """Check if file is a Zeek log"""
        try:
            path = Path(file_path)
            
            # Check file name patterns
            zeek_patterns = ['conn.log', 'http.log', 'dns.log', 'ssl.log', 
                           'files.log', 'notice.log', 'weird.log', 'x509.log']
            
            if any(pattern in path.name for pattern in zeek_patterns):
                return True
            
            # Check if it's a gzipped Zeek log
            if path.suffix == '.gz':
                with gzip.open(file_path, 'rt', encoding='utf-8', errors='replace') as f:
                    header = f.read(1024)
            else:
                with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                    header = f.read(1024)
            
            # Check for Zeek header markers
            if '#separator' in header or '#fields' in header or '#types' in header:
                return True
            
            # Check for Zeek JSON format
            if header.strip().startswith('{') and '"ts"' in header:
                return True
            
            return False
            
        except Exception:
            return False
    
    def parse(self, file_path: str, progress_callback: Optional[callable] = None) -> Dict[str, Any]:
        """Parse Zeek log file"""
        self.file_path = Path(file_path)
        results = {
            'events': [],
            'metadata': {},
            'iocs': [],
            'statistics': {
                'total_events': 0,
                'log_type': None,
                'unique_connections': set(),
                'unique_hosts': set(),
                'protocols': {},
                'services': {},
                'status_codes': {},
                'query_types': {},
                'file_types': {},
                'notice_types': {},
                'suspicious_events': 0,
                'data_transferred': {'sent': 0, 'received': 0},
                'top_talkers': {},
                'top_destinations': {},
                'events_timeline': {}
            },
            'errors': [],
            'warnings': []
        }
        
        try:
            # Detect if file is gzipped
            if self.file_path.suffix == '.gz':
                open_func = gzip.open
                mode = 'rt'
            else:
                open_func = open
                mode = 'r'
            
            # Detect log format and type
            with open_func(file_path, mode, encoding='utf-8', errors='replace') as f:
                self._detect_format(f)
            
            results['statistics']['log_type'] = self.log_type
            
            # Get file size for progress
            file_size = self.file_path.stat().st_size
            bytes_processed = 0
            
            # Parse the log file
            with open_func(file_path, mode, encoding='utf-8', errors='replace') as f:
                # Skip header lines if TSV format
                if not self.is_json:
                    for line in f:
                        if not line.startswith('#'):
                            break
                        bytes_processed += len(line.encode('utf-8'))
                
                # Parse events
                for line_num, line in enumerate(f, 1):
                    try:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        
                        # Parse the line
                        event = self._parse_line(line, line_num)
                        if event:
                            results['events'].append(event)
                            self._update_statistics(event, results['statistics'])
                            
                            # Extract IOCs
                            iocs = self._extract_iocs(event)
                            results['iocs'].extend(iocs)
                        
                        # Update progress
                        bytes_processed += len(line.encode('utf-8'))
                        if progress_callback and line_num % 1000 == 0:
                            progress = (bytes_processed / file_size) * 100
                            progress_callback(progress, f"Processed {line_num:,} lines")
                    
                    except Exception as e:
                        if len(results['warnings']) < 100:
                            results['warnings'].append({
                                'line': line_num,
                                'error': str(e),
                                'content': line[:100]
                            })
            
            # Correlate events across log types
            if self.log_type:
                results = self._correlate_events(results)
            
            # Finalize statistics
            results['statistics'] = self._finalize_statistics(results['statistics'])
            
            # Generate metadata
            results['metadata'] = self._generate_metadata(results)
            
            return results
            
        except Exception as e:
            results['errors'].append(f"Fatal parsing error: {str(e)}")
            return results
    
    def _detect_format(self, file_handle):
        """Detect Zeek log format and type"""
        # Read header
        header_lines = []
        pos = file_handle.tell()
        
        for _ in range(10):
            line = file_handle.readline()
            if not line:
                break
            header_lines.append(line.strip())
        
        file_handle.seek(pos)
        
        # Check if JSON format
        if header_lines and header_lines[0].startswith('{'):
            self.is_json = True
            # Detect log type from JSON fields
            try:
                sample = json.loads(header_lines[0])
                self._detect_log_type_from_fields(list(sample.keys()))
            except:
                pass
            return
        
        # Parse TSV header
        for line in header_lines:
            if line.startswith('#separator'):
                # Usually \x09 (tab)
                pass
            elif line.startswith('#fields'):
                fields = line.split('\t')[1:]  # Skip #fields
                self.field_names = fields
                self._detect_log_type_from_fields(fields)
            elif line.startswith('#types'):
                types = line.split('\t')[1:]  # Skip #types
                self.field_types = types
    
    def _detect_log_type_from_fields(self, fields):
        """Detect log type from field names"""
        # Normalize field names
        normalized_fields = [f.replace('.', '_') for f in fields]
        
        # Check against known log types
        for log_type, expected_fields in self.ZEEK_LOG_TYPES.items():
            # Check if key fields match
            key_fields = expected_fields[:5]  # First few fields are usually enough
            if all(field in fields or field.replace('.', '_') in normalized_fields 
                  for field in key_fields):
                self.log_type = log_type
                return
        
        # Check filename for log type
        filename = self.file_path.name.lower()
        for log_type in self.ZEEK_LOG_TYPES:
            if log_type in filename:
                self.log_type = log_type
                return
    
    def _parse_line(self, line: str, line_num: int) -> Optional[Dict[str, Any]]:
        """Parse a single log line"""
        if self.is_json:
            return self._parse_json_line(line, line_num)
        else:
            return self._parse_tsv_line(line, line_num)
    
    def _parse_json_line(self, line: str, line_num: int) -> Optional[Dict[str, Any]]:
        """Parse JSON format Zeek log line"""
        try:
            data = json.loads(line)
            
            event = {
                'type': f'zeek_{self.log_type}' if self.log_type else 'zeek',
                'line_number': line_num,
                'raw': line
            }
            
            # Convert Zeek timestamp
            if 'ts' in data:
                event['timestamp'] = unix_to_datetime(float(data['ts']))
            
            # Map fields based on log type
            if self.log_type == 'conn':
                event.update(self._parse_conn_log(data))
            elif self.log_type == 'http':
                event.update(self._parse_http_log(data))
            elif self.log_type == 'dns':
                event.update(self._parse_dns_log(data))
            elif self.log_type == 'ssl':
                event.update(self._parse_ssl_log(data))
            elif self.log_type == 'files':
                event.update(self._parse_files_log(data))
            elif self.log_type == 'notice':
                event.update(self._parse_notice_log(data))
            else:
                # Generic parsing
                event.update(data)
            
            return event
            
        except Exception:
            return None
    
    def _parse_tsv_line(self, line: str, line_num: int) -> Optional[Dict[str, Any]]:
        """Parse TSV format Zeek log line"""
        fields = line.split('\t')
        
        if len(fields) != len(self.field_names):
            return None
        
        # Create event dict
        data = {}
        for i, field_name in enumerate(self.field_names):
            value = fields[i]
            
            # Handle Zeek null values
            if value == '-':
                continue
            
            # Convert types based on field type
            if i < len(self.field_types):
                field_type = self.field_types[i]
                if field_type == 'time':
                    try:
                        value = float(value)
                    except:
                        pass
                elif field_type == 'int' or field_type == 'count':
                    try:
                        value = int(value)
                    except:
                        pass
                elif field_type == 'double' or field_type == 'interval':
                    try:
                        value = float(value)
                    except:
                        pass
                elif field_type == 'bool':
                    value = value.upper() == 'T'
            
            data[field_name] = value
        
        return self._parse_json_line(json.dumps(data), line_num)
    
    def _parse_conn_log(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse connection log specific fields"""
        event = {
            'log_type': 'connection',
            'uid': data.get('uid', ''),
            'source_ip': data.get('id.orig_h', data.get('id_orig_h', '')),
            'source_port': data.get('id.orig_p', data.get('id_orig_p', 0)),
            'dest_ip': data.get('id.resp_h', data.get('id_resp_h', '')),
            'dest_port': data.get('id.resp_p', data.get('id_resp_p', 0)),
            'protocol': data.get('proto', ''),
            'service': data.get('service', ''),
            'duration': data.get('duration', 0),
            'orig_bytes': data.get('orig_bytes', 0),
            'resp_bytes': data.get('resp_bytes', 0),
            'conn_state': data.get('conn_state', ''),
            'conn_state_desc': self.CONN_STATES.get(data.get('conn_state', ''), ''),
            'orig_pkts': data.get('orig_pkts', 0),
            'resp_pkts': data.get('resp_pkts', 0),
            'history': data.get('history', '')
        }
        
        # Determine severity based on connection state
        if event['conn_state'] in ['REJ', 'RSTR', 'RSTOS0', 'RSTRH']:
            event['severity'] = 'warning'
        elif event['conn_state'] in ['S0', 'OTH']:
            event['severity'] = 'info'
        else:
            event['severity'] = 'info'
        
        # Check for suspicious ports
        if self._is_suspicious_port(event['source_port']) or self._is_suspicious_port(event['dest_port']):
            event['severity'] = 'warning'
            event['suspicious'] = ['suspicious_port']
        
        return event
    
    def _parse_http_log(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse HTTP log specific fields"""
        event = {
            'log_type': 'http',
            'uid': data.get('uid', ''),
            'source_ip': data.get('id.orig_h', data.get('id_orig_h', '')),
            'source_port': data.get('id.orig_p', data.get('id_orig_p', 0)),
            'dest_ip': data.get('id.resp_h', data.get('id_resp_h', '')),
            'dest_port': data.get('id.resp_p', data.get('id_resp_p', 0)),
            'method': data.get('method', ''),
            'host': data.get('host', ''),
            'uri': data.get('uri', ''),
            'referrer': data.get('referrer', ''),
            'user_agent': data.get('user_agent', ''),
            'status_code': data.get('status_code', 0),
            'request_body_len': data.get('request_body_len', 0),
            'response_body_len': data.get('response_body_len', 0),
            'username': data.get('username', ''),
            'password': data.get('password', '')
        }
        
        # Check for suspicious patterns
        suspicious = []
        
        # Check URI for attacks
        if event['uri']:
            for pattern_name, pattern in self.SUSPICIOUS_PATTERNS.items():
                if pattern.search(event['uri']):
                    suspicious.append(pattern_name)
        
        # Check for suspicious status codes
        if event['status_code'] >= 400:
            event['severity'] = 'warning'
        elif event['status_code'] >= 500:
            event['severity'] = 'error'
        else:
            event['severity'] = 'info'
        
        # Check for credential exposure
        if event['username'] or event['password']:
            event['severity'] = 'high'
            suspicious.append('credentials_exposed')
        
        if suspicious:
            event['suspicious'] = suspicious
            event['severity'] = 'high' if 'credentials_exposed' in suspicious else 'warning'
        
        return event
    
    def _parse_dns_log(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse DNS log specific fields"""
        event = {
            'log_type': 'dns',
            'uid': data.get('uid', ''),
            'source_ip': data.get('id.orig_h', data.get('id_orig_h', '')),
            'source_port': data.get('id.orig_p', data.get('id_orig_p', 0)),
            'dest_ip': data.get('id.resp_h', data.get('id_resp_h', '')),
            'dest_port': data.get('id.resp_p', data.get('id_resp_p', 0)),
            'query': data.get('query', ''),
            'qtype': data.get('qtype', ''),
            'qtype_name': data.get('qtype_name', ''),
            'rcode': data.get('rcode', ''),
            'rcode_name': data.get('rcode_name', ''),
            'answers': data.get('answers', []),
            'TTLs': data.get('TTLs', []),
            'rejected': data.get('rejected', False)
        }
        
        # Check for suspicious domains
        if event['query']:
            # Check for DGA-like domains
            if self._is_dga_domain(event['query']):
                event['suspicious'] = ['possible_dga']
                event['severity'] = 'warning'
            # Check for suspicious TLDs
            elif any(tld in event['query'].lower() for tld in ['.tk', '.ml', '.ga', '.cf']):
                event['suspicious'] = ['suspicious_tld']
                event['severity'] = 'warning'
            else:
                event['severity'] = 'info'
        
        # Check for failed queries
        if event['rcode_name'] and event['rcode_name'] != 'NOERROR':
            event['severity'] = 'warning'
        
        # Check for data exfiltration via DNS
        if event['qtype_name'] == 'TXT' and len(event['query']) > 100:
            event['suspicious'] = event.get('suspicious', []) + ['possible_dns_exfiltration']
            event['severity'] = 'high'
        
        return event
    
    def _parse_ssl_log(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse SSL/TLS log specific fields"""
        event = {
            'log_type': 'ssl',
            'uid': data.get('uid', ''),
            'source_ip': data.get('id.orig_h', data.get('id_orig_h', '')),
            'source_port': data.get('id.orig_p', data.get('id_orig_p', 0)),
            'dest_ip': data.get('id.resp_h', data.get('id_resp_h', '')),
            'dest_port': data.get('id.resp_p', data.get('id_resp_p', 0)),
            'version': data.get('version', ''),
            'cipher': data.get('cipher', ''),
            'server_name': data.get('server_name', ''),
            'subject': data.get('subject', ''),
            'issuer': data.get('issuer', ''),
            'validation_status': data.get('validation_status', ''),
            'resumed': data.get('resumed', False),
            'established': data.get('established', False)
        }
        
        # Check for weak SSL/TLS versions
        if event['version'] in ['SSLv2', 'SSLv3', 'TLSv10', 'TLSv11']:
            event['suspicious'] = ['weak_tls_version']
            event['severity'] = 'warning'
        else:
            event['severity'] = 'info'
        
        # Check for self-signed certificates
        if event['validation_status'] and 'self signed' in event['validation_status'].lower():
            event['suspicious'] = event.get('suspicious', []) + ['self_signed_cert']
            event['severity'] = 'warning'
        
        # Check for certificate validation failures
        if event['validation_status'] and event['validation_status'] != 'ok':
            event['suspicious'] = event.get('suspicious', []) + ['cert_validation_failed']
            event['severity'] = 'high'
        
        return event
    
    def _parse_files_log(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse files log specific fields"""
        event = {
            'log_type': 'file',
            'fuid': data.get('fuid', ''),
            'tx_hosts': data.get('tx_hosts', []),
            'rx_hosts': data.get('rx_hosts', []),
            'conn_uids': data.get('conn_uids', []),
            'source': data.get('source', ''),
            'mime_type': data.get('mime_type', ''),
            'filename': data.get('filename', ''),
            'md5': data.get('md5', ''),
            'sha1': data.get('sha1', ''),
            'sha256': data.get('sha256', ''),
            'total_bytes': data.get('total_bytes', 0),
            'seen_bytes': data.get('seen_bytes', 0),
            'missing_bytes': data.get('missing_bytes', 0),
            'extracted': data.get('extracted', False)
        }
        
        # Check for executable files
        exec_types = ['application/x-dosexec', 'application/x-executable', 
                     'application/x-mach-binary', 'application/x-elf']
        
        if event['mime_type'] in exec_types:
            event['suspicious'] = ['executable_file']
            event['severity'] = 'warning'
        else:
            event['severity'] = 'info'
        
        # Check for suspicious file extensions in filename
        if event['filename']:
            suspicious_exts = ['.exe', '.dll', '.scr', '.vbs', '.js', '.jar', 
                             '.bat', '.cmd', '.ps1', '.hta']
            if any(event['filename'].lower().endswith(ext) for ext in suspicious_exts):
                event['suspicious'] = event.get('suspicious', []) + ['suspicious_extension']
                event['severity'] = 'warning'
        
        # Large file transfers
        if event['total_bytes'] > 100 * 1024 * 1024:  # 100MB
            event['suspicious'] = event.get('suspicious', []) + ['large_file_transfer']
            event['severity'] = 'warning'
        
        return event
    
    def _parse_notice_log(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse notice log specific fields"""
        event = {
            'log_type': 'notice',
            'uid': data.get('uid', ''),
            'note': data.get('note', ''),
            'msg': data.get('msg', ''),
            'sub': data.get('sub', ''),
            'src': data.get('src', ''),
            'dst': data.get('dst', ''),
            'p': data.get('p', ''),
            'proto': data.get('proto', ''),
            'severity': 'high'  # Notices are typically important
        }
        
        # Extract IPs from src/dst fields
        if ':' in str(event['src']):
            parts = str(event['src']).split(':')
            event['source_ip'] = parts[0]
            event['source_port'] = int(parts[1]) if len(parts) > 1 else 0
        else:
            event['source_ip'] = event['src']
        
        if ':' in str(event['dst']):
            parts = str(event['dst']).split(':')
            event['dest_ip'] = parts[0]
            event['dest_port'] = int(parts[1]) if len(parts) > 1 else 0
        else:
            event['dest_ip'] = event['dst']
        
        return event
    
    def _is_suspicious_port(self, port: int) -> bool:
        """Check if port is commonly associated with malware"""
        suspicious_ports = [4444, 31337, 12345, 54321, 1337, 666, 999, 
                          8888, 9999, 6666, 6667, 6668, 6669]
        return port in suspicious_ports
    
    def _is_dga_domain(self, domain: str) -> bool:
        """Check if domain looks like DGA (Domain Generation Algorithm)"""
        if not domain:
            return False
        
        # Remove TLD
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        domain_part = parts[-2]  # Second level domain
        
        # Check length
        if len(domain_part) < 5 or len(domain_part) > 20:
            return False
        
        # Check for high consonant ratio
        vowels = sum(1 for c in domain_part.lower() if c in 'aeiou')
        consonants = len(domain_part) - vowels
        
        if vowels == 0 or consonants / vowels > 4:
            return True
        
        # Check for randomness (simplified entropy check)
        unique_chars = len(set(domain_part.lower()))
        if unique_chars / len(domain_part) > 0.8:
            return True
        
        return False
    
    def _correlate_events(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Correlate events across different log types using uid"""
        # Build uid index
        uid_events = {}
        for event in results['events']:
            uid = event.get('uid')
            if uid:
                if uid not in uid_events:
                    uid_events[uid] = []
                uid_events[uid].append(event)
        
        # Correlate events
        for uid, events in uid_events.items():
            if len(events) > 1:
                # Sort by timestamp
                events.sort(key=lambda x: x.get('timestamp', datetime.min))
                
                # Create correlation
                correlation = {
                    'uid': uid,
                    'event_count': len(events),
                    'log_types': list(set(e.get('log_type', '') for e in events)),
                    'duration': None,
                    'total_bytes': 0,
                    'has_threat': False
                }
                
                # Calculate duration
                timestamps = [e['timestamp'] for e in events if e.get('timestamp')]
                if len(timestamps) >= 2:
                    correlation['duration'] = (timestamps[-1] - timestamps[0]).total_seconds()
                
                # Sum bytes
                for e in events:
                    correlation['total_bytes'] += e.get('orig_bytes', 0) + e.get('resp_bytes', 0)
                    correlation['total_bytes'] += e.get('total_bytes', 0)
                    
                    # Check for threats
                    if e.get('severity') in ['high', 'critical'] or e.get('suspicious'):
                        correlation['has_threat'] = True
                
                # Add correlation info to events
                for e in events:
                    e['correlation'] = correlation
        
        return results
    
    def _extract_iocs(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract IOCs from Zeek event"""
        iocs = []
        
        # Extract IPs
        for ip_field in ['source_ip', 'dest_ip', 'src', 'dst']:
            ip = event.get(ip_field)
            if ip and ip not in ['127.0.0.1', '::1']:
                try:
                    ip_obj = ip_address(ip)
                    if not ip_obj.is_private:
                        iocs.append({
                            'type': 'ip',
                            'value': ip,
                            'context': f"Zeek {event.get('log_type', '')} log",
                            'confidence': 'high'
                        })
                except:
                    pass
        
        # Extract domains
        for domain_field in ['host', 'server_name', 'query']:
            domain = event.get(domain_field)
            if domain and domain != '-':
                # Check if suspicious
                confidence = 'medium'
                if event.get('suspicious'):
                    confidence = 'high'
                
                iocs.append({
                    'type': 'domain',
                    'value': domain,
                    'context': f"Zeek {event.get('log_type', '')} - {', '.join(event.get('suspicious', []))}",
                    'confidence': confidence
                })
        
        # Extract file hashes
        for hash_type in ['md5', 'sha1', 'sha256']:
            hash_value = event.get(hash_type)
            if hash_value and hash_value != '-':
                iocs.append({
                    'type': hash_type,
                    'value': hash_value,
                    'context': f"File: {event.get('filename', 'unknown')} ({event.get('mime_type', 'unknown')})",
                    'confidence': 'high'
                })
        
        # Extract URLs
        if event.get('uri') and event.get('host'):
            url = f"http://{event['host']}{event['uri']}"
            if event.get('suspicious'):
                iocs.append({
                    'type': 'url',
                    'value': url,
                    'context': f"Suspicious: {', '.join(event['suspicious'])}",
                    'confidence': 'high'
                })
        
        return iocs
    
    def _update_statistics(self, event: Dict[str, Any], stats: Dict[str, Any]):
        """Update statistics with event data"""
        stats['total_events'] += 1
        
        # Track unique connections
        uid = event.get('uid')
        if uid:
            stats['unique_connections'].add(uid)
        
        # Track hosts
        for ip_field in ['source_ip', 'dest_ip']:
            ip = event.get(ip_field)
            if ip:
                stats['unique_hosts'].add(ip)
                
                # Track top talkers
                if ip_field == 'source_ip':
                    stats['top_talkers'][ip] = stats['top_talkers'].get(ip, 0) + 1
                else:
                    stats['top_destinations'][ip] = stats['top_destinations'].get(ip, 0) + 1
        
        # Track by log type
        log_type = event.get('log_type')
        
        if log_type == 'connection':
            # Track protocols
            proto = event.get('protocol', 'unknown')
            stats['protocols'][proto] = stats['protocols'].get(proto, 0) + 1
            
            # Track services
            service = event.get('service', 'unknown')
            if service != '-':
                stats['services'][service] = stats['services'].get(service, 0) + 1
            
            # Track data transfer
            stats['data_transferred']['sent'] += event.get('orig_bytes', 0)
            stats['data_transferred']['received'] += event.get('resp_bytes', 0)
        
        elif log_type == 'http':
            # Track status codes
            status = event.get('status_code', 0)
            if status:
                stats['status_codes'][status] = stats['status_codes'].get(status, 0) + 1
        
        elif log_type == 'dns':
            # Track query types
            qtype = event.get('qtype_name', 'unknown')
            stats['query_types'][qtype] = stats['query_types'].get(qtype, 0) + 1
        
        elif log_type == 'file':
            # Track file types
            mime = event.get('mime_type', 'unknown')
            if mime != '-':
                stats['file_types'][mime] = stats['file_types'].get(mime, 0) + 1
        
        elif log_type == 'notice':
            # Track notice types
            note = event.get('note', 'unknown')
            stats['notice_types'][note] = stats['notice_types'].get(note, 0) + 1
        
        # Track suspicious events
        if event.get('suspicious') or event.get('severity') in ['high', 'critical']:
            stats['suspicious_events'] += 1
        
        # Track timeline
        if event.get('timestamp'):
            hour = event['timestamp'].strftime('%Y-%m-%d %H:00')
            stats['events_timeline'][hour] = stats['events_timeline'].get(hour, 0) + 1
    
    def _finalize_statistics(self, stats: Dict[str, Any]) -> Dict[str, Any]:
        """Finalize statistics"""
        # Convert sets to counts
        stats['unique_connections'] = len(stats['unique_connections'])
        stats['unique_hosts'] = len(stats['unique_hosts'])
        
        # Sort and limit top items
        stats['top_talkers'] = dict(sorted(stats['top_talkers'].items(), 
                                         key=lambda x: x[1], reverse=True)[:20])
        stats['top_destinations'] = dict(sorted(stats['top_destinations'].items(), 
                                              key=lambda x: x[1], reverse=True)[:20])
        
        # Calculate percentages
        if stats['total_events'] > 0:
            stats['suspicious_rate'] = (stats['suspicious_events'] / stats['total_events']) * 100
        
        # Format data transferred
        stats['data_transferred']['sent_formatted'] = self._format_bytes(stats['data_transferred']['sent'])
        stats['data_transferred']['received_formatted'] = self._format_bytes(stats['data_transferred']['received'])
        stats['data_transferred']['total_formatted'] = self._format_bytes(
            stats['data_transferred']['sent'] + stats['data_transferred']['received']
        )
        
        return stats
    
    def _generate_metadata(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate metadata"""
        stats = results['statistics']
        
        metadata = {
            'file_name': self.file_path.name,
            'file_size': self.file_path.stat().st_size,
            'log_type': self.log_type,
            'log_format': 'json' if self.is_json else 'tsv',
            'encoding': self.encoding,
            'total_events': len(results['events']),
            'date_range': self._get_date_range(results['events']),
            'parser': 'zeek_parser',
            'version': '1.0.0'
        }
        
        # Add summary
        metadata['summary'] = {
            'log_type': self.log_type,
            'total_events': stats['total_events'],
            'unique_connections': stats['unique_connections'],
            'unique_hosts': stats['unique_hosts'],
            'suspicious_events': stats['suspicious_events'],
            'suspicious_rate': f"{stats.get('suspicious_rate', 0):.2f}%",
            'data_transferred': stats['data_transferred']['total_formatted'],
            'top_protocol': max(stats['protocols'].items(), key=lambda x: x[1])[0] if stats['protocols'] else 'N/A'
        }
        
        return metadata
    
    def _get_date_range(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get date range from events"""
        timestamps = [e['timestamp'] for e in events if e.get('timestamp')]
        
        if not timestamps:
            return {'start': None, 'end': None}
        
        return {
            'start': min(timestamps).isoformat(),
            'end': max(timestamps).isoformat()
        }
    
    def _format_bytes(self, bytes_val: int) -> str:
        """Format bytes to human readable"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024.0:
                return f"{bytes_val:.2f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.2f} PB"