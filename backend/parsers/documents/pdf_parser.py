"""
PDF Parser for SecuNik LogX
Parses PDF files with security analysis
Detects malicious PDFs, embedded scripts, and exploits
"""

import struct
import asyncio
from datetime import datetime
from typing import Dict, Any, List, Optional, Set, AsyncGenerator, Tuple
from pathlib import Path
from collections import defaultdict
import re
import zlib
import base64
import hashlib
import json

from ..base_parser import BaseParser, ParseResult, ParsedEntry, FileMetadata, IOCs


class PDFParser(BaseParser):
    """Parser for PDF documents with security analysis"""
    
    name = "pdf"
    description = "Parses PDF files for security threats"
    supported_extensions = ['.pdf']
    
    # PDF signatures
    PDF_HEADER = b'%PDF-'
    PDF_EOF = b'%%EOF'
    
    # Suspicious PDF elements
    SUSPICIOUS_NAMES = [
        '/JavaScript', '/JS', '/Launch', '/EmbeddedFile', '/XFA',
        '/OpenAction', '/AA', '/Names', '/AcroForm', '/JBIG2Decode',
        '/RichMedia', '/Flash', '/U3D', '/PRC', '/Sound', '/Movie'
    ]
    
    # Exploit indicators
    EXPLOIT_PATTERNS = {
        'javascript': [
            rb'eval\s*\(',
            rb'unescape\s*\(',
            rb'String\.fromCharCode',
            rb'document\.write',
            rb'app\.alert',
            rb'this\.exportDataObject',
            rb'util\.printf',
            rb'Collab\.collectEmailInfo'
        ],
        'shellcode': [
            rb'\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}',
            rb'%u[0-9a-fA-F]{4}%u[0-9a-fA-F]{4}',
            rb'\x90{10,}',  # NOP sled
            rb'\\x41{100,}',  # Heap spray pattern
        ],
        'suspicious_api': [
            rb'getAnnots',
            rb'spell\.customDictionaryOpen',
            rb'media\.newPlayer',
            rb'doc\.printSeps',
            rb'getURL\s*\(',
            rb'submitForm\s*\('
        ]
    }
    
    # Known malicious patterns
    MALWARE_SIGNATURES = {
        'cve_2010_0188': rb'\/Colors\s*(\d+)\s*\/BitsPerComponent\s*(\d+)\s*\/Columns\s*(\d+)',
        'cve_2013_2729': rb'\/JBIG2Decode',
        'embedded_exe': rb'MZ\x90\x00\x03',
        'embedded_flash': rb'(FWS|CWS|ZWS)',
        'heap_spray': rb'(%u0c0c%u0c0c|\\x0c\\x0c\\x0c\\x0c){10,}'
    }
    
    # Stream filters that can hide malicious content
    RISKY_FILTERS = [
        '/ASCIIHexDecode', '/ASCII85Decode', '/LZWDecode',
        '/FlateDecode', '/RunLengthDecode', '/CCITTFaxDecode',
        '/JBIG2Decode', '/DCTDecode', '/JPXDecode', '/Crypt'
    ]
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.objects = {}
        self.streams = []
        self.scripts = []
        self.embedded_files = []
        self.suspicious_elements = []
        self.threat_level = 0
        
    async def parse(self) -> ParseResult:
        """Parse PDF file for security analysis"""
        result = ParseResult(
            file_path=str(self.file_path),
            file_type="pdf",
            parser_name=self.name
        )
        
        try:
            # Get file metadata
            result.metadata = await self._get_file_metadata()
            
            # Verify PDF structure
            is_valid = await self._verify_pdf_structure()
            if not is_valid:
                result.errors.append("Invalid PDF structure")
                result.metadata.additional["corrupted"] = True
                
            # Parse PDF structure
            await self._parse_pdf_structure()
            
            # Create main PDF entry
            pdf_entry = self._create_pdf_entry()
            result.entries.append(pdf_entry)
            
            # Analyze objects
            object_entries = await self._analyze_objects()
            result.entries.extend(object_entries)
            
            # Extract and analyze streams
            stream_entries = await self._analyze_streams()
            result.entries.extend(stream_entries)
            
            # Check for exploits
            exploit_entries = await self._check_exploits()
            result.entries.extend(exploit_entries)
            
            # Extract IOCs
            for entry in result.entries:
                result.iocs.merge(self._extract_pdf_iocs(entry))
                
            # Add suspicious findings
            for finding in self.suspicious_elements[:50]:  # Limit findings
                result.entries.append(finding)
                
            # Calculate threat assessment
            threat_assessment = self._calculate_threat_level()
            
            # Add summary
            result.metadata.additional.update({
                "pdf_version": self._get_pdf_version(),
                "object_count": len(self.objects),
                "stream_count": len(self.streams),
                "javascript_count": len(self.scripts),
                "embedded_files": len(self.embedded_files),
                "suspicious_elements": len(self.suspicious_elements),
                "threat_level": self.threat_level,
                "threat_assessment": threat_assessment,
                "detected_exploits": self._get_detected_exploits(),
                "risky_features": self._get_risky_features()
            })
            
            self.logger.info(f"Parsed PDF with threat level: {self.threat_level}")
            
        except Exception as e:
            self.logger.error(f"Error parsing PDF: {e}")
            result.errors.append(f"Parse error: {str(e)}")
            
        return result
        
    async def _verify_pdf_structure(self) -> bool:
        """Verify basic PDF structure"""
        async with self._open_file('rb') as f:
            # Check header
            header = await f.read(8)
            if not header.startswith(self.PDF_HEADER):
                return False
                
            # Check for EOF marker
            await f.seek(-1024, 2)  # Seek to end
            tail = await f.read()
            
            return self.PDF_EOF in tail
            
    async def _parse_pdf_structure(self):
        """Parse PDF object structure"""
        async with self._open_file('rb') as f:
            content = await f.read()
            
        # Find all objects
        obj_pattern = rb'(\d+)\s+(\d+)\s+obj\s*\n(.*?)\nendobj'
        
        for match in re.finditer(obj_pattern, content, re.DOTALL):
            obj_num = int(match.group(1))
            obj_gen = int(match.group(2))
            obj_content = match.group(3)
            
            self.objects[(obj_num, obj_gen)] = {
                'content': obj_content,
                'offset': match.start(),
                'analyzed': False
            }
            
            # Quick check for suspicious content
            for suspicious in self.SUSPICIOUS_NAMES:
                if suspicious.encode() in obj_content:
                    self.threat_level += 10
                    
        # Find xref table
        xref_match = re.search(rb'xref\s*\n(.*?)trailer', content, re.DOTALL)
        if xref_match:
            self._parse_xref(xref_match.group(1))
            
        # Find trailer
        trailer_match = re.search(rb'trailer\s*\n(.*?)>>>', content, re.DOTALL)
        if trailer_match:
            self._parse_trailer(trailer_match.group(1))
            
    def _parse_xref(self, xref_data: bytes):
        """Parse cross-reference table"""
        # Basic xref parsing
        lines = xref_data.decode('latin-1', errors='ignore').strip().split('\n')
        
        for line in lines:
            parts = line.split()
            if len(parts) == 3 and parts[2] in ['n', 'f']:
                # Valid xref entry
                pass
                
    def _parse_trailer(self, trailer_data: bytes):
        """Parse PDF trailer"""
        # Extract important trailer information
        if b'/Encrypt' in trailer_data:
            self.threat_level += 15
            self.suspicious_elements.append(
                self._create_suspicious_finding(
                    "PDF Encryption",
                    "Document is encrypted - may hide malicious content",
                    "warning"
                )
            )
            
    def _create_pdf_entry(self) -> ParsedEntry:
        """Create main PDF document entry"""
        entry = ParsedEntry(
            timestamp=datetime.now(),
            source="pdf",
            event_type="document",
            severity="info",
            message=f"PDF Document: {self.file_path.name}",
            raw_data={
                'filename': self.file_path.name,
                'size': self.file_path.stat().st_size,
                'objects': len(self.objects)
            }
        )
        
        entry.parsed_data = {
            'version': self._get_pdf_version(),
            'object_count': len(self.objects),
            'has_javascript': len(self.scripts) > 0,
            'has_embedded_files': len(self.embedded_files) > 0,
            'encrypted': any('/Encrypt' in str(obj['content']) for obj in self.objects.values())
        }
        
        return entry
        
    async def _analyze_objects(self) -> List[ParsedEntry]:
        """Analyze PDF objects for suspicious content"""
        entries = []
        
        for (obj_num, obj_gen), obj_data in self.objects.items():
            if obj_data['analyzed']:
                continue
                
            content = obj_data['content']
            
            # Check for JavaScript
            if b'/JavaScript' in content or b'/JS' in content:
                js_entry = await self._extract_javascript(obj_num, content)
                if js_entry:
                    entries.append(js_entry)
                    self.scripts.append(js_entry)
                    
            # Check for embedded files
            if b'/EmbeddedFile' in content:
                file_entry = await self._extract_embedded_file(obj_num, content)
                if file_entry:
                    entries.append(file_entry)
                    self.embedded_files.append(file_entry)
                    
            # Check for launch actions
            if b'/Launch' in content:
                self.threat_level += 30
                launch_entry = self._create_suspicious_finding(
                    "Launch Action Detected",
                    f"Object {obj_num} contains /Launch action - can execute external programs",
                    "critical"
                )
                self.suspicious_elements.append(launch_entry)
                
            # Check for forms
            if b'/AcroForm' in content:
                self.threat_level += 20
                form_entry = self._create_suspicious_finding(
                    "Interactive Form Detected",
                    f"Object {obj_num} contains AcroForm - can be used for data harvesting",
                    "warning"
                )
                self.suspicious_elements.append(form_entry)
                
            # Extract streams
            stream_match = re.search(rb'stream\s*\n(.*?)\nendstream', content, re.DOTALL)
            if stream_match:
                stream_data = stream_match.group(1)
                self.streams.append({
                    'object': (obj_num, obj_gen),
                    'data': stream_data,
                    'filters': self._get_stream_filters(content)
                })
                
            obj_data['analyzed'] = True
            
        return entries
        
    async def _extract_javascript(self, obj_num: int, content: bytes) -> Optional[ParsedEntry]:
        """Extract and analyze JavaScript from object"""
        # Try to extract JavaScript content
        js_content = b''
        
        # Look for direct JavaScript
        js_match = re.search(rb'/JS\s*\((.*?)\)', content, re.DOTALL)
        if js_match:
            js_content = js_match.group(1)
        else:
            # Look for JavaScript in stream
            js_match = re.search(rb'/JS\s*<<.*?>>stream\s*\n(.*?)\nendstream', content, re.DOTALL)
            if js_match:
                js_content = js_match.group(1)
                
        if not js_content:
            return None
            
        # Decode JavaScript
        try:
            js_text = js_content.decode('utf-8', errors='ignore')
            
            # Unescape if needed
            js_text = js_text.replace('\\r', '\r').replace('\\n', '\n')
            js_text = js_text.replace('\\(', '(').replace('\\)', ')')
            
        except:
            js_text = str(js_content)
            
        self.threat_level += 40
        
        entry = ParsedEntry(
            timestamp=datetime.now(),
            source=f"pdf_object_{obj_num}",
            event_type="security_alert",
            severity="critical",
            message=f"JavaScript detected in object {obj_num}",
            raw_data={
                'object_num': obj_num,
                'script_preview': js_text[:500],
                'script_length': len(js_text)
            }
        )
        
        entry.parsed_data = {
            'script_type': 'javascript',
            'obfuscated': self._is_obfuscated(js_text),
            'suspicious_calls': self._find_suspicious_js_calls(js_text)
        }
        
        entry.tags = ["javascript", "pdf_script", "high_risk"]
        
        # Check for known exploits
        if self._check_js_exploits(js_text):
            entry.severity = "critical"
            entry.tags.append("known_exploit")
            self.threat_level += 50
            
        return entry
        
    async def _extract_embedded_file(self, obj_num: int, content: bytes) -> Optional[ParsedEntry]:
        """Extract embedded file information"""
        self.threat_level += 25
        
        # Try to get filename
        filename = "unknown"
        name_match = re.search(rb'/F\s*\((.*?)\)', content)
        if name_match:
            filename = name_match.group(1).decode('utf-8', errors='ignore')
            
        entry = ParsedEntry(
            timestamp=datetime.now(),
            source=f"pdf_object_{obj_num}",
            event_type="security_alert",
            severity="warning",
            message=f"Embedded file detected: {filename}",
            raw_data={
                'object_num': obj_num,
                'filename': filename
            }
        )
        
        entry.parsed_data = {
            'file_type': 'embedded',
            'filename': filename
        }
        
        entry.tags = ["embedded_file", "pdf_attachment"]
        
        # Check for executable extensions
        if any(filename.lower().endswith(ext) for ext in ['.exe', '.scr', '.bat', '.cmd', '.ps1']):
            entry.severity = "critical"
            entry.tags.append("executable_embedded")
            self.threat_level += 40
            
        return entry
        
    async def _analyze_streams(self) -> List[ParsedEntry]:
        """Analyze PDF streams for malicious content"""
        entries = []
        
        for stream in self.streams[:20]:  # Limit analysis
            # Decode stream if needed
            decoded = await self._decode_stream(stream['data'], stream['filters'])
            
            if not decoded:
                continue
                
            # Check for exploits in stream
            for exploit_type, patterns in self.EXPLOIT_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, decoded):
                        exploit_entry = self._create_suspicious_finding(
                            f"{exploit_type.upper()} Pattern Detected",
                            f"Suspicious {exploit_type} pattern found in stream",
                            "critical"
                        )
                        exploit_entry.tags = ["exploit_pattern", exploit_type]
                        entries.append(exploit_entry)
                        self.threat_level += 35
                        break
                        
            # Check for embedded executables
            if decoded.startswith(b'MZ'):
                exe_entry = self._create_suspicious_finding(
                    "Embedded Executable",
                    "Windows executable (PE) found in PDF stream",
                    "critical"
                )
                exe_entry.tags = ["embedded_exe", "malware"]
                entries.append(exe_entry)
                self.threat_level += 60
                
        return entries
        
    async def _decode_stream(self, stream_data: bytes, filters: List[str]) -> Optional[bytes]:
        """Decode PDF stream based on filters"""
        decoded = stream_data
        
        for filter_name in filters:
            try:
                if filter_name == '/FlateDecode':
                    decoded = zlib.decompress(decoded)
                elif filter_name == '/ASCIIHexDecode':
                    decoded = bytes.fromhex(decoded.decode('ascii').replace(' ', '').replace('\n', ''))
                elif filter_name == '/ASCII85Decode':
                    # Simplified ASCII85 decode
                    decoded = base64.a85decode(decoded)
                # Add more filters as needed
            except Exception as e:
                self.logger.debug(f"Failed to decode stream with {filter_name}: {e}")
                return None
                
        return decoded
        
    def _get_stream_filters(self, obj_content: bytes) -> List[str]:
        """Extract stream filters from object"""
        filters = []
        
        filter_match = re.search(rb'/Filter\s*\[(.*?)\]', obj_content)
        if filter_match:
            # Array of filters
            filter_str = filter_match.group(1).decode('latin-1', errors='ignore')
            filters = [f.strip() for f in filter_str.split('/') if f.strip()]
        else:
            # Single filter
            filter_match = re.search(rb'/Filter\s*(/\w+)', obj_content)
            if filter_match:
                filters = [filter_match.group(1).decode('latin-1')]
                
        return filters
        
    async def _check_exploits(self) -> List[ParsedEntry]:
        """Check for known PDF exploits"""
        entries = []
        
        # Read file content for signature matching
        async with self._open_file('rb') as f:
            content = await f.read(1024 * 1024)  # Read first 1MB
            
        for exploit_name, signature in self.MALWARE_SIGNATURES.items():
            if re.search(signature, content):
                exploit_entry = ParsedEntry(
                    timestamp=datetime.now(),
                    source="pdf_exploit_scanner",
                    event_type="security_alert",
                    severity="critical",
                    message=f"Known exploit signature detected: {exploit_name}",
                    raw_data={'exploit': exploit_name}
                )
                exploit_entry.tags = ["known_exploit", exploit_name, "malware"]
                entries.append(exploit_entry)
                self.threat_level += 80
                
        return entries
        
    def _extract_pdf_iocs(self, entry: ParsedEntry) -> IOCs:
        """Extract IOCs from PDF content"""
        iocs = IOCs()
        
        # Extract from raw data
        raw_str = json.dumps(entry.raw_data)
        
        # Extract URLs
        urls = re.findall(r'https?://[^\s\)]+', raw_str)
        for url in urls:
            iocs.urls.add(url)
            # Extract domain
            domain_match = re.match(r'https?://([^/]+)', url)
            if domain_match:
                iocs.domains.add(domain_match.group(1))
                
        # Extract IPs
        ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', raw_str)
        for ip in ips:
            iocs.ips.add(ip)
            
        # Extract file paths from JavaScript
        if 'script_preview' in entry.raw_data:
            script = entry.raw_data['script_preview']
            # Windows paths
            paths = re.findall(r'[A-Za-z]:\\[^"\']+', script)
            for path in paths:
                iocs.file_paths.add(path)
                
        return iocs
        
    def _create_suspicious_finding(self, title: str, description: str, 
                                  severity: str) -> ParsedEntry:
        """Create a suspicious finding entry"""
        return ParsedEntry(
            timestamp=datetime.now(),
            source="pdf_analyzer",
            event_type="security_alert",
            severity=severity,
            message=title,
            raw_data={'description': description}
        )
        
    def _get_pdf_version(self) -> str:
        """Extract PDF version from header"""
        try:
            with open(self.file_path, 'rb') as f:
                header = f.read(20).decode('latin-1', errors='ignore')
                version_match = re.search(r'%PDF-(\d\.\d)', header)
                if version_match:
                    return version_match.group(1)
        except:
            pass
        return "Unknown"
        
    def _is_obfuscated(self, js_text: str) -> bool:
        """Check if JavaScript appears obfuscated"""
        # Check for common obfuscation patterns
        obfuscation_indicators = [
            len(re.findall(r'\\x[0-9a-fA-F]{2}', js_text)) > 50,
            len(re.findall(r'String\.fromCharCode', js_text)) > 5,
            len(re.findall(r'eval\s*\(', js_text)) > 0,
            len(re.findall(r'unescape\s*\(', js_text)) > 0,
            'replace' in js_text and 'function' in js_text,
            len([c for c in js_text if c.isalnum()]) / max(len(js_text), 1) < 0.3
        ]
        
        return sum(obfuscation_indicators) >= 2
        
    def _find_suspicious_js_calls(self, js_text: str) -> List[str]:
        """Find suspicious JavaScript API calls"""
        suspicious_calls = []
        
        suspicious_apis = [
            'exportDataObject', 'getURL', 'launchURL', 'submitForm',
            'mailDoc', 'print', 'saveAs', 'closeDoc', 'getAnnots',
            'importDataObject', 'addScript', 'addToolButton'
        ]
        
        for api in suspicious_apis:
            if api in js_text:
                suspicious_calls.append(api)
                
        return suspicious_calls
        
    def _check_js_exploits(self, js_text: str) -> bool:
        """Check for known JavaScript exploit patterns"""
        exploit_patterns = [
            r'util\.printf\s*\([^)]*%[0-9]+[dns]',  # printf exploit
            r'Collab\.collectEmailInfo',  # Email harvesting
            r'spell\.customDictionaryOpen',  # Dictionary exploit
            r'getIcon.*\.width\s*=',  # getIcon exploit
            r'app\..*\s*=\s*app\.',  # app property manipulation
        ]
        
        for pattern in exploit_patterns:
            if re.search(pattern, js_text):
                return True
                
        return False
        
    def _calculate_threat_level(self) -> str:
        """Calculate overall threat assessment"""
        if self.threat_level >= 150:
            return "CRITICAL - Highly malicious PDF"
        elif self.threat_level >= 100:
            return "HIGH - Likely malicious PDF"
        elif self.threat_level >= 50:
            return "MEDIUM - Suspicious PDF features"
        elif self.threat_level >= 20:
            return "LOW - Some risky features"
        else:
            return "SAFE - No significant threats"
            
    def _get_detected_exploits(self) -> List[str]:
        """Get list of detected exploits"""
        exploits = []
        
        for element in self.suspicious_elements:
            if 'exploit' in element.tags:
                exploits.append(element.message)
                
        return list(set(exploits))
        
    def _get_risky_features(self) -> List[str]:
        """Get list of risky PDF features used"""
        features = []
        
        if self.scripts:
            features.append("JavaScript")
        if self.embedded_files:
            features.append("Embedded Files")
            
        for obj in self.objects.values():
            content_str = str(obj['content'])
            if '/Launch' in content_str:
                features.append("Launch Actions")
            if '/OpenAction' in content_str:
                features.append("Auto-Open Actions")
            if '/AcroForm' in content_str:
                features.append("Interactive Forms")
            if '/XFA' in content_str:
                features.append("XFA Forms")
                
        return list(set(features))