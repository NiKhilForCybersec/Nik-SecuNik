"""
File Identifier for SecuNik LogX
Detects file types and assigns appropriate parsers
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from enum import Enum

# Try to import magic, but make it optional on Windows
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False
    print("Warning: python-magic not available. Using fallback file detection.")

import filetype


class FileCategory(Enum):
    """File categories for parser assignment"""
    LOGS = "logs"
    NETWORK = "network"
    SYSTEM = "system"
    MOBILE = "mobile"
    CLOUD = "cloud"
    EMAIL = "email"
    DOCUMENTS = "documents"
    ARCHIVES = "archives"
    DATABASE = "database"
    FORENSICS = "forensics"
    CODE = "code"
    STRUCTURED = "structured"
    GENERIC = "generic"


class FileIdentifier:
    """Identifies file types and assigns appropriate parsers"""
    
    def __init__(self):
        # Initialize magic for MIME type detection if available
        self.magic_mime = None
        self.magic_desc = None
        
        if MAGIC_AVAILABLE:
            try:
                self.magic_mime = magic.Magic(mime=True)
                self.magic_desc = magic.Magic()
            except Exception as e:
                print(f"Warning: Could not initialize magic: {e}")
                self.magic_mime = None
                self.magic_desc = None
        
        # Define file type mappings
        self._init_mappings()
    
    def _init_mappings(self):
        """Initialize file type to parser mappings"""
        # Extension to parser mapping
        self.extension_map = {
            # Logs
            ".log": ("generic_log", FileCategory.LOGS),
            ".syslog": ("syslog", FileCategory.LOGS),
            ".evtx": ("windows_event", FileCategory.LOGS),
            ".evt": ("windows_event", FileCategory.LOGS),
            ".etl": ("windows_etl", FileCategory.LOGS),
            
            # Network
            ".pcap": ("pcap", FileCategory.NETWORK),
            ".pcapng": ("pcapng", FileCategory.NETWORK),
            ".cap": ("pcap", FileCategory.NETWORK),
            ".netflow": ("netflow", FileCategory.NETWORK),
            ".zeek": ("zeek", FileCategory.NETWORK),
            ".bro": ("zeek", FileCategory.NETWORK),
            
            # Archives
            ".zip": ("zip", FileCategory.ARCHIVES),
            ".rar": ("rar", FileCategory.ARCHIVES),
            ".7z": ("sevenz", FileCategory.ARCHIVES),
            ".tar": ("tar", FileCategory.ARCHIVES),
            ".gz": ("gzip", FileCategory.ARCHIVES),
            ".bz2": ("bzip2", FileCategory.ARCHIVES),
            
            # Documents
            ".pdf": ("pdf", FileCategory.DOCUMENTS),
            ".doc": ("doc", FileCategory.DOCUMENTS),
            ".docx": ("docx", FileCategory.DOCUMENTS),
            ".xls": ("xls", FileCategory.DOCUMENTS),
            ".xlsx": ("xlsx", FileCategory.DOCUMENTS),
            ".ppt": ("ppt", FileCategory.DOCUMENTS),
            ".pptx": ("pptx", FileCategory.DOCUMENTS),
            
            # Email
            ".eml": ("eml", FileCategory.EMAIL),
            ".msg": ("msg", FileCategory.EMAIL),
            ".mbox": ("mbox", FileCategory.EMAIL),
            ".pst": ("pst", FileCategory.EMAIL),
            ".ost": ("ost", FileCategory.EMAIL),
            
            # Database
            ".sqlite": ("sqlite", FileCategory.DATABASE),
            ".db": ("sqlite", FileCategory.DATABASE),
            ".sql": ("sql_dump", FileCategory.DATABASE),
            ".dump": ("sql_dump", FileCategory.DATABASE),
            
            # Structured
            ".json": ("json", FileCategory.STRUCTURED),
            ".xml": ("xml", FileCategory.STRUCTURED),
            ".csv": ("csv", FileCategory.STRUCTURED),
            ".yaml": ("yaml", FileCategory.STRUCTURED),
            ".yml": ("yaml", FileCategory.STRUCTURED),
            ".ini": ("ini", FileCategory.STRUCTURED),
            
            # Forensics
            ".dd": ("disk_image", FileCategory.FORENSICS),
            ".img": ("disk_image", FileCategory.FORENSICS),
            ".e01": ("ewf_image", FileCategory.FORENSICS),
            ".aff": ("aff_image", FileCategory.FORENSICS),
            ".vmdk": ("vmdk", FileCategory.FORENSICS),
            ".vhd": ("vhd", FileCategory.FORENSICS),
            
            # Code
            ".py": ("python", FileCategory.CODE),
            ".js": ("javascript", FileCategory.CODE),
            ".php": ("php", FileCategory.CODE),
            ".sh": ("shell", FileCategory.CODE),
            ".ps1": ("powershell", FileCategory.CODE),
            ".bat": ("batch", FileCategory.CODE),
            ".exe": ("pe_binary", FileCategory.CODE),
            ".dll": ("pe_binary", FileCategory.CODE),
            ".elf": ("elf_binary", FileCategory.CODE),
            
            # Mobile
            ".ab": ("android_backup", FileCategory.MOBILE),
            ".logcat": ("android_logcat", FileCategory.MOBILE),
            ".ips": ("ios_crash", FileCategory.MOBILE),
        }
        
        # MIME type to parser mapping
        self.mime_map = {
            # Text
            "text/plain": ("text", FileCategory.GENERIC),
            "text/html": ("html", FileCategory.DOCUMENTS),
            "text/xml": ("xml", FileCategory.STRUCTURED),
            "text/csv": ("csv", FileCategory.STRUCTURED),
            
            # Application
            "application/json": ("json", FileCategory.STRUCTURED),
            "application/pdf": ("pdf", FileCategory.DOCUMENTS),
            "application/zip": ("zip", FileCategory.ARCHIVES),
            "application/x-rar": ("rar", FileCategory.ARCHIVES),
            "application/x-7z-compressed": ("sevenz", FileCategory.ARCHIVES),
            "application/x-sqlite3": ("sqlite", FileCategory.DATABASE),
            "application/vnd.tcpdump.pcap": ("pcap", FileCategory.NETWORK),
            "application/x-executable": ("binary", FileCategory.CODE),
            "application/x-dosexec": ("pe_binary", FileCategory.CODE),
            
            # Microsoft Office
            "application/vnd.ms-excel": ("xls", FileCategory.DOCUMENTS),
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ("xlsx", FileCategory.DOCUMENTS),
            "application/msword": ("doc", FileCategory.DOCUMENTS),
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ("docx", FileCategory.DOCUMENTS),
            
            # Email
            "message/rfc822": ("eml", FileCategory.EMAIL),
            "application/vnd.ms-outlook": ("msg", FileCategory.EMAIL),
        }
        
        # Content pattern matching
        self.content_patterns = {
            # Log patterns
            r"^\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}": ("timestamp_log", FileCategory.LOGS),
            r"^<\d+>.*\d{4}-\d{2}-\d{2}": ("syslog", FileCategory.LOGS),
            r"^\[\d{4}-\d{2}-\d{2}": ("bracketed_log", FileCategory.LOGS),
            
            # Apache/Nginx patterns
            r'^\d+\.\d+\.\d+\.\d+\s+-\s+-\s+\[': ("apache_access", FileCategory.LOGS),
            r'^\[.*?\]\s+\[.*?\]\s+\[.*?\]': ("apache_error", FileCategory.LOGS),
            
            # Windows Event Log XML
            r'<Event xmlns=.*microsoft.*>': ("windows_event_xml", FileCategory.LOGS),
            
            # JSON
            r'^\s*\{.*\}\s*$': ("json", FileCategory.STRUCTURED),
            r'^\s*\[.*\]\s*$': ("json_array", FileCategory.STRUCTURED),
            
            # CSV
            r'^[^,]+,[^,]+(,[^,]+)*$': ("csv", FileCategory.STRUCTURED),
            
            # Email headers
            r'^(From|To|Subject|Date|Message-ID):': ("email_headers", FileCategory.EMAIL),
        }
    
    def _get_mime_type_fallback(self, file_path: Path) -> Optional[str]:
        """Get MIME type using fallback methods when magic is not available"""
        # Try filetype library first
        try:
            kind = filetype.guess(str(file_path))
            if kind:
                return kind.mime
        except:
            pass
        
        # Extension-based MIME type mapping
        ext_mime_map = {
            '.txt': 'text/plain',
            '.log': 'text/plain',
            '.json': 'application/json',
            '.xml': 'text/xml',
            '.csv': 'text/csv',
            '.html': 'text/html',
            '.pdf': 'application/pdf',
            '.zip': 'application/zip',
            '.gz': 'application/gzip',
            '.tar': 'application/x-tar',
            '.rar': 'application/x-rar',
            '.7z': 'application/x-7z-compressed',
            '.doc': 'application/msword',
            '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            '.xls': 'application/vnd.ms-excel',
            '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            '.exe': 'application/x-dosexec',
            '.dll': 'application/x-dosexec',
        }
        
        ext = file_path.suffix.lower()
        return ext_mime_map.get(ext, 'application/octet-stream')
    
    async def identify_file(self, file_path: Path) -> Dict[str, any]:
        """Identify file type and assign parser"""
        result = {
            "file_path": str(file_path),
            "file_name": file_path.name,
            "file_size": file_path.stat().st_size if file_path.exists() else 0,
            "extension": file_path.suffix.lower(),
            "mime_type": None,
            "description": None,
            "parser": None,
            "category": None,
            "confidence": 0.0,
            "alternate_parsers": []
        }
        
        if not file_path.exists():
            result["error"] = "File not found"
            return result
        
        # Try multiple detection methods
        
        # 1. Extension-based detection (highest priority for known extensions)
        if result["extension"] in self.extension_map:
            parser, category = self.extension_map[result["extension"]]
            result["parser"] = parser
            result["category"] = category.value
            result["confidence"] = 0.9
            result["detection_method"] = "extension"
        
        # 2. MIME type detection
        try:
            if self.magic_mime:
                mime_type = self.magic_mime.from_file(str(file_path))
            else:
                # Use fallback method
                mime_type = self._get_mime_type_fallback(file_path)
            
            result["mime_type"] = mime_type
            
            if mime_type in self.mime_map:
                parser, category = self.mime_map[mime_type]
                if not result["parser"] or result["confidence"] < 0.8:
                    result["parser"] = parser
                    result["category"] = category.value
                    result["confidence"] = 0.8
                    result["detection_method"] = "mime"
                else:
                    result["alternate_parsers"].append({
                        "parser": parser,
                        "category": category.value,
                        "method": "mime"
                    })
        except Exception as e:
            result["mime_error"] = str(e)
        
        # 3. Magic description (only if available)
        if self.magic_desc:
            try:
                description = self.magic_desc.from_file(str(file_path))
                result["description"] = description
                
                # Check for specific patterns in description
                desc_lower = description.lower()
                if "pcap" in desc_lower:
                    self._update_result(result, "pcap", FileCategory.NETWORK, 0.85, "description")
                elif "sqlite" in desc_lower:
                    self._update_result(result, "sqlite", FileCategory.DATABASE, 0.85, "description")
                elif "pdf" in desc_lower:
                    self._update_result(result, "pdf", FileCategory.DOCUMENTS, 0.85, "description")
                elif "zip" in desc_lower or "archive" in desc_lower:
                    self._update_result(result, "zip", FileCategory.ARCHIVES, 0.7, "description")
            except Exception as e:
                result["description_error"] = str(e)
        
        # 4. Content-based detection (for text files)
        if result["mime_type"] and "text" in result["mime_type"]:
            content_type = await self._detect_by_content(file_path)
            if content_type:
                parser, category = content_type
                if not result["parser"] or result["confidence"] < 0.7:
                    result["parser"] = parser
                    result["category"] = category.value
                    result["confidence"] = 0.7
                    result["detection_method"] = "content"
                else:
                    result["alternate_parsers"].append({
                        "parser": parser,
                        "category": category.value,
                        "method": "content"
                    })
        
        # 5. Default fallback
        if not result["parser"]:
            if result["mime_type"] and "text" in result["mime_type"]:
                result["parser"] = "text"
                result["category"] = FileCategory.GENERIC.value
                result["confidence"] = 0.5
                result["detection_method"] = "fallback"
            else:
                result["parser"] = "binary"
                result["category"] = FileCategory.GENERIC.value
                result["confidence"] = 0.3
                result["detection_method"] = "fallback"
        
        return result
    
    async def _detect_by_content(self, file_path: Path) -> Optional[Tuple[str, FileCategory]]:
        """Detect file type by examining content"""
        try:
            # Read first 8KB of file
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(8192)
            
            # Check against content patterns
            for pattern, (parser, category) in self.content_patterns.items():
                if re.search(pattern, content, re.MULTILINE | re.IGNORECASE):
                    return (parser, category)
            
            # Additional heuristics
            lines = content.split('\n')[:10]  # Check first 10 lines
            
            # Check for common log formats
            if any(self._is_log_line(line) for line in lines):
                return ("generic_log", FileCategory.LOGS)
            
            # Check for structured data
            if self._is_likely_json(content):
                return ("json", FileCategory.STRUCTURED)
            
            if self._is_likely_csv(lines):
                return ("csv", FileCategory.STRUCTURED)
            
            if self._is_likely_xml(content):
                return ("xml", FileCategory.STRUCTURED)
            
        except Exception:
            pass
        
        return None
    
    def _update_result(self, result: Dict, parser: str, category: FileCategory, 
                      confidence: float, method: str):
        """Update result if confidence is higher"""
        if not result["parser"] or result["confidence"] < confidence:
            result["parser"] = parser
            result["category"] = category.value
            result["confidence"] = confidence
            result["detection_method"] = method
        else:
            result["alternate_parsers"].append({
                "parser": parser,
                "category": category.value,
                "method": method
            })
    
    def _is_log_line(self, line: str) -> bool:
        """Check if line looks like a log entry"""
        # Common log indicators
        log_patterns = [
            r'\d{4}-\d{2}-\d{2}',  # Date
            r'\d{2}:\d{2}:\d{2}',  # Time
            r'\[(ERROR|WARN|INFO|DEBUG)\]',  # Log levels
            r'^\w+ \d+ \d{2}:\d{2}:\d{2}',  # Syslog format
        ]
        
        return any(re.search(pattern, line) for pattern in log_patterns)
    
    def _is_likely_json(self, content: str) -> bool:
        """Check if content is likely JSON"""
        content = content.strip()
        return (content.startswith('{') and content.endswith('}')) or \
               (content.startswith('[') and content.endswith(']'))
    
    def _is_likely_csv(self, lines: List[str]) -> bool:
        """Check if content is likely CSV"""
        if len(lines) < 2:
            return False
        
        # Count delimiters in first few lines
        delimiter_counts = {}
        for delimiter in [',', '\t', '|', ';']:
            counts = [line.count(delimiter) for line in lines[:5] if line]
            if counts and all(c == counts[0] and c > 0 for c in counts):
                delimiter_counts[delimiter] = counts[0]
        
        return len(delimiter_counts) > 0
    
    def _is_likely_xml(self, content: str) -> bool:
        """Check if content is likely XML"""
        content = content.strip()
        return content.startswith('<?xml') or \
               (content.startswith('<') and content.endswith('>'))
    
    def get_parser_info(self, parser_name: str) -> Dict[str, any]:
        """Get information about a specific parser"""
        # This will be expanded when parsers are implemented
        parser_info = {
            "name": parser_name,
            "supported": parser_name in self._get_supported_parsers(),
            "category": None,
            "description": None
        }
        
        # Find category
        for ext, (parser, category) in self.extension_map.items():
            if parser == parser_name:
                parser_info["category"] = category.value
                break
        
        return parser_info
    
    def _get_supported_parsers(self) -> List[str]:
        """Get list of currently supported parsers"""
        parsers = set()
        for parser, _ in self.extension_map.values():
            parsers.add(parser)
        for parser, _ in self.mime_map.values():
            parsers.add(parser)
        return sorted(list(parsers))