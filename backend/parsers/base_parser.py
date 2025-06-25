"""
Base Parser Abstract Class
Defines the interface that all parsers must implement
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, AsyncIterator, List, Union
from pathlib import Path
import asyncio
import hashlib
from datetime import datetime
import aiofiles
import json
from dataclasses import dataclass, asdict
import logging

logger = logging.getLogger(__name__)


@dataclass
class ParsedEntry:
    """Standard entry format for all parsed data"""
    timestamp: Optional[str]  # ISO format timestamp
    source: str  # Source identifier (file, IP, etc.)
    event_type: str  # Type of event/entry
    severity: Optional[str]  # critical, high, medium, low, info
    message: str  # Main content/message
    raw_data: Optional[str]  # Original raw entry
    metadata: Dict[str, Any]  # Additional parser-specific fields
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with non-null values"""
        data = asdict(self)
        return {k: v for k, v in data.items() if v is not None}


@dataclass
class ParseResult:
    """Standard result format for all parsers"""
    parser_name: str
    file_path: str
    file_hash: str
    parse_started: str  # ISO format
    parse_completed: str  # ISO format
    total_entries: int
    parsed_entries: int
    failed_entries: int
    entries: List[Dict[str, Any]]  # List of ParsedEntry dicts
    metadata: Dict[str, Any]  # File-level metadata
    errors: List[str]  # Any parsing errors
    warnings: List[str]  # Any parsing warnings
    iocs: Dict[str, List[str]]  # Extracted IOCs
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


class BaseParser(ABC):
    """Abstract base class for all parsers"""
    
    def __init__(self, file_path: Union[str, Path], config: Optional[Dict[str, Any]] = None):
        """
        Initialize parser with file path and optional configuration
        
        Args:
            file_path: Path to the file to parse
            config: Optional parser-specific configuration
        """
        self.file_path = Path(file_path)
        self.config = config or {}
        self.file_hash = ""
        self.parse_started = None
        self.entries = []
        self.errors = []
        self.warnings = []
        self.metadata = {}
        self.iocs = {
            "ips": [],
            "domains": [],
            "urls": [],
            "emails": [],
            "hashes": [],
            "files": []
        }
        self._parsed_count = 0
        self._failed_count = 0
        self._total_count = 0
        
    @property
    @abstractmethod
    def parser_name(self) -> str:
        """Return the name of this parser"""
        pass
    
    @property
    @abstractmethod
    def supported_extensions(self) -> List[str]:
        """Return list of supported file extensions"""
        pass
    
    async def parse(self) -> ParseResult:
        """
        Main parse method - handles common operations and calls specific parser logic
        
        Returns:
            ParseResult with all parsed data
        """
        self.parse_started = datetime.utcnow().isoformat()
        
        try:
            # Calculate file hash
            self.file_hash = await self._calculate_file_hash()
            
            # Validate file
            await self._validate_file()
            
            # Extract file metadata
            await self._extract_file_metadata()
            
            # Parse file content
            async for entry in self._parse_content():
                if entry:
                    self.entries.append(entry.to_dict())
                    self._parsed_count += 1
                    
                    # Extract IOCs from entry
                    self._extract_iocs(entry)
                    
                self._total_count += 1
                
                # Yield control periodically for large files
                if self._total_count % 1000 == 0:
                    await asyncio.sleep(0)
                    
        except Exception as e:
            logger.error(f"Parse error in {self.parser_name}: {str(e)}")
            self.errors.append(f"Parse failed: {str(e)}")
            
        parse_completed = datetime.utcnow().isoformat()
        
        # Remove duplicate IOCs
        for ioc_type in self.iocs:
            self.iocs[ioc_type] = list(set(self.iocs[ioc_type]))
        
        return ParseResult(
            parser_name=self.parser_name,
            file_path=str(self.file_path),
            file_hash=self.file_hash,
            parse_started=self.parse_started,
            parse_completed=parse_completed,
            total_entries=self._total_count,
            parsed_entries=self._parsed_count,
            failed_entries=self._failed_count,
            entries=self.entries,
            metadata=self.metadata,
            errors=self.errors,
            warnings=self.warnings,
            iocs=self.iocs
        )
    
    @abstractmethod
    async def _parse_content(self) -> AsyncIterator[Optional[ParsedEntry]]:
        """
        Parse the file content - must be implemented by each parser
        
        Yields:
            ParsedEntry objects or None for failed entries
        """
        pass
    
    async def _validate_file(self) -> None:
        """Validate file exists and is readable"""
        if not self.file_path.exists():
            raise FileNotFoundError(f"File not found: {self.file_path}")
            
        if not self.file_path.is_file():
            raise ValueError(f"Not a file: {self.file_path}")
            
        # Check file extension
        if self.supported_extensions:
            ext = self.file_path.suffix.lower()
            if ext not in self.supported_extensions:
                self.warnings.append(
                    f"File extension '{ext}' not in supported list: {self.supported_extensions}"
                )
    
    async def _calculate_file_hash(self) -> str:
        """Calculate SHA256 hash of the file"""
        sha256_hash = hashlib.sha256()
        
        async with aiofiles.open(self.file_path, 'rb') as f:
            while chunk := await f.read(8192):
                sha256_hash.update(chunk)
                
        return sha256_hash.hexdigest()
    
    async def _extract_file_metadata(self) -> None:
        """Extract basic file metadata"""
        stat = self.file_path.stat()
        self.metadata.update({
            "file_name": self.file_path.name,
            "file_size": stat.st_size,
            "file_modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "file_created": datetime.fromtimestamp(stat.st_ctime).isoformat()
        })
    
    def _extract_iocs(self, entry: ParsedEntry) -> None:
        """Extract IOCs from parsed entry"""
        import re
        
        # Combine message and raw_data for IOC extraction
        text = f"{entry.message} {entry.raw_data or ''}"
        
        # IP addresses (IPv4)
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ips = re.findall(ip_pattern, text)
        self.iocs["ips"].extend(ips)
        
        # Domain names
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        domains = re.findall(domain_pattern, text)
        # Filter out common false positives
        domains = [d for d in domains if not d.endswith(('.log', '.txt', '.json', '.xml'))]
        self.iocs["domains"].extend(domains)
        
        # URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, text)
        self.iocs["urls"].extend(urls)
        
        # Email addresses
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, text)
        self.iocs["emails"].extend(emails)
        
        # File hashes (MD5, SHA1, SHA256)
        hash_patterns = {
            'md5': r'\b[a-fA-F0-9]{32}\b',
            'sha1': r'\b[a-fA-F0-9]{40}\b',
            'sha256': r'\b[a-fA-F0-9]{64}\b'
        }
        for hash_type, pattern in hash_patterns.items():
            hashes = re.findall(pattern, text)
            self.iocs["hashes"].extend(hashes)
        
        # File paths
        file_pattern = r'(?:[A-Za-z]:\\|/)(?:[^\\/:*?"<>|\r\n]+[\\\/])*[^\\/:*?"<>|\r\n]+'
        files = re.findall(file_pattern, text)
        self.iocs["files"].extend(files)
    
    def _determine_severity(self, message: str) -> str:
        """Determine severity level from message content"""
        message_lower = message.lower()
        
        if any(word in message_lower for word in ['critical', 'fatal', 'emergency']):
            return 'critical'
        elif any(word in message_lower for word in ['error', 'fail', 'denied', 'unauthorized']):
            return 'high'
        elif any(word in message_lower for word in ['warning', 'warn', 'alert']):
            return 'medium'
        elif any(word in message_lower for word in ['info', 'information', 'notice']):
            return 'low'
        else:
            return 'info'
    
    async def read_file_lines(self, encoding: str = 'utf-8', errors: str = 'replace') -> AsyncIterator[str]:
        """Async generator to read file line by line"""
        try:
            async with aiofiles.open(self.file_path, 'r', encoding=encoding, errors=errors) as f:
                async for line in f:
                    yield line.rstrip('\n\r')
        except Exception as e:
            self.errors.append(f"Error reading file: {str(e)}")
            raise