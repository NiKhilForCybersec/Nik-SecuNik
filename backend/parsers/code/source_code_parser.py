"""
Source Code Security Parser for SecuNik LogX
Scans source code for security vulnerabilities, secrets, and malicious patterns
Supports multiple programming languages
"""

import re
import asyncio
from datetime import datetime
from typing import Dict, Any, List, Optional, Set, AsyncGenerator, Tuple
from pathlib import Path
from collections import defaultdict
import hashlib
import base64
import json

from ..base_parser import BaseParser, ParseResult, ParsedEntry, FileMetadata, IOCs


class SourceCodeParser(BaseParser):
    """Parser for source code security scanning"""
    
    name = "source_code"
    description = "Scans source code for security vulnerabilities"
    supported_extensions = [
        '.py', '.js', '.java', '.c', '.cpp', '.cs', '.php', '.rb', '.go',
        '.rs', '.swift', '.kt', '.scala', '.pl', '.sh', '.ps1', '.bat',
        '.html', '.xml', '.json', '.yaml', '.yml', '.conf', '.config',
        '.env', '.properties', '.ini', '.toml'
    ]
    
    # Language detection
    LANGUAGE_MAP = {
        '.py': 'python',
        '.js': 'javascript',
        '.java': 'java',
        '.c': 'c',
        '.cpp': 'cpp',
        '.cs': 'csharp',
        '.php': 'php',
        '.rb': 'ruby',
        '.go': 'go',
        '.rs': 'rust',
        '.swift': 'swift',
        '.kt': 'kotlin',
        '.scala': 'scala',
        '.pl': 'perl',
        '.sh': 'bash',
        '.ps1': 'powershell',
        '.bat': 'batch',
        '.html': 'html',
        '.xml': 'xml'
    }
    
    # Secret patterns
    SECRET_PATTERNS = {
        'aws_access_key': {
            'pattern': r'(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}',
            'severity': 'critical',
            'description': 'AWS Access Key ID'
        },
        'aws_secret_key': {
            'pattern': r'(?:aws_secret_access_key|aws_secret_key|aws_secret)[\s:=]+[\'""]?([A-Za-z0-9/+=]{40})[\'""]?',
            'severity': 'critical',
            'description': 'AWS Secret Access Key'
        },
        'github_token': {
            'pattern': r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}',
            'severity': 'critical',
            'description': 'GitHub Personal Access Token'
        },
        'api_key': {
            'pattern': r'(?:api[_-]?key|apikey)[\s:=]+[\'""]?([A-Za-z0-9_\-]{20,})[\'""]?',
            'severity': 'warning',
            'description': 'Generic API Key'
        },
        'private_key': {
            'pattern': r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
            'severity': 'critical',
            'description': 'Private Key'
        },
        'jwt_token': {
            'pattern': r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
            'severity': 'warning',
            'description': 'JWT Token'
        },
        'password': {
            'pattern': r'(?:password|passwd|pwd)[\s:=]+[\'""]?([^\s\'"",]+)[\'""]?',
            'severity': 'warning',
            'description': 'Hardcoded Password'
        },
        'connection_string': {
            'pattern': r'(?:mongodb|mysql|postgres|postgresql|redis|amqp|jdbc):\/\/[^\s]+',
            'severity': 'critical',
            'description': 'Database Connection String'
        },
        'slack_token': {
            'pattern': r'xox[baprs]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,}',
            'severity': 'warning',
            'description': 'Slack Token'
        },
        'google_api': {
            'pattern': r'AIza[0-9A-Za-z_-]{35}',
            'severity': 'warning',
            'description': 'Google API Key'
        }
    }
    
    # Vulnerability patterns by language
    VULNERABILITY_PATTERNS = {
        'sql_injection': {
            'patterns': [
                r'(?:SELECT|INSERT|UPDATE|DELETE).*\+.*(?:request|params|query|body)',
                r'(?:execute|query)\s*\([^)]*\+[^)]*\)',
                r'string\.Format\s*\([^)]*(?:SELECT|INSERT|UPDATE|DELETE)',
                r'"\s*(?:SELECT|INSERT|UPDATE|DELETE).*"\s*\+',
                r'f["\']\s*(?:SELECT|INSERT|UPDATE|DELETE).*{[^}]+}'
            ],
            'languages': ['all'],
            'severity': 'critical',
            'description': 'SQL Injection vulnerability'
        },
        'command_injection': {
            'patterns': [
                r'(?:exec|system|popen|subprocess\.call|os\.system)\s*\([^)]*\+',
                r'Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+',
                r'Process\.Start\s*\([^)]*\+',
                r'`[^`]*\$[^`]*`',
                r'eval\s*\([^)]*(?:request|params|query|body)'
            ],
            'languages': ['all'],
            'severity': 'critical',
            'description': 'Command Injection vulnerability'
        },
        'xss': {
            'patterns': [
                r'innerHTML\s*=.*(?:request|params|query|body)',
                r'document\.write\s*\([^)]*(?:request|params|query|body)',
                r'(?:echo|print).*\$_(?:GET|POST|REQUEST)',
                r'Response\.Write\s*\([^)]*Request',
                r'render_template_string\s*\([^)]*request'
            ],
            'languages': ['javascript', 'php', 'python', 'csharp'],
            'severity': 'warning',
            'description': 'Cross-Site Scripting (XSS) vulnerability'
        },
        'path_traversal': {
            'patterns': [
                r'(?:open|read|include|require)\s*\([^)]*\.\.[/\\]',
                r'File\s*\([^)]*(?:request|params|query|body)',
                r'readFile.*\+.*(?:request|params|query|body)',
                r'include\s*\([^)]*\$_(?:GET|POST|REQUEST)'
            ],
            'languages': ['all'],
            'severity': 'warning',
            'description': 'Path Traversal vulnerability'
        },
        'weak_crypto': {
            'patterns': [
                r'(?:MD5|SHA1)\s*\(',
                r'DES\.new',
                r'Random\s*\(\)',
                r'Math\.random\s*\(\)',
                r'ECB\s*mode'
            ],
            'languages': ['all'],
            'severity': 'warning',
            'description': 'Weak cryptographic algorithm'
        },
        'hardcoded_secret': {
            'patterns': [
                r'(?:secret|key|token|password)\s*=\s*["\'][^"\']+["\']',
                r'(?:AES|DES|RSA)\.new\s*\(["\'][^"\']+["\']',
                r'sign\s*\([^,]+,\s*["\'][^"\']+["\']'
            ],
            'languages': ['all'],
            'severity': 'warning',
            'description': 'Hardcoded secret or key'
        }
    }
    
    # Malicious patterns
    MALICIOUS_PATTERNS = {
        'reverse_shell': {
            'patterns': [
                r'(?:nc|netcat|ncat).*-e.*(?:bash|sh|cmd)',
                r'socket.*SOCK_STREAM.*connect',
                r'exec\s*\(\s*["\']\/bin\/sh["\']',
                r'subprocess.*shell\s*=\s*True',
                r'os\.system\s*\(["\'].*\|.*nc'
            ],
            'severity': 'critical',
            'description': 'Reverse shell code'
        },
        'backdoor': {
            'patterns': [
                r'(?:eval|exec)\s*\(\s*(?:base64|decode|decompress)',
                r'__import__\s*\(["\']os["\']',
                r'globals\s*\(\)\[["\']__builtins__["\']',
                r'compile\s*\([^)]+,\s*["\']<string>["\'],\s*["\']exec["\']'
            ],
            'severity': 'critical',
            'description': 'Backdoor code pattern'
        },
        'data_exfiltration': {
            'patterns': [
                r'requests\.(?:post|put)\s*\([^)]*sensitive',
                r'urllib.*urlopen\s*\([^)]*http',
                r'curl.*-d.*@',
                r'webclient\.uploadstring'
            ],
            'severity': 'critical',
            'description': 'Data exfiltration attempt'
        },
        'crypto_miner': {
            'patterns': [
                r'stratum\+tcp:\/\/',
                r'(?:monero|bitcoin|ethereum).*wallet',
                r'coinhive|cryptonight|jsecoin',
                r'mining.*pool.*worker'
            ],
            'severity': 'warning',
            'description': 'Cryptocurrency mining code'
        }
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.vulnerabilities = []
        self.secrets = []
        self.malicious_code = []
        self.code_metrics = {
            'total_lines': 0,
            'code_lines': 0,
            'comment_lines': 0,
            'blank_lines': 0
        }
        self.imports = defaultdict(set)
        self.functions = []
        
    async def parse(self) -> ParseResult:
        """Parse source code file"""
        result = ParseResult(
            file_path=str(self.file_path),
            file_type="source_code",
            parser_name=self.name
        )
        
        try:
            # Get file metadata
            result.metadata = await self._get_file_metadata()
            
            # Detect language
            language = self._detect_language()
            result.metadata.additional["language"] = language
            
            # Create main entry
            code_entry = ParsedEntry(
                timestamp=datetime.now(),
                source=self.file_path.name,
                event_type="code_file",
                severity="info",
                message=f"Source code file: {self.file_path.name} ({language})",
                raw_data={
                    'filename': self.file_path.name,
                    'language': language,
                    'size': result.metadata.size
                }
            )
            result.entries.append(code_entry)
            
            # Scan code
            await self._scan_code(language)
            
            # Add vulnerability findings
            for vuln in self.vulnerabilities[:100]:  # Limit
                result.entries.append(vuln)
                
            # Add secret findings
            for secret in self.secrets[:50]:
                result.entries.append(secret)
                
            # Add malicious code findings
            for mal in self.malicious_code[:50]:
                result.entries.append(mal)
                
            # Extract IOCs from all findings
            for entry in result.entries:
                result.iocs.merge(self._extract_code_iocs(entry))
                
            # Generate summary
            result.metadata.additional.update({
                'code_metrics': self.code_metrics,
                'vulnerability_count': len(self.vulnerabilities),
                'secret_count': len(self.secrets),
                'malicious_pattern_count': len(self.malicious_code),
                'security_score': self._calculate_security_score(),
                'vulnerability_summary': self._summarize_vulnerabilities(),
                'imports_analysis': self._analyze_imports(),
                'risk_assessment': self._assess_risk()
            })
            
            self.logger.info(f"Scanned {self.code_metrics['total_lines']} lines of {language} code")
            
        except Exception as e:
            self.logger.error(f"Error parsing source code: {e}")
            result.errors.append(f"Parse error: {str(e)}")
            
        return result
        
    def _detect_language(self) -> str:
        """Detect programming language from file extension"""
        ext = self.file_path.suffix.lower()
        return self.LANGUAGE_MAP.get(ext, 'unknown')
        
    async def _scan_code(self, language: str):
        """Scan source code for security issues"""
        line_num = 0
        in_multiline_comment = False
        
        async with self._open_file() as f:
            async for line in f:
                line_num += 1
                
                # Update metrics
                self.code_metrics['total_lines'] += 1
                
                # Check line type
                stripped = line.strip()
                if not stripped:
                    self.code_metrics['blank_lines'] += 1
                    continue
                    
                # Handle comments (simplified)
                if self._is_comment(stripped, language):
                    self.code_metrics['comment_lines'] += 1
                else:
                    self.code_metrics['code_lines'] += 1
                    
                # Extract imports
                self._extract_imports(stripped, language)
                
                # Scan for secrets
                await self._scan_for_secrets(line, line_num)
                
                # Scan for vulnerabilities
                await self._scan_for_vulnerabilities(line, line_num, language)
                
                # Scan for malicious patterns
                await self._scan_for_malicious(line, line_num)
                
                # Yield control periodically
                if line_num % 100 == 0:
                    await asyncio.sleep(0)
                    
    def _is_comment(self, line: str, language: str) -> bool:
        """Check if line is a comment"""
        comment_markers = {
            'python': ['#'],
            'javascript': ['//', '/*', '*'],
            'java': ['//', '/*', '*'],
            'c': ['//', '/*', '*'],
            'cpp': ['//', '/*', '*'],
            'csharp': ['//', '/*', '*'],
            'php': ['//', '/*', '*', '#'],
            'ruby': ['#'],
            'go': ['//', '/*', '*'],
            'rust': ['//', '/*', '*'],
            'bash': ['#'],
            'powershell': ['#'],
            'batch': ['REM', '::']
        }
        
        markers = comment_markers.get(language, ['#', '//'])
        return any(line.startswith(marker) for marker in markers)
        
    def _extract_imports(self, line: str, language: str):
        """Extract import statements"""
        import_patterns = {
            'python': [r'^import\s+(\S+)', r'^from\s+(\S+)\s+import'],
            'javascript': [r'^import.*from\s+[\'"]([^\'""]+)[\'"]', r'^require\s*\([\'"]([^\'""]+)[\'"]\)'],
            'java': [r'^import\s+([\w.]+);'],
            'csharp': [r'^using\s+([\w.]+);'],
            'go': [r'^import\s+"([^"]+)"'],
            'rust': [r'^use\s+([\w:]+);']
        }
        
        patterns = import_patterns.get(language, [])
        for pattern in patterns:
            match = re.match(pattern, line)
            if match:
                self.imports[language].add(match.group(1))
                
    async def _scan_for_secrets(self, line: str, line_num: int):
        """Scan line for hardcoded secrets"""
        for secret_type, config in self.SECRET_PATTERNS.items():
            pattern = config['pattern']
            
            # Skip if line looks like a comment
            if any(marker in line for marker in ['#', '//', '/*', '*']):
                continue
                
            matches = re.finditer(pattern, line, re.IGNORECASE)
            for match in matches:
                # Try to extract the actual secret value
                secret_value = match.group(0)
                if match.groups():
                    secret_value = match.group(1)
                    
                # Mask the secret for security
                if len(secret_value) > 8:
                    masked = secret_value[:4] + '*' * (len(secret_value) - 8) + secret_value[-4:]
                else:
                    masked = '*' * len(secret_value)
                    
                secret_entry = ParsedEntry(
                    timestamp=datetime.now(),
                    source=f"line_{line_num}",
                    event_type="security_alert",
                    severity=config['severity'],
                    message=f"{config['description']} found: {masked}",
                    raw_data={
                        'line_number': line_num,
                        'secret_type': secret_type,
                        'masked_value': masked,
                        'line_preview': line.strip()[:100]
                    }
                )
                secret_entry.tags = ["secret", "credential", secret_type]
                
                self.secrets.append(secret_entry)
                
    async def _scan_for_vulnerabilities(self, line: str, line_num: int, language: str):
        """Scan line for vulnerability patterns"""
        for vuln_type, config in self.VULNERABILITY_PATTERNS.items():
            # Check if applies to this language
            if 'all' not in config['languages'] and language not in config['languages']:
                continue
                
            for pattern in config['patterns']:
                if re.search(pattern, line, re.IGNORECASE):
                    vuln_entry = ParsedEntry(
                        timestamp=datetime.now(),
                        source=f"line_{line_num}",
                        event_type="security_alert",
                        severity=config['severity'],
                        message=f"{config['description']} at line {line_num}",
                        raw_data={
                            'line_number': line_num,
                            'vulnerability_type': vuln_type,
                            'pattern_matched': pattern,
                            'code_snippet': line.strip()
                        }
                    )
                    vuln_entry.tags = ["vulnerability", vuln_type, language]
                    
                    self.vulnerabilities.append(vuln_entry)
                    break
                    
    async def _scan_for_malicious(self, line: str, line_num: int):
        """Scan line for malicious code patterns"""
        for mal_type, config in self.MALICIOUS_PATTERNS.items():
            for pattern in config['patterns']:
                if re.search(pattern, line, re.IGNORECASE):
                    mal_entry = ParsedEntry(
                        timestamp=datetime.now(),
                        source=f"line_{line_num}",
                        event_type="security_alert",
                        severity=config['severity'],
                        message=f"{config['description']} detected at line {line_num}",
                        raw_data={
                            'line_number': line_num,
                            'malicious_type': mal_type,
                            'pattern_matched': pattern,
                            'code_snippet': line.strip()
                        }
                    )
                    mal_entry.tags = ["malicious_code", mal_type, "threat"]
                    
                    self.malicious_code.append(mal_entry)
                    break
                    
    def _extract_code_iocs(self, entry: ParsedEntry) -> IOCs:
        """Extract IOCs from code findings"""
        iocs = IOCs()
        
        # Extract from raw data
        raw_str = json.dumps(entry.raw_data)
        
        # Extract URLs
        urls = re.findall(r'https?://[^\s\'"<>]+', raw_str)
        for url in urls:
            iocs.urls.add(url)
            # Extract domain
            domain_match = re.match(r'https?://([^/]+)', url)
            if domain_match:
                iocs.domains.add(domain_match.group(1))
                
        # Extract IPs
        ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', raw_str)
        for ip in ips:
            # Filter out version numbers and local IPs
            if not ip.startswith(('127.', '0.', '192.168.', '10.', '172.')):
                parts = ip.split('.')
                if all(int(part) <= 255 for part in parts):
                    iocs.ips.add(ip)
                    
        # Extract file paths
        # Windows paths
        win_paths = re.findall(r'[A-Za-z]:\\[^\'"\s]+', raw_str)
        for path in win_paths:
            iocs.file_paths.add(path)
            
        # Unix paths
        unix_paths = re.findall(r'/(?:etc|var|usr|opt|home)/[^\'"\s]+', raw_str)
        for path in unix_paths:
            iocs.file_paths.add(path)
            
        # Extract emails
        emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', raw_str)
        for email in emails:
            iocs.emails.add(email)
            
        # Extract potential malware hashes from secrets
        if 'secret_type' in entry.raw_data:
            if entry.raw_data['secret_type'] == 'api_key':
                # Some API keys might be IOCs
                masked = entry.raw_data.get('masked_value', '')
                if len(masked) in [32, 40, 64]:
                    iocs.hashes.add(f"potential_hash_{masked}")
                    
        return iocs
        
    def _calculate_security_score(self) -> int:
        """Calculate security score (0-100, higher is better)"""
        score = 100
        
        # Deduct for vulnerabilities
        score -= len(self.vulnerabilities) * 5
        score -= len([v for v in self.vulnerabilities if v.severity == 'critical']) * 10
        
        # Deduct for secrets
        score -= len(self.secrets) * 3
        score -= len([s for s in self.secrets if s.severity == 'critical']) * 7
        
        # Deduct for malicious code
        score -= len(self.malicious_code) * 15
        
        # Bonus for good practices (simplified)
        if self.code_metrics['comment_lines'] > self.code_metrics['code_lines'] * 0.1:
            score += 5  # Good documentation
            
        return max(0, min(100, score))
        
    def _summarize_vulnerabilities(self) -> Dict[str, int]:
        """Summarize vulnerabilities by type"""
        summary = defaultdict(int)
        
        for vuln in self.vulnerabilities:
            vuln_type = vuln.raw_data.get('vulnerability_type', 'unknown')
            summary[vuln_type] += 1
            
        return dict(summary)
        
    def _analyze_imports(self) -> Dict[str, List[str]]:
        """Analyze imported libraries for security concerns"""
        analysis = {}
        
        # Known risky imports
        risky_imports = {
            'python': ['pickle', 'subprocess', 'os', 'eval', '__import__'],
            'javascript': ['eval', 'child_process', 'vm'],
            'java': ['Runtime', 'ProcessBuilder', 'ScriptEngine'],
            'csharp': ['Process', 'Diagnostics.Process'],
            'php': ['exec', 'system', 'eval', 'shell_exec'],
            'ruby': ['eval', 'system', 'exec', 'spawn']
        }
        
        for language, imports in self.imports.items():
            risky = risky_imports.get(language, [])
            found_risky = [imp for imp in imports if any(r in imp for r in risky)]
            
            if found_risky:
                analysis[language] = {
                    'total_imports': len(imports),
                    'risky_imports': found_risky
                }
                
        return analysis
        
    def _assess_risk(self) -> str:
        """Assess overall risk level"""
        critical_count = sum(1 for v in self.vulnerabilities if v.severity == 'critical')
        critical_count += sum(1 for s in self.secrets if s.severity == 'critical')
        critical_count += len(self.malicious_code)
        
        total_issues = len(self.vulnerabilities) + len(self.secrets) + len(self.malicious_code)
        
        if critical_count > 5 or len(self.malicious_code) > 0:
            return "CRITICAL - Immediate action required"
        elif critical_count > 0 or total_issues > 10:
            return "HIGH - Significant security issues"
        elif total_issues > 5:
            return "MEDIUM - Several security concerns"
        elif total_issues > 0:
            return "LOW - Minor security issues"
        else:
            return "SAFE - No significant issues found"