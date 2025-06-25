"""
Advanced IOC Extractor - Context-aware extraction of Indicators of Compromise

This module provides advanced IOC extraction with context analysis,
validation, and threat intelligence enrichment.
"""

import re
import logging
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime
import ipaddress
import tldextract
import hashlib
from urllib.parse import urlparse
from collections import defaultdict
import base64
import json

from parsers.base_parser import ParseResult, ParsedEntry

logger = logging.getLogger(__name__)

class AdvancedIOCExtractor:
    """Advanced context-aware IOC extraction and analysis"""
    
    def __init__(self):
        # Regex patterns for IOC extraction
        self.patterns = self._compile_patterns()
        
        # Whitelists to reduce false positives
        self.whitelists = self._load_whitelists()
        
        # Context patterns for better IOC identification
        self.context_patterns = self._compile_context_patterns()
        
        # IOC validators
        self.validators = {
            "ip": self._validate_ip,
            "domain": self._validate_domain,
            "url": self._validate_url,
            "email": self._validate_email,
            "hash": self._validate_hash,
            "bitcoin": self._validate_bitcoin_address,
            "cve": self._validate_cve
        }
        
        # Threat indicators
        self.threat_indicators = self._load_threat_indicators()
    
    def _compile_patterns(self) -> Dict[str, re.Pattern]:
        """Compile regex patterns for IOC extraction"""
        return {
            # Enhanced IP patterns
            "ipv4": re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
            "ipv6": re.compile(r'(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:))'),
            
            # Domain patterns
            "domain": re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'),
            "subdomain": re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){2,}[a-zA-Z]{2,}\b'),
            
            # URL patterns
            "url": re.compile(r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&/=]*)'),
            "suspicious_url": re.compile(r'https?://[^\s]+(?:\.php\?|\.exe|\.zip|\.rar|\.7z|\.bat|\.cmd|\.ps1|\.vbs)'),
            
            # Email patterns
            "email": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            
            # Hash patterns
            "md5": re.compile(r'\b[a-fA-F0-9]{32}\b'),
            "sha1": re.compile(r'\b[a-fA-F0-9]{40}\b'),
            "sha256": re.compile(r'\b[a-fA-F0-9]{64}\b'),
            "sha512": re.compile(r'\b[a-fA-F0-9]{128}\b'),
            
            # File paths
            "windows_path": re.compile(r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]+'),
            "unix_path": re.compile(r'(?:/[^/\0]+)+/?'),
            
            # Registry keys
            "registry_key": re.compile(r'(?:HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU|HKEY_CLASSES_ROOT|HKCR|HKEY_USERS|HKU)\\[\\A-Za-z0-9_\-\.]+'),
            
            # Cryptocurrency addresses
            "bitcoin": re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|bc1[a-z0-9]{39,59}'),
            "ethereum": re.compile(r'\b0x[a-fA-F0-9]{40}\b'),
            "monero": re.compile(r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b'),
            
            # CVE patterns
            "cve": re.compile(r'CVE-\d{4}-\d{4,7}'),
            
            # Base64 patterns
            "base64": re.compile(r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'),
            
            # Command patterns
            "powershell_encoded": re.compile(r'-[Ee]nc(?:odedCommand)?\s+[A-Za-z0-9+/=]+'),
            "suspicious_command": re.compile(r'(?:cmd|powershell|bash|sh).*(?:/c|/k|-Command|-c)\s+["\']?.*["\']?')
        }
    
    def _compile_context_patterns(self) -> Dict[str, re.Pattern]:
        """Compile patterns for contextual IOC identification"""
        return {
            # C2 communication patterns
            "c2_beacon": re.compile(r'(?:beacon|heartbeat|check-?in|callback|poll).*(?:interval|frequency|period)', re.I),
            "c2_commands": re.compile(r'(?:exec|execute|run|download|upload|shell|cmd).*(?:command|payload|task)', re.I),
            
            # Data exfiltration patterns
            "exfil_keywords": re.compile(r'(?:exfil|steal|harvest|collect|gather|extract).*(?:data|file|document|credential)', re.I),
            "large_transfer": re.compile(r'(?:transfer|upload|send).*(?:\d+\s*[MG]B|\d{7,}\s*bytes)', re.I),
            
            # Malware patterns
            "malware_family": re.compile(r'(?:emotet|trickbot|ryuk|conti|lockbit|revil|darkside|maze|netwalker|sodinokibi)', re.I),
            "malware_behavior": re.compile(r'(?:inject|hook|persistence|elevation|bypass|disable.*(?:defender|antivirus))', re.I),
            
            # Exploit patterns
            "exploit_attempt": re.compile(r'(?:exploit|overflow|injection|traversal|inclusion|deserializ)', re.I),
            "cve_exploit": re.compile(r'(?:exploit.*CVE|CVE.*exploit|vulnerability.*exploit)', re.I),
            
            # Phishing patterns
            "phishing_keywords": re.compile(r'(?:verify.*account|suspended.*account|click.*here|urgent.*action|confirm.*identity)', re.I),
            "phishing_domains": re.compile(r'(?:secure|account|verify|update|confirm|banking|paypal|amazon|microsoft|google|apple).*(?:\.tk|\.ml|\.ga|\.cf)', re.I)
        }
    
    def _load_whitelists(self) -> Dict[str, Set[str]]:
        """Load whitelists for reducing false positives"""
        return {
            "domains": {
                "google.com", "googleapis.com", "microsoft.com", "windows.com",
                "apple.com", "amazon.com", "cloudflare.com", "akamai.com",
                "github.com", "stackoverflow.com", "wikipedia.org"
            },
            "ips": {
                "8.8.8.8", "8.8.4.4",  # Google DNS
                "1.1.1.1", "1.0.0.1",  # Cloudflare DNS
                "208.67.222.222", "208.67.220.220",  # OpenDNS
                "127.0.0.1", "::1",  # Localhost
                "0.0.0.0"  # Any address
            },
            "file_extensions": {
                ".txt", ".log", ".conf", ".ini", ".cfg",
                ".jpg", ".png", ".gif", ".pdf", ".doc"
            },
            "common_hashes": {
                "d41d8cd98f00b204e9800998ecf8427e",  # Empty file MD5
                "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # Empty file SHA1
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # Empty file SHA256
            }
        }
    
    def _load_threat_indicators(self) -> Dict[str, List[str]]:
        """Load known threat indicators"""
        return {
            "malicious_domains": [
                "evil.com", "malware-delivery.net", "phishing-site.tk"
            ],
            "malicious_ips": [
                "192.168.1.1",  # Example - would be real threat intel
            ],
            "malware_hashes": [
                # Would contain real malware hashes from threat intel
            ],
            "suspicious_user_agents": [
                "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)",
                "Python-urllib", "curl", "Wget"
            ],
            "known_c2_ports": [
                4444, 8080, 8443, 9001, 9002, 12345, 31337
            ]
        }
    
    async def extract_advanced(self, parse_result: ParseResult, 
                             file_type: str) -> Dict[str, List[Any]]:
        """
        Extract IOCs with advanced context-aware analysis
        
        Args:
            parse_result: Parsed data containing entries and basic IOCs
            file_type: Type of file being analyzed
            
        Returns:
            Dictionary of advanced IOCs with context and threat levels
        """
        advanced_iocs = {
            "ips": [],
            "domains": [],
            "urls": [],
            "emails": [],
            "hashes": [],
            "file_paths": [],
            "registry_keys": [],
            "bitcoin_addresses": [],
            "cves": [],
            "commands": [],
            "malicious_ips": [],
            "malicious_domains": [],
            "suspicious_strings": [],
            "base64_strings": [],
            "c2_indicators": [],
            "exfiltration_indicators": []
        }
        
        # Extract IOCs from all entries
        for entry in parse_result.entries:
            extracted = self._extract_iocs_from_text(entry.message, entry)
            
            # Merge extracted IOCs
            for ioc_type, iocs in extracted.items():
                if ioc_type in advanced_iocs:
                    advanced_iocs[ioc_type].extend(iocs)
        
        # Extract from additional metadata
        if parse_result.metadata.additional:
            metadata_text = json.dumps(parse_result.metadata.additional)
            metadata_iocs = self._extract_iocs_from_text(metadata_text)
            
            for ioc_type, iocs in metadata_iocs.items():
                if ioc_type in advanced_iocs:
                    advanced_iocs[ioc_type].extend(iocs)
        
        # Enhance basic IOCs with context
        enhanced_iocs = self._enhance_basic_iocs(parse_result.iocs, advanced_iocs)
        
        # Deduplicate and validate
        for ioc_type in advanced_iocs:
            if ioc_type in ["c2_indicators", "exfiltration_indicators"]:
                # These are dictionaries, not simple lists
                continue
            advanced_iocs[ioc_type] = list(set(advanced_iocs[ioc_type]))
            
            # Validate IOCs
            if ioc_type in self.validators:
                advanced_iocs[ioc_type] = [
                    ioc for ioc in advanced_iocs[ioc_type]
                    if self.validators[ioc_type](ioc)
                ]
        
        # Perform threat intelligence checks
        advanced_iocs = self._check_threat_intelligence(advanced_iocs)
        
        # Extract context-specific IOCs based on file type
        context_iocs = self._extract_context_specific_iocs(parse_result, file_type)
        for key, value in context_iocs.items():
            if key in advanced_iocs:
                if isinstance(value, list):
                    advanced_iocs[key].extend(value)
                else:
                    advanced_iocs[key] = value
        
        # Analyze relationships between IOCs
        ioc_relationships = self._analyze_ioc_relationships(advanced_iocs)
        advanced_iocs["relationships"] = ioc_relationships
        
        return advanced_iocs
    
    def _extract_iocs_from_text(self, text: str, 
                               entry: Optional[ParsedEntry] = None) -> Dict[str, List[Any]]:
        """Extract IOCs from text with context"""
        iocs = defaultdict(list)
        
        # Extract IPs
        for match in self.patterns["ipv4"].finditer(text):
            ip = match.group()
            if self._validate_ip(ip):
                iocs["ips"].append(ip)
        
        for match in self.patterns["ipv6"].finditer(text):
            ip = match.group()
            if self._validate_ip(ip):
                iocs["ips"].append(ip)
        
        # Extract domains
        for match in self.patterns["domain"].finditer(text):
            domain = match.group().lower()
            if self._validate_domain(domain):
                iocs["domains"].append(domain)
        
        # Extract URLs
        for match in self.patterns["url"].finditer(text):
            url = match.group()
            if self._validate_url(url):
                iocs["urls"].append(url)
        
        # Extract suspicious URLs
        for match in self.patterns["suspicious_url"].finditer(text):
            url = match.group()
            iocs["urls"].append(url)
            iocs["suspicious_strings"].append(f"Suspicious URL: {url}")
        
        # Extract emails
        for match in self.patterns["email"].finditer(text):
            email = match.group().lower()
            if self._validate_email(email):
                iocs["emails"].append(email)
        
        # Extract hashes
        for hash_type in ["md5", "sha1", "sha256", "sha512"]:
            for match in self.patterns[hash_type].finditer(text):
                hash_value = match.group().lower()
                if self._validate_hash(hash_value):
                    iocs["hashes"].append({
                        "value": hash_value,
                        "type": hash_type,
                        "context": text[max(0, match.start()-50):match.end()+50]
                    })
        
        # Extract file paths
        for match in self.patterns["windows_path"].finditer(text):
            path = match.group()
            if len(path) > 3:  # Avoid single drive letters
                iocs["file_paths"].append(path)
        
        for match in self.patterns["unix_path"].finditer(text):
            path = match.group()
            if len(path) > 1 and not path in ["/", "//", "///", "//"]:
                iocs["file_paths"].append(path)
        
        # Extract registry keys
        for match in self.patterns["registry_key"].finditer(text):
            iocs["registry_keys"].append(match.group())
        
        # Extract cryptocurrency addresses
        for match in self.patterns["bitcoin"].finditer(text):
            if self._validate_bitcoin_address(match.group()):
                iocs["bitcoin_addresses"].append(match.group())
        
        # Extract CVEs
        for match in self.patterns["cve"].finditer(text):
            iocs["cves"].append(match.group())
        
        # Extract base64 strings
        for match in self.patterns["base64"].finditer(text):
            b64_string = match.group()
            if len(b64_string) >= 40:  # Minimum length for interesting content
                try:
                    decoded = base64.b64decode(b64_string).decode('utf-8', errors='ignore')
                    if any(c.isprintable() for c in decoded):
                        iocs["base64_strings"].append({
                            "encoded": b64_string[:100] + "..." if len(b64_string) > 100 else b64_string,
                            "decoded_preview": decoded[:50] + "..." if len(decoded) > 50 else decoded
                        })
                except:
                    pass
        
        # Extract commands
        for match in self.patterns["suspicious_command"].finditer(text):
            iocs["commands"].append(match.group())
        
        # Extract PowerShell encoded commands
        for match in self.patterns["powershell_encoded"].finditer(text):
            iocs["commands"].append(match.group())
            iocs["suspicious_strings"].append(f"Encoded PowerShell: {match.group()}")
        
        # Check for C2 indicators
        for pattern_name, pattern in self.context_patterns.items():
            if pattern_name.startswith("c2_"):
                if pattern.search(text):
                    iocs["c2_indicators"].append({
                        "type": pattern_name,
                        "context": text[:200],
                        "severity": "high" if entry and entry.severity in ["error", "critical"] else "medium"
                    })
        
        # Check for exfiltration indicators
        if self.context_patterns["exfil_keywords"].search(text) or \
           self.context_patterns["large_transfer"].search(text):
            iocs["exfiltration_indicators"].append({
                "context": text[:200],
                "timestamp": entry.timestamp.isoformat() if entry and entry.timestamp else None
            })
        
        return dict(iocs)
    
    def _validate_ip(self, ip: str) -> bool:
        """Validate IP address"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            # Filter out local/private IPs unless suspicious
            if ip_obj.is_private or ip_obj.is_loopback:
                return False
            if ip in self.whitelists["ips"]:
                return False
            return True
        except:
            return False
    
    def _validate_domain(self, domain: str) -> bool:
        """Validate domain"""
        if len(domain) < 4 or "." not in domain:
            return False
        
        # Skip common file extensions
        if any(domain.endswith(ext) for ext in self.whitelists["file_extensions"]):
            return False
        
        # Skip whitelisted domains
        extracted = tldextract.extract(domain)
        if f"{extracted.domain}.{extracted.suffix}" in self.whitelists["domains"]:
            return False
        
        # Skip if no valid TLD
        if not extracted.suffix:
            return False
        
        return True
    
    def _validate_url(self, url: str) -> bool:
        """Validate URL"""
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                return False
            
            # Extract domain and validate
            domain = parsed.netloc.lower()
            if domain.startswith("www."):
                domain = domain[4:]
            
            return self._validate_domain(domain)
        except:
            return False
    
    def _validate_email(self, email: str) -> bool:
        """Validate email address"""
        if "@" not in email or email.count("@") != 1:
            return False
        
        local, domain = email.split("@")
        if not local or not domain:
            return False
        
        return self._validate_domain(domain)
    
    def _validate_hash(self, hash_value: str) -> bool:
        """Validate hash"""
        if hash_value in self.whitelists["common_hashes"]:
            return False
        
        # Check if it's a valid hex string
        try:
            int(hash_value, 16)
            return True
        except:
            return False
    
    def _validate_bitcoin_address(self, address: str) -> bool:
        """Validate Bitcoin address (basic check)"""
        if len(address) < 26 or len(address) > 35:
            return False
        
        # More sophisticated validation would check the checksum
        return True
    
    def _validate_cve(self, cve: str) -> bool:
        """Validate CVE format"""
        return bool(re.match(r'^CVE-\d{4}-\d{4,7}$', cve))
    
    def _enhance_basic_iocs(self, basic_iocs: Dict[str, List[str]], 
                           advanced_iocs: Dict[str, List[Any]]) -> Dict[str, List[Any]]:
        """Enhance basic IOCs with advanced ones"""
        # Merge basic IOCs
        for ioc_type, iocs in basic_iocs.items():
            if ioc_type in advanced_iocs:
                advanced_iocs[ioc_type].extend(iocs)
        
        return advanced_iocs
    
    def _check_threat_intelligence(self, iocs: Dict[str, List[Any]]) -> Dict[str, List[Any]]:
        """Check IOCs against threat intelligence"""
        # Check IPs
        for ip in iocs.get("ips", []):
            if ip in self.threat_indicators["malicious_ips"]:
                iocs["malicious_ips"].append({
                    "ip": ip,
                    "threat_type": "known_malicious",
                    "confidence": 0.95
                })
        
        # Check domains
        for domain in iocs.get("domains", []):
            if domain in self.threat_indicators["malicious_domains"]:
                iocs["malicious_domains"].append({
                    "domain": domain,
                    "threat_type": "known_malicious",
                    "confidence": 0.95
                })
            
            # Check for DGA patterns
            if self._is_dga_domain(domain):
                iocs["malicious_domains"].append({
                    "domain": domain,
                    "threat_type": "potential_dga",
                    "confidence": 0.7
                })
            
            # Check for phishing patterns
            if self.context_patterns["phishing_domains"].search(domain):
                iocs["malicious_domains"].append({
                    "domain": domain,
                    "threat_type": "potential_phishing",
                    "confidence": 0.8
                })
        
        # Check URLs for suspicious patterns
        for url in iocs.get("urls", []):
            parsed = urlparse(url)
            
            # Check for suspicious ports
            if parsed.port and parsed.port in self.threat_indicators["known_c2_ports"]:
                iocs["c2_indicators"].append({
                    "type": "suspicious_port",
                    "url": url,
                    "port": parsed.port,
                    "confidence": 0.8
                })
            
            # Check for suspicious paths
            suspicious_paths = ["/shell.php", "/c99.php", "/r57.php", "/upload.php", "/cmd.php"]
            if any(path in parsed.path.lower() for path in suspicious_paths):
                iocs["suspicious_strings"].append(f"Webshell URL: {url}")
        
        return iocs
    
    def _is_dga_domain(self, domain: str) -> bool:
        """Check if domain appears to be DGA-generated"""
        # Remove TLD
        parts = domain.split(".")
        if len(parts) < 2:
            return False
        
        domain_name = parts[0]
        
        # Check length
        if len(domain_name) < 8 or len(domain_name) > 30:
            return False
        
        # Calculate entropy
        import math
        from collections import Counter
        
        prob = [float(domain_name.count(c)) / len(domain_name) for c in dict(Counter(domain_name))]
        entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
        
        # High entropy suggests DGA
        if entropy > 3.5:
            # Additional checks
            vowels = sum(1 for c in domain_name if c in "aeiou")
            vowel_ratio = vowels / len(domain_name)
            
            # DGA domains often have low vowel ratio
            if vowel_ratio < 0.3:
                return True
        
        return False
    
    def _extract_context_specific_iocs(self, parse_result: ParseResult, 
                                      file_type: str) -> Dict[str, Any]:
        """Extract IOCs specific to file type"""
        context_iocs = defaultdict(list)
        
        if file_type == "pcap" or file_type == "network":
            # Extract network-specific IOCs
            for entry in parse_result.entries:
                # Look for User-Agent strings
                if "User-Agent:" in entry.message:
                    ua = entry.message.split("User-Agent:")[1].split("\n")[0].strip()
                    if ua in self.threat_indicators["suspicious_user_agents"]:
                        context_iocs["suspicious_strings"].append(f"Suspicious User-Agent: {ua}")
                
                # Look for DNS queries to suspicious domains
                if "DNS query" in entry.message or "DNS response" in entry.message:
                    for domain in parse_result.iocs.get("domains", []):
                        if self._is_dga_domain(domain):
                            context_iocs["c2_indicators"].append({
                                "type": "dga_dns_query",
                                "domain": domain,
                                "confidence": 0.8
                            })
        
        elif file_type == "email":
            # Extract email-specific IOCs
            for entry in parse_result.entries:
                # Check for phishing indicators
                if self.context_patterns["phishing_keywords"].search(entry.message):
                    context_iocs["suspicious_strings"].append("Phishing keywords detected")
                
                # Look for suspicious attachments
                attachment_pattern = re.compile(r'filename["\']?[:=]\s*["\']?([^"\';\s]+)["\']?', re.I)
                for match in attachment_pattern.finditer(entry.message):
                    filename = match.group(1)
                    suspicious_exts = [".exe", ".scr", ".vbs", ".js", ".zip", ".rar"]
                    if any(filename.lower().endswith(ext) for ext in suspicious_exts):
                        context_iocs["suspicious_strings"].append(f"Suspicious attachment: {filename}")
        
        elif file_type in ["apache", "nginx", "iis"]:
            # Extract web server specific IOCs
            for entry in parse_result.entries:
                # SQL injection attempts
                sqli_pattern = re.compile(r'(union.*select|select.*from|insert.*into|update.*set|delete.*from|drop.*table)', re.I)
                if sqli_pattern.search(entry.message):
                    context_iocs["suspicious_strings"].append("SQL injection attempt detected")
                
                # XSS attempts
                xss_pattern = re.compile(r'<script|javascript:|onerror=|onload=|onclick=', re.I)
                if xss_pattern.search(entry.message):
                    context_iocs["suspicious_strings"].append("XSS attempt detected")
                
                # Path traversal
                if "../" in entry.message or "..%2F" in entry.message or "..%5C" in entry.message:
                    context_iocs["suspicious_strings"].append("Path traversal attempt detected")
        
        return dict(context_iocs)
    
    def _analyze_ioc_relationships(self, iocs: Dict[str, List[Any]]) -> List[Dict[str, Any]]:
        """Analyze relationships between IOCs"""
        relationships = []
        
        # Domain to IP relationships
        domains = iocs.get("domains", [])
        ips = iocs.get("ips", [])
        
        # In real implementation, would do DNS lookups
        # For now, look for co-occurrence in URLs
        for url in iocs.get("urls", []):
            parsed = urlparse(url)
            domain = parsed.netloc
            
            # Check if URL contains both domain and IP
            for ip in ips:
                if ip in url and domain in domains:
                    relationships.append({
                        "type": "domain_ip_mapping",
                        "domain": domain,
                        "ip": ip,
                        "source": "url_analysis"
                    })
        
        # Hash to filename relationships
        for path in iocs.get("file_paths", []):
            filename = path.split("\\")[-1] if "\\" in path else path.split("/")[-1]
            
            # Look for hash mentions near filenames
            for hash_info in iocs.get("hashes", []):
                if filename.lower() in hash_info.get("context", "").lower():
                    relationships.append({
                        "type": "file_hash_mapping",
                        "file": filename,
                        "hash": hash_info["value"],
                        "hash_type": hash_info["type"]
                    })
        
        # C2 relationships
        c2_domains = [d["domain"] for d in iocs.get("malicious_domains", []) 
                     if d.get("threat_type") in ["potential_dga", "known_malicious"]]
        
        if c2_domains and iocs.get("c2_indicators"):
            relationships.append({
                "type": "c2_infrastructure",
                "domains": c2_domains[:5],  # Top 5
                "indicators": len(iocs["c2_indicators"])
            })
        
        return relationships