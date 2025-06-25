"""
EML Email Parser for SecuNik LogX
Parses email files (.eml, .msg) with security analysis
Detects phishing, malicious attachments, and suspicious content
"""

import email
import asyncio
from datetime import datetime
from typing import Dict, Any, List, Optional, Set, AsyncGenerator, Tuple
from pathlib import Path
from collections import defaultdict
import re
import base64
import quopri
import hashlib
import mimetypes
from urllib.parse import urlparse
import json

from ..base_parser import BaseParser, ParseResult, ParsedEntry, FileMetadata, IOCs


class EMLParser(BaseParser):
    """Parser for email files (EML, MSG formats)"""
    
    name = "eml"
    description = "Parses email files with security analysis"
    supported_extensions = ['.eml', '.msg', '.email', '.mime']
    
    # Phishing indicators
    PHISHING_INDICATORS = {
        'urgency_words': [
            'urgent', 'immediate', 'expire', 'suspend', 'deadline',
            'limited time', 'act now', 'verify account', 'confirm identity'
        ],
        'credential_words': [
            'password', 'username', 'pin', 'ssn', 'social security',
            'credit card', 'account number', 'routing number', 'cvv'
        ],
        'financial_words': [
            'payment', 'invoice', 'refund', 'tax', 'irs', 'hmrc',
            'wire transfer', 'bitcoin', 'cryptocurrency', 'wallet'
        ],
        'threat_words': [
            'locked', 'blocked', 'suspended', 'disabled', 'unauthorized',
            'security alert', 'breach', 'compromised', 'illegal'
        ]
    }
    
    # Suspicious attachment types
    SUSPICIOUS_EXTENSIONS = {
        '.exe': 'Executable file',
        '.scr': 'Screensaver executable',
        '.vbs': 'Visual Basic Script',
        '.js': 'JavaScript file',
        '.jar': 'Java Archive',
        '.bat': 'Batch file',
        '.cmd': 'Command file',
        '.com': 'DOS executable',
        '.pif': 'Program Information File',
        '.lnk': 'Windows Shortcut',
        '.ps1': 'PowerShell script',
        '.reg': 'Registry file',
        '.hta': 'HTML Application',
        '.iso': 'Disk image',
        '.img': 'Disk image',
        '.rar': 'RAR archive (often password protected malware)',
        '.ace': 'ACE archive (exploit prone)'
    }
    
    # Email header anomalies
    HEADER_CHECKS = {
        'spf_fail': re.compile(r'spf=fail|spf=softfail', re.IGNORECASE),
        'dkim_fail': re.compile(r'dkim=fail', re.IGNORECASE),
        'dmarc_fail': re.compile(r'dmarc=fail', re.IGNORECASE),
        'suspicious_received': re.compile(r'forged|spoofed|localhost|127\.0\.0\.1', re.IGNORECASE),
        'suspicious_mailer': re.compile(r'PHPMailer|Python|bulk\s*mailer|mass\s*mail', re.IGNORECASE)
    }
    
    # URL shorteners
    URL_SHORTENERS = [
        'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'short.link',
        't.co', 'tiny.cc', 'is.gd', 'buff.ly', 'y2u.be'
    ]
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.attachments = []
        self.suspicious_urls = []
        self.phishing_score = 0
        self.security_issues = []
        
    async def parse(self) -> ParseResult:
        """Parse email file"""
        result = ParseResult(
            file_path=str(self.file_path),
            file_type="email",
            parser_name=self.name
        )
        
        try:
            # Get file metadata
            result.metadata = await self._get_file_metadata()
            
            # Parse email
            email_msg = await self._parse_email_file()
            if not email_msg:
                result.errors.append("Failed to parse email file")
                return result
                
            # Extract email metadata
            email_entry = await self._create_email_entry(email_msg)
            result.entries.append(email_entry)
            
            # Extract and analyze headers
            header_entries = await self._analyze_headers(email_msg)
            result.entries.extend(header_entries)
            
            # Extract and analyze body
            body_entries = await self._analyze_body(email_msg)
            result.entries.extend(body_entries)
            
            # Extract and analyze attachments
            attachment_entries = await self._analyze_attachments(email_msg)
            result.entries.extend(attachment_entries)
            
            # Extract IOCs from all content
            for entry in result.entries:
                result.iocs.merge(self._extract_email_iocs(entry))
                
            # Add security findings
            for issue in self.security_issues:
                result.entries.append(issue)
                
            # Calculate phishing score
            phishing_assessment = self._calculate_phishing_score()
            
            # Add summary
            result.metadata.additional.update({
                "email_subject": email_msg.get('Subject', 'No Subject'),
                "email_from": email_msg.get('From', 'Unknown'),
                "email_to": email_msg.get('To', 'Unknown'),
                "email_date": email_msg.get('Date', 'Unknown'),
                "attachment_count": len(self.attachments),
                "suspicious_attachments": sum(1 for a in self.attachments if a['suspicious']),
                "phishing_score": self.phishing_score,
                "phishing_assessment": phishing_assessment,
                "suspicious_urls": len(self.suspicious_urls),
                "security_issues": len(self.security_issues),
                "authentication_results": self._get_auth_results(email_msg)
            })
            
            self.logger.info(f"Parsed email with {len(self.attachments)} attachments")
            
        except Exception as e:
            self.logger.error(f"Error parsing email: {e}")
            result.errors.append(f"Parse error: {str(e)}")
            
        return result
        
    async def _parse_email_file(self) -> Optional[email.message.Message]:
        """Parse email file into message object"""
        # Try parsing as EML
        try:
            async with self._open_file('rb') as f:
                content = await f.read()
                
            # Parse email
            if self.file_path.suffix.lower() == '.msg':
                # MSG files need special handling
                # For now, we'll try to extract what we can
                return self._parse_msg_file(content)
            else:
                # Standard EML parsing
                return email.message_from_bytes(content)
                
        except Exception as e:
            self.logger.error(f"Error parsing email file: {e}")
            return None
            
    def _parse_msg_file(self, content: bytes) -> Optional[email.message.Message]:
        """Basic MSG file parsing (simplified)"""
        # MSG files are complex OLE structures
        # This is a simplified extraction focusing on key fields
        
        try:
            # Look for common patterns in MSG files
            msg = email.message.EmailMessage()
            
            # Extract what we can from the binary content
            # This is very simplified - real MSG parsing requires python-oletools
            
            # Try to find email addresses
            email_pattern = rb'[\w\.\-]+@[\w\.\-]+'
            emails = re.findall(email_pattern, content)
            
            if emails:
                msg['From'] = emails[0].decode('utf-8', errors='ignore')
                if len(emails) > 1:
                    msg['To'] = emails[1].decode('utf-8', errors='ignore')
                    
            # Try to find subject
            subject_patterns = [
                rb'Subject:(.*?)\r\n',
                rb'\x00S\x00u\x00b\x00j\x00e\x00c\x00t\x00.*?\x00\x00(.*?)\x00\x00'
            ]
            
            for pattern in subject_patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    subject = match.group(1).decode('utf-8', errors='ignore').strip()
                    msg['Subject'] = subject
                    break
                    
            # Set a note about limited MSG support
            msg.set_payload("Note: Limited MSG file support. Some data may be missing.")
            
            return msg
            
        except Exception as e:
            self.logger.error(f"Error parsing MSG file: {e}")
            return None
            
    async def _create_email_entry(self, msg: email.message.Message) -> ParsedEntry:
        """Create main email entry"""
        # Extract key fields
        subject = msg.get('Subject', 'No Subject')
        from_addr = msg.get('From', 'Unknown')
        to_addr = msg.get('To', 'Unknown')
        date_str = msg.get('Date', '')
        
        # Parse date
        try:
            timestamp = email.utils.parsedate_to_datetime(date_str)
        except:
            timestamp = datetime.now()
            
        # Clean addresses
        from_email = self._extract_email_address(from_addr)
        to_email = self._extract_email_address(to_addr)
        
        entry = ParsedEntry(
            timestamp=timestamp,
            source=from_email,
            event_type="email",
            severity="info",
            message=f"Email: {subject}",
            raw_data={
                'headers': dict(msg.items()),
                'subject': subject,
                'from': from_addr,
                'to': to_addr
            }
        )
        
        entry.parsed_data = {
            'subject': subject,
            'from_address': from_email,
            'from_display': self._extract_display_name(from_addr),
            'to_address': to_email,
            'message_id': msg.get('Message-ID', ''),
            'in_reply_to': msg.get('In-Reply-To', ''),
            'return_path': msg.get('Return-Path', ''),
            'reply_to': msg.get('Reply-To', '')
        }
        
        return entry
        
    async def _analyze_headers(self, msg: email.message.Message) -> List[ParsedEntry]:
        """Analyze email headers for security issues"""
        entries = []
        
        # Check authentication results
        auth_results = msg.get('Authentication-Results', '')
        if auth_results:
            for check_name, pattern in self.HEADER_CHECKS.items():
                if pattern.search(auth_results):
                    issue = ParsedEntry(
                        timestamp=datetime.now(),
                        source="email_header",
                        event_type="security_alert",
                        severity="warning",
                        message=f"Email authentication failure: {check_name}",
                        raw_data={'header': 'Authentication-Results', 'value': auth_results}
                    )
                    issue.tags = ["email_auth_fail", check_name]
                    self.security_issues.append(issue)
                    self.phishing_score += 20
                    
        # Analyze Received headers
        received_headers = msg.get_all('Received', [])
        for received in received_headers:
            # Check for suspicious patterns
            if self.HEADER_CHECKS['suspicious_received'].search(received):
                issue = ParsedEntry(
                    timestamp=datetime.now(),
                    source="email_header",
                    event_type="security_alert",
                    severity="warning",
                    message="Suspicious Received header detected",
                    raw_data={'header': 'Received', 'value': received}
                )
                issue.tags = ["suspicious_header", "potential_spoof"]
                self.security_issues.append(issue)
                self.phishing_score += 15
                
        # Check X-Mailer
        x_mailer = msg.get('X-Mailer', '')
        if x_mailer and self.HEADER_CHECKS['suspicious_mailer'].search(x_mailer):
            issue = ParsedEntry(
                timestamp=datetime.now(),
                source="email_header",
                event_type="security_alert",
                severity="warning",
                message=f"Suspicious mail client: {x_mailer}",
                raw_data={'header': 'X-Mailer', 'value': x_mailer}
            )
            issue.tags = ["suspicious_mailer", "bulk_email"]
            self.security_issues.append(issue)
            self.phishing_score += 10
            
        # Check for spoofing indicators
        from_addr = msg.get('From', '')
        return_path = msg.get('Return-Path', '')
        reply_to = msg.get('Reply-To', '')
        
        from_email = self._extract_email_address(from_addr)
        return_email = self._extract_email_address(return_path)
        reply_email = self._extract_email_address(reply_to)
        
        # Check for mismatch
        if from_email and return_email and from_email != return_email:
            if not self._same_domain(from_email, return_email):
                issue = ParsedEntry(
                    timestamp=datetime.now(),
                    source="email_header",
                    event_type="security_alert",
                    severity="warning",
                    message="From/Return-Path mismatch detected",
                    raw_data={
                        'from': from_email,
                        'return_path': return_email
                    }
                )
                issue.tags = ["header_mismatch", "potential_spoof"]
                self.security_issues.append(issue)
                self.phishing_score += 25
                
        return entries
        
    async def _analyze_body(self, msg: email.message.Message) -> List[ParsedEntry]:
        """Analyze email body for security issues"""
        entries = []
        
        # Extract body content
        body_text = ""
        body_html = ""
        
        for part in msg.walk():
            if part.get_content_type() == 'text/plain':
                try:
                    body_text = part.get_content()
                except:
                    body_text = str(part.get_payload(decode=True), 'utf-8', errors='ignore')
                    
            elif part.get_content_type() == 'text/html':
                try:
                    body_html = part.get_content()
                except:
                    body_html = str(part.get_payload(decode=True), 'utf-8', errors='ignore')
                    
        # Analyze text content
        all_content = body_text + " " + body_html
        
        # Check for phishing indicators
        for category, words in self.PHISHING_INDICATORS.items():
            matches = []
            for word in words:
                if word.lower() in all_content.lower():
                    matches.append(word)
                    
            if matches:
                self.phishing_score += len(matches) * 5
                
                if len(matches) >= 3:
                    issue = ParsedEntry(
                        timestamp=datetime.now(),
                        source="email_body",
                        event_type="security_alert",
                        severity="warning",
                        message=f"Multiple {category} indicators found: {', '.join(matches[:5])}",
                        raw_data={'category': category, 'matches': matches}
                    )
                    issue.tags = ["phishing_content", category]
                    self.security_issues.append(issue)
                    
        # Extract and analyze URLs
        urls = self._extract_urls(all_content)
        for url in urls:
            url_entry = await self._analyze_url(url)
            if url_entry:
                entries.append(url_entry)
                
        # Check for credential harvesting forms in HTML
        if body_html:
            forms = re.findall(r'<form[^>]*>(.*?)</form>', body_html, re.IGNORECASE | re.DOTALL)
            for form in forms:
                if any(field in form.lower() for field in ['password', 'pin', 'ssn', 'credit']):
                    issue = ParsedEntry(
                        timestamp=datetime.now(),
                        source="email_body",
                        event_type="security_alert",
                        severity="critical",
                        message="Credential harvesting form detected",
                        raw_data={'form_snippet': form[:200]}
                    )
                    issue.tags = ["credential_harvesting", "phishing_form"]
                    self.security_issues.append(issue)
                    self.phishing_score += 40
                    
        return entries
        
    async def _analyze_attachments(self, msg: email.message.Message) -> List[ParsedEntry]:
        """Analyze email attachments"""
        entries = []
        
        for part in msg.walk():
            if part.get_content_disposition() == 'attachment':
                filename = part.get_filename()
                if not filename:
                    filename = 'unknown_attachment'
                    
                # Get attachment data
                try:
                    attachment_data = part.get_payload(decode=True)
                except:
                    attachment_data = b''
                    
                # Calculate hash
                file_hash = hashlib.sha256(attachment_data).hexdigest() if attachment_data else ''
                
                # Check file extension
                file_ext = Path(filename).suffix.lower()
                is_suspicious = file_ext in self.SUSPICIOUS_EXTENSIONS
                
                attachment_info = {
                    'filename': filename,
                    'size': len(attachment_data),
                    'hash': file_hash,
                    'content_type': part.get_content_type(),
                    'extension': file_ext,
                    'suspicious': is_suspicious
                }
                
                self.attachments.append(attachment_info)
                
                # Create entry
                severity = "warning" if is_suspicious else "info"
                entry = ParsedEntry(
                    timestamp=datetime.now(),
                    source="email_attachment",
                    event_type="attachment",
                    severity=severity,
                    message=f"Attachment: {filename} ({len(attachment_data):,} bytes)",
                    raw_data=attachment_info
                )
                
                entry.parsed_data = attachment_info
                
                if is_suspicious:
                    entry.tags = ["suspicious_attachment", file_ext[1:]]
                    self.phishing_score += 30
                    
                    # Create alert
                    alert = ParsedEntry(
                        timestamp=datetime.now(),
                        source="email_attachment",
                        event_type="security_alert",
                        severity="critical",
                        message=f"Suspicious attachment type: {filename} ({self.SUSPICIOUS_EXTENSIONS[file_ext]})",
                        raw_data=attachment_info
                    )
                    alert.tags = ["malicious_attachment", "high_risk"]
                    self.security_issues.append(alert)
                    
                entries.append(entry)
                
                # Check for double extensions
                if filename.count('.') > 1:
                    parts = filename.split('.')
                    if len(parts) >= 3 and parts[-2].lower() in ['jpg', 'pdf', 'doc', 'txt']:
                        alert = ParsedEntry(
                            timestamp=datetime.now(),
                            source="email_attachment",
                            event_type="security_alert",
                            severity="critical",
                            message=f"Double extension detected: {filename}",
                            raw_data=attachment_info
                        )
                        alert.tags = ["double_extension", "deception"]
                        self.security_issues.append(alert)
                        self.phishing_score += 35
                        
        return entries
        
    async def _analyze_url(self, url: str) -> Optional[ParsedEntry]:
        """Analyze URL for suspicious characteristics"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Check for URL shorteners
            if any(shortener in domain for shortener in self.URL_SHORTENERS):
                self.suspicious_urls.append(url)
                self.phishing_score += 15
                
                return ParsedEntry(
                    timestamp=datetime.now(),
                    source="email_url",
                    event_type="security_alert",
                    severity="warning",
                    message=f"URL shortener detected: {url}",
                    raw_data={'url': url, 'domain': domain}
                )
                
            # Check for homograph attacks
            if self._has_homograph(domain):
                self.suspicious_urls.append(url)
                self.phishing_score += 25
                
                return ParsedEntry(
                    timestamp=datetime.now(),
                    source="email_url",
                    event_type="security_alert",
                    severity="warning",
                    message=f"Possible homograph attack: {domain}",
                    raw_data={'url': url, 'domain': domain}
                )
                
            # Check for suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download', '.bid']
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                self.suspicious_urls.append(url)
                self.phishing_score += 20
                
                return ParsedEntry(
                    timestamp=datetime.now(),
                    source="email_url",
                    event_type="security_alert",
                    severity="warning",
                    message=f"Suspicious TLD in URL: {url}",
                    raw_data={'url': url, 'domain': domain}
                )
                
            # Check for IP addresses instead of domains
            if re.match(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', domain):
                self.suspicious_urls.append(url)
                self.phishing_score += 20
                
                return ParsedEntry(
                    timestamp=datetime.now(),
                    source="email_url",
                    event_type="security_alert",
                    severity="warning",
                    message=f"IP address URL detected: {url}",
                    raw_data={'url': url, 'ip': domain}
                )
                
        except Exception as e:
            self.logger.debug(f"Error analyzing URL {url}: {e}")
            
        return None
        
    def _extract_email_iocs(self, entry: ParsedEntry) -> IOCs:
        """Extract IOCs from email content"""
        iocs = IOCs()
        
        # Extract from raw data
        raw_str = json.dumps(entry.raw_data)
        
        # Extract email addresses
        emails = re.findall(r'[\w\.\-]+@[\w\.\-]+', raw_str)
        for email_addr in emails:
            if '@' in email_addr:
                iocs.emails.add(email_addr.lower())
                # Add domain
                domain = email_addr.split('@')[1]
                iocs.domains.add(domain.lower())
                
        # Extract URLs
        urls = self._extract_urls(raw_str)
        for url in urls:
            iocs.urls.add(url)
            # Extract domain
            try:
                parsed = urlparse(url)
                if parsed.netloc:
                    iocs.domains.add(parsed.netloc.lower())
            except:
                pass
                
        # Extract IPs
        ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', raw_str)
        for ip in ips:
            iocs.ips.add(ip)
            
        # Extract file hashes from attachments
        if 'hash' in entry.parsed_data:
            hash_val = entry.parsed_data['hash']
            if hash_val:
                iocs.hashes.add(hash_val)
                
        return iocs
        
    def _extract_urls(self, text: str) -> List[str]:
        """Extract URLs from text"""
        # Regex for URLs
        url_pattern = re.compile(
            r'https?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )
        
        urls = []
        for match in url_pattern.finditer(text):
            url = match.group(0)
            # Clean up URL
            url = url.rstrip('.,;:)')
            urls.append(url)
            
        return urls
        
    def _extract_email_address(self, addr_str: str) -> str:
        """Extract email address from address string"""
        if not addr_str:
            return ""
            
        # Handle "Display Name <email@domain.com>" format
        match = re.search(r'<([^>]+)>', addr_str)
        if match:
            return match.group(1).lower()
            
        # Handle plain email
        match = re.search(r'[\w\.\-]+@[\w\.\-]+', addr_str)
        if match:
            return match.group(0).lower()
            
        return addr_str.lower()
        
    def _extract_display_name(self, addr_str: str) -> str:
        """Extract display name from address string"""
        if not addr_str:
            return ""
            
        # Handle "Display Name <email@domain.com>" format
        match = re.match(r'^([^<]+)<', addr_str)
        if match:
            return match.group(1).strip().strip('"')
            
        return ""
        
    def _same_domain(self, email1: str, email2: str) -> bool:
        """Check if two emails are from the same domain"""
        try:
            domain1 = email1.split('@')[1].lower()
            domain2 = email2.split('@')[1].lower()
            
            # Check exact match or parent domain
            if domain1 == domain2:
                return True
                
            # Check if one is subdomain of other
            if domain1.endswith('.' + domain2) or domain2.endswith('.' + domain1):
                return True
                
        except:
            pass
            
        return False
        
    def _has_homograph(self, domain: str) -> bool:
        """Check for potential homograph attacks"""
        # Common homograph substitutions
        homographs = {
            'o': ['0'],
            'i': ['1', 'l'],
            'e': ['3'],
            'a': ['@'],
            's': ['5', '$'],
            'g': ['9']
        }
        
        # Check for mix of scripts (Latin + Cyrillic, etc)
        if re.search(r'[а-яА-Я]', domain) and re.search(r'[a-zA-Z]', domain):
            return True
            
        # Check for suspicious substitutions in common domains
        common_targets = ['google', 'microsoft', 'apple', 'amazon', 'paypal', 'ebay']
        for target in common_targets:
            if target in domain:
                # Check for homograph substitutions
                for char, subs in homographs.items():
                    for sub in subs:
                        if sub in domain:
                            return True
                            
        return False
        
    def _calculate_phishing_score(self) -> str:
        """Calculate phishing assessment based on score"""
        if self.phishing_score >= 100:
            return "CRITICAL - Very likely phishing"
        elif self.phishing_score >= 70:
            return "HIGH - Likely phishing"
        elif self.phishing_score >= 40:
            return "MEDIUM - Possible phishing"
        elif self.phishing_score >= 20:
            return "LOW - Some suspicious indicators"
        else:
            return "SAFE - No significant threats detected"
            
    def _get_auth_results(self, msg: email.message.Message) -> Dict[str, str]:
        """Extract authentication results"""
        auth_results = {}
        
        auth_header = msg.get('Authentication-Results', '')
        if auth_header:
            # Extract SPF
            spf_match = re.search(r'spf=(\w+)', auth_header)
            if spf_match:
                auth_results['spf'] = spf_match.group(1)
                
            # Extract DKIM
            dkim_match = re.search(r'dkim=(\w+)', auth_header)
            if dkim_match:
                auth_results['dkim'] = dkim_match.group(1)
                
            # Extract DMARC
            dmarc_match = re.search(r'dmarc=(\w+)', auth_header)
            if dmarc_match:
                auth_results['dmarc'] = dmarc_match.group(1)
                
        return auth_results