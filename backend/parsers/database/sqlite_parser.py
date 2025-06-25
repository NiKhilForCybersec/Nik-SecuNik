"""
SQLite Database Parser for SecuNik LogX
Parses SQLite databases for forensic analysis
Extracts data, detects sensitive information, and identifies security issues
"""

import sqlite3
import asyncio
from datetime import datetime
from typing import Dict, Any, List, Optional, Set, AsyncGenerator, Tuple
from pathlib import Path
from collections import defaultdict
import re
import json
import hashlib
import base64

from ..base_parser import BaseParser, ParseResult, ParsedEntry, FileMetadata, IOCs


class SQLiteParser(BaseParser):
    """Parser for SQLite database files"""
    
    name = "sqlite"
    description = "Parses SQLite databases for security analysis"
    supported_extensions = ['.db', '.sqlite', '.sqlite3', '.db3', '.s3db']
    
    # SQLite header magic
    SQLITE_MAGIC = b'SQLite format 3\x00'
    
    # Common sensitive table patterns
    SENSITIVE_TABLES = {
        'users': ['password', 'email', 'username', 'ssn', 'credit_card'],
        'accounts': ['account_number', 'routing_number', 'balance', 'pin'],
        'auth': ['token', 'session', 'api_key', 'secret'],
        'cookies': ['value', 'host_key', 'encrypted_value'],
        'credentials': ['username', 'password', 'key', 'secret'],
        'messages': ['content', 'body', 'from', 'to'],
        'history': ['url', 'title', 'visit_count'],
        'downloads': ['url', 'path', 'referrer'],
        'config': ['value', 'setting', 'parameter'],
        'logs': ['message', 'data', 'payload']
    }
    
    # Browser artifact patterns
    BROWSER_ARTIFACTS = {
        'chrome': {
            'cookies': 'cookies',
            'history': 'urls',
            'downloads': 'downloads',
            'logins': 'logins',
            'autofill': 'autofill'
        },
        'firefox': {
            'cookies': 'moz_cookies',
            'history': 'moz_places',
            'downloads': 'moz_downloads',
            'logins': 'logins',
            'bookmarks': 'moz_bookmarks'
        }
    }
    
    # Mobile app databases
    MOBILE_APP_PATTERNS = {
        'whatsapp': {
            'messages': 'messages',
            'contacts': 'wa_contacts',
            'media': 'message_media'
        },
        'telegram': {
            'messages': 'messages',
            'dialogs': 'dialogs',
            'users': 'users'
        },
        'signal': {
            'messages': 'sms',
            'identities': 'identities',
            'sessions': 'sessions'
        }
    }
    
    # Malware artifact patterns
    MALWARE_PATTERNS = {
        'c2_urls': r'https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',
        'base64_payload': r'[A-Za-z0-9+/]{50,}={0,2}',
        'obfuscated': r'\\x[0-9a-fA-F]{2}',
        'suspicious_domains': r'\.(?:tk|ml|ga|cf|bit|onion|i2p)\b',
        'crypto_wallet': r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40}'
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.tables = {}
        self.sensitive_data = []
        self.browser_artifacts = []
        self.app_artifacts = []
        self.suspicious_entries = []
        self.extracted_credentials = []
        
    async def parse(self) -> ParseResult:
        """Parse SQLite database file"""
        result = ParseResult(
            file_path=str(self.file_path),
            file_type="sqlite",
            parser_name=self.name
        )
        
        try:
            # Get file metadata
            result.metadata = await self._get_file_metadata()
            
            # Verify SQLite file
            is_valid = await self._verify_sqlite()
            if not is_valid:
                result.errors.append("Invalid SQLite database file")
                return result
                
            # Connect to database
            conn = await self._connect_db()
            if not conn:
                result.errors.append("Failed to connect to SQLite database")
                return result
                
            try:
                # Get database info
                db_info = await self._get_database_info(conn)
                result.metadata.additional.update(db_info)
                
                # Create main database entry
                db_entry = ParsedEntry(
                    timestamp=datetime.now(),
                    source=self.file_path.name,
                    event_type="database",
                    severity="info",
                    message=f"SQLite database: {self.file_path.name}",
                    raw_data=db_info
                )
                result.entries.append(db_entry)
                
                # Analyze tables
                await self._analyze_tables(conn)
                
                # Extract data
                await self._extract_sensitive_data(conn)
                
                # Detect browser artifacts
                await self._detect_browser_artifacts(conn)
                
                # Detect app artifacts
                await self._detect_app_artifacts(conn)
                
                # Scan for malware indicators
                await self._scan_for_malware(conn)
                
                # Add findings to results
                for finding in self.sensitive_data[:100]:  # Limit
                    result.entries.append(finding)
                    
                for artifact in self.browser_artifacts[:50]:
                    result.entries.append(artifact)
                    
                for artifact in self.app_artifacts[:50]:
                    result.entries.append(artifact)
                    
                for suspicious in self.suspicious_entries[:50]:
                    result.entries.append(suspicious)
                    
                # Extract IOCs
                for entry in result.entries:
                    result.iocs.merge(self._extract_sqlite_iocs(entry))
                    
                # Generate summary
                result.metadata.additional.update({
                    'table_count': len(self.tables),
                    'total_records': sum(t.get('row_count', 0) for t in self.tables.values()),
                    'sensitive_data_found': len(self.sensitive_data),
                    'browser_artifacts': len(self.browser_artifacts),
                    'app_artifacts': len(self.app_artifacts),
                    'suspicious_entries': len(self.suspicious_entries),
                    'extracted_credentials': len(self.extracted_credentials),
                    'database_type': self._identify_database_type(),
                    'security_assessment': self._assess_security()
                })
                
                self.logger.info(f"Parsed SQLite database with {len(self.tables)} tables")
                
            finally:
                conn.close()
                
        except Exception as e:
            self.logger.error(f"Error parsing SQLite database: {e}")
            result.errors.append(f"Parse error: {str(e)}")
            
        return result
        
    async def _verify_sqlite(self) -> bool:
        """Verify SQLite file format"""
        async with self._open_file('rb') as f:
            header = await f.read(16)
            
        return header == self.SQLITE_MAGIC
        
    async def _connect_db(self) -> Optional[sqlite3.Connection]:
        """Connect to SQLite database"""
        try:
            # Use read-only connection for safety
            conn = sqlite3.connect(f'file:{self.file_path}?mode=ro', uri=True)
            conn.row_factory = sqlite3.Row
            return conn
        except Exception as e:
            self.logger.error(f"Failed to connect to database: {e}")
            return None
            
    async def _get_database_info(self, conn: sqlite3.Connection) -> Dict:
        """Get database metadata"""
        info = {
            'page_size': 0,
            'page_count': 0,
            'encoding': '',
            'user_version': 0,
            'application_id': 0,
            'sqlite_version': ''
        }
        
        try:
            # Get PRAGMA values
            cursor = conn.execute("PRAGMA page_size")
            info['page_size'] = cursor.fetchone()[0]
            
            cursor = conn.execute("PRAGMA page_count")
            info['page_count'] = cursor.fetchone()[0]
            
            cursor = conn.execute("PRAGMA encoding")
            info['encoding'] = cursor.fetchone()[0]
            
            cursor = conn.execute("PRAGMA user_version")
            info['user_version'] = cursor.fetchone()[0]
            
            cursor = conn.execute("PRAGMA application_id")
            info['application_id'] = cursor.fetchone()[0]
            
            cursor = conn.execute("SELECT sqlite_version()")
            info['sqlite_version'] = cursor.fetchone()[0]
            
            info['database_size'] = info['page_size'] * info['page_count']
            
        except Exception as e:
            self.logger.debug(f"Error getting database info: {e}")
            
        return info
        
    async def _analyze_tables(self, conn: sqlite3.Connection):
        """Analyze database tables"""
        try:
            # Get list of tables
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
            
            for row in cursor:
                table_name = row[0]
                
                # Get table info
                table_info = {
                    'name': table_name,
                    'columns': [],
                    'row_count': 0,
                    'has_sensitive_data': False
                }
                
                # Get columns
                col_cursor = conn.execute(f"PRAGMA table_info({table_name})")
                for col in col_cursor:
                    col_info = {
                        'name': col[1],
                        'type': col[2],
                        'notnull': col[3],
                        'default': col[4],
                        'pk': col[5]
                    }
                    table_info['columns'].append(col_info)
                    
                    # Check for sensitive column names
                    col_lower = col[1].lower()
                    if any(sensitive in col_lower for sensitive in 
                          ['password', 'passwd', 'secret', 'token', 'key', 'ssn', 
                           'credit', 'card', 'cvv', 'pin']):
                        table_info['has_sensitive_data'] = True
                        
                # Get row count
                try:
                    count_cursor = conn.execute(f"SELECT COUNT(*) FROM {table_name}")
                    table_info['row_count'] = count_cursor.fetchone()[0]
                except:
                    table_info['row_count'] = 0
                    
                self.tables[table_name] = table_info
                
                # Yield control
                await asyncio.sleep(0)
                
        except Exception as e:
            self.logger.error(f"Error analyzing tables: {e}")
            
    async def _extract_sensitive_data(self, conn: sqlite3.Connection):
        """Extract sensitive data from tables"""
        for table_name, table_info in self.tables.items():
            if not table_info['has_sensitive_data'] or table_info['row_count'] == 0:
                continue
                
            # Check against known sensitive patterns
            table_lower = table_name.lower()
            
            for pattern, columns in self.SENSITIVE_TABLES.items():
                if pattern in table_lower:
                    # Look for sensitive columns
                    for col in table_info['columns']:
                        col_lower = col['name'].lower()
                        
                        if any(sens in col_lower for sens in columns):
                            # Extract sample data
                            await self._extract_column_data(
                                conn, table_name, col['name'], 'sensitive'
                            )
                            
            # Yield control
            await asyncio.sleep(0)
            
    async def _extract_column_data(self, conn: sqlite3.Connection, 
                                 table: str, column: str, data_type: str):
        """Extract data from specific column"""
        try:
            # Limit extraction for safety
            cursor = conn.execute(
                f"SELECT {column} FROM {table} WHERE {column} IS NOT NULL LIMIT 100"
            )
            
            values = []
            for row in cursor:
                value = row[0]
                if value:
                    values.append(str(value))
                    
            if values:
                # Create finding
                finding = ParsedEntry(
                    timestamp=datetime.now(),
                    source=f"{table}.{column}",
                    event_type="sensitive_data",
                    severity="warning",
                    message=f"Sensitive data found in {table}.{column}: {len(values)} entries",
                    raw_data={
                        'table': table,
                        'column': column,
                        'data_type': data_type,
                        'sample_count': len(values),
                        'samples': self._mask_sensitive_data(values[:5])  # First 5 samples
                    }
                )
                finding.tags = ["sensitive_data", data_type, table.lower()]
                
                # Check for specific data types
                if 'password' in column.lower():
                    finding.severity = "critical"
                    finding.tags.append("password")
                    
                    # Check if passwords are hashed
                    if values and not self._looks_like_hash(values[0]):
                        finding.tags.append("plaintext_password")
                        finding.severity = "critical"
                        
                elif 'credit' in column.lower() or 'card' in column.lower():
                    finding.severity = "critical"
                    finding.tags.append("payment_card")
                    
                elif 'ssn' in column.lower():
                    finding.severity = "critical"
                    finding.tags.append("ssn")
                    
                self.sensitive_data.append(finding)
                
                # Extract potential credentials
                if any(cred in column.lower() for cred in ['user', 'email', 'name']):
                    self.extracted_credentials.extend(values[:10])
                    
        except Exception as e:
            self.logger.debug(f"Error extracting column data: {e}")
            
    async def _detect_browser_artifacts(self, conn: sqlite3.Connection):
        """Detect browser-related artifacts"""
        for browser, artifacts in self.BROWSER_ARTIFACTS.items():
            for artifact_type, table_name in artifacts.items():
                if table_name in self.tables:
                    # Found browser artifact
                    artifact = ParsedEntry(
                        timestamp=datetime.now(),
                        source=browser,
                        event_type="browser_artifact",
                        severity="info",
                        message=f"{browser.title()} {artifact_type} found",
                        raw_data={
                            'browser': browser,
                            'artifact_type': artifact_type,
                            'table': table_name,
                            'row_count': self.tables[table_name]['row_count']
                        }
                    )
                    artifact.tags = ["browser", browser, artifact_type]
                    
                    # Extract specific artifacts
                    if artifact_type == 'cookies':
                        await self._extract_cookies(conn, table_name, browser)
                    elif artifact_type == 'history':
                        await self._extract_history(conn, table_name, browser)
                    elif artifact_type == 'logins':
                        await self._extract_logins(conn, table_name, browser)
                        
                    self.browser_artifacts.append(artifact)
                    
    async def _extract_cookies(self, conn: sqlite3.Connection, 
                             table: str, browser: str):
        """Extract browser cookies"""
        try:
            # Get cookie data
            if browser == 'chrome':
                query = f"SELECT host_key, name, value, encrypted_value FROM {table} LIMIT 100"
            else:
                query = f"SELECT host, name, value FROM {table} LIMIT 100"
                
            cursor = conn.execute(query)
            
            suspicious_cookies = []
            for row in cursor:
                host = row[0]
                name = row[1]
                
                # Check for suspicious cookies
                if any(susp in name.lower() for susp in ['session', 'token', 'auth', 'api']):
                    suspicious_cookies.append({
                        'host': host,
                        'name': name,
                        'type': 'authentication'
                    })
                    
            if suspicious_cookies:
                finding = ParsedEntry(
                    timestamp=datetime.now(),
                    source=f"{browser}_cookies",
                    event_type="security_alert",
                    severity="warning",
                    message=f"Authentication cookies found for {len(set(c['host'] for c in suspicious_cookies))} domains",
                    raw_data={
                        'browser': browser,
                        'cookie_count': len(suspicious_cookies),
                        'samples': suspicious_cookies[:10]
                    }
                )
                finding.tags = ["browser_cookies", "authentication", browser]
                self.browser_artifacts.append(finding)
                
        except Exception as e:
            self.logger.debug(f"Error extracting cookies: {e}")
            
    async def _extract_history(self, conn: sqlite3.Connection,
                             table: str, browser: str):
        """Extract browser history"""
        try:
            # Get history data
            if browser == 'chrome':
                query = f"SELECT url, title, visit_count FROM {table} ORDER BY visit_count DESC LIMIT 100"
            else:
                query = f"SELECT url, title, visit_count FROM {table} ORDER BY visit_count DESC LIMIT 100"
                
            cursor = conn.execute(query)
            
            suspicious_urls = []
            for row in cursor:
                url = row[0]
                
                # Check for suspicious URLs
                if any(pattern in url for pattern in ['.onion', '.i2p', 'tor2web']):
                    suspicious_urls.append({
                        'url': url,
                        'type': 'darkweb'
                    })
                elif re.search(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', url):
                    suspicious_urls.append({
                        'url': url,
                        'type': 'ip_address'
                    })
                    
            if suspicious_urls:
                finding = ParsedEntry(
                    timestamp=datetime.now(),
                    source=f"{browser}_history",
                    event_type="security_alert",
                    severity="warning",
                    message=f"Suspicious browsing activity detected: {len(suspicious_urls)} URLs",
                    raw_data={
                        'browser': browser,
                        'suspicious_count': len(suspicious_urls),
                        'samples': suspicious_urls[:10]
                    }
                )
                finding.tags = ["browser_history", "suspicious_activity", browser]
                self.browser_artifacts.append(finding)
                
        except Exception as e:
            self.logger.debug(f"Error extracting history: {e}")
            
    async def _extract_logins(self, conn: sqlite3.Connection,
                            table: str, browser: str):
        """Extract saved logins"""
        try:
            # Get login data
            query = f"SELECT origin_url, username_value FROM {table} LIMIT 100"
            cursor = conn.execute(query)
            
            login_sites = []
            for row in cursor:
                origin = row[0]
                username = row[1]
                
                if username:
                    login_sites.append({
                        'site': origin,
                        'username': self._mask_username(username)
                    })
                    
            if login_sites:
                finding = ParsedEntry(
                    timestamp=datetime.now(),
                    source=f"{browser}_logins",
                    event_type="sensitive_data",
                    severity="critical",
                    message=f"Saved passwords found for {len(login_sites)} sites",
                    raw_data={
                        'browser': browser,
                        'site_count': len(login_sites),
                        'sites': login_sites[:10]
                    }
                )
                finding.tags = ["saved_passwords", "credentials", browser]
                self.browser_artifacts.append(finding)
                
        except Exception as e:
            self.logger.debug(f"Error extracting logins: {e}")
            
    async def _detect_app_artifacts(self, conn: sqlite3.Connection):
        """Detect mobile app artifacts"""
        for app, artifacts in self.MOBILE_APP_PATTERNS.items():
            app_tables = []
            
            for artifact_type, table_pattern in artifacts.items():
                # Check if any table matches the pattern
                for table_name in self.tables:
                    if table_pattern in table_name.lower():
                        app_tables.append((artifact_type, table_name))
                        
            if app_tables:
                # Found app database
                artifact = ParsedEntry(
                    timestamp=datetime.now(),
                    source=app,
                    event_type="app_artifact",
                    severity="info",
                    message=f"{app.title()} database detected with {len(app_tables)} tables",
                    raw_data={
                        'app': app,
                        'tables': app_tables
                    }
                )
                artifact.tags = ["mobile_app", app]
                
                # Extract app-specific data
                if app == 'whatsapp':
                    await self._extract_whatsapp_data(conn, dict(app_tables))
                elif app == 'telegram':
                    await self._extract_telegram_data(conn, dict(app_tables))
                    
                self.app_artifacts.append(artifact)
                
    async def _extract_whatsapp_data(self, conn: sqlite3.Connection,
                                   tables: Dict[str, str]):
        """Extract WhatsApp artifacts"""
        if 'messages' in tables:
            try:
                # Get message count
                cursor = conn.execute(f"SELECT COUNT(*) FROM {tables['messages']}")
                msg_count = cursor.fetchone()[0]
                
                # Get contact count if available
                contact_count = 0
                if 'contacts' in tables:
                    cursor = conn.execute(f"SELECT COUNT(*) FROM {tables['contacts']}")
                    contact_count = cursor.fetchone()[0]
                    
                finding = ParsedEntry(
                    timestamp=datetime.now(),
                    source="whatsapp",
                    event_type="app_data",
                    severity="info",
                    message=f"WhatsApp data: {msg_count} messages, {contact_count} contacts",
                    raw_data={
                        'message_count': msg_count,
                        'contact_count': contact_count
                    }
                )
                finding.tags = ["whatsapp", "messages", "mobile"]
                self.app_artifacts.append(finding)
                
            except Exception as e:
                self.logger.debug(f"Error extracting WhatsApp data: {e}")
                
    async def _extract_telegram_data(self, conn: sqlite3.Connection,
                                   tables: Dict[str, str]):
        """Extract Telegram artifacts"""
        if 'messages' in tables:
            try:
                # Similar extraction for Telegram
                cursor = conn.execute(f"SELECT COUNT(*) FROM {tables['messages']}")
                msg_count = cursor.fetchone()[0]
                
                finding = ParsedEntry(
                    timestamp=datetime.now(),
                    source="telegram",
                    event_type="app_data",
                    severity="info",
                    message=f"Telegram data: {msg_count} messages",
                    raw_data={'message_count': msg_count}
                )
                finding.tags = ["telegram", "messages", "mobile"]
                self.app_artifacts.append(finding)
                
            except Exception as e:
                self.logger.debug(f"Error extracting Telegram data: {e}")
                
    async def _scan_for_malware(self, conn: sqlite3.Connection):
        """Scan for malware indicators in database"""
        for table_name, table_info in self.tables.items():
            if table_info['row_count'] == 0:
                continue
                
            # Check text columns for malware patterns
            text_columns = [
                col['name'] for col in table_info['columns']
                if col['type'] in ['TEXT', 'BLOB', 'VARCHAR']
            ]
            
            for column in text_columns[:5]:  # Limit columns checked
                try:
                    cursor = conn.execute(
                        f"SELECT {column} FROM {table_name} "
                        f"WHERE {column} IS NOT NULL LIMIT 1000"
                    )
                    
                    for row in cursor:
                        value = str(row[0])
                        
                        # Check malware patterns
                        for pattern_type, pattern in self.MALWARE_PATTERNS.items():
                            if re.search(pattern, value):
                                finding = ParsedEntry(
                                    timestamp=datetime.now(),
                                    source=f"{table_name}.{column}",
                                    event_type="security_alert",
                                    severity="warning",
                                    message=f"Suspicious pattern '{pattern_type}' found in database",
                                    raw_data={
                                        'table': table_name,
                                        'column': column,
                                        'pattern_type': pattern_type,
                                        'sample': value[:100]
                                    }
                                )
                                finding.tags = ["malware_indicator", pattern_type]
                                
                                if pattern_type in ['c2_urls', 'crypto_wallet']:
                                    finding.severity = "critical"
                                    
                                self.suspicious_entries.append(finding)
                                break
                                
                except Exception as e:
                    self.logger.debug(f"Error scanning for malware: {e}")
                    
                # Yield control
                await asyncio.sleep(0)
                
    def _extract_sqlite_iocs(self, entry: ParsedEntry) -> IOCs:
        """Extract IOCs from SQLite findings"""
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
            iocs.ips.add(ip)
            
        # Extract emails
        emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', raw_str)
        for email in emails:
            iocs.emails.add(email)
            
        # Extract potential malware hashes
        hashes = re.findall(r'\b[a-fA-F0-9]{32,64}\b', raw_str)
        for hash_val in hashes:
            if len(hash_val) in [32, 40, 64]:
                iocs.hashes.add(hash_val.lower())
                
        # Extract file paths from browser downloads or app data
        if 'path' in raw_str:
            paths = re.findall(r'[A-Za-z]:\\[^\'"\s]+|/[^\'"\s]+', raw_str)
            for path in paths:
                iocs.file_paths.add(path)
                
        return iocs
        
    def _mask_sensitive_data(self, values: List[str]) -> List[str]:
        """Mask sensitive data for display"""
        masked = []
        
        for value in values:
            if len(value) > 4:
                masked_value = value[:2] + '*' * (len(value) - 4) + value[-2:]
            else:
                masked_value = '*' * len(value)
            masked.append(masked_value)
            
        return masked
        
    def _mask_username(self, username: str) -> str:
        """Mask username for privacy"""
        if '@' in username:
            # Email address
            parts = username.split('@')
            if len(parts[0]) > 2:
                masked = parts[0][:1] + '*' * (len(parts[0]) - 2) + parts[0][-1:] + '@' + parts[1]
            else:
                masked = '*' * len(parts[0]) + '@' + parts[1]
            return masked
        else:
            # Regular username
            if len(username) > 2:
                return username[0] + '*' * (len(username) - 2) + username[-1]
            else:
                return '*' * len(username)
                
    def _looks_like_hash(self, value: str) -> bool:
        """Check if value looks like a password hash"""
        # Common hash patterns
        hash_patterns = [
            r'^\$2[aby]\$\d+\$',  # bcrypt
            r'^\$argon2',  # Argon2
            r'^[a-fA-F0-9]{32}$',  # MD5
            r'^[a-fA-F0-9]{40}$',  # SHA1
            r'^[a-fA-F0-9]{64}$',  # SHA256
            r'^\$\d+\$',  # Various salted hashes
            r'^pbkdf2:',  # PBKDF2
        ]
        
        return any(re.match(pattern, value) for pattern in hash_patterns)
        
    def _identify_database_type(self) -> str:
        """Identify the type of database based on tables"""
        # Check for browser databases
        for browser, artifacts in self.BROWSER_ARTIFACTS.items():
            if any(table in self.tables for table in artifacts.values()): 
                return f"{browser}_browser"
                
        # Check for mobile apps
        for app, artifacts in self.MOBILE_APP_PATTERNS.items():
            if any(table in str(self.tables).lower() for table in artifacts.values()):
                return f"{app}_mobile"
                
        # Check for specific patterns
        table_names = [t.lower() for t in self.tables.keys()]
        
        if any('user' in t or 'account' in t for t in table_names):
            return "user_database"
        elif any('log' in t or 'event' in t for t in table_names):
            return "log_database"
        elif any('config' in t or 'setting' in t for t in table_names):
            return "configuration_database"
        else:
            return "generic_database"
            
    def _assess_security(self) -> str:
        """Assess database security level"""
        risk_score = 0
        
        # Check for plaintext passwords
        if any('plaintext_password' in e.tags for e in self.sensitive_data):
            risk_score += 50
            
        # Check for sensitive data
        risk_score += len(self.sensitive_data) * 2
        
        # Check for malware indicators
        risk_score += len(self.suspicious_entries) * 5
        
        # Check for saved browser passwords
        if any('saved_passwords' in e.tags for e in self.browser_artifacts):
            risk_score += 30
            
        # Determine assessment
        if risk_score >= 100:
            return "CRITICAL - Immediate security action required"
        elif risk_score >= 50:
            return "HIGH - Significant security concerns"
        elif risk_score >= 20:
            return "MEDIUM - Some security issues found"
        elif risk_score > 0:
            return "LOW - Minor security concerns"
        else:
            return "SAFE - No significant security issues"