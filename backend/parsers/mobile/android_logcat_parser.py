"""
Android Logcat Parser for SecuNik LogX
Parses Android system logs (logcat) for security analysis
Detects malware activity, privacy violations, and system compromises
"""

import re
import asyncio
from datetime import datetime
from typing import Dict, Any, List, Optional, Set, AsyncGenerator, Tuple
from pathlib import Path
from collections import defaultdict
import json

from ..base_parser import BaseParser, ParseResult, ParsedEntry, FileMetadata, IOCs


class AndroidLogcatParser(BaseParser):
    """Parser for Android logcat logs"""
    
    name = "android_logcat"
    description = "Parses Android logcat logs for security analysis"
    supported_extensions = ['.log', '.txt', '.logcat']
    
    # Logcat format patterns
    LOGCAT_PATTERNS = {
        'threadtime': re.compile(
            r'^(?P<date>\d{2}-\d{2})\s+'
            r'(?P<time>\d{2}:\d{2}:\d{2}\.\d{3})\s+'
            r'(?P<pid>\d+)\s+'
            r'(?P<tid>\d+)\s+'
            r'(?P<level>[VDIWEF])\s+'
            r'(?P<tag>[^:]+):\s*'
            r'(?P<message>.*)$'
        ),
        'time': re.compile(
            r'^(?P<date>\d{2}-\d{2})\s+'
            r'(?P<time>\d{2}:\d{2}:\d{2}\.\d{3})\s+'
            r'(?P<level>[VDIWEF])/(?P<tag>[^(]+)\(\s*(?P<pid>\d+)\):\s*'
            r'(?P<message>.*)$'
        ),
        'brief': re.compile(
            r'^(?P<level>[VDIWEF])/(?P<tag>[^(]+)\(\s*(?P<pid>\d+)\):\s*'
            r'(?P<message>.*)$'
        )
    }
    
    # Log levels
    LOG_LEVELS = {
        'V': ('verbose', 'debug'),
        'D': ('debug', 'debug'),
        'I': ('info', 'info'),
        'W': ('warning', 'warning'),
        'E': ('error', 'error'),
        'F': ('fatal', 'critical')
    }
    
    # Security-relevant tags
    SECURITY_TAGS = {
        # System security
        'PackageManager': 'Package management',
        'ActivityManager': 'Activity management',
        'WindowManager': 'Window management',
        'PowerManager': 'Power management',
        'KeyguardService': 'Lock screen',
        'DevicePolicyManager': 'Device policy',
        'SELinux': 'SELinux policy',
        
        # Permissions and access
        'AppOps': 'App operations',
        'PermissionMonitor': 'Permission monitoring',
        'Privacy': 'Privacy manager',
        'LocationManager': 'Location access',
        'CameraService': 'Camera access',
        'AudioService': 'Audio access',
        'ContactsProvider': 'Contacts access',
        
        # Network and connectivity
        'ConnectivityService': 'Network connectivity',
        'WifiService': 'WiFi service',
        'BluetoothService': 'Bluetooth service',
        'TelephonyService': 'Telephony service',
        'NetworkMonitor': 'Network monitoring',
        
        # Security events
        'Cryptfs': 'Encryption service',
        'keystore': 'Keystore service',
        'Firewall': 'Firewall service',
        'MalwareScanner': 'Malware detection',
        'AntiVirus': 'Antivirus service'
    }
    
    # Suspicious patterns
    SUSPICIOUS_PATTERNS = {
        'malware_indicators': [
            r'dex2oat.*failed',
            r'Permission denied.*\/(system|data)',
            r'SELinux.*denied',
            r'INJECT_EVENTS',
            r'android\.permission\..*denied',
            r'Exploit.*detected',
            r'Root.*detected',
            r'su\s+binary',
            r'magisk|supersu|kingroot'
        ],
        'privacy_violations': [
            r'accessing.*contacts.*without permission',
            r'accessing.*location.*without permission',
            r'accessing.*camera.*without permission',
            r'accessing.*microphone.*without permission',
            r'reading.*SMS.*without permission',
            r'clipboard.*accessed',
            r'screenshot.*captured'
        ],
        'network_suspicious': [
            r'connecting to.*(\d{1,3}\.){3}\d{1,3}',
            r'SSL.*certificate.*invalid',
            r'HTTP.*plaintext',
            r'DNS.*spoofing',
            r'MITM.*detected',
            r'Proxy.*detected',
            r'VPN.*connection'
        ],
        'system_compromise': [
            r'bootloader.*unlocked',
            r'dm-verity.*disabled',
            r'SELinux.*permissive',
            r'debuggerd.*crash',
            r'tombstone.*written',
            r'native.*crash',
            r'SIGSEGV|SIGBUS|SIGILL'
        ],
        'app_suspicious': [
            r'overlay.*detected',
            r'accessibility.*abuse',
            r'admin.*privileges.*requested',
            r'factory.*reset',
            r'package.*installed.*unknown.*source',
            r'adb.*install',
            r'pm\s+install'
        ]
    }
    
    # Known malicious packages
    MALICIOUS_PACKAGES = [
        'com.malware', 'com.spyware', 'com.trojan',
        'com.android.system.update',  # Common fake system app
        'com.google.service',  # Typosquatting
        'com.whatsapp.update',  # Fake update
        'com.android.systemui.overlay'  # Overlay attack
    ]
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.processes = {}
        self.suspicious_events = []
        self.security_events = []
        self.crash_events = []
        self.permission_denials = []
        self.network_events = []
        self.app_installs = []
        
    async def parse(self) -> ParseResult:
        """Parse Android logcat file"""
        result = ParseResult(
            file_path=str(self.file_path),
            file_type="android_logcat",
            parser_name=self.name
        )
        
        try:
            # Get file metadata
            result.metadata = await self._get_file_metadata()
            
            # Detect logcat format
            log_format = await self._detect_format()
            if not log_format:
                result.errors.append("Unable to detect logcat format")
                return result
                
            result.metadata.additional["log_format"] = log_format
            
            # Parse log entries
            entry_count = 0
            async for entry in self._parse_entries(log_format):
                result.entries.append(entry)
                entry_count += 1
                
                # Extract IOCs
                result.iocs.merge(self._extract_android_iocs(entry))
                
                # Analyze entry
                await self._analyze_entry(entry)
                
                # Yield control periodically
                if entry_count % 1000 == 0:
                    await asyncio.sleep(0)
                    
            # Add security findings
            for event in self.security_events[:100]:  # Limit
                result.entries.append(event)
                
            # Add suspicious events
            for event in self.suspicious_events[:100]:
                result.entries.append(event)
                
            # Analyze patterns
            await self._analyze_patterns()
            
            # Generate summary
            result.metadata.additional.update({
                "total_entries": entry_count,
                "unique_processes": len(self.processes),
                "suspicious_events": len(self.suspicious_events),
                "security_events": len(self.security_events),
                "crash_events": len(self.crash_events),
                "permission_denials": len(self.permission_denials),
                "app_installs": len(self.app_installs),
                "top_processes": self._get_top_processes(),
                "security_summary": self._generate_security_summary(),
                "malware_indicators": self._get_malware_indicators()
            })
            
            self.logger.info(f"Parsed {entry_count} logcat entries")
            
        except Exception as e:
            self.logger.error(f"Error parsing logcat: {e}")
            result.errors.append(f"Parse error: {str(e)}")
            
        return result
        
    async def _detect_format(self) -> Optional[str]:
        """Detect logcat format"""
        async with self._open_file() as f:
            # Read sample lines
            sample_lines = []
            for _ in range(100):
                line = await f.readline()
                if not line:
                    break
                sample_lines.append(line.strip())
                
        # Try each format
        for format_name, pattern in self.LOGCAT_PATTERNS.items():
            matches = 0
            for line in sample_lines:
                if pattern.match(line):
                    matches += 1
                    
            if matches > len(sample_lines) * 0.5:  # 50% match
                self.logger.info(f"Detected logcat format: {format_name}")
                return format_name
                
        return None
        
    async def _parse_entries(self, log_format: str) -> AsyncGenerator[ParsedEntry, None]:
        """Parse logcat entries"""
        pattern = self.LOGCAT_PATTERNS[log_format]
        line_num = 0
        current_year = datetime.now().year
        
        async with self._open_file() as f:
            async for line in f:
                line_num += 1
                line = line.strip()
                
                if not line:
                    continue
                    
                match = pattern.match(line)
                if not match:
                    # Could be continuation of previous message
                    continue
                    
                data = match.groupdict()
                
                # Parse timestamp
                if 'date' in data and 'time' in data:
                    # Logcat doesn't include year, assume current year
                    date_str = f"{current_year}-{data['date']} {data['time']}"
                    try:
                        timestamp = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S.%f")
                    except:
                        timestamp = datetime.now()
                else:
                    timestamp = datetime.now()
                    
                # Get log level
                level_char = data.get('level', 'I')
                level_name, severity = self.LOG_LEVELS.get(level_char, ('info', 'info'))
                
                # Get process info
                pid = int(data.get('pid', 0))
                tid = int(data.get('tid', pid))
                tag = data.get('tag', 'Unknown')
                message = data.get('message', '')
                
                # Track process
                if pid not in self.processes:
                    self.processes[pid] = {
                        'tags': set(),
                        'first_seen': timestamp,
                        'last_seen': timestamp,
                        'message_count': 0
                    }
                    
                self.processes[pid]['tags'].add(tag)
                self.processes[pid]['last_seen'] = timestamp
                self.processes[pid]['message_count'] += 1
                
                # Create entry
                entry = ParsedEntry(
                    timestamp=timestamp,
                    source=f"PID:{pid}",
                    event_type="android_log",
                    severity=severity,
                    message=f"[{tag}] {message}",
                    raw_data={
                        'line_num': line_num,
                        'pid': pid,
                        'tid': tid,
                        'level': level_char,
                        'tag': tag,
                        'message': message
                    }
                )
                
                entry.parsed_data = {
                    'process_id': pid,
                    'thread_id': tid,
                    'log_level': level_name,
                    'tag': tag,
                    'message': message
                }
                
                # Add security tags
                if tag in self.SECURITY_TAGS:
                    entry.tags.append("security_relevant")
                    entry.tags.append(tag.lower())
                    
                yield entry
                
    async def _analyze_entry(self, entry: ParsedEntry):
        """Analyze log entry for security issues"""
        data = entry.parsed_data
        tag = data['tag']
        message = data['message']
        
        # Check for crashes
        if 'crash' in message.lower() or 'fatal' in message.lower():
            self.crash_events.append(entry)
            
        # Check for permission denials
        if 'permission denied' in message.lower() or 'not granted' in message.lower():
            self.permission_denials.append(entry)
            
            # Create security event
            perm_event = ParsedEntry(
                timestamp=entry.timestamp,
                source=entry.source,
                event_type="security_alert",
                severity="warning",
                message=f"Permission denial: {message[:100]}",
                raw_data=entry.raw_data
            )
            perm_event.tags = ["permission_denial", "security"]
            self.security_events.append(perm_event)
            
        # Check for app installations
        if tag == 'PackageManager' and ('install' in message.lower() or 'added' in message.lower()):
            self.app_installs.append(entry)
            
            # Check for suspicious packages
            for mal_pkg in self.MALICIOUS_PACKAGES:
                if mal_pkg in message:
                    mal_event = ParsedEntry(
                        timestamp=entry.timestamp,
                        source=entry.source,
                        event_type="security_alert",
                        severity="critical",
                        message=f"Malicious package detected: {mal_pkg}",
                        raw_data=entry.raw_data
                    )
                    mal_event.tags = ["malware", "malicious_app", "critical"]
                    self.security_events.append(mal_event)
                    
        # Check for network events
        if tag in ['ConnectivityService', 'NetworkMonitor', 'WifiService']:
            self.network_events.append(entry)
            
        # Check suspicious patterns
        await self._check_suspicious_patterns(entry)
        
    async def _check_suspicious_patterns(self, entry: ParsedEntry):
        """Check for suspicious patterns in log entry"""
        message = entry.parsed_data['message']
        
        for category, patterns in self.SUSPICIOUS_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, message, re.IGNORECASE):
                    # Create suspicious event
                    susp_event = ParsedEntry(
                        timestamp=entry.timestamp,
                        source=entry.source,
                        event_type="security_alert",
                        severity="warning" if category != "system_compromise" else "critical",
                        message=f"{category.replace('_', ' ').title()} detected: {message[:100]}",
                        raw_data=entry.raw_data
                    )
                    susp_event.tags = ["suspicious", category]
                    susp_event.parsed_data = entry.parsed_data.copy()
                    susp_event.parsed_data['pattern_matched'] = pattern
                    
                    self.suspicious_events.append(susp_event)
                    
                    # Special handling for certain categories
                    if category == 'malware_indicators':
                        susp_event.severity = "critical"
                        susp_event.tags.append("malware")
                        
                        # Check for root detection
                        if any(root in message.lower() for root in ['root', 'su', 'magisk']):
                            susp_event.tags.append("rooted_device")
                            
                    elif category == 'privacy_violations':
                        susp_event.tags.append("privacy")
                        
                        # Extract app doing the violation
                        if 'PID:' in entry.source:
                            pid = entry.parsed_data['process_id']
                            if pid in self.processes:
                                tags = self.processes[pid]['tags']
                                susp_event.parsed_data['app_tags'] = list(tags)
                                
                    break
                    
    async def _analyze_patterns(self):
        """Analyze overall patterns in the logs"""
        # Check for rapid crashes
        if len(self.crash_events) > 10:
            crash_apps = defaultdict(int)
            for event in self.crash_events:
                tag = event.parsed_data['tag']
                crash_apps[tag] += 1
                
            # Find apps crashing repeatedly
            for app, count in crash_apps.items():
                if count >= 5:
                    alert = ParsedEntry(
                        timestamp=self.crash_events[0].timestamp,
                        source="pattern_analysis",
                        event_type="security_alert",
                        severity="warning",
                        message=f"Application '{app}' crashed {count} times - possible exploit attempts",
                        raw_data={'app': app, 'crash_count': count}
                    )
                    alert.tags = ["crash_pattern", "potential_exploit"]
                    self.security_events.append(alert)
                    
        # Check for permission denial patterns
        if len(self.permission_denials) > 20:
            perm_apps = defaultdict(list)
            for event in self.permission_denials:
                pid = event.parsed_data['process_id']
                perm_apps[pid].append(event.parsed_data['message'])
                
            # Find apps repeatedly denied permissions
            for pid, denials in perm_apps.items():
                if len(denials) >= 10:
                    tags = self.processes.get(pid, {}).get('tags', set())
                    alert = ParsedEntry(
                        timestamp=datetime.now(),
                        source=f"PID:{pid}",
                        event_type="security_alert",
                        severity="warning",
                        message=f"Process repeatedly denied permissions ({len(denials)} times) - possible malicious behavior",
                        raw_data={
                            'pid': pid,
                            'denial_count': len(denials),
                            'process_tags': list(tags),
                            'sample_denials': denials[:5]
                        }
                    )
                    alert.tags = ["permission_abuse", "suspicious_app"]
                    self.security_events.append(alert)
                    
    def _extract_android_iocs(self, entry: ParsedEntry) -> IOCs:
        """Extract IOCs from Android log entry"""
        iocs = IOCs()
        message = entry.parsed_data['message']
        
        # Extract IPs
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        for ip in re.findall(ip_pattern, message):
            # Filter out local IPs
            if not ip.startswith(('127.', '192.168.', '10.', '172.')):
                iocs.ips.add(ip)
                
        # Extract domains
        domain_pattern = r'(?:https?://)?([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.)+[a-zA-Z]{2,}'
        for domain in re.findall(domain_pattern, message):
            # Filter out Android domains
            if not domain.endswith(('.android.com', '.google.com', '.googleapis.com')):
                iocs.domains.add(domain)
                
        # Extract URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        for url in re.findall(url_pattern, message):
            iocs.urls.add(url)
            
        # Extract package names
        pkg_pattern = r'(?:package:|pkg:|com\.|org\.|net\.)[a-zA-Z0-9._]+'
        for pkg in re.findall(pkg_pattern, message):
            # Check if it's a suspicious package
            for mal_pkg in self.MALICIOUS_PACKAGES:
                if mal_pkg in pkg:
                    iocs.file_paths.add(f"android_package:{pkg}")
                    
        # Extract file paths
        path_pattern = r'(?:/data/|/system/|/sdcard/|/storage/)[^\s<>"{}|\\^`\[\]]+'
        for path in re.findall(path_pattern, message):
            iocs.file_paths.add(path)
            
        # Extract hashes
        hash_pattern = r'\b[a-fA-F0-9]{32,64}\b'
        for hash_val in re.findall(hash_pattern, message):
            if len(hash_val) in [32, 40, 64]:  # MD5, SHA1, SHA256
                iocs.hashes.add(hash_val.lower())
                
        return iocs
        
    def _get_top_processes(self, limit: int = 10) -> List[Dict]:
        """Get most active processes"""
        process_list = []
        
        for pid, info in self.processes.items():
            duration = (info['last_seen'] - info['first_seen']).total_seconds()
            
            process_list.append({
                'pid': pid,
                'tags': list(info['tags'])[:5],
                'message_count': info['message_count'],
                'duration_seconds': duration,
                'first_seen': info['first_seen'].isoformat(),
                'last_seen': info['last_seen'].isoformat()
            })
            
        # Sort by message count
        process_list.sort(key=lambda x: x['message_count'], reverse=True)
        
        return process_list[:limit]
        
    def _generate_security_summary(self) -> Dict:
        """Generate security summary"""
        summary = {
            'total_security_events': len(self.security_events),
            'total_suspicious_events': len(self.suspicious_events),
            'categories': defaultdict(int)
        }
        
        # Count by category
        for event in self.suspicious_events:
            for tag in event.tags:
                if tag in self.SUSPICIOUS_PATTERNS:
                    summary['categories'][tag] += 1
                    
        # Identify risks
        risks = []
        
        if any('rooted_device' in e.tags for e in self.security_events):
            risks.append("Device appears to be rooted")
            
        if any('malware' in e.tags for e in self.security_events):
            risks.append("Malware indicators detected")
            
        if len(self.permission_denials) > 50:
            risks.append("Excessive permission denial activity")
            
        if any('privacy_violations' in e.tags for e in self.suspicious_events):
            risks.append("Privacy violations detected")
            
        if len(self.crash_events) > 20:
            risks.append("System instability - multiple crashes")
            
        summary['identified_risks'] = risks
        summary['categories'] = dict(summary['categories'])
        
        return summary
        
    def _get_malware_indicators(self) -> List[Dict]:
        """Get detected malware indicators"""
        indicators = []
        
        # Group by indicator type
        malware_events = [e for e in self.security_events if 'malware' in e.tags]
        
        for event in malware_events[:20]:  # Limit
            indicator = {
                'timestamp': event.timestamp.isoformat(),
                'type': 'unknown',
                'description': event.message,
                'severity': event.severity
            }
            
            # Determine type
            if 'malicious_app' in event.tags:
                indicator['type'] = 'malicious_package'
            elif 'rooted_device' in event.tags:
                indicator['type'] = 'root_detection'
            elif 'permission_abuse' in event.tags:
                indicator['type'] = 'permission_abuse'
            else:
                # Check pattern
                data = event.parsed_data
                if 'pattern_matched' in data:
                    if 'root' in data['pattern_matched']:
                        indicator['type'] = 'root_exploit'
                    elif 'dex' in data['pattern_matched']:
                        indicator['type'] = 'code_injection'
                    elif 'SELinux' in data['pattern_matched']:
                        indicator['type'] = 'selinux_bypass'
                        
            indicators.append(indicator)
            
        return indicators