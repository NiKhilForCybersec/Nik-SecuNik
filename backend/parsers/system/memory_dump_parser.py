"""
Memory Dump Parser for SecuNik LogX
Analyzes memory dumps using Volatility framework and custom analysis
"""

import re
import json
import struct
import subprocess
from datetime import datetime
from typing import Dict, List, Any, Optional, Iterator, Tuple
from pathlib import Path
import tempfile
import hashlib
import magic

from parsers.base_parser import BaseParser
from backend.utils.hash_utils import calculate_file_hash


class MemoryDumpParser(BaseParser):
    """Parser for memory dumps (raw, crashdump, hibernation files)"""
    
    # Supported memory dump formats
    SUPPORTED_FORMATS = {
        'raw': ['.raw', '.bin', '.mem', '.dmp'],
        'crashdump': ['.dmp', '.mdmp', '.hdmp'],
        'hibernation': ['hiberfil.sys'],
        'vmware': ['.vmem', '.vmss', '.vmsn'],
        'virtualbox': ['.sav'],
        'lime': ['.lime'],
        'mach': ['.macho']
    }
    
    # Common malware indicators in memory
    MALWARE_INDICATORS = {
        'process_injection': [
            'CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory',
            'SetWindowsHookEx', 'SetThreadContext', 'QueueUserAPC'
        ],
        'api_hooking': [
            'SetWindowsHookEx', 'UnhookWindowsHookEx', 'CallNextHookEx',
            'inline hook', 'IAT hook', 'EAT hook'
        ],
        'persistence': [
            'Run', 'RunOnce', 'Winlogon\\Shell', 'Userinit',
            'ServiceDll', 'AppInit_DLLs', 'IFEO'
        ],
        'network': [
            'WSASocket', 'connect', 'send', 'recv', 'InternetOpen',
            'InternetConnect', 'HttpSendRequest', 'WinHttpOpen'
        ],
        'evasion': [
            'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
            'NtQueryInformationProcess', 'GetTickCount',
            'Sleep', 'VirtualProtect'
        ]
    }
    
    # Suspicious process names
    SUSPICIOUS_PROCESSES = [
        'svchost.exe', 'csrss.exe', 'winlogon.exe', 'services.exe',
        'lsass.exe', 'explorer.exe', 'rundll32.exe', 'regsvr32.exe',
        'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe'
    ]
    
    def __init__(self):
        super().__init__()
        self.file_path = None
        self.dump_format = None
        self.profile = None
        self.volatility_path = self._find_volatility()
        self.use_builtin = self.volatility_path is None
    
    def _find_volatility(self) -> Optional[str]:
        """Find Volatility installation"""
        # Try to find vol.py or vol3.py
        try:
            # Check for Volatility 3
            result = subprocess.run(['vol', '-h'], capture_output=True, text=True)
            if result.returncode == 0:
                return 'vol'
        except:
            pass
        
        try:
            # Check for Volatility 2
            result = subprocess.run(['vol.py', '-h'], capture_output=True, text=True)
            if result.returncode == 0:
                return 'vol.py'
        except:
            pass
        
        # Try common installation paths
        common_paths = [
            '/usr/bin/vol',
            '/usr/local/bin/vol',
            '/opt/volatility/vol.py',
            '/opt/volatility3/vol.py'
        ]
        
        for path in common_paths:
            if Path(path).exists():
                return path
        
        return None
    
    def can_parse(self, file_path: str) -> bool:
        """Check if file is a memory dump"""
        try:
            path = Path(file_path)
            
            # Check file extension
            for format_type, extensions in self.SUPPORTED_FORMATS.items():
                if path.suffix.lower() in extensions or path.name.lower() in extensions:
                    return True
            
            # Check file magic
            mime = magic.from_file(file_path, mime=True)
            if 'application/x-dosexec' in mime or 'application/octet-stream' in mime:
                # Could be a memory dump, check size
                if path.stat().st_size > 100 * 1024 * 1024:  # > 100MB
                    return True
            
            return False
            
        except Exception:
            return False
    
    def parse(self, file_path: str, progress_callback: Optional[callable] = None) -> Dict[str, Any]:
        """Parse memory dump file"""
        self.file_path = Path(file_path)
        results = {
            'events': [],
            'metadata': {},
            'iocs': [],
            'statistics': {
                'total_processes': 0,
                'hidden_processes': 0,
                'injected_processes': 0,
                'network_connections': 0,
                'suspicious_dlls': 0,
                'registry_keys': 0,
                'extracted_strings': 0,
                'malware_indicators': {},
                'process_tree': {},
                'loaded_modules': {},
                'network_activity': {},
                'timeline': []
            },
            'errors': [],
            'warnings': []
        }
        
        try:
            # Detect dump format
            self._detect_dump_format()
            
            # If Volatility is available, use it
            if self.volatility_path and not self.use_builtin:
                results = self._parse_with_volatility(results, progress_callback)
            else:
                # Use built-in analysis
                results = self._parse_builtin(results, progress_callback)
            
            # Extract IOCs from results
            results['iocs'] = self._extract_all_iocs(results)
            
            # Generate metadata
            results['metadata'] = self._generate_metadata(results)
            
            return results
            
        except Exception as e:
            results['errors'].append(f"Fatal parsing error: {str(e)}")
            return results
    
    def _detect_dump_format(self):
        """Detect memory dump format"""
        # Check file extension first
        for format_type, extensions in self.SUPPORTED_FORMATS.items():
            if self.file_path.suffix.lower() in extensions:
                self.dump_format = format_type
                return
        
        # Check file header
        with open(self.file_path, 'rb') as f:
            header = f.read(1024)
            
            # Windows crash dump
            if header.startswith(b'PAGE') or header.startswith(b'DU64'):
                self.dump_format = 'crashdump'
            # Hibernation file
            elif header.startswith(b'hibr') or header.startswith(b'HIBR'):
                self.dump_format = 'hibernation'
            # VMware
            elif b'VMware' in header:
                self.dump_format = 'vmware'
            # Lime
            elif header.startswith(b'EMiL'):
                self.dump_format = 'lime'
            else:
                self.dump_format = 'raw'
    
    def _parse_with_volatility(self, results: Dict[str, Any], progress_callback: Optional[callable]) -> Dict[str, Any]:
        """Parse using Volatility framework"""
        # Run imageinfo to detect profile
        if progress_callback:
            progress_callback(10, "Detecting memory image profile...")
        
        profile = self._detect_profile()
        if not profile:
            results['warnings'].append("Could not detect memory profile, using built-in analysis")
            return self._parse_builtin(results, progress_callback)
        
        self.profile = profile
        
        # Run various Volatility plugins
        plugins = [
            ('pslist', 20, self._parse_pslist),
            ('psscan', 30, self._parse_psscan),
            ('netscan', 40, self._parse_netscan),
            ('malfind', 50, self._parse_malfind),
            ('dlllist', 60, self._parse_dlllist),
            ('handles', 70, self._parse_handles),
            ('cmdline', 80, self._parse_cmdline),
            ('filescan', 90, self._parse_filescan)
        ]
        
        for plugin_name, progress, parser_func in plugins:
            if progress_callback:
                progress_callback(progress, f"Running {plugin_name} analysis...")
            
            try:
                output = self._run_volatility_plugin(plugin_name)
                parser_func(output, results)
            except Exception as e:
                results['warnings'].append(f"Failed to run {plugin_name}: {str(e)}")
        
        if progress_callback:
            progress_callback(100, "Memory analysis complete")
        
        return results
    
    def _detect_profile(self) -> Optional[str]:
        """Detect memory profile using Volatility"""
        try:
            cmd = [self.volatility_path, '-f', str(self.file_path), 'imageinfo']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                # Parse suggested profiles
                for line in result.stdout.split('\n'):
                    if 'Suggested Profile' in line:
                        profiles = line.split(':')[1].strip()
                        # Return first suggested profile
                        return profiles.split(',')[0].strip()
            
            return None
            
        except Exception:
            return None
    
    def _run_volatility_plugin(self, plugin: str) -> str:
        """Run a Volatility plugin and return output"""
        cmd = [
            self.volatility_path,
            '-f', str(self.file_path),
            '--profile', self.profile,
            plugin
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode != 0:
            raise Exception(f"Volatility plugin {plugin} failed: {result.stderr}")
        
        return result.stdout
    
    def _parse_pslist(self, output: str, results: Dict[str, Any]):
        """Parse process list output"""
        lines = output.strip().split('\n')
        
        for line in lines[2:]:  # Skip header
            if not line.strip():
                continue
            
            parts = line.split()
            if len(parts) < 7:
                continue
            
            try:
                event = {
                    'type': 'process',
                    'offset': parts[0],
                    'name': parts[1],
                    'pid': int(parts[2]),
                    'ppid': int(parts[3]),
                    'threads': int(parts[4]),
                    'handles': int(parts[5]),
                    'start_time': ' '.join(parts[6:8]) if len(parts) > 7 else 'N/A'
                }
                
                # Check for suspicious processes
                if self._is_suspicious_process(event['name'], event['ppid']):
                    event['suspicious'] = True
                    event['severity'] = 'warning'
                else:
                    event['severity'] = 'info'
                
                results['events'].append(event)
                results['statistics']['total_processes'] += 1
                
                # Build process tree
                if event['ppid'] not in results['statistics']['process_tree']:
                    results['statistics']['process_tree'][event['ppid']] = []
                results['statistics']['process_tree'][event['ppid']].append(event['pid'])
                
            except Exception:
                continue
    
    def _parse_psscan(self, output: str, results: Dict[str, Any]):
        """Parse process scan output to find hidden processes"""
        lines = output.strip().split('\n')
        
        # Get PIDs from pslist
        pslist_pids = set(e['pid'] for e in results['events'] if e['type'] == 'process')
        
        for line in lines[2:]:  # Skip header
            if not line.strip():
                continue
            
            parts = line.split()
            if len(parts) < 7:
                continue
            
            try:
                pid = int(parts[2])
                
                # Check if this process was hidden
                if pid not in pslist_pids:
                    event = {
                        'type': 'hidden_process',
                        'offset': parts[0],
                        'name': parts[1],
                        'pid': pid,
                        'ppid': int(parts[3]),
                        'severity': 'high',
                        'suspicious': True,
                        'hidden': True
                    }
                    
                    results['events'].append(event)
                    results['statistics']['hidden_processes'] += 1
                    
            except Exception:
                continue
    
    def _parse_netscan(self, output: str, results: Dict[str, Any]):
        """Parse network connections"""
        lines = output.strip().split('\n')
        
        for line in lines[1:]:  # Skip header
            if not line.strip():
                continue
            
            parts = line.split()
            if len(parts) < 6:
                continue
            
            try:
                event = {
                    'type': 'network_connection',
                    'offset': parts[0],
                    'protocol': parts[1],
                    'local_address': parts[2],
                    'foreign_address': parts[3],
                    'state': parts[4] if len(parts) > 4 else 'N/A',
                    'pid': int(parts[5]) if len(parts) > 5 else 0,
                    'owner': parts[6] if len(parts) > 6 else 'N/A'
                }
                
                # Check for suspicious connections
                if self._is_suspicious_connection(event['foreign_address']):
                    event['suspicious'] = True
                    event['severity'] = 'warning'
                else:
                    event['severity'] = 'info'
                
                results['events'].append(event)
                results['statistics']['network_connections'] += 1
                
                # Track network activity
                if event['pid'] not in results['statistics']['network_activity']:
                    results['statistics']['network_activity'][event['pid']] = []
                results['statistics']['network_activity'][event['pid']].append(event['foreign_address'])
                
            except Exception:
                continue
    
    def _parse_malfind(self, output: str, results: Dict[str, Any]):
        """Parse malware findings"""
        lines = output.strip().split('\n')
        current_process = None
        
        for line in lines:
            if not line.strip():
                continue
            
            # Process header
            if line.startswith('Process:'):
                parts = line.split()
                current_process = {
                    'name': parts[1],
                    'pid': int(parts[3])
                }
            
            # Suspicious injection
            elif 'MZ' in line or 'This program' in line:
                if current_process:
                    event = {
                        'type': 'process_injection',
                        'process': current_process['name'],
                        'pid': current_process['pid'],
                        'severity': 'high',
                        'suspicious': True,
                        'indicator': 'Injected PE file detected'
                    }
                    
                    results['events'].append(event)
                    results['statistics']['injected_processes'] += 1
                    
                    # Track malware indicators
                    indicator = 'process_injection'
                    results['statistics']['malware_indicators'][indicator] = \
                        results['statistics']['malware_indicators'].get(indicator, 0) + 1
    
    def _parse_dlllist(self, output: str, results: Dict[str, Any]):
        """Parse loaded DLLs"""
        lines = output.strip().split('\n')
        current_pid = None
        
        for line in lines:
            if not line.strip():
                continue
            
            # PID line
            if line.startswith('*' * 10):
                continue
            
            parts = line.split()
            if len(parts) >= 3 and parts[1] == 'pid:':
                current_pid = int(parts[2])
                continue
            
            # DLL entry
            if len(parts) >= 3 and current_pid:
                try:
                    dll_name = parts[2]
                    
                    # Check for suspicious DLLs
                    if self._is_suspicious_dll(dll_name):
                        event = {
                            'type': 'suspicious_dll',
                            'pid': current_pid,
                            'dll_name': dll_name,
                            'base': parts[0],
                            'size': parts[1],
                            'severity': 'warning',
                            'suspicious': True
                        }
                        
                        results['events'].append(event)
                        results['statistics']['suspicious_dlls'] += 1
                    
                    # Track loaded modules
                    if current_pid not in results['statistics']['loaded_modules']:
                        results['statistics']['loaded_modules'][current_pid] = []
                    results['statistics']['loaded_modules'][current_pid].append(dll_name)
                    
                except Exception:
                    continue
    
    def _parse_handles(self, output: str, results: Dict[str, Any]):
        """Parse handle information"""
        lines = output.strip().split('\n')
        
        for line in lines[2:]:  # Skip header
            if not line.strip():
                continue
            
            parts = line.split(None, 5)
            if len(parts) < 6:
                continue
            
            try:
                handle_type = parts[3]
                handle_name = parts[5]
                
                # Look for suspicious registry keys
                if handle_type == 'Key' and self._is_suspicious_registry(handle_name):
                    event = {
                        'type': 'suspicious_registry',
                        'offset': parts[0],
                        'pid': int(parts[1]),
                        'handle': parts[2],
                        'key': handle_name,
                        'severity': 'warning',
                        'suspicious': True
                    }
                    
                    results['events'].append(event)
                    results['statistics']['registry_keys'] += 1
                    
            except Exception:
                continue
    
    def _parse_cmdline(self, output: str, results: Dict[str, Any]):
        """Parse command lines"""
        lines = output.strip().split('\n')
        
        for line in lines[2:]:  # Skip header
            if not line.strip():
                continue
            
            parts = line.split(None, 2)
            if len(parts) < 3:
                continue
            
            try:
                pid = int(parts[1])
                cmdline = parts[2]
                
                # Check for suspicious command lines
                if self._is_suspicious_cmdline(cmdline):
                    event = {
                        'type': 'suspicious_cmdline',
                        'pid': pid,
                        'process': parts[0],
                        'cmdline': cmdline,
                        'severity': 'high',
                        'suspicious': True
                    }
                    
                    results['events'].append(event)
                    
                    # Track malware indicators
                    for indicator_type, patterns in self.MALWARE_INDICATORS.items():
                        if any(pattern in cmdline for pattern in patterns):
                            results['statistics']['malware_indicators'][indicator_type] = \
                                results['statistics']['malware_indicators'].get(indicator_type, 0) + 1
                    
            except Exception:
                continue
    
    def _parse_filescan(self, output: str, results: Dict[str, Any]):
        """Parse file scan results"""
        lines = output.strip().split('\n')
        
        for line in lines[2:]:  # Skip header
            if not line.strip():
                continue
            
            parts = line.split(None, 3)
            if len(parts) < 4:
                continue
            
            try:
                file_path = parts[3]
                
                # Check for suspicious files
                if self._is_suspicious_file(file_path):
                    event = {
                        'type': 'suspicious_file',
                        'offset': parts[0],
                        'handles': int(parts[1]),
                        'access': parts[2],
                        'file_path': file_path,
                        'severity': 'warning',
                        'suspicious': True
                    }
                    
                    results['events'].append(event)
                    
            except Exception:
                continue
    
    def _parse_builtin(self, results: Dict[str, Any], progress_callback: Optional[callable]) -> Dict[str, Any]:
        """Built-in memory analysis without Volatility"""
        file_size = self.file_path.stat().st_size
        
        # Extract strings
        if progress_callback:
            progress_callback(20, "Extracting strings...")
        
        strings = self._extract_strings()
        results['statistics']['extracted_strings'] = len(strings)
        
        # Analyze strings for indicators
        if progress_callback:
            progress_callback(40, "Analyzing extracted strings...")
        
        self._analyze_strings(strings, results)
        
        # Search for patterns
        if progress_callback:
            progress_callback(60, "Searching for malware patterns...")
        
        self._search_patterns(results)
        
        # Extract URLs and IPs
        if progress_callback:
            progress_callback(80, "Extracting network indicators...")
        
        self._extract_network_indicators(strings, results)
        
        if progress_callback:
            progress_callback(100, "Analysis complete")
        
        return results
    
    def _extract_strings(self, min_length: int = 6) -> List[str]:
        """Extract ASCII and Unicode strings from memory dump"""
        strings = []
        
        # Read in chunks to handle large files
        chunk_size = 1024 * 1024  # 1MB chunks
        
        with open(self.file_path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                
                # Extract ASCII strings
                ascii_strings = re.findall(b'[\x20-\x7e]{%d,}' % min_length, chunk)
                strings.extend(s.decode('ascii', errors='ignore') for s in ascii_strings)
                
                # Extract Unicode strings (simplified)
                unicode_strings = re.findall(b'(?:[\x20-\x7e]\x00){%d,}' % min_length, chunk)
                for s in unicode_strings:
                    try:
                        decoded = s.decode('utf-16le', errors='ignore')
                        if decoded:
                            strings.append(decoded)
                    except:
                        pass
        
        return list(set(strings))  # Remove duplicates
    
    def _analyze_strings(self, strings: List[str], results: Dict[str, Any]):
        """Analyze extracted strings for indicators"""
        for string in strings:
            # Check for malware indicators
            for indicator_type, patterns in self.MALWARE_INDICATORS.items():
                for pattern in patterns:
                    if pattern.lower() in string.lower():
                        event = {
                            'type': 'malware_indicator',
                            'indicator_type': indicator_type,
                            'pattern': pattern,
                            'context': string[:200],
                            'severity': 'high',
                            'suspicious': True
                        }
                        
                        results['events'].append(event)
                        results['statistics']['malware_indicators'][indicator_type] = \
                            results['statistics']['malware_indicators'].get(indicator_type, 0) + 1
            
            # Check for suspicious process names
            for proc in self.SUSPICIOUS_PROCESSES:
                if proc in string and ('\\' in string or '/' in string):
                    event = {
                        'type': 'suspicious_process_string',
                        'process': proc,
                        'full_path': string[:200],
                        'severity': 'warning',
                        'suspicious': True
                    }
                    
                    results['events'].append(event)
    
    def _search_patterns(self, results: Dict[str, Any]):
        """Search for specific patterns in memory"""
        # PE header pattern
        pe_pattern = b'MZ\x90\x00\x03'
        
        # Search for PE files in memory
        with open(self.file_path, 'rb') as f:
            data = f.read(1024 * 1024)  # Read 1MB at a time
            offset = 0
            
            while data:
                pos = data.find(pe_pattern)
                if pos != -1:
                    event = {
                        'type': 'pe_file_in_memory',
                        'offset': hex(offset + pos),
                        'severity': 'warning',
                        'suspicious': True,
                        'description': 'Portable Executable found in memory'
                    }
                    
                    results['events'].append(event)
                
                offset += len(data)
                data = f.read(1024 * 1024)
    
    def _extract_network_indicators(self, strings: List[str], results: Dict[str, Any]):
        """Extract network indicators from strings"""
        # IP address pattern
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        
        # URL pattern
        url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
        
        # Domain pattern
        domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
        
        for string in strings:
            # Extract IPs
            ips = ip_pattern.findall(string)
            for ip in ips:
                # Skip private IPs
                if not ip.startswith(('10.', '172.', '192.168.', '127.')):
                    event = {
                        'type': 'network_indicator',
                        'indicator': 'ip',
                        'value': ip,
                        'context': string[:200],
                        'severity': 'info'
                    }
                    results['events'].append(event)
            
            # Extract URLs
            urls = url_pattern.findall(string)
            for url in urls:
                event = {
                    'type': 'network_indicator',
                    'indicator': 'url',
                    'value': url,
                    'severity': 'warning' if any(s in url.lower() for s in ['malware', 'c2', 'command']) else 'info'
                }
                results['events'].append(event)
            
            # Extract domains
            domains = domain_pattern.findall(string)
            for domain in domains:
                if domain not in ['microsoft.com', 'windows.com', 'google.com']:
                    event = {
                        'type': 'network_indicator',
                        'indicator': 'domain',
                        'value': domain,
                        'severity': 'info'
                    }
                    results['events'].append(event)
    
    def _is_suspicious_process(self, name: str, ppid: int) -> bool:
        """Check if process is suspicious"""
        # Check for suspicious process names in wrong paths
        if name.lower() in [p.lower() for p in self.SUSPICIOUS_PROCESSES]:
            # These system processes should have specific parent PIDs
            if name.lower() in ['csrss.exe', 'winlogon.exe'] and ppid != 4:
                return True
            # Multiple instances of these are suspicious
            if name.lower() in ['lsass.exe', 'services.exe']:
                return True
        
        # Check for process name spoofing
        if any(c in name for c in [' ', '\t', '\n']):
            return True
        
        return False
    
    def _is_suspicious_connection(self, address: str) -> bool:
        """Check if network connection is suspicious"""
        # Check for connections to known bad ports
        if ':' in address:
            port = address.split(':')[-1]
            try:
                port_num = int(port)
                if port_num in [4444, 31337, 12345, 54321, 1337, 666, 999]:
                    return True
            except:
                pass
        
        # Check for connections to private IP ranges from public IPs
        # This could indicate lateral movement
        
        return False
    
    def _is_suspicious_dll(self, dll_name: str) -> bool:
        """Check if DLL is suspicious"""
        suspicious_dlls = [
            'unknown', 'malware.dll', 'inject.dll', 'hook.dll',
            'rootkit.dll', 'backdoor.dll', 'trojan.dll'
        ]
        
        dll_lower = dll_name.lower()
        
        # Check for known suspicious DLLs
        if any(s in dll_lower for s in suspicious_dlls):
            return True
        
        # Check for DLLs loaded from temp directories
        if any(path in dll_lower for path in ['\\temp\\', '\\tmp\\', '%temp%']):
            return True
        
        # Check for randomly named DLLs
        import re
        if re.match(r'^[a-f0-9]{8,}\.dll', dll_lower):
            return True
        
        return False
    
    def _is_suspicious_registry(self, key: str) -> bool:
        """Check if registry key is suspicious"""
        suspicious_keys = [
            'Run', 'RunOnce', 'RunServices', 'RunServicesOnce',
            'Winlogon\\Shell', 'Winlogon\\Userinit',
            'Windows\\CurrentVersion\\ShellServiceObjectDelayLoad',
            'Windows\\CurrentVersion\\Explorer\\SharedTaskScheduler',
            'Services\\', 'AppInit_DLLs', 'Image File Execution Options'
        ]
        
        return any(s in key for s in suspicious_keys)
    
    def _is_suspicious_cmdline(self, cmdline: str) -> bool:
        """Check if command line is suspicious"""
        suspicious_patterns = [
            'powershell.*-enc', 'powershell.*-e.*',
            'powershell.*bypass', 'powershell.*hidden',
            'cmd.*/c.*&.*&', 'wmic.*process.*call.*create',
            'rundll32.*,.*', 'regsvr32.*/s.*/n.*/u.*/i:',
            'mshta.*http', 'certutil.*-decode',
            'bitsadmin.*/transfer', 'net.*user.*/add'
        ]
        
        cmdline_lower = cmdline.lower()
        
        for pattern in suspicious_patterns:
            if re.search(pattern, cmdline_lower):
                return True
        
        return False
    
    def _is_suspicious_file(self, file_path: str) -> bool:
        """Check if file path is suspicious"""
        suspicious_paths = [
            '\\temp\\', '\\tmp\\', '\\appdata\\local\\temp\\',
            '\\users\\public\\', '\\programdata\\',
            '\\windows\\temp\\', '\\recycler\\', '\\$recycle.bin\\'
        ]
        
        suspicious_extensions = [
            '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs',
            '.js', '.jar', '.scr', '.com', '.pif'
        ]
        
        path_lower = file_path.lower()
        
        # Check suspicious paths
        if any(path in path_lower for path in suspicious_paths):
            # Check for executables in temp directories
            if any(path_lower.endswith(ext) for ext in suspicious_extensions):
                return True
        
        return False
    
    def _extract_all_iocs(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract all IOCs from analysis results"""
        iocs = []
        
        # Extract from events
        for event in results['events']:
            if event['type'] == 'network_indicator':
                ioc_type = event['indicator']
                iocs.append({
                    'type': ioc_type,
                    'value': event['value'],
                    'context': 'Memory dump analysis',
                    'confidence': 'high' if event.get('suspicious') else 'medium'
                })
            
            elif event['type'] == 'suspicious_file':
                # Extract file hash if possible
                iocs.append({
                    'type': 'file_path',
                    'value': event['file_path'],
                    'context': 'Suspicious file in memory',
                    'confidence': 'medium'
                })
        
        # Deduplicate IOCs
        seen = set()
        unique_iocs = []
        for ioc in iocs:
            key = (ioc['type'], ioc['value'])
            if key not in seen:
                seen.add(key)
                unique_iocs.append(ioc)
        
        return unique_iocs
    
    def _generate_metadata(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate metadata for the memory dump"""
        stats = results['statistics']
        
        metadata = {
            'file_name': self.file_path.name,
            'file_size': self.file_path.stat().st_size,
            'file_hash': calculate_file_hash(str(self.file_path)),
            'dump_format': self.dump_format,
            'profile': self.profile,
            'analysis_method': 'volatility' if self.volatility_path and not self.use_builtin else 'builtin',
            'total_events': len(results['events']),
            'parser': 'memory_dump_parser',
            'version': '1.0.0'
        }
        
        # Add summary
        metadata['summary'] = {
            'total_processes': stats.get('total_processes', 0),
            'hidden_processes': stats.get('hidden_processes', 0),
            'injected_processes': stats.get('injected_processes', 0),
            'network_connections': stats.get('network_connections', 0),
            'suspicious_dlls': stats.get('suspicious_dlls', 0),
            'malware_indicators': len(stats.get('malware_indicators', {})),
            'extracted_strings': stats.get('extracted_strings', 0)
        }
        
        # Risk assessment
        risk_score = 0
        if stats.get('hidden_processes', 0) > 0:
            risk_score += 30
        if stats.get('injected_processes', 0) > 0:
            risk_score += 40
        if len(stats.get('malware_indicators', {})) > 0:
            risk_score += 30
        
        metadata['risk_level'] = 'critical' if risk_score >= 70 else 'high' if risk_score >= 40 else 'medium' if risk_score >= 20 else 'low'
        
        return metadata