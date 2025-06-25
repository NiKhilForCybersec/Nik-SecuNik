"""
NetFlow Parser for SecuNik LogX
Parses NetFlow v5 and v9 data with security analysis
Detects network anomalies, scans, and suspicious flows
"""

import struct
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Set, AsyncGenerator, Tuple
from pathlib import Path
from collections import defaultdict
import ipaddress
import json

from ..base_parser import BaseParser, ParseResult, ParsedEntry, FileMetadata, IOCs


class NetFlowParser(BaseParser):
    """Parser for NetFlow v5 and v9 data"""
    
    name = "netflow"
    description = "Parses NetFlow v5 and v9 network flow data"
    supported_extensions = ['.nfcapd', '.netflow', '.nflow', '.flow']
    
    # NetFlow v5 constants
    V5_HEADER_SIZE = 24
    V5_RECORD_SIZE = 48
    
    # NetFlow v9 constants
    V9_HEADER_SIZE = 20
    V9_TEMPLATE_FLOWSET_ID = 0
    V9_OPTIONS_TEMPLATE_FLOWSET_ID = 1
    
    # Common ports for security analysis
    SUSPICIOUS_PORTS = {
        20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
        25: "SMTP", 53: "DNS", 69: "TFTP", 80: "HTTP",
        110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
        161: "SNMP", 162: "SNMP-Trap", 389: "LDAP", 443: "HTTPS",
        445: "SMB", 512: "rexec", 513: "rlogin", 514: "rsh",
        1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 
        8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch",
        27017: "MongoDB"
    }
    
    # Scan detection thresholds
    SCAN_THRESHOLDS = {
        'port_scan': {'unique_ports': 20, 'time_window': 60},
        'network_scan': {'unique_hosts': 20, 'time_window': 60},
        'syn_flood': {'syn_packets': 1000, 'time_window': 10}
    }
    
    # Protocol numbers
    PROTOCOLS = {
        1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE",
        50: "ESP", 51: "AH", 88: "EIGRP", 89: "OSPF"
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.templates = {}  # NetFlow v9 templates
        self.flow_stats = defaultdict(lambda: {
            'bytes': 0, 'packets': 0, 'flows': 0,
            'protocols': defaultdict(int),
            'ports': defaultdict(int)
        })
        self.suspicious_flows = []
        self.potential_scans = defaultdict(list)
        self.anomalies = []
        
    async def parse(self) -> ParseResult:
        """Parse NetFlow data file"""
        result = ParseResult(
            file_path=str(self.file_path),
            file_type="netflow",
            parser_name=self.name
        )
        
        try:
            # Get file metadata
            result.metadata = await self._get_file_metadata()
            
            # Detect NetFlow version
            version = await self._detect_version()
            if not version:
                result.errors.append("Unable to detect NetFlow version")
                return result
                
            result.metadata.additional["netflow_version"] = version
            
            # Parse flows based on version
            if version == 5:
                async for entry in self._parse_v5():
                    result.entries.append(entry)
                    result.iocs.merge(self._extract_flow_iocs(entry))
                    await self._analyze_flow(entry)
            else:  # v9
                async for entry in self._parse_v9():
                    result.entries.append(entry)
                    result.iocs.merge(self._extract_flow_iocs(entry))
                    await self._analyze_flow(entry)
                    
            # Detect scans and anomalies
            await self._detect_scans()
            await self._detect_anomalies()
            
            # Add security findings
            for scan in self.suspicious_flows[:100]:  # Limit to top 100
                result.entries.append(scan)
                
            # Add summary statistics
            result.metadata.additional.update({
                "total_flows": len(result.entries),
                "unique_sources": len(set(e.source for e in result.entries if e.source)),
                "unique_destinations": len(self._get_unique_destinations(result.entries)),
                "flow_statistics": self._summarize_flow_stats(),
                "detected_scans": len(self.suspicious_flows),
                "anomalies": len(self.anomalies),
                "top_talkers": self._get_top_talkers(),
                "suspicious_ports": self._get_suspicious_port_usage()
            })
            
            self.logger.info(f"Parsed {len(result.entries)} NetFlow records")
            
        except Exception as e:
            self.logger.error(f"Error parsing NetFlow data: {e}")
            result.errors.append(f"Parse error: {str(e)}")
            
        return result
        
    async def _detect_version(self) -> Optional[int]:
        """Detect NetFlow version from file header"""
        async with self._open_file('rb') as f:
            header = await f.read(2)
            if len(header) < 2:
                return None
                
            version = struct.unpack('!H', header)[0]
            
            if version in [5, 9]:
                self.logger.info(f"Detected NetFlow version: {version}")
                return version
                
        return None
        
    async def _parse_v5(self) -> AsyncGenerator[ParsedEntry, None]:
        """Parse NetFlow v5 data"""
        flow_num = 0
        
        async with self._open_file('rb') as f:
            while True:
                # Read header
                header_data = await f.read(self.V5_HEADER_SIZE)
                if len(header_data) < self.V5_HEADER_SIZE:
                    break
                    
                header = self._parse_v5_header(header_data)
                
                # Read flow records
                for i in range(header['count']):
                    record_data = await f.read(self.V5_RECORD_SIZE)
                    if len(record_data) < self.V5_RECORD_SIZE:
                        break
                        
                    flow_num += 1
                    
                    # Yield control periodically
                    if flow_num % 1000 == 0:
                        await asyncio.sleep(0)
                        
                    flow = self._parse_v5_record(record_data, header)
                    entry = self._create_flow_entry(flow, flow_num)
                    
                    yield entry
                    
    def _parse_v5_header(self, data: bytes) -> Dict:
        """Parse NetFlow v5 header"""
        fields = struct.unpack('!HHIIIIBBH', data)
        
        return {
            'version': fields[0],
            'count': fields[1],
            'sys_uptime': fields[2],
            'unix_secs': fields[3],
            'unix_nsecs': fields[4],
            'flow_sequence': fields[5],
            'engine_type': fields[6],
            'engine_id': fields[7],
            'sampling_interval': fields[8]
        }
        
    def _parse_v5_record(self, data: bytes, header: Dict) -> Dict:
        """Parse NetFlow v5 flow record"""
        fields = struct.unpack('!IIIHHIIIIHHBBBBHHBBH', data)
        
        # Calculate timestamps
        start_time = datetime.fromtimestamp(header['unix_secs'])
        start_time -= timedelta(milliseconds=(header['sys_uptime'] - fields[9]))
        
        end_time = datetime.fromtimestamp(header['unix_secs'])
        end_time -= timedelta(milliseconds=(header['sys_uptime'] - fields[10]))
        
        return {
            'src_addr': self._int_to_ip(fields[0]),
            'dst_addr': self._int_to_ip(fields[1]),
            'next_hop': self._int_to_ip(fields[2]),
            'input': fields[3],
            'output': fields[4],
            'packets': fields[5],
            'bytes': fields[6],
            'first': start_time,
            'last': end_time,
            'src_port': fields[7],
            'dst_port': fields[8],
            'tcp_flags': fields[13],
            'protocol': fields[14],
            'tos': fields[15],
            'src_as': fields[16],
            'dst_as': fields[17],
            'src_mask': fields[18],
            'dst_mask': fields[19]
        }
        
    async def _parse_v9(self) -> AsyncGenerator[ParsedEntry, None]:
        """Parse NetFlow v9 data"""
        flow_num = 0
        
        async with self._open_file('rb') as f:
            while True:
                # Read header
                header_data = await f.read(self.V9_HEADER_SIZE)
                if len(header_data) < self.V9_HEADER_SIZE:
                    break
                    
                header = self._parse_v9_header(header_data)
                
                # Process flowsets
                remaining = header['length'] - self.V9_HEADER_SIZE
                
                while remaining > 0:
                    # Read flowset header
                    flowset_header = await f.read(4)
                    if len(flowset_header) < 4:
                        break
                        
                    flowset_id, flowset_length = struct.unpack('!HH', flowset_header)
                    remaining -= 4
                    
                    # Read flowset data
                    flowset_data = await f.read(flowset_length - 4)
                    remaining -= (flowset_length - 4)
                    
                    if flowset_id == self.V9_TEMPLATE_FLOWSET_ID:
                        # Parse template
                        self._parse_v9_template(flowset_data, header['source_id'])
                    elif flowset_id > 255:
                        # Data flowset
                        template = self.templates.get((header['source_id'], flowset_id))
                        if template:
                            flows = self._parse_v9_data(flowset_data, template)
                            for flow in flows:
                                flow_num += 1
                                
                                # Yield control periodically
                                if flow_num % 1000 == 0:
                                    await asyncio.sleep(0)
                                    
                                entry = self._create_flow_entry(flow, flow_num)
                                yield entry
                                
    def _parse_v9_header(self, data: bytes) -> Dict:
        """Parse NetFlow v9 header"""
        fields = struct.unpack('!HHIIII', data)
        
        return {
            'version': fields[0],
            'count': fields[1],
            'sys_uptime': fields[2],
            'unix_secs': fields[3],
            'sequence': fields[4],
            'source_id': fields[5],
            'length': 20  # Fixed header size
        }
        
    def _parse_v9_template(self, data: bytes, source_id: int):
        """Parse NetFlow v9 template"""
        offset = 0
        
        while offset < len(data):
            if offset + 4 > len(data):
                break
                
            template_id, field_count = struct.unpack('!HH', data[offset:offset+4])
            offset += 4
            
            fields = []
            for i in range(field_count):
                if offset + 4 > len(data):
                    break
                    
                field_type, field_length = struct.unpack('!HH', data[offset:offset+4])
                offset += 4
                
                fields.append({
                    'type': field_type,
                    'length': field_length
                })
                
            self.templates[(source_id, template_id)] = fields
            
    def _parse_v9_data(self, data: bytes, template: List[Dict]) -> List[Dict]:
        """Parse NetFlow v9 data records using template"""
        flows = []
        offset = 0
        
        while offset < len(data):
            flow = {}
            
            for field in template:
                if offset + field['length'] > len(data):
                    break
                    
                value = data[offset:offset+field['length']]
                offset += field['length']
                
                # Map common field types
                if field['type'] == 8:  # Source IP
                    flow['src_addr'] = self._bytes_to_ip(value)
                elif field['type'] == 12:  # Destination IP
                    flow['dst_addr'] = self._bytes_to_ip(value)
                elif field['type'] == 7:  # Source port
                    flow['src_port'] = struct.unpack('!H', value)[0]
                elif field['type'] == 11:  # Destination port
                    flow['dst_port'] = struct.unpack('!H', value)[0]
                elif field['type'] == 2:  # Packets
                    flow['packets'] = struct.unpack('!I', value)[0]
                elif field['type'] == 1:  # Bytes
                    flow['bytes'] = struct.unpack('!I', value)[0]
                elif field['type'] == 4:  # Protocol
                    flow['protocol'] = struct.unpack('!B', value)[0]
                    
            if flow:
                flows.append(flow)
                
        return flows
        
    def _create_flow_entry(self, flow: Dict, flow_num: int) -> ParsedEntry:
        """Create parsed entry from flow data"""
        # Build message
        proto = self.PROTOCOLS.get(flow.get('protocol', 0), str(flow.get('protocol', 0)))
        message = (f"{proto} {flow.get('src_addr', 'unknown')}:"
                  f"{flow.get('src_port', 0)} -> "
                  f"{flow.get('dst_addr', 'unknown')}:"
                  f"{flow.get('dst_port', 0)} "
                  f"({flow.get('packets', 0)} pkts, "
                  f"{flow.get('bytes', 0)} bytes)")
        
        # Determine severity based on analysis
        severity = "info"
        if self._is_suspicious_port(flow.get('dst_port', 0)):
            severity = "warning"
        if flow.get('tcp_flags') and self._is_suspicious_flags(flow['tcp_flags']):
            severity = "warning"
            
        entry = ParsedEntry(
            timestamp=flow.get('first', datetime.now()),
            source=flow.get('src_addr', 'unknown'),
            event_type="network_flow",
            severity=severity,
            message=message,
            raw_data=flow
        )
        
        entry.parsed_data = {
            "src_ip": flow.get('src_addr'),
            "dst_ip": flow.get('dst_addr'),
            "src_port": flow.get('src_port', 0),
            "dst_port": flow.get('dst_port', 0),
            "protocol": proto,
            "packets": flow.get('packets', 0),
            "bytes": flow.get('bytes', 0),
            "duration": self._calculate_duration(flow)
        }
        
        if 'tcp_flags' in flow:
            entry.parsed_data['tcp_flags'] = self._parse_tcp_flags(flow['tcp_flags'])
            
        return entry
        
    def _extract_flow_iocs(self, entry: ParsedEntry) -> IOCs:
        """Extract IOCs from flow data"""
        iocs = IOCs()
        data = entry.parsed_data
        
        # Add IPs
        if data.get('src_ip'):
            iocs.ips.add(data['src_ip'])
        if data.get('dst_ip'):
            iocs.ips.add(data['dst_ip'])
            
        # Check for known malicious ports
        port = data.get('dst_port', 0)
        if port in [4444, 5555, 6666, 7777, 8888, 9999]:  # Common backdoor ports
            iocs.domains.add(f"backdoor-port-{port}")
            
        return iocs
        
    async def _analyze_flow(self, entry: ParsedEntry):
        """Analyze flow for security issues"""
        data = entry.parsed_data
        src_ip = data.get('src_ip')
        dst_ip = data.get('dst_ip')
        dst_port = data.get('dst_port', 0)
        
        # Update statistics
        if src_ip:
            stats = self.flow_stats[src_ip]
            stats['flows'] += 1
            stats['bytes'] += data.get('bytes', 0)
            stats['packets'] += data.get('packets', 0)
            stats['protocols'][data.get('protocol', 'unknown')] += 1
            stats['ports'][dst_port] += 1
            
        # Check for suspicious patterns
        
        # 1. Port scanning detection
        if src_ip:
            self.potential_scans[src_ip].append({
                'timestamp': entry.timestamp,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'packets': data.get('packets', 0)
            })
            
        # 2. Suspicious ports
        if self._is_suspicious_port(dst_port):
            entry.tags.append(f"suspicious_port_{dst_port}")
            
            # Create alert for highly suspicious ports
            if dst_port in [135, 139, 445, 3389]:  # Windows attack vectors
                alert = ParsedEntry(
                    timestamp=entry.timestamp,
                    source=src_ip,
                    event_type="security_alert",
                    severity="warning",
                    message=f"Access to suspicious port {dst_port} ({self.SUSPICIOUS_PORTS.get(dst_port, 'Unknown')})",
                    raw_data=entry.raw_data
                )
                alert.tags = ["suspicious_activity", f"port_{dst_port}"]
                self.suspicious_flows.append(alert)
                
        # 3. TCP flags analysis
        if 'tcp_flags' in entry.parsed_data:
            flags = entry.parsed_data['tcp_flags']
            
            # SYN flood detection
            if 'SYN' in flags and 'ACK' not in flags:
                entry.tags.append("syn_packet")
                
            # NULL scan
            if not flags:
                entry.tags.append("null_scan")
                
            # XMAS scan
            if all(f in flags for f in ['FIN', 'PSH', 'URG']):
                entry.tags.append("xmas_scan")
                
        # 4. Data exfiltration detection
        if data.get('bytes', 0) > 10_000_000:  # 10MB+
            if dst_port not in [80, 443, 22]:  # Not standard ports
                alert = ParsedEntry(
                    timestamp=entry.timestamp,
                    source=src_ip,
                    event_type="security_alert", 
                    severity="warning",
                    message=f"Large data transfer detected: {data['bytes']:,} bytes to port {dst_port}",
                    raw_data=entry.raw_data
                )
                alert.tags = ["data_exfiltration", "suspicious_transfer"]
                self.suspicious_flows.append(alert)
                
    async def _detect_scans(self):
        """Detect various types of network scans"""
        current_time = datetime.now()
        
        for src_ip, flows in self.potential_scans.items():
            # Group flows by time windows
            time_windows = defaultdict(list)
            
            for flow in flows:
                window = int(flow['timestamp'].timestamp() / 60)  # 1-minute windows
                time_windows[window].append(flow)
                
            # Check each time window
            for window, window_flows in time_windows.items():
                # Port scan detection
                unique_ports = len(set(f['dst_port'] for f in window_flows))
                if unique_ports >= self.SCAN_THRESHOLDS['port_scan']['unique_ports']:
                    scan_alert = ParsedEntry(
                        timestamp=window_flows[0]['timestamp'],
                        source=src_ip,
                        event_type="security_alert",
                        severity="critical",
                        message=f"Port scan detected: {unique_ports} ports scanned in 1 minute",
                        raw_data={'flows': window_flows[:10]}  # Sample flows
                    )
                    scan_alert.tags = ["port_scan", "reconnaissance", "attack"]
                    self.suspicious_flows.append(scan_alert)
                    
                # Network scan detection
                unique_hosts = len(set(f['dst_ip'] for f in window_flows))
                if unique_hosts >= self.SCAN_THRESHOLDS['network_scan']['unique_hosts']:
                    scan_alert = ParsedEntry(
                        timestamp=window_flows[0]['timestamp'],
                        source=src_ip,
                        event_type="security_alert",
                        severity="critical",
                        message=f"Network scan detected: {unique_hosts} hosts scanned in 1 minute",
                        raw_data={'flows': window_flows[:10]}
                    )
                    scan_alert.tags = ["network_scan", "reconnaissance", "attack"]
                    self.suspicious_flows.append(scan_alert)
                    
    async def _detect_anomalies(self):
        """Detect traffic anomalies"""
        # Detect top talkers
        sorted_ips = sorted(
            self.flow_stats.items(),
            key=lambda x: x[1]['bytes'],
            reverse=True
        )
        
        if sorted_ips:
            # Check for data exfiltration patterns
            for ip, stats in sorted_ips[:10]:
                # High outbound traffic to unusual ports
                unusual_port_traffic = sum(
                    bytes_count for port, bytes_count in stats['ports'].items()
                    if port not in [80, 443, 22, 25, 53]
                )
                
                if unusual_port_traffic > 100_000_000:  # 100MB+
                    self.anomalies.append({
                        'type': 'unusual_traffic_pattern',
                        'ip': ip,
                        'bytes': unusual_port_traffic,
                        'ports': list(stats['ports'].keys())
                    })
                    
    def _int_to_ip(self, ip_int: int) -> str:
        """Convert integer to IP address string"""
        return str(ipaddress.IPv4Address(ip_int))
        
    def _bytes_to_ip(self, ip_bytes: bytes) -> str:
        """Convert bytes to IP address string"""
        if len(ip_bytes) == 4:
            return str(ipaddress.IPv4Address(ip_bytes))
        elif len(ip_bytes) == 16:
            return str(ipaddress.IPv6Address(ip_bytes))
        return "unknown"
        
    def _is_suspicious_port(self, port: int) -> bool:
        """Check if port is commonly associated with attacks"""
        suspicious = [
            135, 139, 445,  # Windows SMB/RPC
            1433, 3306, 5432,  # Databases
            3389,  # RDP
            4444, 5555, 6666, 7777, 8888, 9999,  # Common backdoors
            6379,  # Redis
            9200,  # Elasticsearch
            27017  # MongoDB
        ]
        return port in suspicious
        
    def _is_suspicious_flags(self, flags: int) -> bool:
        """Check for suspicious TCP flag combinations"""
        # NULL scan (no flags)
        if flags == 0:
            return True
            
        # XMAS scan (FIN, PSH, URG)
        if flags & 0x29 == 0x29:
            return True
            
        # SYN-FIN (invalid combination)
        if flags & 0x03 == 0x03:
            return True
            
        return False
        
    def _parse_tcp_flags(self, flags: int) -> List[str]:
        """Parse TCP flags from integer"""
        flag_names = []
        
        if flags & 0x01: flag_names.append("FIN")
        if flags & 0x02: flag_names.append("SYN")
        if flags & 0x04: flag_names.append("RST")
        if flags & 0x08: flag_names.append("PSH")
        if flags & 0x10: flag_names.append("ACK")
        if flags & 0x20: flag_names.append("URG")
        if flags & 0x40: flag_names.append("ECE")
        if flags & 0x80: flag_names.append("CWR")
        
        return flag_names
        
    def _calculate_duration(self, flow: Dict) -> float:
        """Calculate flow duration in seconds"""
        if 'first' in flow and 'last' in flow:
            duration = (flow['last'] - flow['first']).total_seconds()
            return max(0, duration)
        return 0
        
    def _get_unique_destinations(self, entries: List[ParsedEntry]) -> Set[str]:
        """Get unique destination IPs"""
        destinations = set()
        for entry in entries:
            if entry.parsed_data.get('dst_ip'):
                destinations.add(entry.parsed_data['dst_ip'])
        return destinations
        
    def _summarize_flow_stats(self) -> Dict:
        """Summarize flow statistics"""
        total_bytes = sum(s['bytes'] for s in self.flow_stats.values())
        total_packets = sum(s['packets'] for s in self.flow_stats.values())
        total_flows = sum(s['flows'] for s in self.flow_stats.values())
        
        protocol_dist = defaultdict(int)
        for stats in self.flow_stats.values():
            for proto, count in stats['protocols'].items():
                protocol_dist[proto] += count
                
        return {
            'total_bytes': total_bytes,
            'total_packets': total_packets,
            'total_flows': total_flows,
            'protocol_distribution': dict(protocol_dist),
            'avg_flow_size': total_bytes // max(total_flows, 1)
        }
        
    def _get_top_talkers(self, limit: int = 10) -> List[Dict]:
        """Get top talking IPs by bytes"""
        sorted_ips = sorted(
            self.flow_stats.items(),
            key=lambda x: x[1]['bytes'],
            reverse=True
        )
        
        return [
            {
                'ip': ip,
                'bytes': stats['bytes'],
                'packets': stats['packets'],
                'flows': stats['flows'],
                'protocols': list(stats['protocols'].keys())
            }
            for ip, stats in sorted_ips[:limit]
        ]
        
    def _get_suspicious_port_usage(self) -> List[Dict]:
        """Get usage of suspicious ports"""
        port_usage = defaultdict(lambda: {'count': 0, 'sources': set()})
        
        for ip, stats in self.flow_stats.items():
            for port, count in stats['ports'].items():
                if self._is_suspicious_port(port):
                    port_usage[port]['count'] += count
                    port_usage[port]['sources'].add(ip)
                    
        return [
            {
                'port': port,
                'service': self.SUSPICIOUS_PORTS.get(port, 'Unknown'),
                'access_count': data['count'],
                'unique_sources': len(data['sources'])
            }
            for port, data in sorted(port_usage.items(), 
                                    key=lambda x: x[1]['count'], 
                                    reverse=True)
        ]