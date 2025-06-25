"""
PCAP Parser
Parses network packet capture files (.pcap, .pcapng)
"""

import struct
from typing import Optional, AsyncIterator, Dict, Any, List
from datetime import datetime, timezone
import asyncio
import aiofiles
from scapy.all import rdpcap, IP, TCP, UDP, DNS, ARP, ICMP, Raw
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse

from parsers.base_parser import BaseParser, ParsedEntry

class PcapParser(BaseParser):
    """Parser for PCAP network capture files"""
    
    @property
    def parser_name(self) -> str:
        return "pcap"
    
    @property
    def supported_extensions(self) -> list:
        return ['.pcap', '.cap', '.pcapng', '.dmp']
    
    def __init__(self, file_path, config=None):
        super().__init__(file_path, config)
        
        # Analysis configuration
        self.analyze_payload = config.get('analyze_payload', True) if config else True
        self.extract_files = config.get('extract_files', False) if config else False
        self.dns_cache = {}  # Cache DNS resolutions
        self.tcp_streams = {}  # Track TCP streams
        self.suspicious_ports = {20, 21, 22, 23, 25, 135, 139, 445, 1433, 3306, 3389, 5900}
        
        # Protocol statistics
        self.protocol_stats = {
            'total_packets': 0,
            'protocols': {},
            'top_talkers': {},
            'port_stats': {},
            'dns_queries': []
        }
    
    async def _parse_content(self) -> AsyncIterator[Optional[ParsedEntry]]:
        """Parse PCAP file content"""
        try:
            # Read packets using scapy
            packets = await self._read_pcap_file()
            
            for i, packet in enumerate(packets):
                entry = self._parse_packet(packet, i)
                if entry:
                    yield entry
                else:
                    self._failed_count += 1
                
                # Update statistics
                self._update_statistics(packet)
                
                # Yield control periodically
                if i % 100 == 0:
                    await asyncio.sleep(0)
                    
        except Exception as e:
            self.errors.append(f"PCAP parse error: {str(e)}")
    
    async def _read_pcap_file(self) -> List:
        """Read PCAP file asynchronously"""
        # Scapy doesn't support async, so we run it in executor
        import concurrent.futures
        
        loop = asyncio.get_event_loop()
        with concurrent.futures.ThreadPoolExecutor() as pool:
            packets = await loop.run_in_executor(
                pool, 
                rdpcap, 
                str(self.file_path)
            )
        
        return packets
    
    def _parse_packet(self, packet, packet_num: int) -> Optional[ParsedEntry]:
        """Parse a single packet"""
        try:
            # Extract basic info
            timestamp = datetime.fromtimestamp(float(packet.time), tz=timezone.utc).isoformat()
            
            # Initialize metadata
            metadata = {
                'packet_number': packet_num,
                'packet_length': len(packet),
                'layers': [layer.name for layer in packet.layers()]
            }
            
            # Parse based on packet type
            if IP in packet:
                return self._parse_ip_packet(packet, timestamp, metadata)
            elif ARP in packet:
                return self._parse_arp_packet(packet, timestamp, metadata)
            else:
                # Unknown packet type
                return ParsedEntry(
                    timestamp=timestamp,
                    source='unknown',
                    event_type='network_unknown',
                    severity='info',
                    message=f"Unknown packet type: {packet.summary()}",
                    raw_data=packet.show(dump=True),
                    metadata=metadata
                )
                
        except Exception as e:
            self.warnings.append(f"Failed to parse packet {packet_num}: {str(e)}")
            return None
    
    def _parse_ip_packet(self, packet, timestamp: str, metadata: Dict) -> ParsedEntry:
        """Parse IP packet"""
        ip_layer = packet[IP]
        
        # Extract IP info
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto
        
        metadata.update({
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'ip_version': ip_layer.version,
            'ttl': ip_layer.ttl,
            'protocol_num': protocol
        })
        
        # Add IPs to IOCs
        self.iocs['ips'].extend([src_ip, dst_ip])
        
        # Determine protocol and parse accordingly
        if TCP in packet:
            return self._parse_tcp_packet(packet, timestamp, metadata)
        elif UDP in packet:
            return self._parse_udp_packet(packet, timestamp, metadata)
        elif ICMP in packet:
            return self._parse_icmp_packet(packet, timestamp, metadata)
        else:
            # Generic IP packet
            message = f"IP {src_ip} > {dst_ip} proto:{protocol}"
            
            return ParsedEntry(
                timestamp=timestamp,
                source=src_ip,
                event_type='network_ip',
                severity='info',
                message=message,
                raw_data=packet.show(dump=True),
                metadata=metadata
            )
    
    def _parse_tcp_packet(self, packet, timestamp: str, metadata: Dict) -> ParsedEntry:
        """Parse TCP packet"""
        tcp_layer = packet[TCP]
        ip_layer = packet[IP]
        
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport
        flags = tcp_layer.flags
        
        metadata.update({
            'src_port': src_port,
            'dst_port': dst_port,
            'tcp_flags': str(flags),
            'seq': tcp_layer.seq,
            'ack': tcp_layer.ack,
            'window': tcp_layer.window
        })
        
        # Track TCP stream
        stream_id = f"{ip_layer.src}:{src_port}-{ip_layer.dst}:{dst_port}"
        if stream_id not in self.tcp_streams:
            self.tcp_streams[stream_id] = {
                'start_time': timestamp,
                'packets': 0,
                'bytes': 0
            }
        self.tcp_streams[stream_id]['packets'] += 1
        self.tcp_streams[stream_id]['bytes'] += len(packet)
        metadata['stream_id'] = stream_id
        
        # Determine event type and severity
        event_type = 'network_tcp'
        severity = 'info'
        
        # Check for suspicious activity
        if dst_port in self.suspicious_ports or src_port in self.suspicious_ports:
            severity = 'medium'
            metadata['suspicious_port'] = True
        
        # Check for port scan patterns
        if flags == 'S' and dst_port < 1024:
            event_type = 'network_scan'
            severity = 'high'
        
        # Parse application layer if present
        if HTTP in packet or packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
            return self._parse_http_packet(packet, timestamp, metadata)
        
        # Build message
        flag_str = self._tcp_flags_to_string(flags)
        message = f"TCP {ip_layer.src}:{src_port} > {ip_layer.dst}:{dst_port} [{flag_str}]"
        
        # Check for payload
        if Raw in packet:
            payload = packet[Raw].load
            if self.analyze_payload:
                payload_info = self._analyze_payload(payload)
                if payload_info:
                    metadata['payload_info'] = payload_info
                    message += f" | {payload_info['type']}"
        
        return ParsedEntry(
            timestamp=timestamp,
            source=ip_layer.src,
            event_type=event_type,
            severity=severity,
            message=message,
            raw_data=packet.show(dump=True),
            metadata=metadata
        )
    
    def _parse_udp_packet(self, packet, timestamp: str, metadata: Dict) -> ParsedEntry:
        """Parse UDP packet"""
        udp_layer = packet[UDP]
        ip_layer = packet[IP]
        
        src_port = udp_layer.sport
        dst_port = udp_layer.dport
        
        metadata.update({
            'src_port': src_port,
            'dst_port': dst_port,
            'udp_length': udp_layer.len
        })
        
        # Check for DNS
        if DNS in packet:
            return self._parse_dns_packet(packet, timestamp, metadata)
        
        # Determine severity
        severity = 'info'
        if dst_port in self.suspicious_ports or src_port in self.suspicious_ports:
            severity = 'medium'
            metadata['suspicious_port'] = True
        
        message = f"UDP {ip_layer.src}:{src_port} > {ip_layer.dst}:{dst_port}"
        
        # Check for payload
        if Raw in packet:
            payload = packet[Raw].load
            if self.analyze_payload:
                payload_info = self._analyze_payload(payload)
                if payload_info:
                    metadata['payload_info'] = payload_info
        
        return ParsedEntry(
            timestamp=timestamp,
            source=ip_layer.src,
            event_type='network_udp',
            severity=severity,
            message=message,
            raw_data=packet.show(dump=True),
            metadata=metadata
        )
    
    def _parse_dns_packet(self, packet, timestamp: str, metadata: Dict) -> ParsedEntry:
        """Parse DNS packet"""
        dns_layer = packet[DNS]
        ip_layer = packet[IP]
        
        # Determine if query or response
        is_response = dns_layer.qr == 1
        
        metadata['dns_type'] = 'response' if is_response else 'query'
        metadata['dns_id'] = dns_layer.id
        
        if is_response:
            # Parse DNS response
            answers = []
            for i in range(dns_layer.ancount):
                if i < len(dns_layer.an):
                    rr = dns_layer.an[i]
                    if hasattr(rr, 'rdata'):
                        answers.append({
                            'name': rr.rrname.decode() if isinstance(rr.rrname, bytes) else str(rr.rrname),
                            'type': rr.type,
                            'data': str(rr.rdata)
                        })
                        
                        # Add to IOCs
                        if rr.type == 1:  # A record
                            self.iocs['ips'].append(str(rr.rdata))
                        
            metadata['dns_answers'] = answers
            message = f"DNS Response: {len(answers)} answers"
            
            # Cache DNS responses
            for answer in answers:
                if answer['type'] == 1:  # A record
                    self.dns_cache[answer['name']] = answer['data']
                    
        else:
            # Parse DNS query
            queries = []
            for i in range(dns_layer.qdcount):
                if i < len(dns_layer.qd):
                    qr = dns_layer.qd[i]
                    query_name = qr.qname.decode() if isinstance(qr.qname, bytes) else str(qr.qname)
                    queries.append({
                        'name': query_name,
                        'type': qr.qtype
                    })
                    
                    # Add to IOCs
                    self.iocs['domains'].append(query_name.rstrip('.'))
                    
            metadata['dns_queries'] = queries
            message = f"DNS Query: {queries[0]['name'] if queries else 'unknown'}"
            
            # Track DNS queries
            self.protocol_stats['dns_queries'].extend([q['name'] for q in queries])
        
        return ParsedEntry(
            timestamp=timestamp,
            source=ip_layer.src,
            event_type='network_dns',
            severity='info',
            message=message,
            raw_data=packet.show(dump=True),
            metadata=metadata
        )
    
    def _parse_http_packet(self, packet, timestamp: str, metadata: Dict) -> ParsedEntry:
        """Parse HTTP packet"""
        ip_layer = packet[IP]
        
        # Extract HTTP info
        if packet.haslayer(HTTPRequest):
            http_layer = packet[HTTPRequest]
            method = http_layer.Method.decode() if hasattr(http_layer, 'Method') else 'UNKNOWN'
            host = http_layer.Host.decode() if hasattr(http_layer, 'Host') else ip_layer.dst
            path = http_layer.Path.decode() if hasattr(http_layer, 'Path') else '/'
            
            metadata.update({
                'http_method': method,
                'http_host': host,
                'http_path': path,
                'http_type': 'request'
            })
            
            # Extract user agent
            if hasattr(http_layer, 'User_Agent'):
                metadata['user_agent'] = http_layer.User_Agent.decode()
            
            message = f"HTTP {method} {host}{path}"
            
            # Add to IOCs
            self.iocs['domains'].append(host)
            if path != '/':
                self.iocs['urls'].append(f"http://{host}{path}")
                
        elif packet.haslayer(HTTPResponse):
            http_layer = packet[HTTPResponse]
            status = http_layer.Status_Code.decode() if hasattr(http_layer, 'Status_Code') else 'unknown'
            
            metadata.update({
                'http_status': status,
                'http_type': 'response'
            })
            
            message = f"HTTP Response: {status}"
        else:
            message = "HTTP Traffic"
            metadata['http_type'] = 'unknown'
        
        # Check for suspicious patterns
        severity = 'info'
        if 'http_path' in metadata:
            suspicious_paths = ['/admin', '/shell', '/cmd', '.php', '.asp', '../']
            if any(p in metadata['http_path'].lower() for p in suspicious_paths):
                severity = 'high'
                metadata['suspicious_path'] = True
        
        return ParsedEntry(
            timestamp=timestamp,
            source=ip_layer.src,
            event_type='network_http',
            severity=severity,
            message=message,
            raw_data=packet.show(dump=True),
            metadata=metadata
        )
    
    def _parse_icmp_packet(self, packet, timestamp: str, metadata: Dict) -> ParsedEntry:
        """Parse ICMP packet"""
        icmp_layer = packet[ICMP]
        ip_layer = packet[IP]
        
        icmp_types = {
            0: 'Echo Reply',
            3: 'Destination Unreachable',
            8: 'Echo Request',
            11: 'Time Exceeded'
        }
        
        icmp_type = icmp_layer.type
        icmp_code = icmp_layer.code
        type_name = icmp_types.get(icmp_type, f'Type {icmp_type}')
        
        metadata.update({
            'icmp_type': icmp_type,
            'icmp_code': icmp_code,
            'icmp_type_name': type_name
        })
        
        message = f"ICMP {ip_layer.src} > {ip_layer.dst} {type_name}"
        
        # Determine severity
        severity = 'info'
        if icmp_type == 3:  # Destination unreachable
            severity = 'medium'
        
        return ParsedEntry(
            timestamp=timestamp,
            source=ip_layer.src,
            event_type='network_icmp',
            severity=severity,
            message=message,
            raw_data=packet.show(dump=True),
            metadata=metadata
        )
    
    def _parse_arp_packet(self, packet, timestamp: str, metadata: Dict) -> ParsedEntry:
        """Parse ARP packet"""
        arp_layer = packet[ARP]
        
        op_types = {1: 'Request', 2: 'Reply'}
        op_type = op_types.get(arp_layer.op, f'Op {arp_layer.op}')
        
        metadata.update({
            'arp_op': arp_layer.op,
            'arp_op_type': op_type,
            'arp_src_mac': arp_layer.hwsrc,
            'arp_src_ip': arp_layer.psrc,
            'arp_dst_mac': arp_layer.hwdst,
            'arp_dst_ip': arp_layer.pdst
        })
        
        # Add IPs to IOCs
        self.iocs['ips'].extend([arp_layer.psrc, arp_layer.pdst])
        
        if arp_layer.op == 1:  # Request
            message = f"ARP Request: Who has {arp_layer.pdst}? Tell {arp_layer.psrc}"
        else:  # Reply
            message = f"ARP Reply: {arp_layer.psrc} is at {arp_layer.hwsrc}"
        
        # Check for ARP spoofing indicators
        severity = 'info'
        # Simple check - could be enhanced
        if arp_layer.op == 2 and arp_layer.hwdst == 'ff:ff:ff:ff:ff:ff':
            severity = 'high'
            metadata['possible_arp_spoofing'] = True
        
        return ParsedEntry(
            timestamp=timestamp,
            source=arp_layer.psrc,
            event_type='network_arp',
            severity=severity,
            message=message,
            raw_data=packet.show(dump=True),
            metadata=metadata
        )
    
    def _tcp_flags_to_string(self, flags) -> str:
        """Convert TCP flags to readable string"""
        flag_names = {
            'F': 'FIN',
            'S': 'SYN',
            'R': 'RST',
            'P': 'PSH',
            'A': 'ACK',
            'U': 'URG',
            'E': 'ECE',
            'C': 'CWR'
        }
        
        if isinstance(flags, int):
            # Convert numeric flags to string
            flag_str = ''
            if flags & 0x01: flag_str += 'F'
            if flags & 0x02: flag_str += 'S'
            if flags & 0x04: flag_str += 'R'
            if flags & 0x08: flag_str += 'P'
            if flags & 0x10: flag_str += 'A'
            if flags & 0x20: flag_str += 'U'
            if flags & 0x40: flag_str += 'E'
            if flags & 0x80: flag_str += 'C'
            return flag_str
        else:
            return str(flags)
    
    def _analyze_payload(self, payload: bytes) -> Optional[Dict[str, Any]]:
        """Analyze packet payload for patterns"""
        if not payload or len(payload) < 4:
            return None
        
        payload_info = {}
        
        # Try to decode as text
        try:
            text = payload.decode('utf-8', errors='ignore')
            if text.isprintable():
                payload_info['type'] = 'text'
                payload_info['preview'] = text[:100]
                
                # Check for credentials
                if any(word in text.lower() for word in ['password', 'passwd', 'pwd', 'pass']):
                    payload_info['possible_credentials'] = True
                    
        except:
            pass
        
        # Check for file signatures
        file_sigs = {
            b'\x4D\x5A': 'PE/EXE',
            b'\x7F\x45\x4C\x46': 'ELF',
            b'\x25\x50\x44\x46': 'PDF',
            b'\x50\x4B\x03\x04': 'ZIP',
            b'\x52\x61\x72\x21': 'RAR'
        }
        
        for sig, file_type in file_sigs.items():
            if payload.startswith(sig):
                payload_info['type'] = 'file'
                payload_info['file_type'] = file_type
                break
        
        return payload_info if payload_info else None
    
    def _update_statistics(self, packet) -> None:
        """Update protocol statistics"""
        self.protocol_stats['total_packets'] += 1
        
        # Protocol stats
        if IP in packet:
            proto = packet[IP].proto
            proto_name = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(proto, f'Proto_{proto}')
            self.protocol_stats['protocols'][proto_name] = \
                self.protocol_stats['protocols'].get(proto_name, 0) + 1
            
            # Top talkers
            src = packet[IP].src
            self.protocol_stats['top_talkers'][src] = \
                self.protocol_stats['top_talkers'].get(src, 0) + 1
        
        # Port stats
        if TCP in packet:
            port = packet[TCP].dport
            self.protocol_stats['port_stats'][port] = \
                self.protocol_stats['port_stats'].get(port, 0) + 1
        elif UDP in packet:
            port = packet[UDP].dport
            self.protocol_stats['port_stats'][port] = \
                self.protocol_stats['port_stats'].get(port, 0) + 1
    
    async def _extract_file_metadata(self) -> None:
        """Extract PCAP-specific metadata"""
        await super()._extract_file_metadata()
        
        self.metadata['file_type'] = 'pcap'
        self.metadata['parser_version'] = '1.0'
        
        # Add capture statistics after parsing
        self.metadata['capture_stats'] = {
            'total_packets': self.protocol_stats['total_packets'],
            'protocols': dict(sorted(
                self.protocol_stats['protocols'].items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:10]),
            'top_talkers': dict(sorted(
                self.protocol_stats['top_talkers'].items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:10]),
            'top_ports': dict(sorted(
                self.protocol_stats['port_stats'].items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:10]),
            'unique_dns_queries': len(set(self.protocol_stats['dns_queries'])),
            'tcp_streams': len(self.tcp_streams)
        }