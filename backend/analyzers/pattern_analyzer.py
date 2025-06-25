"""
Pattern Analyzer - Detects complex behavioral patterns in security data

This module identifies multi-stage attacks, lateral movement patterns,
persistence mechanisms, and other complex behavioral patterns.
"""

import logging
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import re
import statistics
from dataclasses import dataclass
import networkx as nx

from parsers.base_parser import ParsedEntry

logger = logging.getLogger(__name__)

@dataclass
class Pattern:
    """Represents a detected security pattern"""
    name: str
    type: str  # temporal, behavioral, statistical, network
    description: str
    confidence: float
    severity: str
    evidence: List[Dict[str, Any]]
    timeline: List[Tuple[datetime, str]]
    iocs_involved: List[str]
    entries_matched: List[int]  # Indices of matched entries
    recommendations: List[str]

class PatternAnalyzer:
    """Advanced pattern detection for security analysis"""
    
    def __init__(self):
        # Pattern detection configurations
        self.patterns = self._define_patterns()
        
        # Statistical thresholds
        self.anomaly_threshold = 2.5  # Standard deviations
        self.frequency_threshold = 0.1  # 10% of entries
        self.burst_window = timedelta(minutes=5)
        self.sequence_window = timedelta(minutes=30)
        
        # Network analysis
        self.network_graph = nx.DiGraph()
        
        # Pattern matchers
        self.behavioral_patterns = self._compile_behavioral_patterns()
        self.temporal_patterns = self._compile_temporal_patterns()
    
    def _define_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Define security patterns to detect"""
        return {
            # Attack patterns
            "brute_force": {
                "type": "temporal",
                "indicators": ["failed login", "authentication failure", "invalid password"],
                "threshold": 5,
                "window": timedelta(minutes=5),
                "severity": "high"
            },
            "port_scan": {
                "type": "network",
                "indicators": ["connection refused", "port closed", "timeout", "SYN"],
                "threshold": 20,
                "window": timedelta(minutes=1),
                "severity": "medium"
            },
            "lateral_movement": {
                "type": "behavioral",
                "indicators": ["remote connection", "psexec", "wmic", "rdp", "ssh"],
                "sequence": True,
                "severity": "high"
            },
            "data_exfiltration": {
                "type": "statistical",
                "indicators": ["large data transfer", "upload", "outbound", "archive"],
                "anomaly_detection": True,
                "severity": "critical"
            },
            "privilege_escalation": {
                "type": "behavioral",
                "indicators": ["elevation", "admin", "root", "sudo", "runas"],
                "context_required": True,
                "severity": "high"
            },
            "persistence_mechanism": {
                "type": "behavioral",
                "indicators": ["registry", "startup", "scheduled task", "cron", "service"],
                "severity": "high"
            },
            "defense_evasion": {
                "type": "behavioral",
                "indicators": ["disable", "stop", "kill", "bypass", "clear log"],
                "severity": "high"
            },
            "command_control": {
                "type": "network",
                "indicators": ["beacon", "callback", "heartbeat", "check-in"],
                "periodic": True,
                "severity": "critical"
            },
            "ransomware_behavior": {
                "type": "behavioral",
                "indicators": ["encrypt", "locked", "ransom", "bitcoin", ".locked"],
                "rapid_file_changes": True,
                "severity": "critical"
            },
            "supply_chain": {
                "type": "behavioral",
                "indicators": ["update", "patch", "installer", "signed", "certificate"],
                "anomaly_context": True,
                "severity": "critical"
            }
        }
    
    def _compile_behavioral_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Compile regex patterns for behavioral detection"""
        return {
            "credential_access": [
                re.compile(r'(lsass|sam\.hive|ntds\.dit|hashdump|mimikatz)', re.I),
                re.compile(r'(password|credential|secret).*dump', re.I)
            ],
            "discovery": [
                re.compile(r'(net\s+view|net\s+user|net\s+group|whoami|ipconfig|ifconfig)', re.I),
                re.compile(r'(systeminfo|hostname|arp\s+-a|route\s+print)', re.I)
            ],
            "execution": [
                re.compile(r'(powershell|cmd|bash|sh).*(-c|-command|/c)', re.I),
                re.compile(r'(invoke-expression|iex|eval|exec)', re.I)
            ],
            "collection": [
                re.compile(r'(compress|zip|rar|7z|tar).*\.(zip|rar|7z|tar)', re.I),
                re.compile(r'(copy|xcopy|robocopy|cp|rsync).*\*', re.I)
            ],
            "impact": [
                re.compile(r'(delete|remove|destroy|wipe|format)', re.I),
                re.compile(r'(shutdown|reboot|stop-computer|halt)', re.I)
            ]
        }
    
    def _compile_temporal_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Define temporal pattern detection rules"""
        return {
            "rapid_succession": {
                "description": "Multiple similar events in rapid succession",
                "window": timedelta(seconds=10),
                "min_events": 5
            },
            "periodic_behavior": {
                "description": "Regular periodic activity suggesting automation",
                "variance_threshold": 0.1,  # 10% variance in intervals
                "min_occurrences": 5
            },
            "time_based_trigger": {
                "description": "Activity at specific times suggesting scheduled tasks",
                "time_patterns": ["00:00", "01:00", "02:00", "03:00"],  # Common scheduled times
                "tolerance": timedelta(minutes=5)
            },
            "burst_activity": {
                "description": "Sudden burst of activity after quiet period",
                "quiet_threshold": timedelta(hours=1),
                "burst_threshold": 10  # events
            }
        }
    
    async def analyze_patterns(self, entries: List[ParsedEntry], 
                             iocs: Dict[str, List[str]],
                             metadata: Any) -> List[Dict[str, Any]]:
        """
        Analyze entries for complex security patterns
        
        Args:
            entries: Parsed log entries
            iocs: Extracted IOCs
            metadata: Additional metadata
            
        Returns:
            List of detected patterns with details
        """
        if not entries:
            return []
        
        detected_patterns = []
        
        # Sort entries by timestamp for temporal analysis
        sorted_entries = sorted(
            [e for e in entries if e.timestamp],
            key=lambda x: x.timestamp
        )
        
        # Detect temporal patterns
        temporal_patterns = await self._detect_temporal_patterns(sorted_entries)
        detected_patterns.extend(temporal_patterns)
        
        # Detect behavioral patterns
        behavioral_patterns = await self._detect_behavioral_patterns(sorted_entries, iocs)
        detected_patterns.extend(behavioral_patterns)
        
        # Detect statistical anomalies
        statistical_patterns = await self._detect_statistical_patterns(sorted_entries)
        detected_patterns.extend(statistical_patterns)
        
        # Detect network patterns
        network_patterns = await self._detect_network_patterns(sorted_entries, iocs)
        detected_patterns.extend(network_patterns)
        
        # Detect multi-stage attack patterns
        attack_chains = await self._detect_attack_chains(sorted_entries, detected_patterns)
        detected_patterns.extend(attack_chains)
        
        # Convert Pattern objects to dictionaries
        return [self._pattern_to_dict(p) for p in detected_patterns]
    
    async def _detect_temporal_patterns(self, entries: List[ParsedEntry]) -> List[Pattern]:
        """Detect patterns based on timing of events"""
        patterns = []
        
        # Group entries by message similarity
        message_groups = defaultdict(list)
        for i, entry in enumerate(entries):
            # Create a simplified key for grouping
            key = self._normalize_message(entry.message)
            message_groups[key].append((i, entry))
        
        # Check each group for temporal patterns
        for key, group_entries in message_groups.items():
            if len(group_entries) < 3:
                continue
            
            timestamps = [e[1].timestamp for e in group_entries if e[1].timestamp]
            if len(timestamps) < 3:
                continue
            
            # Check for rapid succession
            rapid_pattern = self._check_rapid_succession(timestamps, group_entries)
            if rapid_pattern:
                patterns.append(rapid_pattern)
            
            # Check for periodic behavior
            periodic_pattern = self._check_periodic_behavior(timestamps, group_entries)
            if periodic_pattern:
                patterns.append(periodic_pattern)
            
            # Check for burst activity
            burst_pattern = self._check_burst_activity(timestamps, group_entries)
            if burst_pattern:
                patterns.append(burst_pattern)
        
        # Check for time-based triggers
        time_patterns = self._check_time_based_triggers(entries)
        patterns.extend(time_patterns)
        
        return patterns
    
    async def _detect_behavioral_patterns(self, entries: List[ParsedEntry], 
                                        iocs: Dict[str, List[str]]) -> List[Pattern]:
        """Detect behavioral security patterns"""
        patterns = []
        
        # Track behavior sequences
        behavior_sequences = defaultdict(list)
        
        for i, entry in enumerate(entries):
            message_lower = entry.message.lower()
            
            # Check against behavioral patterns
            for behavior_type, pattern_list in self.behavioral_patterns.items():
                for pattern in pattern_list:
                    if pattern.search(entry.message):
                        behavior_sequences[behavior_type].append((i, entry))
                        break
            
            # Check for specific pattern indicators
            for pattern_name, pattern_config in self.patterns.items():
                if pattern_config["type"] != "behavioral":
                    continue
                
                # Check if entry matches pattern indicators
                if any(indicator in message_lower for indicator in pattern_config["indicators"]):
                    # Collect evidence
                    evidence = self._collect_pattern_evidence(
                        entry, entries, pattern_config, i
                    )
                    
                    if evidence:
                        pattern = Pattern(
                            name=pattern_name,
                            type="behavioral",
                            description=f"Detected {pattern_name.replace('_', ' ')} behavior",
                            confidence=self._calculate_confidence(evidence, pattern_config),
                            severity=pattern_config["severity"],
                            evidence=evidence,
                            timeline=[(entry.timestamp, entry.message[:100])] if entry.timestamp else [],
                            iocs_involved=self._extract_related_iocs(entry.message, iocs),
                            entries_matched=[i],
                            recommendations=self._generate_recommendations(pattern_name)
                        )
                        patterns.append(pattern)
        
        # Analyze behavior sequences
        sequence_patterns = self._analyze_behavior_sequences(behavior_sequences, entries)
        patterns.extend(sequence_patterns)
        
        return patterns
    
    async def _detect_statistical_patterns(self, entries: List[ParsedEntry]) -> List[Pattern]:
        """Detect statistical anomalies in the data"""
        patterns = []
        
        # Analyze entry frequency over time
        time_buckets = defaultdict(int)
        severity_distribution = Counter()
        
        for entry in entries:
            if entry.timestamp:
                # Create hourly buckets
                bucket = entry.timestamp.replace(minute=0, second=0, microsecond=0)
                time_buckets[bucket] += 1
            severity_distribution[entry.severity] += 1
        
        # Detect anomalous time periods
        if time_buckets:
            frequencies = list(time_buckets.values())
            mean_freq = statistics.mean(frequencies)
            std_freq = statistics.stdev(frequencies) if len(frequencies) > 1 else 0
            
            for timestamp, count in time_buckets.items():
                if std_freq > 0 and count > mean_freq + (self.anomaly_threshold * std_freq):
                    # Anomalous activity spike
                    affected_entries = [
                        (i, e) for i, e in enumerate(entries)
                        if e.timestamp and 
                        e.timestamp >= timestamp and 
                        e.timestamp < timestamp + timedelta(hours=1)
                    ]
                    
                    pattern = Pattern(
                        name="anomalous_activity_spike",
                        type="statistical",
                        description=f"Unusual spike in activity: {count} events vs average {mean_freq:.1f}",
                        confidence=min((count - mean_freq) / (std_freq + 1), 1.0),
                        severity="medium",
                        evidence=[{
                            "timestamp": timestamp.isoformat(),
                            "event_count": count,
                            "average": mean_freq,
                            "std_dev": std_freq
                        }],
                        timeline=[(e[1].timestamp, e[1].message[:100]) for e in affected_entries[:10]],
                        iocs_involved=[],
                        entries_matched=[e[0] for e in affected_entries],
                        recommendations=["Investigate cause of activity spike", 
                                       "Check for automated tools or scripts"]
                    )
                    patterns.append(pattern)
        
        # Detect anomalous severity distribution
        total_entries = len(entries)
        if total_entries > 100:  # Need sufficient data
            error_rate = severity_distribution.get("error", 0) / total_entries
            critical_rate = severity_distribution.get("critical", 0) / total_entries
            
            if error_rate > 0.2:  # More than 20% errors
                pattern = Pattern(
                    name="high_error_rate",
                    type="statistical",
                    description=f"Abnormally high error rate: {error_rate:.1%}",
                    confidence=min(error_rate * 2, 0.95),
                    severity="high",
                    evidence=[{
                        "error_count": severity_distribution["error"],
                        "total_entries": total_entries,
                        "error_rate": error_rate
                    }],
                    timeline=[],
                    iocs_involved=[],
                    entries_matched=[],
                    recommendations=["Investigate error sources", 
                                   "Check system health"]
                )
                patterns.append(pattern)
        
        return patterns
    
    async def _detect_network_patterns(self, entries: List[ParsedEntry], 
                                     iocs: Dict[str, List[str]]) -> List[Pattern]:
        """Detect network-based attack patterns"""
        patterns = []
        
        # Build network graph
        self.network_graph.clear()
        ip_communications = defaultdict(lambda: defaultdict(int))
        port_accesses = defaultdict(set)
        
        for i, entry in enumerate(entries):
            # Extract network information
            src_ips = re.findall(r'src[:\s]+(\d+\.\d+\.\d+\.\d+)', entry.message)
            dst_ips = re.findall(r'dst[:\s]+(\d+\.\d+\.\d+\.\d+)', entry.message)
            ports = re.findall(r'port[:\s]+(\d+)', entry.message, re.I)
            
            # Build communication graph
            for src in src_ips:
                for dst in dst_ips:
                    ip_communications[src][dst] += 1
                    self.network_graph.add_edge(src, dst, weight=1)
            
            # Track port access
            for port in ports:
                port_num = int(port)
                if port_num < 65536:
                    for ip in src_ips + dst_ips:
                        port_accesses[ip].add(port_num)
        
        # Detect port scanning
        for ip, ports in port_accesses.items():
            if len(ports) > 20:  # Threshold for port scan
                pattern = Pattern(
                    name="port_scan",
                    type="network",
                    description=f"Port scanning detected from {ip}",
                    confidence=min(len(ports) / 50, 0.95),
                    severity="high",
                    evidence=[{
                        "source_ip": ip,
                        "ports_scanned": len(ports),
                        "sample_ports": sorted(list(ports))[:20]
                    }],
                    timeline=[],
                    iocs_involved=[ip],
                    entries_matched=[],
                    recommendations=["Block source IP", 
                                   "Review firewall rules"]
                )
                patterns.append(pattern)
        
        # Detect lateral movement patterns
        if self.network_graph.number_of_nodes() > 0:
            # Find nodes with high out-degree (potential pivot points)
            out_degrees = dict(self.network_graph.out_degree())
            
            for node, degree in out_degrees.items():
                if degree > 5:  # Connecting to many hosts
                    targets = list(self.network_graph.successors(node))
                    
                    pattern = Pattern(
                        name="lateral_movement",
                        type="network",
                        description=f"Potential lateral movement from {node}",
                        confidence=min(degree / 10, 0.9),
                        severity="high",
                        evidence=[{
                            "pivot_host": node,
                            "targets": targets[:10],
                            "connection_count": degree
                        }],
                        timeline=[],
                        iocs_involved=[node] + targets[:5],
                        entries_matched=[],
                        recommendations=["Isolate pivot host", 
                                       "Review access logs",
                                       "Check for compromised credentials"]
                    )
                    patterns.append(pattern)
        
        # Detect C2 communication patterns
        c2_patterns = self._detect_c2_patterns(entries, iocs)
        patterns.extend(c2_patterns)
        
        return patterns
    
    async def _detect_attack_chains(self, entries: List[ParsedEntry], 
                                  detected_patterns: List[Pattern]) -> List[Pattern]:
        """Detect multi-stage attack chains"""
        attack_chains = []
        
        # Define common attack sequences
        attack_sequences = {
            "kill_chain": [
                ["recon", "discovery", "scan"],
                ["exploit", "execution", "powershell"],
                ["privilege_escalation", "elevation"],
                ["credential_access", "dump"],
                ["lateral_movement", "remote"],
                ["collection", "archive"],
                ["exfiltration", "upload"]
            ],
            "ransomware_chain": [
                ["initial_access", "phishing", "download"],
                ["execution", "script"],
                ["defense_evasion", "disable"],
                ["discovery", "enumerate"],
                ["impact", "encrypt", "ransom"]
            ]
        }
        
        # Check for attack sequences
        for chain_name, sequence in attack_sequences.items():
            matched_stages = []
            
            for stage_keywords in sequence:
                # Check if any detected pattern matches this stage
                for pattern in detected_patterns:
                    if any(keyword in pattern.name.lower() for keyword in stage_keywords):
                        matched_stages.append({
                            "stage": stage_keywords[0],
                            "pattern": pattern.name,
                            "confidence": pattern.confidence
                        })
                        break
            
            # If we matched multiple stages, we have an attack chain
            if len(matched_stages) >= 3:
                chain_confidence = sum(s["confidence"] for s in matched_stages) / len(matched_stages)
                
                pattern = Pattern(
                    name=f"{chain_name}_detected",
                    type="attack_chain",
                    description=f"Multi-stage {chain_name.replace('_', ' ')} detected",
                    confidence=chain_confidence,
                    severity="critical",
                    evidence=matched_stages,
                    timeline=[],
                    iocs_involved=[],
                    entries_matched=[],
                    recommendations=[
                        "Initiate incident response procedures",
                        "Isolate affected systems",
                        "Preserve evidence for forensics",
                        "Review security controls"
                    ]
                )
                attack_chains.append(pattern)
        
        return attack_chains
    
    def _normalize_message(self, message: str) -> str:
        """Normalize message for grouping similar events"""
        # Remove timestamps
        message = re.sub(r'\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}', '', message)
        
        # Remove IPs
        message = re.sub(r'\d+\.\d+\.\d+\.\d+', 'IP', message)
        
        # Remove numbers
        message = re.sub(r'\d+', 'NUM', message)
        
        # Remove UUIDs
        message = re.sub(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', 'UUID', message, re.I)
        
        # Lowercase and strip
        return message.lower().strip()[:100]  # First 100 chars
    
    def _check_rapid_succession(self, timestamps: List[datetime], 
                               entries: List[Tuple[int, ParsedEntry]]) -> Optional[Pattern]:
        """Check for rapid succession pattern"""
        if len(timestamps) < 5:
            return None
        
        # Calculate intervals
        intervals = []
        for i in range(1, len(timestamps)):
            interval = (timestamps[i] - timestamps[i-1]).total_seconds()
            intervals.append(interval)
        
        # Check if events are happening rapidly
        rapid_threshold = 10  # seconds
        rapid_count = sum(1 for i in intervals if i < rapid_threshold)
        
        if rapid_count >= 5:
            return Pattern(
                name="rapid_succession_events",
                type="temporal",
                description=f"{rapid_count} events in rapid succession",
                confidence=min(rapid_count / 10, 0.95),
                severity="medium",
                evidence=[{
                    "event_count": len(entries),
                    "rapid_events": rapid_count,
                    "average_interval": sum(intervals) / len(intervals)
                }],
                timeline=[(e[1].timestamp, e[1].message[:100]) for e in entries[:10]],
                iocs_involved=[],
                entries_matched=[e[0] for e in entries],
                recommendations=["Check for automated activity", 
                               "Review source of rapid events"]
            )
        
        return None
    
    def _check_periodic_behavior(self, timestamps: List[datetime], 
                                entries: List[Tuple[int, ParsedEntry]]) -> Optional[Pattern]:
        """Check for periodic behavior pattern"""
        if len(timestamps) < 5:
            return None
        
        # Calculate intervals
        intervals = []
        for i in range(1, len(timestamps)):
            interval = (timestamps[i] - timestamps[i-1]).total_seconds()
            if interval > 0:  # Avoid zero intervals
                intervals.append(interval)
        
        if len(intervals) < 4:
            return None
        
        # Check for regularity
        mean_interval = statistics.mean(intervals)
        std_interval = statistics.stdev(intervals)
        
        # Low variance suggests periodic behavior
        if mean_interval > 0 and std_interval / mean_interval < 0.2:
            return Pattern(
                name="periodic_behavior",
                type="temporal",
                description=f"Regular periodic activity every {mean_interval:.1f} seconds",
                confidence=1 - (std_interval / mean_interval),
                severity="high",
                evidence=[{
                    "period": mean_interval,
                    "variance": std_interval,
                    "occurrence_count": len(timestamps)
                }],
                timeline=[(e[1].timestamp, e[1].message[:100]) for e in entries[:10]],
                iocs_involved=[],
                entries_matched=[e[0] for e in entries],
                recommendations=["Potential automated/bot activity", 
                               "Check for scheduled tasks or scripts"]
            )
        
        return None
    
    def _check_burst_activity(self, timestamps: List[datetime], 
                             entries: List[Tuple[int, ParsedEntry]]) -> Optional[Pattern]:
        """Check for burst activity pattern"""
        if len(timestamps) < 10:
            return None
        
        # Look for quiet period followed by burst
        max_gap = timedelta(0)
        gap_index = 0
        
        for i in range(1, len(timestamps)):
            gap = timestamps[i] - timestamps[i-1]
            if gap > max_gap:
                max_gap = gap
                gap_index = i
        
        # Check if there's a significant quiet period
        if max_gap > timedelta(hours=1):
            # Count events after the gap
            burst_start = timestamps[gap_index]
            burst_end = burst_start + self.burst_window
            
            burst_events = [
                e for e in entries[gap_index:]
                if e[1].timestamp and e[1].timestamp <= burst_end
            ]
            
            if len(burst_events) >= 10:
                return Pattern(
                    name="burst_activity",
                    type="temporal",
                    description=f"Burst of {len(burst_events)} events after {max_gap} quiet period",
                    confidence=min(len(burst_events) / 20, 0.9),
                    severity="medium",
                    evidence=[{
                        "quiet_duration": str(max_gap),
                        "burst_events": len(burst_events),
                        "burst_window": str(self.burst_window)
                    }],
                    timeline=[(e[1].timestamp, e[1].message[:100]) for e in burst_events[:10]],
                    iocs_involved=[],
                    entries_matched=[e[0] for e in burst_events],
                    recommendations=["Investigate trigger for burst activity",
                                   "Check for scheduled or triggered events"]
                )
        
        return None
    
    def _check_time_based_triggers(self, entries: List[ParsedEntry]) -> List[Pattern]:
        """Check for events at specific times"""
        patterns = []
        
        # Group events by hour
        hourly_events = defaultdict(list)
        
        for i, entry in enumerate(entries):
            if entry.timestamp:
                hour = entry.timestamp.hour
                hourly_events[hour].append((i, entry))
        
        # Check for suspicious time patterns
        suspicious_hours = [0, 1, 2, 3, 4]  # Late night hours
        
        for hour in suspicious_hours:
            if hour in hourly_events and len(hourly_events[hour]) > 5:
                pattern = Pattern(
                    name="suspicious_time_activity",
                    type="temporal",
                    description=f"Unusual activity at {hour:02d}:00 hours",
                    confidence=0.7,
                    severity="medium",
                    evidence=[{
                        "hour": hour,
                        "event_count": len(hourly_events[hour]),
                        "sample_events": [e[1].message[:100] for e in hourly_events[hour][:5]]
                    }],
                    timeline=[(e[1].timestamp, e[1].message[:100]) for e in hourly_events[hour][:10]],
                    iocs_involved=[],
                    entries_matched=[e[0] for e in hourly_events[hour]],
                    recommendations=["Check for scheduled tasks",
                                   "Review after-hours access policies"]
                )
                patterns.append(pattern)
        
        return patterns
    
    def _collect_pattern_evidence(self, entry: ParsedEntry, all_entries: List[ParsedEntry],
                                 pattern_config: Dict[str, Any], 
                                 entry_index: int) -> List[Dict[str, Any]]:
        """Collect evidence for a pattern match"""
        evidence = []
        
        # Look for related entries within a time window
        if entry.timestamp and "window" in pattern_config:
            window = pattern_config["window"]
            related_entries = [
                (i, e) for i, e in enumerate(all_entries)
                if e.timestamp and 
                abs(e.timestamp - entry.timestamp) <= window and
                any(ind in e.message.lower() for ind in pattern_config["indicators"])
            ]
            
            if len(related_entries) >= pattern_config.get("threshold", 1):
                evidence.append({
                    "type": "temporal_correlation",
                    "related_events": len(related_entries),
                    "time_window": str(window),
                    "samples": [e[1].message[:100] for e in related_entries[:5]]
                })
        
        # Check for context requirements
        if pattern_config.get("context_required"):
            context_found = self._check_pattern_context(entry, all_entries, entry_index)
            if context_found:
                evidence.append({
                    "type": "contextual_evidence",
                    "context": context_found
                })
        
        return evidence
    
    def _check_pattern_context(self, entry: ParsedEntry, all_entries: List[ParsedEntry],
                              entry_index: int) -> Optional[str]:
        """Check for required context around a pattern"""
        # Look at nearby entries for context
        context_window = 5
        start_idx = max(0, entry_index - context_window)
        end_idx = min(len(all_entries), entry_index + context_window + 1)
        
        context_entries = all_entries[start_idx:end_idx]
        
        # Look for specific context indicators
        context_keywords = ["success", "failure", "error", "denied", "granted", "admin", "root"]
        
        for ctx_entry in context_entries:
            if any(keyword in ctx_entry.message.lower() for keyword in context_keywords):
                return ctx_entry.message[:200]
        
        return None
    
    def _calculate_confidence(self, evidence: List[Dict[str, Any]], 
                            pattern_config: Dict[str, Any]) -> float:
        """Calculate confidence score for a pattern"""
        base_confidence = 0.6
        
        # Increase confidence based on evidence
        if evidence:
            evidence_boost = min(len(evidence) * 0.1, 0.3)
            base_confidence += evidence_boost
        
        # Adjust based on pattern type
        if pattern_config.get("severity") == "critical":
            base_confidence += 0.1
        
        return min(base_confidence, 0.95)
    
    def _extract_related_iocs(self, message: str, iocs: Dict[str, List[str]]) -> List[str]:
        """Extract IOCs related to a pattern"""
        related = []
        
        # Check each IOC type
        for ioc_type, ioc_list in iocs.items():
            for ioc in ioc_list:
                if ioc in message:
                    related.append(ioc)
        
        return related[:10]  # Limit to 10 IOCs
    
    def _generate_recommendations(self, pattern_name: str) -> List[str]:
        """Generate recommendations based on pattern type"""
        recommendations = {
            "brute_force": [
                "Implement account lockout policies",
                "Enable multi-factor authentication",
                "Review failed login sources"
            ],
            "port_scan": [
                "Review firewall rules",
                "Implement port scan detection",
                "Block scanning source IPs"
            ],
            "lateral_movement": [
                "Segment network access",
                "Review privileged account usage",
                "Implement jump box controls"
            ],
            "data_exfiltration": [
                "Implement DLP controls",
                "Monitor outbound traffic",
                "Review data access logs"
            ],
            "privilege_escalation": [
                "Audit privileged accounts",
                "Implement least privilege",
                "Monitor elevation events"
            ],
            "persistence_mechanism": [
                "Audit startup locations",
                "Review scheduled tasks",
                "Monitor registry changes"
            ],
            "defense_evasion": [
                "Harden security tools",
                "Implement tamper protection",
                "Monitor security tool status"
            ],
            "command_control": [
                "Block known C2 infrastructure",
                "Implement egress filtering",
                "Monitor periodic connections"
            ],
            "ransomware_behavior": [
                "Isolate affected systems immediately",
                "Verify backup integrity",
                "Implement ransomware protection"
            ]
        }
        
        return recommendations.get(pattern_name, ["Investigate detected pattern",
                                                 "Review security logs",
                                                 "Consider additional monitoring"])
    
    def _analyze_behavior_sequences(self, behavior_sequences: Dict[str, List[Tuple[int, ParsedEntry]]],
                                  all_entries: List[ParsedEntry]) -> List[Pattern]:
        """Analyze sequences of behaviors for attack patterns"""
        patterns = []
        
        # Look for specific behavior combinations
        if "discovery" in behavior_sequences and "execution" in behavior_sequences:
            # Potential reconnaissance followed by execution
            discovery_times = [e[1].timestamp for e in behavior_sequences["discovery"] if e[1].timestamp]
            execution_times = [e[1].timestamp for e in behavior_sequences["execution"] if e[1].timestamp]
            
            if discovery_times and execution_times:
                # Check if execution follows discovery
                for disc_time in discovery_times:
                    for exec_time in execution_times:
                        if timedelta(0) < exec_time - disc_time < timedelta(hours=1):
                            pattern = Pattern(
                                name="recon_before_execution",
                                type="behavioral",
                                description="Discovery activity followed by execution",
                                confidence=0.8,
                                severity="high",
                                evidence=[{
                                    "discovery_count": len(behavior_sequences["discovery"]),
                                    "execution_count": len(behavior_sequences["execution"]),
                                    "time_gap": str(exec_time - disc_time)
                                }],
                                timeline=[],
                                iocs_involved=[],
                                entries_matched=[],
                                recommendations=["Potential attack in progress",
                                               "Review discovery and execution events"]
                            )
                            patterns.append(pattern)
                            break
        
        return patterns
    
    def _detect_c2_patterns(self, entries: List[ParsedEntry], 
                           iocs: Dict[str, List[str]]) -> List[Pattern]:
        """Detect command and control communication patterns"""
        patterns = []
        
        # Look for beacon-like behavior
        beacon_candidates = defaultdict(list)
        
        for i, entry in enumerate(entries):
            # Look for outbound connections
            if any(keyword in entry.message.lower() for keyword in ["outbound", "connect", "post", "get"]):
                # Extract destination
                dst_match = re.search(r'dst[:\s]+(\d+\.\d+\.\d+\.\d+|\S+\.\S+)', entry.message)
                if dst_match:
                    dst = dst_match.group(1)
                    if entry.timestamp:
                        beacon_candidates[dst].append((i, entry))
        
        # Analyze beacon candidates
        for dst, connections in beacon_candidates.items():
            if len(connections) >= 5:
                # Check for periodic behavior
                timestamps = [c[1].timestamp for c in connections if c[1].timestamp]
                
                if len(timestamps) >= 5:
                    intervals = []
                    for j in range(1, len(timestamps)):
                        intervals.append((timestamps[j] - timestamps[j-1]).total_seconds())
                    
                    if intervals:
                        mean_interval = statistics.mean(intervals)
                        std_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
                        
                        # Low variance suggests beaconing
                        if mean_interval > 30 and std_interval < mean_interval * 0.3:
                            pattern = Pattern(
                                name="c2_beaconing",
                                type="network",
                                description=f"Potential C2 beaconing to {dst}",
                                confidence=0.85,
                                severity="critical",
                                evidence=[{
                                    "destination": dst,
                                    "beacon_count": len(connections),
                                    "average_interval": mean_interval,
                                    "interval_variance": std_interval
                                }],
                                timeline=[(c[1].timestamp, c[1].message[:100]) for c in connections[:10]],
                                iocs_involved=[dst],
                                entries_matched=[c[0] for c in connections],
                                recommendations=["Block communication to destination",
                                               "Investigate infected host",
                                               "Check for malware"]
                            )
                            patterns.append(pattern)
        
        return patterns
    
    def _pattern_to_dict(self, pattern: Pattern) -> Dict[str, Any]:
        """Convert Pattern object to dictionary"""
        return {
            "name": pattern.name,
            "type": pattern.type,
            "description": pattern.description,
            "confidence": pattern.confidence,
            "severity": pattern.severity,
            "evidence": pattern.evidence,
            "timeline": [(t[0].isoformat() if t[0] else "", t[1]) for t in pattern.timeline],
            "iocs_involved": pattern.iocs_involved,
            "entries_matched": pattern.entries_matched,
            "recommendations": pattern.recommendations
        }