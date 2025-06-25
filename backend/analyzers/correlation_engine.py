"""
Correlation Engine - Cross-source event correlation
Identifies relationships between events across different data sources
"""

import asyncio
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, deque
import networkx as nx
import numpy as np
from dataclasses import dataclass, field
import json
import re
import hashlib
from enum import Enum

class CorrelationType(Enum):
    """Types of correlations"""
    TEMPORAL = "temporal"
    CAUSAL = "causal"
    BEHAVIORAL = "behavioral"
    ENTITY = "entity"
    PATTERN = "pattern"
    STATISTICAL = "statistical"

@dataclass
class CorrelationRule:
    """Defines a correlation rule"""
    id: str
    name: str
    description: str
    correlation_type: CorrelationType
    conditions: Dict[str, Any]
    time_window: Optional[timedelta] = None
    min_events: int = 2
    confidence_threshold: float = 0.7
    severity: str = "medium"

@dataclass
class CorrelatedEvent:
    """Represents a correlated event group"""
    id: str
    events: List[Dict[str, Any]]
    correlation_type: CorrelationType
    confidence: float
    evidence: Dict[str, Any]
    timeline: List[Tuple[datetime, str]]
    entities: Set[str] = field(default_factory=set)
    attack_chain: Optional[List[str]] = None
    severity: str = "medium"
    description: str = ""

class CorrelationEngine:
    """Cross-source event correlation engine"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.correlation_rules = self._load_correlation_rules()
        self.event_cache = deque(maxlen=10000)  # Sliding window
        self.correlation_graph = nx.DiGraph()
        self.entity_index = defaultdict(list)  # Entity -> Events mapping
        self.time_index = defaultdict(list)  # Time bucket -> Events mapping
        
    def _load_correlation_rules(self) -> List[CorrelationRule]:
        """Load predefined correlation rules"""
        rules = []
        
        # Rule 1: Brute Force Attack
        rules.append(CorrelationRule(
            id="brute_force",
            name="Brute Force Attack Detection",
            description="Multiple failed logins followed by success",
            correlation_type=CorrelationType.BEHAVIORAL,
            conditions={
                "failed_threshold": 5,
                "success_after_failures": True,
                "same_target": True
            },
            time_window=timedelta(minutes=10),
            min_events=6,
            confidence_threshold=0.8,
            severity="high"
        ))
        
        # Rule 2: Lateral Movement
        rules.append(CorrelationRule(
            id="lateral_movement",
            name="Lateral Movement Detection",
            description="Sequential access to multiple systems from same source",
            correlation_type=CorrelationType.PATTERN,
            conditions={
                "unique_targets": 3,
                "same_source": True,
                "privileged_access": True
            },
            time_window=timedelta(hours=1),
            min_events=3,
            confidence_threshold=0.75,
            severity="critical"
        ))
        
        # Rule 3: Data Exfiltration
        rules.append(CorrelationRule(
            id="data_exfiltration",
            name="Data Exfiltration Detection",
            description="Large data transfer after suspicious access",
            correlation_type=CorrelationType.CAUSAL,
            conditions={
                "suspicious_access": True,
                "large_transfer": True,
                "external_destination": True
            },
            time_window=timedelta(hours=2),
            min_events=2,
            confidence_threshold=0.7,
            severity="critical"
        ))
        
        # Rule 4: Malware C2 Communication
        rules.append(CorrelationRule(
            id="c2_communication",
            name="C2 Communication Pattern",
            description="Regular beaconing with process creation",
            correlation_type=CorrelationType.TEMPORAL,
            conditions={
                "regular_interval": True,
                "process_creation": True,
                "network_activity": True
            },
            time_window=timedelta(hours=4),
            min_events=5,
            confidence_threshold=0.8,
            severity="critical"
        ))
        
        # Rule 5: Privilege Escalation
        rules.append(CorrelationRule(
            id="privilege_escalation",
            name="Privilege Escalation Chain",
            description="Service modification followed by elevated process",
            correlation_type=CorrelationType.CAUSAL,
            conditions={
                "service_modification": True,
                "elevated_process": True,
                "registry_changes": True
            },
            time_window=timedelta(minutes=30),
            min_events=3,
            confidence_threshold=0.75,
            severity="high"
        ))
        
        # Rule 6: Account Compromise
        rules.append(CorrelationRule(
            id="account_compromise",
            name="Account Compromise Indicators",
            description="Unusual login followed by suspicious activities",
            correlation_type=CorrelationType.BEHAVIORAL,
            conditions={
                "unusual_login": True,
                "config_changes": True,
                "data_access": True
            },
            time_window=timedelta(hours=1),
            min_events=3,
            confidence_threshold=0.7,
            severity="high"
        ))
        
        return rules
        
    async def correlate_events(
        self,
        events: List[Dict[str, Any]],
        source_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """Main correlation method"""
        # Add new events to cache
        self._update_event_cache(events)
        
        # Update indices
        self._update_indices(events)
        
        # Run correlation algorithms
        correlations = []
        
        # 1. Rule-based correlation
        rule_correlations = await self._apply_correlation_rules()
        correlations.extend(rule_correlations)
        
        # 2. Entity-based correlation
        entity_correlations = await self._correlate_by_entity()
        correlations.extend(entity_correlations)
        
        # 3. Temporal correlation
        temporal_correlations = await self._correlate_temporal()
        correlations.extend(temporal_correlations)
        
        # 4. Graph-based correlation
        graph_correlations = await self._correlate_graph_based()
        correlations.extend(graph_correlations)
        
        # 5. Statistical correlation
        statistical_correlations = await self._correlate_statistical()
        correlations.extend(statistical_correlations)
        
        # Merge and deduplicate correlations
        merged_correlations = self._merge_correlations(correlations)
        
        # Build attack chains
        attack_chains = self._build_attack_chains(merged_correlations)
        
        return {
            'correlations': merged_correlations,
            'total_correlations': len(merged_correlations),
            'attack_chains': attack_chains,
            'correlation_graph': self._export_correlation_graph(),
            'summary': self._generate_correlation_summary(merged_correlations)
        }
        
    def _update_event_cache(self, events: List[Dict[str, Any]]):
        """Update sliding window event cache"""
        for event in events:
            # Add metadata if not present
            if 'correlation_id' not in event:
                event['correlation_id'] = self._generate_event_id(event)
            if 'timestamp' not in event:
                event['timestamp'] = datetime.now()
            elif isinstance(event['timestamp'], str):
                event['timestamp'] = datetime.fromisoformat(event['timestamp'])
                
            self.event_cache.append(event)
            
    def _update_indices(self, events: List[Dict[str, Any]]):
        """Update entity and time indices"""
        for event in events:
            # Update entity index
            entities = self._extract_entities(event)
            for entity in entities:
                self.entity_index[entity].append(event)
                
            # Update time index
            if 'timestamp' in event:
                time_bucket = self._get_time_bucket(event['timestamp'])
                self.time_index[time_bucket].append(event)
                
            # Update correlation graph
            self._update_correlation_graph(event)
            
    async def _apply_correlation_rules(self) -> List[CorrelatedEvent]:
        """Apply predefined correlation rules"""
        correlations = []
        
        for rule in self.correlation_rules:
            matches = await self._match_rule(rule)
            correlations.extend(matches)
            
        return correlations
        
    async def _match_rule(self, rule: CorrelationRule) -> List[CorrelatedEvent]:
        """Match events against a correlation rule"""
        correlations = []
        
        if rule.id == "brute_force":
            correlations.extend(await self._detect_brute_force(rule))
        elif rule.id == "lateral_movement":
            correlations.extend(await self._detect_lateral_movement(rule))
        elif rule.id == "data_exfiltration":
            correlations.extend(await self._detect_data_exfiltration(rule))
        elif rule.id == "c2_communication":
            correlations.extend(await self._detect_c2_communication(rule))
        elif rule.id == "privilege_escalation":
            correlations.extend(await self._detect_privilege_escalation(rule))
        elif rule.id == "account_compromise":
            correlations.extend(await self._detect_account_compromise(rule))
            
        return correlations
        
    async def _detect_brute_force(self, rule: CorrelationRule) -> List[CorrelatedEvent]:
        """Detect brute force attack patterns"""
        correlations = []
        
        # Group events by target
        target_events = defaultdict(list)
        
        for event in self.event_cache:
            if self._is_login_event(event):
                target = event.get('target', event.get('destination'))
                if target:
                    target_events[target].append(event)
                    
        # Check each target
        for target, events in target_events.items():
            # Sort by timestamp
            events.sort(key=lambda x: x['timestamp'])
            
            # Look for pattern: multiple failures followed by success
            for i in range(len(events) - rule.min_events + 1):
                window_events = events[i:i + rule.min_events + 5]  # Extra buffer
                
                failed_count = 0
                success_after_failures = False
                source = None
                
                for event in window_events:
                    if self._is_failed_login(event):
                        failed_count += 1
                        if not source:
                            source = event.get('source', event.get('user'))
                    elif self._is_successful_login(event) and failed_count >= rule.conditions['failed_threshold']:
                        if event.get('source', event.get('user')) == source:
                            success_after_failures = True
                            break
                            
                if success_after_failures:
                    # Time check
                    time_diff = window_events[-1]['timestamp'] - window_events[0]['timestamp']
                    if time_diff <= rule.time_window:
                        correlation = CorrelatedEvent(
                            id=f"brute_force_{target}_{window_events[0]['timestamp'].timestamp()}",
                            events=window_events[:failed_count + 1],  # Include failures and success
                            correlation_type=rule.correlation_type,
                            confidence=0.9,
                            evidence={
                                'failed_attempts': failed_count,
                                'target': target,
                                'source': source,
                                'time_span': str(time_diff)
                            },
                            timeline=[(e['timestamp'], self._describe_event(e)) for e in window_events[:failed_count + 1]],
                            entities={target, source} if source else {target},
                            severity=rule.severity,
                            description=f"Brute force attack detected: {failed_count} failed attempts before successful login to {target}"
                        )
                        correlations.append(correlation)
                        
        return correlations
        
    async def _detect_lateral_movement(self, rule: CorrelationRule) -> List[CorrelatedEvent]:
        """Detect lateral movement patterns"""
        correlations = []
        
        # Group events by source
        source_events = defaultdict(list)
        
        for event in self.event_cache:
            if self._is_access_event(event):
                source = event.get('source', event.get('user'))
                if source:
                    source_events[source].append(event)
                    
        # Check each source
        for source, events in source_events.items():
            # Sort by timestamp
            events.sort(key=lambda x: x['timestamp'])
            
            # Look for access to multiple unique targets
            for i in range(len(events)):
                window_start = events[i]['timestamp']
                window_events = []
                unique_targets = set()
                
                for j in range(i, len(events)):
                    if events[j]['timestamp'] - window_start <= rule.time_window:
                        window_events.append(events[j])
                        target = events[j].get('target', events[j].get('destination'))
                        if target:
                            unique_targets.add(target)
                    else:
                        break
                        
                if len(unique_targets) >= rule.conditions['unique_targets']:
                    # Check for privileged access
                    privileged = any(self._is_privileged_access(e) for e in window_events)
                    
                    if privileged or not rule.conditions.get('privileged_access', True):
                        correlation = CorrelatedEvent(
                            id=f"lateral_movement_{source}_{window_start.timestamp()}",
                            events=window_events,
                            correlation_type=rule.correlation_type,
                            confidence=0.85,
                            evidence={
                                'source': source,
                                'targets': list(unique_targets),
                                'privileged_access': privileged,
                                'time_span': str(window_events[-1]['timestamp'] - window_events[0]['timestamp'])
                            },
                            timeline=[(e['timestamp'], self._describe_event(e)) for e in window_events],
                            entities={source}.union(unique_targets),
                            attack_chain=['initial_access', 'lateral_movement'],
                            severity=rule.severity,
                            description=f"Lateral movement detected: {source} accessed {len(unique_targets)} systems"
                        )
                        correlations.append(correlation)
                        
        return correlations
        
    async def _detect_data_exfiltration(self, rule: CorrelationRule) -> List[CorrelatedEvent]:
        """Detect data exfiltration patterns"""
        correlations = []
        
        # Look for suspicious access followed by large transfers
        access_events = [e for e in self.event_cache if self._is_suspicious_access(e)]
        transfer_events = [e for e in self.event_cache if self._is_large_transfer(e)]
        
        for access in access_events:
            source = access.get('source', access.get('user'))
            if not source:
                continue
                
            # Find transfers after this access
            for transfer in transfer_events:
                if transfer['timestamp'] > access['timestamp']:
                    time_diff = transfer['timestamp'] - access['timestamp']
                    if time_diff <= rule.time_window:
                        # Check if same source
                        transfer_source = transfer.get('source', transfer.get('user'))
                        if transfer_source == source:
                            # Check if external destination
                            if self._is_external_destination(transfer):
                                correlation = CorrelatedEvent(
                                    id=f"exfiltration_{source}_{access['timestamp'].timestamp()}",
                                    events=[access, transfer],
                                    correlation_type=rule.correlation_type,
                                    confidence=0.8,
                                    evidence={
                                        'source': source,
                                        'data_accessed': access.get('file', access.get('resource', 'unknown')),
                                        'bytes_transferred': transfer.get('bytes', 0),
                                        'destination': transfer.get('destination', 'unknown'),
                                        'time_between_events': str(time_diff)
                                    },
                                    timeline=[
                                        (access['timestamp'], f"Suspicious access: {self._describe_event(access)}"),
                                        (transfer['timestamp'], f"Large transfer: {self._describe_event(transfer)}")
                                    ],
                                    entities={source, transfer.get('destination', 'unknown')},
                                    attack_chain=['collection', 'exfiltration'],
                                    severity=rule.severity,
                                    description=f"Potential data exfiltration: {source} accessed sensitive data then transferred {transfer.get('bytes', 0)} bytes externally"
                                )
                                correlations.append(correlation)
                                
        return correlations
        
    async def _detect_c2_communication(self, rule: CorrelationRule) -> List[CorrelatedEvent]:
        """Detect C2 communication patterns"""
        correlations = []
        
        # Group network events by source-destination pair
        connections = defaultdict(list)
        
        for event in self.event_cache:
            if event.get('event_type') == 'network' or 'destination' in event:
                key = (event.get('source'), event.get('destination'))
                if key[0] and key[1]:
                    connections[key].append(event)
                    
        # Check for beaconing behavior
        for (source, destination), events in connections.items():
            if len(events) < rule.min_events:
                continue
                
            # Sort by timestamp
            events.sort(key=lambda x: x['timestamp'])
            
            # Calculate intervals
            intervals = []
            for i in range(1, len(events)):
                interval = (events[i]['timestamp'] - events[i-1]['timestamp']).total_seconds()
                intervals.append(interval)
                
            if intervals:
                # Check for regular intervals (beaconing)
                mean_interval = sum(intervals) / len(intervals)
                std_interval = (sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)) ** 0.5
                cv = std_interval / mean_interval if mean_interval > 0 else float('inf')
                
                if cv < 0.2:  # Low coefficient of variation = regular intervals
                    # Look for associated process creation
                    process_events = self._find_related_process_events(source, events[0]['timestamp'], rule.time_window)
                    
                    if process_events:
                        all_events = events + process_events
                        all_events.sort(key=lambda x: x['timestamp'])
                        
                        correlation = CorrelatedEvent(
                            id=f"c2_comm_{source}_{destination}_{events[0]['timestamp'].timestamp()}",
                            events=all_events[:20],  # Limit events
                            correlation_type=rule.correlation_type,
                            confidence=0.85,
                            evidence={
                                'source': source,
                                'destination': destination,
                                'beacon_interval': mean_interval,
                                'regularity_score': 1 - cv,
                                'connection_count': len(events),
                                'associated_processes': len(process_events)
                            },
                            timeline=[(e['timestamp'], self._describe_event(e)) for e in all_events[:10]],
                            entities={source, destination},
                            attack_chain=['command_and_control'],
                            severity=rule.severity,
                            description=f"C2 communication detected: {source} beaconing to {destination} every {mean_interval:.1f}s"
                        )
                        correlations.append(correlation)
                        
        return correlations
        
    async def _detect_privilege_escalation(self, rule: CorrelationRule) -> List[CorrelatedEvent]:
        """Detect privilege escalation patterns"""
        correlations = []
        
        # Look for service modifications
        service_events = [e for e in self.event_cache if self._is_service_modification(e)]
        
        for service_event in service_events:
            source = service_event.get('source', service_event.get('user'))
            if not source:
                continue
                
            # Look for elevated process creation after service modification
            elevated_processes = []
            registry_changes = []
            
            for event in self.event_cache:
                if event['timestamp'] > service_event['timestamp']:
                    time_diff = event['timestamp'] - service_event['timestamp']
                    if time_diff <= rule.time_window:
                        # Check for elevated process
                        if self._is_elevated_process(event) and event.get('source', event.get('user')) == source:
                            elevated_processes.append(event)
                        # Check for registry changes
                        elif self._is_registry_change(event) and event.get('source', event.get('user')) == source:
                            registry_changes.append(event)
                            
            if elevated_processes and (registry_changes or not rule.conditions.get('registry_changes', True)):
                all_events = [service_event] + elevated_processes + registry_changes
                all_events.sort(key=lambda x: x['timestamp'])
                
                correlation = CorrelatedEvent(
                    id=f"priv_esc_{source}_{service_event['timestamp'].timestamp()}",
                    events=all_events,
                    correlation_type=rule.correlation_type,
                    confidence=0.8,
                    evidence={
                        'source': source,
                        'service_modified': service_event.get('service', 'unknown'),
                        'elevated_processes': [p.get('process', 'unknown') for p in elevated_processes],
                        'registry_keys_modified': len(registry_changes)
                    },
                    timeline=[(e['timestamp'], self._describe_event(e)) for e in all_events],
                    entities={source},
                    attack_chain=['privilege_escalation', 'defense_evasion'],
                    severity=rule.severity,
                    description=f"Privilege escalation detected: {source} modified service and created elevated process"
                )
                correlations.append(correlation)
                
        return correlations
        
    async def _detect_account_compromise(self, rule: CorrelationRule) -> List[CorrelatedEvent]:
        """Detect account compromise patterns"""
        correlations = []
        
        # Look for unusual logins
        unusual_logins = [e for e in self.event_cache if self._is_unusual_login(e)]
        
        for login in unusual_logins:
            user = login.get('user', login.get('username'))
            if not user:
                continue
                
            # Look for suspicious activities after unusual login
            config_changes = []
            data_accesses = []
            
            for event in self.event_cache:
                if event['timestamp'] > login['timestamp']:
                    time_diff = event['timestamp'] - login['timestamp']
                    if time_diff <= rule.time_window:
                        event_user = event.get('user', event.get('username'))
                        if event_user == user:
                            if self._is_config_change(event):
                                config_changes.append(event)
                            elif self._is_sensitive_data_access(event):
                                data_accesses.append(event)
                                
            if config_changes and data_accesses:
                all_events = [login] + config_changes + data_accesses
                all_events.sort(key=lambda x: x['timestamp'])
                
                correlation = CorrelatedEvent(
                    id=f"account_comp_{user}_{login['timestamp'].timestamp()}",
                    events=all_events,
                    correlation_type=rule.correlation_type,
                    confidence=0.75,
                    evidence={
                        'user': user,
                        'unusual_login_reason': login.get('anomaly_reason', 'unknown'),
                        'config_changes': len(config_changes),
                        'sensitive_data_accessed': len(data_accesses),
                        'time_span': str(all_events[-1]['timestamp'] - all_events[0]['timestamp'])
                    },
                    timeline=[(e['timestamp'], self._describe_event(e)) for e in all_events],
                    entities={user},
                    attack_chain=['initial_access', 'credential_access', 'collection'],
                    severity=rule.severity,
                    description=f"Account compromise indicators: {user} unusual login followed by suspicious activities"
                )
                correlations.append(correlation)
                
        return correlations
        
    async def _correlate_by_entity(self) -> List[CorrelatedEvent]:
        """Correlate events by common entities"""
        correlations = []
        
        # Focus on entities with multiple event types
        for entity, events in self.entity_index.items():
            if len(events) < 3:
                continue
                
            # Group by event type
            type_groups = defaultdict(list)
            for event in events:
                event_type = event.get('event_type', 'unknown')
                type_groups[event_type].append(event)
                
            # Look for suspicious combinations
            if len(type_groups) >= 3:
                # Multi-stage activity
                all_events = sorted(events, key=lambda x: x['timestamp'])[:20]
                
                correlation = CorrelatedEvent(
                    id=f"entity_activity_{entity}_{all_events[0]['timestamp'].timestamp()}",
                    events=all_events,
                    correlation_type=CorrelationType.ENTITY,
                    confidence=0.7,
                    evidence={
                        'entity': entity,
                        'event_types': list(type_groups.keys()),
                        'event_count': len(events),
                        'time_span': str(all_events[-1]['timestamp'] - all_events[0]['timestamp'])
                    },
                    timeline=[(e['timestamp'], self._describe_event(e)) for e in all_events[:10]],
                    entities={entity},
                    severity="medium",
                    description=f"Multiple suspicious activities associated with {entity}"
                )
                correlations.append(correlation)
                
        return correlations
        
    async def _correlate_temporal(self) -> List[CorrelatedEvent]:
        """Correlate events based on temporal proximity"""
        correlations = []
        
        # Look for event clusters in time
        time_buckets = sorted(self.time_index.keys())
        
        for i in range(len(time_buckets) - 2):
            # Check consecutive buckets
            bucket_events = []
            for j in range(3):  # Look at 3 consecutive buckets
                if i + j < len(time_buckets):
                    bucket_events.extend(self.time_index[time_buckets[i + j]])
                    
            if len(bucket_events) > 10:
                # Analyze event diversity
                event_types = set()
                sources = set()
                targets = set()
                
                for event in bucket_events:
                    event_types.add(event.get('event_type', 'unknown'))
                    if 'source' in event:
                        sources.add(event['source'])
                    if 'target' in event or 'destination' in event:
                        targets.add(event.get('target', event.get('destination')))
                        
                # High diversity suggests coordinated activity
                if len(event_types) >= 4 and len(sources) >= 3:
                    bucket_events.sort(key=lambda x: x['timestamp'])
                    
                    correlation = CorrelatedEvent(
                        id=f"temporal_cluster_{time_buckets[i]}",
                        events=bucket_events[:20],
                        correlation_type=CorrelationType.TEMPORAL,
                        confidence=0.65,
                        evidence={
                            'time_window': f"{time_buckets[i]} - {time_buckets[i+2]}",
                            'event_types': list(event_types),
                            'source_count': len(sources),
                            'target_count': len(targets),
                            'event_density': len(bucket_events) / 3  # Events per bucket
                        },
                        timeline=[(e['timestamp'], self._describe_event(e)) for e in bucket_events[:10]],
                        entities=sources.union(targets),
                        severity="medium",
                        description=f"Suspicious cluster of {len(bucket_events)} diverse events"
                    )
                    correlations.append(correlation)
                    
        return correlations
        
    async def _correlate_graph_based(self) -> List[CorrelatedEvent]:
        """Use graph analysis for correlation"""
        correlations = []
        
        if len(self.correlation_graph) < 10:
            return correlations
            
        # Find suspicious patterns in the graph
        
        # 1. High centrality nodes (potential pivot points)
        centrality = nx.degree_centrality(self.correlation_graph)
        high_centrality_nodes = [
            node for node, cent in centrality.items()
            if cent > 0.1 and self.correlation_graph.degree(node) >= 5
        ]
        
        for node in high_centrality_nodes:
            # Get connected events
            connected_events = []
            for neighbor in self.correlation_graph.neighbors(node):
                if 'event' in self.correlation_graph.nodes[neighbor]:
                    connected_events.append(self.correlation_graph.nodes[neighbor]['event'])
                    
            if len(connected_events) >= 5:
                connected_events.sort(key=lambda x: x.get('timestamp', datetime.now()))
                
                correlation = CorrelatedEvent(
                    id=f"graph_pivot_{node}_{datetime.now().timestamp()}",
                    events=connected_events[:15],
                    correlation_type=CorrelationType.PATTERN,
                    confidence=0.7,
                    evidence={
                        'pivot_entity': node,
                        'centrality_score': centrality[node],
                        'connection_count': self.correlation_graph.degree(node),
                        'graph_metrics': {
                            'clustering': nx.clustering(self.correlation_graph, node) if not isinstance(self.correlation_graph, nx.DiGraph) else 0
                        }
                    },
                    timeline=[(e.get('timestamp', datetime.now()), self._describe_event(e)) for e in connected_events[:10]],
                    entities={node},
                    severity="medium",
                    description=f"{node} is a central pivot point in suspicious activity"
                )
                correlations.append(correlation)
                
        # 2. Find suspicious paths
        if len(self.correlation_graph) > 20:
            # Look for long paths (potential attack chains)
            for source in self.correlation_graph.nodes():
                if self.correlation_graph.in_degree(source) == 0:  # Potential start node
                    for target in self.correlation_graph.nodes():
                        if self.correlation_graph.out_degree(target) == 0:  # Potential end node
                            if source != target:
                                try:
                                    paths = list(nx.all_simple_paths(
                                        self.correlation_graph, source, target, cutoff=5
                                    ))
                                    
                                    for path in paths[:3]:  # Limit paths
                                        if len(path) >= 4:
                                            # Extract events along path
                                            path_events = []
                                            for node in path:
                                                if 'event' in self.correlation_graph.nodes[node]:
                                                    path_events.append(
                                                        self.correlation_graph.nodes[node]['event']
                                                    )
                                                    
                                            if len(path_events) >= 3:
                                                correlation = CorrelatedEvent(
                                                    id=f"attack_path_{source}_{target}_{datetime.now().timestamp()}",
                                                    events=path_events,
                                                    correlation_type=CorrelationType.CAUSAL,
                                                    confidence=0.75,
                                                    evidence={
                                                        'path': path,
                                                        'path_length': len(path),
                                                        'start_entity': source,
                                                        'end_entity': target
                                                    },
                                                    timeline=[(e.get('timestamp', datetime.now()), self._describe_event(e)) for e in path_events],
                                                    entities=set(path),
                                                    attack_chain=self._infer_attack_chain(path_events),
                                                    severity="high",
                                                    description=f"Potential attack path from {source} to {target}"
                                                )
                                                correlations.append(correlation)
                                except nx.NetworkXNoPath:
                                    continue
                                    
        return correlations
        
    async def _correlate_statistical(self) -> List[CorrelatedEvent]:
        """Statistical correlation analysis"""
        correlations = []
        
        # Group events by type for statistical analysis
        type_timeseries = defaultdict(list)
        
        for event in self.event_cache:
            event_type = event.get('event_type', 'unknown')
            type_timeseries[event_type].append(event['timestamp'])
            
        # Find correlated event types
        type_pairs = []
        types = list(type_timeseries.keys())
        
        for i in range(len(types)):
            for j in range(i + 1, len(types)):
                type1, type2 = types[i], types[j]
                
                # Calculate correlation
                correlation_score = self._calculate_event_correlation(
                    type_timeseries[type1],
                    type_timeseries[type2]
                )
                
                if correlation_score > 0.7:
                    type_pairs.append((type1, type2, correlation_score))
                    
        # Create correlations for highly correlated event types
        for type1, type2, score in type_pairs:
            # Get sample events
            events1 = [e for e in self.event_cache if e.get('event_type') == type1][:10]
            events2 = [e for e in self.event_cache if e.get('event_type') == type2][:10]
            all_events = sorted(events1 + events2, key=lambda x: x['timestamp'])
            
            correlation = CorrelatedEvent(
                id=f"statistical_corr_{type1}_{type2}_{datetime.now().timestamp()}",
                events=all_events,
                correlation_type=CorrelationType.STATISTICAL,
                confidence=score,
                evidence={
                    'event_type_1': type1,
                    'event_type_2': type2,
                    'correlation_score': score,
                    'count_type_1': len(events1),
                    'count_type_2': len(events2)
                },
                timeline=[(e['timestamp'], self._describe_event(e)) for e in all_events[:10]],
                entities=set(),
                severity="low",
                description=f"Statistical correlation between {type1} and {type2} events (score: {score:.2f})"
            )
            correlations.append(correlation)
            
        return correlations
        
    def _merge_correlations(self, correlations: List[CorrelatedEvent]) -> List[CorrelatedEvent]:
        """Merge and deduplicate correlations"""
        # Group by overlapping events
        merged = []
        used = set()
        
        for i, corr1 in enumerate(correlations):
            if i in used:
                continue
                
            # Find overlapping correlations
            event_ids1 = {e.get('correlation_id', id(e)) for e in corr1.events}
            overlapping = [corr1]
            
            for j, corr2 in enumerate(correlations[i+1:], i+1):
                if j not in used:
                    event_ids2 = {e.get('correlation_id', id(e)) for e in corr2.events}
                    
                    # Check for overlap
                    overlap = len(event_ids1.intersection(event_ids2))
                    if overlap >= min(len(event_ids1), len(event_ids2)) * 0.5:
                        overlapping.append(corr2)
                        used.add(j)
                        
            # Merge overlapping correlations
            if len(overlapping) > 1:
                merged_corr = self._merge_correlation_group(overlapping)
                merged.append(merged_corr)
            else:
                merged.append(corr1)
                
        return merged
        
    def _merge_correlation_group(self, correlations: List[CorrelatedEvent]) -> CorrelatedEvent:
        """Merge a group of overlapping correlations"""
        # Combine all events
        all_events = []
        seen_ids = set()
        
        for corr in correlations:
            for event in corr.events:
                event_id = event.get('correlation_id', id(event))
                if event_id not in seen_ids:
                    all_events.append(event)
                    seen_ids.add(event_id)
                    
        all_events.sort(key=lambda x: x.get('timestamp', datetime.now()))
        
        # Combine entities
        all_entities = set()
        for corr in correlations:
            all_entities.update(corr.entities)
            
        # Determine best correlation type and confidence
        best_confidence = max(corr.confidence for corr in correlations)
        best_type = max(correlations, key=lambda x: x.confidence).correlation_type
        
        # Combine evidence
        combined_evidence = {}
        for corr in correlations:
            combined_evidence[f"{corr.correlation_type.value}_evidence"] = corr.evidence
            
        # Determine severity
        severity_order = ['critical', 'high', 'medium', 'low']
        highest_severity = min(
            (severity_order.index(corr.severity) for corr in correlations),
            default=2
        )
        
        # Combine attack chains
        attack_chain = []
        for corr in correlations:
            if corr.attack_chain:
                for stage in corr.attack_chain:
                    if stage not in attack_chain:
                        attack_chain.append(stage)
                        
        return CorrelatedEvent(
            id=f"merged_{datetime.now().timestamp()}",
            events=all_events[:50],  # Limit size
            correlation_type=best_type,
            confidence=best_confidence,
            evidence=combined_evidence,
            timeline=[(e.get('timestamp', datetime.now()), self._describe_event(e)) for e in all_events[:20]],
            entities=all_entities,
            attack_chain=attack_chain,
            severity=severity_order[highest_severity],
            description=f"Merged correlation: {len(correlations)} related patterns detected"
        )
        
    def _build_attack_chains(self, correlations: List[CorrelatedEvent]) -> List[Dict[str, Any]]:
        """Build complete attack chains from correlations"""
        attack_chains = []
        
        # MITRE ATT&CK tactics in order
        tactics_order = [
            'reconnaissance', 'resource_development', 'initial_access',
            'execution', 'persistence', 'privilege_escalation',
            'defense_evasion', 'credential_access', 'discovery',
            'lateral_movement', 'collection', 'command_and_control',
            'exfiltration', 'impact'
        ]
        
        # Group correlations by entity
        entity_correlations = defaultdict(list)
        for corr in correlations:
            for entity in corr.entities:
                entity_correlations[entity].append(corr)
                
        # Build chains for each entity
        for entity, corrs in entity_correlations.items():
            if len(corrs) < 2:
                continue
                
            # Sort by time
            corrs.sort(key=lambda x: x.events[0]['timestamp'])
            
            # Extract tactics
            chain_tactics = []
            chain_events = []
            
            for corr in corrs:
                if corr.attack_chain:
                    for tactic in corr.attack_chain:
                        if tactic not in chain_tactics:
                            chain_tactics.append(tactic)
                            chain_events.append({
                                'tactic': tactic,
                                'events': corr.events[:3],  # Sample events
                                'timestamp': corr.events[0]['timestamp'],
                                'confidence': corr.confidence
                            })
                            
            if len(chain_tactics) >= 3:
                # Order tactics
                ordered_tactics = sorted(
                    chain_tactics,
                    key=lambda x: tactics_order.index(x) if x in tactics_order else 999
                )
                
                attack_chains.append({
                    'id': f"chain_{entity}_{datetime.now().timestamp()}",
                    'entity': entity,
                    'tactics': ordered_tactics,
                    'stages': chain_events,
                    'duration': str(corrs[-1].events[-1]['timestamp'] - corrs[0].events[0]['timestamp']),
                    'confidence': min(corr.confidence for corr in corrs),
                    'severity': min(
                        (corr.severity for corr in corrs),
                        key=lambda x: ['low', 'medium', 'high', 'critical'].index(x)
                    )
                })
                
        return attack_chains
        
    def _export_correlation_graph(self) -> Dict[str, Any]:
        """Export correlation graph for visualization"""
        if len(self.correlation_graph) == 0:
            return {'nodes': [], 'edges': []}
            
        nodes = []
        edges = []
        
        # Export nodes
        for node in self.correlation_graph.nodes():
            node_data = {
                'id': str(node),
                'label': str(node),
                'type': self.correlation_graph.nodes[node].get('type', 'entity')
            }
            
            # Add metrics
            if len(self.correlation_graph) < 1000:  # Avoid expensive calculations for large graphs
                node_data['degree'] = self.correlation_graph.degree(node)
                node_data['centrality'] = nx.degree_centrality(self.correlation_graph)[node]
                
            nodes.append(node_data)
            
        # Export edges
        for source, target in self.correlation_graph.edges():
            edge_data = {
                'source': str(source),
                'target': str(target),
                'weight': self.correlation_graph[source][target].get('weight', 1)
            }
            edges.append(edge_data)
            
        return {
            'nodes': nodes[:500],  # Limit for performance
            'edges': edges[:1000],
            'metrics': {
                'total_nodes': len(self.correlation_graph),
                'total_edges': self.correlation_graph.number_of_edges(),
                'density': nx.density(self.correlation_graph) if len(self.correlation_graph) > 0 else 0
            }
        }
        
    def _generate_correlation_summary(self, correlations: List[CorrelatedEvent]) -> str:
        """Generate summary of correlations"""
        if not correlations:
            return "No significant correlations detected."
            
        # Count by type
        type_counts = defaultdict(int)
        severity_counts = defaultdict(int)
        total_entities = set()
        
        for corr in correlations:
            type_counts[corr.correlation_type.value] += 1
            severity_counts[corr.severity] += 1
            total_entities.update(corr.entities)
            
        # Build summary
        summary_parts = [
            f"Detected {len(correlations)} correlation patterns"
        ]
        
        # Severity breakdown
        if severity_counts.get('critical', 0) > 0:
            summary_parts.append(f"{severity_counts['critical']} critical severity")
        if severity_counts.get('high', 0) > 0:
            summary_parts.append(f"{severity_counts['high']} high severity")
            
        # Type breakdown
        top_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:3]
        if top_types:
            types_str = ", ".join(f"{t[0]} ({t[1]})" for t in top_types)
            summary_parts.append(f"Types: {types_str}")
            
        # Entities
        summary_parts.append(f"Involving {len(total_entities)} unique entities")
        
        return ". ".join(summary_parts) + "."
        
    # Helper methods
    def _generate_event_id(self, event: Dict[str, Any]) -> str:
        """Generate unique ID for event"""
        # Create ID from event attributes
        id_parts = [
            str(event.get('timestamp', datetime.now())),
            event.get('event_type', 'unknown'),
            event.get('source', ''),
            event.get('target', event.get('destination', ''))
        ]
        
        id_string = '|'.join(id_parts)
        return hashlib.md5(id_string.encode()).hexdigest()
        
    def _extract_entities(self, event: Dict[str, Any]) -> Set[str]:
        """Extract entities from event"""
        entities = set()
        
        # Common entity fields
        entity_fields = [
            'source', 'destination', 'target', 'user', 'username',
            'src_ip', 'dst_ip', 'domain', 'hostname', 'process',
            'file', 'registry_key', 'service'
        ]
        
        for field in entity_fields:
            if field in event and event[field]:
                entities.add(str(event[field]))
                
        return entities
        
    def _get_time_bucket(self, timestamp: datetime) -> str:
        """Get time bucket for timestamp (5-minute buckets)"""
        bucket = timestamp.replace(second=0, microsecond=0)
        bucket = bucket.replace(minute=(bucket.minute // 5) * 5)
        return bucket.isoformat()
        
    def _update_correlation_graph(self, event: Dict[str, Any]):
        """Update correlation graph with event"""
        entities = self._extract_entities(event)
        
        # Add event node
        event_id = event.get('correlation_id')
        if event_id:
            self.correlation_graph.add_node(
                event_id,
                type='event',
                event=event
            )
            
            # Connect to entities
            for entity in entities:
                self.correlation_graph.add_node(entity, type='entity')
                self.correlation_graph.add_edge(event_id, entity)
                
        # Connect entities that appear together
        entity_list = list(entities)
        for i in range(len(entity_list)):
            for j in range(i + 1, len(entity_list)):
                if self.correlation_graph.has_edge(entity_list[i], entity_list[j]):
                    # Increase weight
                    self.correlation_graph[entity_list[i]][entity_list[j]]['weight'] += 1
                else:
                    self.correlation_graph.add_edge(
                        entity_list[i],
                        entity_list[j],
                        weight=1
                    )
                    
    def _describe_event(self, event: Dict[str, Any]) -> str:
        """Generate human-readable event description"""
        event_type = event.get('event_type', 'unknown')
        
        if event_type == 'login':
            return f"Login by {event.get('user', 'unknown')} from {event.get('source', 'unknown')}"
        elif event_type == 'network':
            return f"Network connection from {event.get('source', 'unknown')} to {event.get('destination', 'unknown')}"
        elif event_type == 'process':
            return f"Process {event.get('process', 'unknown')} started by {event.get('user', 'unknown')}"
        elif event_type == 'file':
            return f"File operation on {event.get('file', 'unknown')} by {event.get('user', 'unknown')}"
        else:
            # Generic description
            parts = [event_type]
            if 'action' in event:
                parts.append(event['action'])
            if 'source' in event:
                parts.append(f"from {event['source']}")
            if 'target' in event or 'destination' in event:
                parts.append(f"to {event.get('target', event.get('destination'))}")
                
            return ' '.join(parts)
            
    def _is_login_event(self, event: Dict[str, Any]) -> bool:
        """Check if event is a login event"""
        return (
            event.get('event_type') == 'login' or
            event.get('action') in ['login', 'logon', 'authentication'] or
            'login' in str(event.get('message', '')).lower()
        )
        
    def _is_failed_login(self, event: Dict[str, Any]) -> bool:
        """Check if event is a failed login"""
        return (
            self._is_login_event(event) and (
                event.get('result') in ['failed', 'failure', 'denied'] or
                event.get('status') in ['failed', 'failure', 'denied'] or
                'fail' in str(event.get('message', '')).lower()
            )
        )
        
    def _is_successful_login(self, event: Dict[str, Any]) -> bool:
        """Check if event is a successful login"""
        return (
            self._is_login_event(event) and (
                event.get('result') in ['success', 'successful', 'granted'] or
                event.get('status') in ['success', 'successful', 'granted'] or
                (
                    'success' in str(event.get('message', '')).lower() and
                    'fail' not in str(event.get('message', '')).lower()
                )
            )
        )
        
    def _is_access_event(self, event: Dict[str, Any]) -> bool:
        """Check if event is an access event"""
        return (
            event.get('event_type') in ['access', 'file_access', 'resource_access'] or
            event.get('action') in ['access', 'read', 'open'] or
            'access' in str(event.get('message', '')).lower()
        )
        
    def _is_privileged_access(self, event: Dict[str, Any]) -> bool:
        """Check if event involves privileged access"""
        return (
            event.get('privileged') == True or
            event.get('elevation') == True or
            'admin' in str(event.get('user', '')).lower() or
            'root' in str(event.get('user', '')).lower() or
            'sudo' in str(event.get('command', '')).lower()
        )
        
    def _is_suspicious_access(self, event: Dict[str, Any]) -> bool:
        """Check if access is suspicious"""
        suspicious_indicators = [
            'sensitive', 'confidential', 'secret', 'password',
            'credential', 'private', 'admin', 'config'
        ]
        
        for field in ['file', 'resource', 'path', 'target']:
            if field in event:
                value = str(event[field]).lower()
                if any(indicator in value for indicator in suspicious_indicators):
                    return True
                    
        return False
        
    def _is_large_transfer(self, event: Dict[str, Any]) -> bool:
        """Check if event represents large data transfer"""
        # Check for large byte counts
        for field in ['bytes', 'bytes_sent', 'bytes_transferred', 'size']:
            if field in event:
                try:
                    bytes_value = int(event[field])
                    if bytes_value > 100_000_000:  # 100MB
                        return True
                except:
                    pass
                    
        return False
        
    def _is_external_destination(self, event: Dict[str, Any]) -> bool:
        """Check if destination is external"""
        dest = event.get('destination', event.get('dst_ip', ''))
        
        # Check for internal IP ranges
        internal_patterns = [
            r'^10\.',
            r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
            r'^192\.168\.'
        ]
        
        for pattern in internal_patterns:
            if re.match(pattern, str(dest)):
                return False
                
        # If has destination and not internal, consider external
        return bool(dest)
        
    def _find_related_process_events(
        self,
        entity: str,
        start_time: datetime,
        window: timedelta
    ) -> List[Dict[str, Any]]:
        """Find process events related to entity"""
        related = []
        
        for event in self.event_cache:
            if (
                event.get('event_type') == 'process' and
                event['timestamp'] >= start_time and
                event['timestamp'] <= start_time + window
            ):
                # Check if entity is involved
                if (
                    event.get('source') == entity or
                    event.get('user') == entity or
                    event.get('parent_process') == entity
                ):
                    related.append(event)
                    
        return related
        
    def _is_service_modification(self, event: Dict[str, Any]) -> bool:
        """Check if event is service modification"""
        return (
            event.get('event_type') == 'service' or
            event.get('action') in ['service_create', 'service_modify', 'service_delete'] or
            (
                'service' in str(event.get('target', '')).lower() and
                event.get('action') in ['create', 'modify', 'delete', 'change']
            )
        )
        
    def _is_elevated_process(self, event: Dict[str, Any]) -> bool:
        """Check if process is elevated"""
        return (
            event.get('event_type') == 'process' and (
                event.get('elevated') == True or
                event.get('integrity_level') in ['high', 'system'] or
                'admin' in str(event.get('user', '')).lower()
            )
        )
        
    def _is_registry_change(self, event: Dict[str, Any]) -> bool:
        """Check if event is registry change"""
        return (
            event.get('event_type') == 'registry' or
            'registry' in str(event.get('target', '')).lower() or
            event.get('action') in ['registry_set', 'registry_delete', 'registry_create']
        )
        
    def _is_unusual_login(self, event: Dict[str, Any]) -> bool:
        """Check if login is unusual"""
        return (
            self._is_login_event(event) and (
                event.get('anomaly') == True or
                event.get('unusual') == True or
                event.get('risk_score', 0) > 70 or
                'unusual' in str(event.get('message', '')).lower()
            )
        )
        
    def _is_config_change(self, event: Dict[str, Any]) -> bool:
        """Check if event is configuration change"""
        return (
            event.get('event_type') == 'config' or
            event.get('action') in ['config_change', 'settings_modified'] or
            any(
                indicator in str(event.get('file', '')).lower()
                for indicator in ['config', 'conf', 'settings', 'ini', 'cfg']
            )
        )
        
    def _is_sensitive_data_access(self, event: Dict[str, Any]) -> bool:
        """Check if event accesses sensitive data"""
        return (
            self._is_access_event(event) and
            self._is_suspicious_access(event)
        )
        
    def _calculate_event_correlation(
        self,
        timestamps1: List[datetime],
        timestamps2: List[datetime]
    ) -> float:
        """Calculate correlation between two event time series"""
        if len(timestamps1) < 5 or len(timestamps2) < 5:
            return 0.0
            
        # Create time bins (1-minute bins)
        min_time = min(min(timestamps1), min(timestamps2))
        max_time = max(max(timestamps1), max(timestamps2))
        
        # Calculate number of bins
        time_range = (max_time - min_time).total_seconds()
        num_bins = max(10, min(100, int(time_range / 60)))  # 1-minute bins
        
        # Create histograms
        hist1 = np.zeros(num_bins)
        hist2 = np.zeros(num_bins)
        
        for ts in timestamps1:
            bin_idx = int((ts - min_time).total_seconds() / 60)
            if 0 <= bin_idx < num_bins:
                hist1[bin_idx] += 1
                
        for ts in timestamps2:
            bin_idx = int((ts - min_time).total_seconds() / 60)
            if 0 <= bin_idx < num_bins:
                hist2[bin_idx] += 1
                
        # Calculate correlation
        if np.std(hist1) > 0 and np.std(hist2) > 0:
            correlation = np.corrcoef(hist1, hist2)[0, 1]
            return max(0, correlation)  # Only positive correlation
        else:
            return 0.0
            
    def _infer_attack_chain(self, events: List[Dict[str, Any]]) -> List[str]:
        """Infer MITRE ATT&CK chain from events"""
        attack_chain = []
        
        # Map event patterns to MITRE tactics
        tactic_patterns = {
            'initial_access': ['login', 'authentication', 'exploit'],
            'execution': ['process', 'command', 'script'],
            'persistence': ['service', 'registry', 'scheduled'],
            'privilege_escalation': ['elevated', 'admin', 'root'],
            'defense_evasion': ['delete', 'clear', 'disable'],
            'credential_access': ['password', 'credential', 'hash'],
            'discovery': ['scan', 'enumerate', 'query'],
            'lateral_movement': ['remote', 'share', 'rdp'],
            'collection': ['archive', 'compress', 'stage'],
            'command_and_control': ['beacon', 'callback', 'c2'],
            'exfiltration': ['upload', 'transfer', 'send'],
            'impact': ['encrypt', 'destroy', 'wipe']
        }
        
        for event in events:
            event_str = json.dumps(event).lower()
            
            for tactic, patterns in tactic_patterns.items():
                if tactic not in attack_chain:
                    if any(pattern in event_str for pattern in patterns):
                        attack_chain.append(tactic)
                        
        return attack_chain