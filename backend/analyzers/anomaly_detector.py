"""
Anomaly Detector - Statistical anomaly detection
Identifies unusual patterns and outliers in data
"""

import numpy as np
from typing import Dict, List, Any, Optional, Tuple, Set
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import statistics
import math
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
import pandas as pd
from scipy import stats
import json

class AnomalyDetector:
    """Detects statistical anomalies in security data"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.models = {}
        self.baselines = {}
        self.thresholds = {
            'zscore': config.get('zscore_threshold', 3.0),
            'iqr_multiplier': config.get('iqr_multiplier', 1.5),
            'isolation_contamination': config.get('isolation_contamination', 0.1),
            'dbscan_eps': config.get('dbscan_eps', 0.5),
            'dbscan_min_samples': config.get('dbscan_min_samples', 5)
        }
        
    async def detect_anomalies(
        self,
        data: List[Dict[str, Any]],
        data_type: str
    ) -> Dict[str, Any]:
        """Main anomaly detection method"""
        anomalies = []
        
        if data_type == 'logs':
            anomalies.extend(await self._detect_log_anomalies(data))
        elif data_type == 'network':
            anomalies.extend(await self._detect_network_anomalies(data))
        elif data_type == 'system':
            anomalies.extend(await self._detect_system_anomalies(data))
        elif data_type == 'time_series':
            anomalies.extend(await self._detect_time_series_anomalies(data))
        else:
            # Generic anomaly detection
            anomalies.extend(await self._detect_generic_anomalies(data))
            
        # Score and rank anomalies
        scored_anomalies = self._score_anomalies(anomalies)
        
        return {
            'anomalies': scored_anomalies,
            'total_anomalies': len(scored_anomalies),
            'by_type': self._group_anomalies_by_type(scored_anomalies),
            'severity_distribution': self._get_severity_distribution(scored_anomalies),
            'summary': self._generate_anomaly_summary(scored_anomalies)
        }
        
    async def _detect_log_anomalies(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect anomalies in log data"""
        anomalies = []
        
        # 1. Volume anomalies
        volume_anomalies = await self._detect_volume_anomalies(logs)
        anomalies.extend(volume_anomalies)
        
        # 2. Pattern anomalies
        pattern_anomalies = await self._detect_pattern_anomalies(logs)
        anomalies.extend(pattern_anomalies)
        
        # 3. Timing anomalies
        timing_anomalies = await self._detect_timing_anomalies(logs)
        anomalies.extend(timing_anomalies)
        
        # 4. Error rate anomalies
        error_anomalies = await self._detect_error_rate_anomalies(logs)
        anomalies.extend(error_anomalies)
        
        # 5. User behavior anomalies
        user_anomalies = await self._detect_user_behavior_anomalies(logs)
        anomalies.extend(user_anomalies)
        
        return anomalies
        
    async def _detect_network_anomalies(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect network-specific anomalies"""
        anomalies = []
        
        # 1. Traffic volume anomalies
        traffic_features = self._extract_traffic_features(data)
        if traffic_features:
            volume_anomalies = self._detect_outliers_isolation_forest(
                traffic_features,
                feature_names=['bytes_sent', 'bytes_received', 'packet_count']
            )
            
            for idx in volume_anomalies:
                anomalies.append({
                    'type': 'network_traffic_volume',
                    'description': 'Unusual network traffic volume detected',
                    'data': data[idx],
                    'severity': 'medium',
                    'confidence': 0.8
                })
                
        # 2. Port scanning detection
        port_scan_anomalies = self._detect_port_scanning(data)
        anomalies.extend(port_scan_anomalies)
        
        # 3. Unusual protocol usage
        protocol_anomalies = self._detect_protocol_anomalies(data)
        anomalies.extend(protocol_anomalies)
        
        # 4. Geographic anomalies
        geo_anomalies = self._detect_geographic_anomalies(data)
        anomalies.extend(geo_anomalies)
        
        # 5. Connection pattern anomalies
        conn_anomalies = self._detect_connection_anomalies(data)
        anomalies.extend(conn_anomalies)
        
        return anomalies
        
    async def _detect_system_anomalies(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect system-level anomalies"""
        anomalies = []
        
        # 1. Resource usage anomalies
        resource_anomalies = self._detect_resource_anomalies(data)
        anomalies.extend(resource_anomalies)
        
        # 2. Process anomalies
        process_anomalies = self._detect_process_anomalies(data)
        anomalies.extend(process_anomalies)
        
        # 3. File system anomalies
        fs_anomalies = self._detect_filesystem_anomalies(data)
        anomalies.extend(fs_anomalies)
        
        # 4. Registry anomalies (Windows)
        registry_anomalies = self._detect_registry_anomalies(data)
        anomalies.extend(registry_anomalies)
        
        return anomalies
        
    async def _detect_time_series_anomalies(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect anomalies in time series data"""
        anomalies = []
        
        # Group data by metric
        metrics = defaultdict(list)
        for item in data:
            if 'metric' in item and 'value' in item and 'timestamp' in item:
                metrics[item['metric']].append({
                    'timestamp': item['timestamp'],
                    'value': item['value'],
                    'data': item
                })
                
        # Analyze each metric
        for metric_name, values in metrics.items():
            # Sort by timestamp
            values.sort(key=lambda x: x['timestamp'])
            
            # Extract values
            ts_values = [v['value'] for v in values]
            
            if len(ts_values) < 10:
                continue
                
            # 1. Statistical outliers
            outliers = self._detect_statistical_outliers(ts_values)
            for idx in outliers:
                anomalies.append({
                    'type': 'time_series_outlier',
                    'metric': metric_name,
                    'description': f'Statistical outlier detected in {metric_name}',
                    'value': ts_values[idx],
                    'expected_range': self._calculate_expected_range(ts_values),
                    'data': values[idx]['data'],
                    'severity': 'medium',
                    'confidence': 0.85
                })
                
            # 2. Trend changes
            trend_changes = self._detect_trend_changes(ts_values)
            for change in trend_changes:
                anomalies.append({
                    'type': 'trend_change',
                    'metric': metric_name,
                    'description': f'Significant trend change in {metric_name}',
                    'change_point': change['index'],
                    'change_magnitude': change['magnitude'],
                    'data': values[change['index']]['data'],
                    'severity': 'low',
                    'confidence': 0.7
                })
                
            # 3. Seasonality violations
            if len(ts_values) > 100:
                seasonal_anomalies = self._detect_seasonal_anomalies(ts_values)
                for idx in seasonal_anomalies:
                    anomalies.append({
                        'type': 'seasonal_anomaly',
                        'metric': metric_name,
                        'description': f'Value violates seasonal pattern in {metric_name}',
                        'data': values[idx]['data'],
                        'severity': 'low',
                        'confidence': 0.65
                    })
                    
        return anomalies
        
    async def _detect_generic_anomalies(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generic anomaly detection for any data type"""
        anomalies = []
        
        # Extract numerical features
        features = []
        feature_names = set()
        
        for item in data:
            feature_dict = {}
            for key, value in item.items():
                if isinstance(value, (int, float)):
                    feature_dict[key] = value
                    feature_names.add(key)
                    
            if feature_dict:
                features.append(feature_dict)
                
        if not features:
            return anomalies
            
        # Convert to matrix
        feature_names = sorted(list(feature_names))
        feature_matrix = []
        
        for feat in features:
            row = [feat.get(name, 0) for name in feature_names]
            feature_matrix.append(row)
            
        feature_matrix = np.array(feature_matrix)
        
        # Apply multiple detection methods
        # 1. Isolation Forest
        iso_anomalies = self._detect_outliers_isolation_forest(
            feature_matrix,
            feature_names
        )
        
        for idx in iso_anomalies:
            anomalies.append({
                'type': 'multivariate_outlier',
                'description': 'Unusual combination of feature values',
                'features': {name: features[idx].get(name) for name in feature_names},
                'data': data[idx],
                'severity': 'medium',
                'confidence': 0.75
            })
            
        # 2. Clustering-based anomalies
        if len(feature_matrix) > 20:
            cluster_anomalies = self._detect_clustering_anomalies(
                feature_matrix,
                feature_names
            )
            
            for idx in cluster_anomalies:
                if idx not in iso_anomalies:  # Avoid duplicates
                    anomalies.append({
                        'type': 'cluster_outlier',
                        'description': 'Data point does not belong to any cluster',
                        'features': {name: features[idx].get(name) for name in feature_names},
                        'data': data[idx],
                        'severity': 'low',
                        'confidence': 0.65
                    })
                    
        return anomalies
        
    async def _detect_volume_anomalies(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect anomalies in log volume"""
        anomalies = []
        
        # Group logs by time window
        time_buckets = defaultdict(list)
        
        for log in logs:
            if 'timestamp' in log:
                # Convert to datetime
                if isinstance(log['timestamp'], str):
                    ts = datetime.fromisoformat(log['timestamp'])
                else:
                    ts = log['timestamp']
                    
                # 5-minute buckets
                bucket = ts.replace(second=0, microsecond=0)
                bucket = bucket.replace(minute=(bucket.minute // 5) * 5)
                time_buckets[bucket].append(log)
                
        # Calculate volume per bucket
        volumes = [(bucket, len(logs)) for bucket, logs in time_buckets.items()]
        volumes.sort(key=lambda x: x[0])
        
        if len(volumes) < 5:
            return anomalies
            
        # Extract counts
        counts = [v[1] for v in volumes]
        
        # Detect outliers
        outlier_indices = self._detect_statistical_outliers(counts)
        
        for idx in outlier_indices:
            bucket, count = volumes[idx]
            expected = statistics.median(counts)
            
            anomalies.append({
                'type': 'log_volume_spike',
                'description': f'Unusual log volume: {count} logs (expected ~{expected})',
                'timestamp': bucket.isoformat(),
                'actual_count': count,
                'expected_count': expected,
                'deviation': abs(count - expected) / expected if expected > 0 else float('inf'),
                'severity': 'high' if count > expected * 3 else 'medium',
                'confidence': 0.9
            })
            
        return anomalies
        
    async def _detect_pattern_anomalies(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect unusual patterns in logs"""
        anomalies = []
        
        # Extract patterns
        patterns = defaultdict(int)
        pattern_examples = defaultdict(list)
        
        for log in logs:
            # Create pattern from log structure
            pattern = self._extract_log_pattern(log)
            patterns[pattern] += 1
            pattern_examples[pattern].append(log)
            
        # Find rare patterns
        total_logs = len(logs)
        rare_threshold = max(1, total_logs * 0.001)  # 0.1% threshold
        
        for pattern, count in patterns.items():
            if count <= rare_threshold:
                examples = pattern_examples[pattern][:3]  # First 3 examples
                
                anomalies.append({
                    'type': 'rare_log_pattern',
                    'description': f'Rare log pattern occurred {count} times',
                    'pattern': pattern,
                    'occurrences': count,
                    'frequency': count / total_logs,
                    'examples': examples,
                    'severity': 'low',
                    'confidence': 0.7
                })
                
        return anomalies
        
    async def _detect_timing_anomalies(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect timing-based anomalies"""
        anomalies = []
        
        # Group by source/user
        source_timings = defaultdict(list)
        
        for log in logs:
            source = log.get('source', log.get('user', 'unknown'))
            if 'timestamp' in log:
                source_timings[source].append(log['timestamp'])
                
        # Analyze timing patterns
        for source, timestamps in source_timings.items():
            if len(timestamps) < 5:
                continue
                
            # Sort timestamps
            timestamps.sort()
            
            # Calculate intervals
            intervals = []
            for i in range(1, len(timestamps)):
                if isinstance(timestamps[i], str):
                    t1 = datetime.fromisoformat(timestamps[i-1])
                    t2 = datetime.fromisoformat(timestamps[i])
                else:
                    t1 = timestamps[i-1]
                    t2 = timestamps[i]
                    
                interval = (t2 - t1).total_seconds()
                intervals.append(interval)
                
            if not intervals:
                continue
                
            # Detect rapid-fire events
            min_interval = min(intervals)
            if min_interval < 0.1:  # Less than 100ms
                anomalies.append({
                    'type': 'rapid_fire_events',
                    'description': f'Suspiciously fast events from {source}',
                    'source': source,
                    'min_interval_ms': min_interval * 1000,
                    'event_count': len(timestamps),
                    'severity': 'high',
                    'confidence': 0.95
                })
                
            # Detect unusual timing patterns
            if len(intervals) > 10:
                # Check for automation (regular intervals)
                std_dev = statistics.stdev(intervals)
                mean_interval = statistics.mean(intervals)
                cv = std_dev / mean_interval if mean_interval > 0 else float('inf')
                
                if cv < 0.1:  # Very regular intervals
                    anomalies.append({
                        'type': 'automated_activity',
                        'description': f'Detected automated/scripted activity from {source}',
                        'source': source,
                        'interval_regularity': 1 - cv,
                        'mean_interval': mean_interval,
                        'severity': 'medium',
                        'confidence': 0.8
                    })
                    
        return anomalies
        
    async def _detect_error_rate_anomalies(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect unusual error rates"""
        anomalies = []
        
        # Group by time and calculate error rates
        time_buckets = defaultdict(lambda: {'total': 0, 'errors': 0})
        
        for log in logs:
            if 'timestamp' in log:
                # Get time bucket
                if isinstance(log['timestamp'], str):
                    ts = datetime.fromisoformat(log['timestamp'])
                else:
                    ts = log['timestamp']
                    
                bucket = ts.replace(second=0, microsecond=0)
                bucket = bucket.replace(minute=(bucket.minute // 5) * 5)
                
                time_buckets[bucket]['total'] += 1
                
                # Check if error
                if self._is_error_log(log):
                    time_buckets[bucket]['errors'] += 1
                    
        # Calculate error rates
        error_rates = []
        for bucket, counts in sorted(time_buckets.items()):
            if counts['total'] > 0:
                rate = counts['errors'] / counts['total']
                error_rates.append({
                    'bucket': bucket,
                    'rate': rate,
                    'errors': counts['errors'],
                    'total': counts['total']
                })
                
        if len(error_rates) < 3:
            return anomalies
            
        # Detect spikes
        rates = [r['rate'] for r in error_rates]
        baseline = statistics.median(rates)
        threshold = baseline + 2 * statistics.stdev(rates) if len(rates) > 2 else baseline * 2
        
        for rate_info in error_rates:
            if rate_info['rate'] > threshold:
                anomalies.append({
                    'type': 'error_rate_spike',
                    'description': f'High error rate: {rate_info["rate"]:.1%}',
                    'timestamp': rate_info['bucket'].isoformat(),
                    'error_rate': rate_info['rate'],
                    'error_count': rate_info['errors'],
                    'total_events': rate_info['total'],
                    'baseline_rate': baseline,
                    'severity': 'high' if rate_info['rate'] > 0.5 else 'medium',
                    'confidence': 0.85
                })
                
        return anomalies
        
    async def _detect_user_behavior_anomalies(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect anomalies in user behavior"""
        anomalies = []
        
        # Build user profiles
        user_profiles = defaultdict(lambda: {
            'actions': defaultdict(int),
            'timestamps': [],
            'sources': set(),
            'errors': 0,
            'total': 0
        })
        
        for log in logs:
            user = log.get('user', log.get('username'))
            if not user:
                continue
                
            profile = user_profiles[user]
            profile['total'] += 1
            
            # Track actions
            action = log.get('action', log.get('event_type', 'unknown'))
            profile['actions'][action] += 1
            
            # Track timestamps
            if 'timestamp' in log:
                profile['timestamps'].append(log['timestamp'])
                
            # Track sources
            source = log.get('source_ip', log.get('source', 'unknown'))
            profile['sources'].add(source)
            
            # Track errors
            if self._is_error_log(log):
                profile['errors'] += 1
                
        # Analyze profiles
        for user, profile in user_profiles.items():
            # 1. Unusual action diversity
            action_entropy = self._calculate_entropy(list(profile['actions'].values()))
            if action_entropy > 3.0:  # High entropy
                anomalies.append({
                    'type': 'unusual_user_behavior',
                    'description': f'User {user} showing unusually diverse behavior',
                    'user': user,
                    'action_count': len(profile['actions']),
                    'action_entropy': action_entropy,
                    'total_actions': profile['total'],
                    'severity': 'medium',
                    'confidence': 0.75
                })
                
            # 2. Multiple source IPs
            if len(profile['sources']) > 5:
                anomalies.append({
                    'type': 'multiple_source_ips',
                    'description': f'User {user} accessed from {len(profile["sources"])} different sources',
                    'user': user,
                    'sources': list(profile['sources']),
                    'severity': 'high',
                    'confidence': 0.9
                })
                
            # 3. Unusual activity times
            if profile['timestamps']:
                unusual_times = self._detect_unusual_activity_times(profile['timestamps'])
                if unusual_times:
                    anomalies.append({
                        'type': 'unusual_activity_time',
                        'description': f'User {user} active at unusual times',
                        'user': user,
                        'unusual_hours': unusual_times,
                        'severity': 'medium',
                        'confidence': 0.7
                    })
                    
        return anomalies
        
    def _detect_port_scanning(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect port scanning behavior"""
        anomalies = []
        
        # Track connections by source
        source_ports = defaultdict(lambda: defaultdict(set))
        
        for item in data:
            src = item.get('src_ip', item.get('source'))
            dst = item.get('dst_ip', item.get('destination'))
            port = item.get('dst_port', item.get('port'))
            
            if src and dst and port:
                source_ports[src][dst].add(port)
                
        # Detect scanning
        for src, destinations in source_ports.items():
            for dst, ports in destinations.items():
                if len(ports) > 20:  # Many ports to same destination
                    anomalies.append({
                        'type': 'port_scan',
                        'description': f'Port scanning detected from {src} to {dst}',
                        'source': src,
                        'destination': dst,
                        'port_count': len(ports),
                        'ports': sorted(list(ports))[:50],  # First 50 ports
                        'severity': 'high',
                        'confidence': 0.95
                    })
                    
            # Check for distributed scanning
            total_unique_ports = len(set().union(*destinations.values()))
            if len(destinations) > 10 and total_unique_ports > 100:
                anomalies.append({
                    'type': 'distributed_scan',
                    'description': f'Distributed scanning from {src}',
                    'source': src,
                    'target_count': len(destinations),
                    'total_ports_scanned': total_unique_ports,
                    'severity': 'critical',
                    'confidence': 0.9
                })
                
        return anomalies
        
    def _detect_protocol_anomalies(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect unusual protocol usage"""
        anomalies = []
        
        # Expected port-protocol mappings
        standard_ports = {
            80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 21: 'FTP',
            25: 'SMTP', 53: 'DNS', 3389: 'RDP', 3306: 'MySQL'
        }
        
        protocol_stats = defaultdict(int)
        unusual_protocols = []
        
        for item in data:
            port = item.get('dst_port', item.get('port'))
            protocol = item.get('protocol', item.get('proto'))
            
            if port and protocol:
                protocol_stats[protocol] += 1
                
                # Check for non-standard usage
                if port in standard_ports:
                    expected = standard_ports[port]
                    if protocol.upper() != expected and protocol.upper() != 'TCP':
                        unusual_protocols.append({
                            'port': port,
                            'expected': expected,
                            'actual': protocol,
                            'item': item
                        })
                        
        # Report unusual protocols
        for unusual in unusual_protocols:
            anomalies.append({
                'type': 'protocol_mismatch',
                'description': f'Unusual protocol on port {unusual["port"]}',
                'port': unusual['port'],
                'expected_protocol': unusual['expected'],
                'actual_protocol': unusual['actual'],
                'severity': 'medium',
                'confidence': 0.8,
                'data': unusual['item']
            })
            
        return anomalies
        
    def _detect_geographic_anomalies(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect geographic anomalies"""
        anomalies = []
        
        # Track locations by user/source
        user_locations = defaultdict(set)
        location_changes = defaultdict(list)
        
        for item in data:
            user = item.get('user', item.get('src_ip'))
            location = item.get('geo_country', item.get('country'))
            timestamp = item.get('timestamp')
            
            if user and location:
                user_locations[user].add(location)
                
                if timestamp:
                    location_changes[user].append({
                        'location': location,
                        'timestamp': timestamp
                    })
                    
        # Detect anomalies
        for user, locations in user_locations.items():
            # Multiple countries
            if len(locations) > 3:
                anomalies.append({
                    'type': 'multiple_geolocations',
                    'description': f'Access from {len(locations)} different countries',
                    'user': user,
                    'countries': list(locations),
                    'severity': 'high',
                    'confidence': 0.85
                })
                
        # Check for impossible travel
        for user, changes in location_changes.items():
            if len(changes) < 2:
                continue
                
            # Sort by timestamp
            changes.sort(key=lambda x: x['timestamp'])
            
            for i in range(1, len(changes)):
                loc1 = changes[i-1]
                loc2 = changes[i]
                
                if loc1['location'] != loc2['location']:
                    # Calculate time difference
                    if isinstance(loc1['timestamp'], str):
                        t1 = datetime.fromisoformat(loc1['timestamp'])
                        t2 = datetime.fromisoformat(loc2['timestamp'])
                    else:
                        t1 = loc1['timestamp']
                        t2 = loc2['timestamp']
                        
                    time_diff = (t2 - t1).total_seconds() / 3600  # Hours
                    
                    # Rough check - would need real distance calculation
                    if time_diff < 2:  # Less than 2 hours between countries
                        anomalies.append({
                            'type': 'impossible_travel',
                            'description': f'Impossible travel detected for {user}',
                            'user': user,
                            'location1': loc1['location'],
                            'location2': loc2['location'],
                            'time_difference_hours': time_diff,
                            'severity': 'critical',
                            'confidence': 0.95
                        })
                        
        return anomalies
        
    def _detect_connection_anomalies(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect anomalies in connection patterns"""
        anomalies = []
        
        # Build connection graph
        connections = defaultdict(lambda: defaultdict(int))
        connection_times = defaultdict(list)
        
        for item in data:
            src = item.get('src_ip', item.get('source'))
            dst = item.get('dst_ip', item.get('destination'))
            timestamp = item.get('timestamp')
            
            if src and dst:
                connections[src][dst] += 1
                
                if timestamp:
                    connection_times[f"{src}->{dst}"].append(timestamp)
                    
        # Detect anomalies
        for src, destinations in connections.items():
            # Fan-out detection
            if len(destinations) > 50:
                anomalies.append({
                    'type': 'connection_fanout',
                    'description': f'Unusual fan-out from {src}',
                    'source': src,
                    'destination_count': len(destinations),
                    'total_connections': sum(destinations.values()),
                    'severity': 'medium',
                    'confidence': 0.75
                })
                
        # Detect beaconing
        for conn_id, timestamps in connection_times.items():
            if len(timestamps) > 10:
                beacon_score = self._calculate_beacon_score(timestamps)
                if beacon_score > 0.8:
                    src, dst = conn_id.split('->')
                    anomalies.append({
                        'type': 'beaconing',
                        'description': f'Potential beaconing behavior detected',
                        'source': src,
                        'destination': dst,
                        'beacon_score': beacon_score,
                        'connection_count': len(timestamps),
                        'severity': 'high',
                        'confidence': beacon_score
                    })
                    
        return anomalies
        
    def _detect_resource_anomalies(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect resource usage anomalies"""
        anomalies = []
        
        # Extract resource metrics
        cpu_usage = []
        memory_usage = []
        disk_io = []
        network_io = []
        
        for item in data:
            if 'cpu_percent' in item:
                cpu_usage.append(item['cpu_percent'])
            if 'memory_percent' in item:
                memory_usage.append(item['memory_percent'])
            if 'disk_read_bytes' in item or 'disk_write_bytes' in item:
                disk_io.append(
                    item.get('disk_read_bytes', 0) + item.get('disk_write_bytes', 0)
                )
            if 'network_bytes_sent' in item or 'network_bytes_recv' in item:
                network_io.append(
                    item.get('network_bytes_sent', 0) + item.get('network_bytes_recv', 0)
                )
                
        # Detect CPU anomalies
        if cpu_usage:
            cpu_outliers = self._detect_statistical_outliers(cpu_usage)
            for idx in cpu_outliers:
                if cpu_usage[idx] > 90:
                    anomalies.append({
                        'type': 'high_cpu_usage',
                        'description': f'Abnormally high CPU usage: {cpu_usage[idx]:.1f}%',
                        'value': cpu_usage[idx],
                        'threshold': 90,
                        'severity': 'high',
                        'confidence': 0.9
                    })
                    
        # Detect memory anomalies
        if memory_usage:
            mem_outliers = self._detect_statistical_outliers(memory_usage)
            for idx in mem_outliers:
                if memory_usage[idx] > 85:
                    anomalies.append({
                        'type': 'high_memory_usage',
                        'description': f'Abnormally high memory usage: {memory_usage[idx]:.1f}%',
                        'value': memory_usage[idx],
                        'threshold': 85,
                        'severity': 'high',
                        'confidence': 0.9
                    })
                    
        return anomalies
        
    def _detect_process_anomalies(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect process-related anomalies"""
        anomalies = []
        
        # Track process information
        process_info = defaultdict(lambda: {
            'count': 0,
            'parents': set(),
            'children': set(),
            'users': set(),
            'commands': set()
        })
        
        suspicious_processes = [
            'powershell', 'cmd', 'wscript', 'cscript', 'rundll32',
            'regsvr32', 'mshta', 'bitsadmin', 'certutil'
        ]
        
        for item in data:
            if 'process_name' in item:
                proc_name = item['process_name'].lower()
                info = process_info[proc_name]
                
                info['count'] += 1
                
                if 'parent_process' in item:
                    info['parents'].add(item['parent_process'])
                if 'child_processes' in item:
                    info['children'].update(item['child_processes'])
                if 'user' in item:
                    info['users'].add(item['user'])
                if 'command_line' in item:
                    info['commands'].add(item['command_line'])
                    
                # Check for suspicious processes
                for susp in suspicious_processes:
                    if susp in proc_name:
                        anomalies.append({
                            'type': 'suspicious_process',
                            'description': f'Suspicious process detected: {item["process_name"]}',
                            'process': item['process_name'],
                            'command_line': item.get('command_line'),
                            'user': item.get('user'),
                            'severity': 'medium',
                            'confidence': 0.8
                        })
                        
        # Analyze process relationships
        for proc_name, info in process_info.items():
            # Unusual parent-child relationships
            if len(info['parents']) > 5:
                anomalies.append({
                    'type': 'process_parent_anomaly',
                    'description': f'Process {proc_name} has unusual number of parents',
                    'process': proc_name,
                    'parent_count': len(info['parents']),
                    'parents': list(info['parents']),
                    'severity': 'medium',
                    'confidence': 0.75
                })
                
        return anomalies
        
    def _detect_filesystem_anomalies(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect file system anomalies"""
        anomalies = []
        
        # Track file operations
        file_operations = defaultdict(lambda: defaultdict(int))
        suspicious_paths = [
            'system32', 'temp', 'appdata', 'programdata',
            '.ssh', '.aws', '.config', 'passwords', 'credentials'
        ]
        
        for item in data:
            if 'file_path' in item and 'operation' in item:
                path = item['file_path'].lower()
                operation = item['operation']
                
                file_operations[path][operation] += 1
                
                # Check for suspicious paths
                for susp in suspicious_paths:
                    if susp in path:
                        if operation in ['write', 'delete', 'modify']:
                            anomalies.append({
                                'type': 'suspicious_file_operation',
                                'description': f'Suspicious {operation} on {item["file_path"]}',
                                'file_path': item['file_path'],
                                'operation': operation,
                                'severity': 'high',
                                'confidence': 0.85
                            })
                            
        # Detect mass file operations
        for path, operations in file_operations.items():
            total_ops = sum(operations.values())
            if total_ops > 100:
                anomalies.append({
                    'type': 'mass_file_operation',
                    'description': f'Large number of operations on {path}',
                    'file_path': path,
                    'operation_count': total_ops,
                    'operations': dict(operations),
                    'severity': 'medium',
                    'confidence': 0.7
                })
                
        return anomalies
        
    def _detect_registry_anomalies(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect Windows registry anomalies"""
        anomalies = []
        
        # Sensitive registry keys
        sensitive_keys = [
            'run', 'runonce', 'services', 'drivers',
            'winlogon', 'userinit', 'shell', 'startup'
        ]
        
        for item in data:
            if 'registry_key' in item:
                key = item['registry_key'].lower()
                operation = item.get('operation', 'unknown')
                
                # Check for sensitive key modifications
                for sensitive in sensitive_keys:
                    if sensitive in key:
                        if operation in ['create', 'modify', 'delete']:
                            anomalies.append({
                                'type': 'registry_modification',
                                'description': f'Sensitive registry key {operation}',
                                'registry_key': item['registry_key'],
                                'operation': operation,
                                'value': item.get('value'),
                                'severity': 'high',
                                'confidence': 0.9
                            })
                            
        return anomalies
        
    def _detect_statistical_outliers(self, values: List[float]) -> List[int]:
        """Detect statistical outliers using multiple methods"""
        outliers = set()
        
        if len(values) < 3:
            return list(outliers)
            
        # Method 1: Z-score
        mean = statistics.mean(values)
        std = statistics.stdev(values)
        
        for i, value in enumerate(values):
            if std > 0:
                z_score = abs((value - mean) / std)
                if z_score > self.thresholds['zscore']:
                    outliers.add(i)
                    
        # Method 2: IQR
        sorted_values = sorted(values)
        q1 = sorted_values[len(sorted_values) // 4]
        q3 = sorted_values[3 * len(sorted_values) // 4]
        iqr = q3 - q1
        
        lower_bound = q1 - self.thresholds['iqr_multiplier'] * iqr
        upper_bound = q3 + self.thresholds['iqr_multiplier'] * iqr
        
        for i, value in enumerate(values):
            if value < lower_bound or value > upper_bound:
                outliers.add(i)
                
        return list(outliers)
        
    def _detect_outliers_isolation_forest(
        self,
        features: np.ndarray,
        feature_names: List[str]
    ) -> List[int]:
        """Detect outliers using Isolation Forest"""
        if len(features) < 10:
            return []
            
        # Standardize features
        scaler = StandardScaler()
        scaled_features = scaler.fit_transform(features)
        
        # Train Isolation Forest
        iso_forest = IsolationForest(
            contamination=self.thresholds['isolation_contamination'],
            random_state=42
        )
        predictions = iso_forest.fit_predict(scaled_features)
        
        # Get outlier indices
        outlier_indices = [i for i, pred in enumerate(predictions) if pred == -1]
        
        return outlier_indices
        
    def _detect_clustering_anomalies(
        self,
        features: np.ndarray,
        feature_names: List[str]
    ) -> List[int]:
        """Detect anomalies using DBSCAN clustering"""
        if len(features) < 20:
            return []
            
        # Standardize features
        scaler = StandardScaler()
        scaled_features = scaler.fit_transform(features)
        
        # Apply DBSCAN
        dbscan = DBSCAN(
            eps=self.thresholds['dbscan_eps'],
            min_samples=self.thresholds['dbscan_min_samples']
        )
        clusters = dbscan.fit_predict(scaled_features)
        
        # Outliers are labeled as -1
        outlier_indices = [i for i, cluster in enumerate(clusters) if cluster == -1]
        
        return outlier_indices
        
    def _calculate_beacon_score(self, timestamps: List[Any]) -> float:
        """Calculate beaconing score based on timing regularity"""
        if len(timestamps) < 5:
            return 0.0
            
        # Convert to seconds
        intervals = []
        sorted_ts = sorted(timestamps)
        
        for i in range(1, len(sorted_ts)):
            if isinstance(sorted_ts[i], str):
                t1 = datetime.fromisoformat(sorted_ts[i-1])
                t2 = datetime.fromisoformat(sorted_ts[i])
            else:
                t1 = sorted_ts[i-1]
                t2 = sorted_ts[i]
                
            interval = (t2 - t1).total_seconds()
            if interval > 0:
                intervals.append(interval)
                
        if not intervals:
            return 0.0
            
        # Calculate regularity
        mean_interval = statistics.mean(intervals)
        std_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
        
        # Coefficient of variation
        cv = std_interval / mean_interval if mean_interval > 0 else float('inf')
        
        # Score: higher for more regular intervals
        score = 1.0 / (1.0 + cv)
        
        return score
        
    def _calculate_entropy(self, values: List[int]) -> float:
        """Calculate Shannon entropy"""
        total = sum(values)
        if total == 0:
            return 0.0
            
        entropy = 0.0
        for value in values:
            if value > 0:
                p = value / total
                entropy -= p * math.log2(p)
                
        return entropy
        
    def _extract_log_pattern(self, log: Dict[str, Any]) -> str:
        """Extract pattern from log entry"""
        # Simple pattern extraction - could be more sophisticated
        pattern_parts = []
        
        if 'event_type' in log:
            pattern_parts.append(f"type:{log['event_type']}")
        if 'source' in log:
            pattern_parts.append(f"src:{log['source']}")
        if 'action' in log:
            pattern_parts.append(f"action:{log['action']}")
        if 'result' in log:
            pattern_parts.append(f"result:{log['result']}")
            
        return '|'.join(pattern_parts)
        
    def _is_error_log(self, log: Dict[str, Any]) -> bool:
        """Check if log entry is an error"""
        error_indicators = [
            'error', 'fail', 'denied', 'reject', 'unauthor',
            'forbidden', 'invalid', 'timeout', 'exception'
        ]
        
        # Check common fields
        for field in ['level', 'severity', 'status', 'result', 'message']:
            if field in log:
                value = str(log[field]).lower()
                for indicator in error_indicators:
                    if indicator in value:
                        return True
                        
        return False
        
    def _detect_unusual_activity_times(self, timestamps: List[Any]) -> List[int]:
        """Detect activity at unusual hours"""
        unusual_hours = []
        
        for ts in timestamps:
            if isinstance(ts, str):
                dt = datetime.fromisoformat(ts)
            else:
                dt = ts
                
            hour = dt.hour
            
            # Consider 1 AM - 5 AM as unusual
            if 1 <= hour <= 5:
                unusual_hours.append(hour)
                
        return unusual_hours
        
    def _extract_traffic_features(self, data: List[Dict[str, Any]]) -> np.ndarray:
        """Extract network traffic features"""
        features = []
        
        for item in data:
            if all(k in item for k in ['bytes_sent', 'bytes_received', 'packet_count']):
                features.append([
                    item['bytes_sent'],
                    item['bytes_received'],
                    item['packet_count']
                ])
                
        return np.array(features) if features else np.array([])
        
    def _calculate_expected_range(self, values: List[float]) -> Tuple[float, float]:
        """Calculate expected range for values"""
        if not values:
            return (0, 0)
            
        mean = statistics.mean(values)
        std = statistics.stdev(values) if len(values) > 1 else 0
        
        return (mean - 2 * std, mean + 2 * std)
        
    def _detect_trend_changes(self, values: List[float]) -> List[Dict[str, Any]]:
        """Detect significant trend changes in time series"""
        changes = []
        
        if len(values) < 10:
            return changes
            
        # Simple moving average
        window = 5
        for i in range(window, len(values) - window):
            before = statistics.mean(values[i-window:i])
            after = statistics.mean(values[i:i+window])
            
            change = abs(after - before) / before if before != 0 else float('inf')
            
            if change > 0.5:  # 50% change
                changes.append({
                    'index': i,
                    'magnitude': change,
                    'before': before,
                    'after': after
                })
                
        return changes
        
    def _detect_seasonal_anomalies(self, values: List[float]) -> List[int]:
        """Detect violations of seasonal patterns"""
        # Simplified seasonal detection
        # In production, use proper time series decomposition
        anomalies = []
        
        # Assume daily seasonality (24 hours)
        season_length = 24
        
        if len(values) < season_length * 2:
            return anomalies
            
        # Calculate seasonal averages
        seasonal_avgs = [0] * season_length
        counts = [0] * season_length
        
        for i, value in enumerate(values):
            season_idx = i % season_length
            seasonal_avgs[season_idx] += value
            counts[season_idx] += 1
            
        # Compute averages
        for i in range(season_length):
            if counts[i] > 0:
                seasonal_avgs[i] /= counts[i]
                
        # Find anomalies
        for i, value in enumerate(values):
            season_idx = i % season_length
            expected = seasonal_avgs[season_idx]
            
            if expected > 0:
                deviation = abs(value - expected) / expected
                if deviation > 1.0:  # 100% deviation
                    anomalies.append(i)
                    
        return anomalies
        
    def _score_anomalies(self, anomalies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Score and rank anomalies"""
        # Severity weights
        severity_weights = {
            'critical': 1.0,
            'high': 0.8,
            'medium': 0.5,
            'low': 0.3
        }
        
        # Type weights
        type_weights = {
            'port_scan': 0.9,
            'impossible_travel': 0.95,
            'beaconing': 0.85,
            'suspicious_process': 0.8,
            'registry_modification': 0.85,
            'error_rate_spike': 0.7,
            'rapid_fire_events': 0.8
        }
        
        # Score each anomaly
        for anomaly in anomalies:
            severity = anomaly.get('severity', 'medium')
            anomaly_type = anomaly.get('type', 'unknown')
            confidence = anomaly.get('confidence', 0.5)
            
            severity_score = severity_weights.get(severity, 0.5)
            type_score = type_weights.get(anomaly_type, 0.5)
            
            # Combined score
            anomaly['score'] = severity_score * type_score * confidence
            
        # Sort by score
        anomalies.sort(key=lambda x: x['score'], reverse=True)
        
        return anomalies
        
    def _group_anomalies_by_type(self, anomalies: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group anomalies by type"""
        grouped = defaultdict(list)
        
        for anomaly in anomalies:
            anomaly_type = anomaly.get('type', 'unknown')
            grouped[anomaly_type].append(anomaly)
            
        return dict(grouped)
        
    def _get_severity_distribution(self, anomalies: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get distribution of anomaly severities"""
        distribution = defaultdict(int)
        
        for anomaly in anomalies:
            severity = anomaly.get('severity', 'unknown')
            distribution[severity] += 1
            
        return dict(distribution)
        
    def _generate_anomaly_summary(self, anomalies: List[Dict[str, Any]]) -> str:
        """Generate summary of detected anomalies"""
        if not anomalies:
            return "No significant anomalies detected."
            
        summary_parts = []
        
        # Count by severity
        severity_counts = self._get_severity_distribution(anomalies)
        
        if severity_counts.get('critical', 0) > 0:
            summary_parts.append(f"{severity_counts['critical']} critical anomalies detected")
        if severity_counts.get('high', 0) > 0:
            summary_parts.append(f"{severity_counts['high']} high-severity anomalies")
            
        # Top anomaly types
        type_groups = self._group_anomalies_by_type(anomalies)
        top_types = sorted(type_groups.items(), key=lambda x: len(x[1]), reverse=True)[:3]
        
        if top_types:
            summary_parts.append(
                f"Most common: {', '.join(t[0].replace('_', ' ') for t in top_types)}"
            )
            
        return ". ".join(summary_parts) + "."