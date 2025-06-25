"""
AWS CloudTrail Parser for SecuNik LogX
Parses CloudTrail logs for security analysis
Detects suspicious AWS API activity, privilege escalation, and data exfiltration
"""

import json
import gzip
import asyncio
from datetime import datetime
from typing import Dict, Any, List, Optional, Set, AsyncGenerator, Tuple
from pathlib import Path
from collections import defaultdict
import re

from ..base_parser import BaseParser, ParseResult, ParsedEntry, FileMetadata, IOCs


class AWSCloudTrailParser(BaseParser):
    """Parser for AWS CloudTrail logs"""
    
    name = "aws_cloudtrail"
    description = "Parses AWS CloudTrail logs for security analysis"
    supported_extensions = ['.json', '.gz', '.log']
    
    # High-risk AWS API calls
    HIGH_RISK_APIS = {
        # IAM operations
        'CreateAccessKey': 'Credential creation',
        'CreateUser': 'User creation',
        'AttachUserPolicy': 'Policy attachment',
        'PutUserPolicy': 'Inline policy creation',
        'CreateRole': 'Role creation',
        'AssumeRole': 'Role assumption',
        'UpdateAssumeRolePolicy': 'Trust policy modification',
        'CreateLoginProfile': 'Console access granted',
        'UpdateLoginProfile': 'Password change',
        'DeleteLoginProfile': 'Console access removed',
        
        # Permission escalation
        'AttachRolePolicy': 'Role policy attachment',
        'PutRolePolicy': 'Inline role policy',
        'CreatePolicyVersion': 'Policy version creation',
        'SetDefaultPolicyVersion': 'Policy version change',
        'PassRole': 'Role passing',
        
        # Data access
        'GetSecretValue': 'Secret access',
        'Decrypt': 'KMS decryption',
        'GetParameter': 'SSM parameter access',
        'GetParameters': 'Bulk parameter access',
        
        # Network changes
        'AuthorizeSecurityGroupIngress': 'Firewall rule added',
        'AuthorizeSecurityGroupEgress': 'Outbound rule added',
        'CreateSecurityGroup': 'Security group created',
        'ModifyInstanceAttribute': 'Instance modified',
        'CreateVpcPeering': 'VPC peering created',
        
        # Resource deletion
        'DeleteBucket': 'S3 bucket deleted',
        'DeleteDBInstance': 'Database deleted',
        'TerminateInstances': 'EC2 instances terminated',
        'DeleteAccessKey': 'Access key deleted',
        'DeleteUser': 'User deleted',
        
        # Logging/Monitoring
        'StopLogging': 'CloudTrail disabled',
        'DeleteTrail': 'CloudTrail deleted',
        'PutEventSelectors': 'CloudTrail modified',
        'DisableAlarmActions': 'Alarms disabled',
        'DeleteAlarms': 'Alarms deleted'
    }
    
    # Suspicious patterns
    SUSPICIOUS_PATTERNS = {
        'enumeration': [
            'List', 'Describe', 'Get'
        ],
        'persistence': [
            'CreateAccessKey', 'CreateUser', 'CreateRole',
            'CreateFunction', 'PutBucketPolicy'
        ],
        'defense_evasion': [
            'StopLogging', 'DeleteTrail', 'DeleteLogGroup',
            'DeleteAlarms', 'DisableAlarmActions'
        ],
        'credential_access': [
            'GetSecretValue', 'GetParameter', 'Decrypt',
            'GetSessionToken', 'AssumeRole'
        ],
        'exfiltration': [
            'GetObject', 'CopyObject', 'CreateSnapshot',
            'CreateImage', 'ExportSnapshot'
        ]
    }
    
    # Error codes indicating potential issues
    SUSPICIOUS_ERROR_CODES = {
        'UnauthorizedOperation': 'Unauthorized attempt',
        'AccessDenied': 'Permission denied',
        'TokenRefreshRequired': 'Token refresh attempted',
        'CredentialsNotFound': 'Missing credentials',
        'InvalidUserID.NotFound': 'Invalid user access',
        'AuthFailure': 'Authentication failure',
        'UnauthorizedAccess': 'Unauthorized access attempt',
        'Forbidden': 'Forbidden action'
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.events_by_user = defaultdict(list)
        self.events_by_ip = defaultdict(list)
        self.error_events = []
        self.high_risk_events = []
        self.suspicious_sequences = []
        self.api_call_stats = defaultdict(int)
        
    async def parse(self) -> ParseResult:
        """Parse CloudTrail log file"""
        result = ParseResult(
            file_path=str(self.file_path),
            file_type="cloudtrail",
            parser_name=self.name
        )
        
        try:
            # Get file metadata
            result.metadata = await self._get_file_metadata()
            
            # Parse CloudTrail events
            events = await self._load_cloudtrail_events()
            
            if not events:
                result.errors.append("No CloudTrail events found")
                return result
                
            result.metadata.additional["total_events"] = len(events)
            
            # Process each event
            for idx, event in enumerate(events):
                # Yield control periodically
                if idx % 100 == 0:
                    await asyncio.sleep(0)
                    
                entry = await self._process_cloudtrail_event(event, idx)
                result.entries.append(entry)
                
                # Extract IOCs
                result.iocs.merge(self._extract_cloudtrail_iocs(entry))
                
                # Categorize events
                await self._categorize_event(entry, event)
                
            # Detect suspicious patterns
            await self._detect_suspicious_patterns()
            
            # Add high-risk events
            for risk_event in self.high_risk_events[:100]:  # Limit
                result.entries.append(risk_event)
                
            # Add suspicious sequences
            for sequence in self.suspicious_sequences[:50]:
                result.entries.append(sequence)
                
            # Generate summary
            result.metadata.additional.update({
                "unique_users": len(self.events_by_user),
                "unique_ips": len(self.events_by_ip),
                "error_events": len(self.error_events),
                "high_risk_events": len(self.high_risk_events),
                "suspicious_sequences": len(self.suspicious_sequences),
                "top_users": self._get_top_users(),
                "top_api_calls": self._get_top_api_calls(),
                "risk_summary": self._generate_risk_summary(),
                "geographic_summary": self._get_geographic_summary()
            })
            
            self.logger.info(f"Parsed {len(events)} CloudTrail events")
            
        except Exception as e:
            self.logger.error(f"Error parsing CloudTrail: {e}")
            result.errors.append(f"Parse error: {str(e)}")
            
        return result
        
    async def _load_cloudtrail_events(self) -> List[Dict]:
        """Load CloudTrail events from file"""
        events = []
        
        # Check if gzipped
        if self.file_path.suffix == '.gz':
            async with self._open_file('rb') as f:
                content = await f.read()
            content = gzip.decompress(content)
            data = json.loads(content)
        else:
            async with self._open_file('r') as f:
                content = await f.read()
            data = json.loads(content)
            
        # CloudTrail format can be single object or Records array
        if isinstance(data, dict):
            if 'Records' in data:
                events = data['Records']
            else:
                events = [data]
        elif isinstance(data, list):
            events = data
            
        return events
        
    async def _process_cloudtrail_event(self, event: Dict, idx: int) -> ParsedEntry:
        """Process individual CloudTrail event"""
        # Extract key fields
        event_time = event.get('eventTime', '')
        event_name = event.get('eventName', 'Unknown')
        event_source = event.get('eventSource', 'Unknown')
        user_identity = event.get('userIdentity', {})
        source_ip = event.get('sourceIPAddress', 'Unknown')
        user_agent = event.get('userAgent', '')
        error_code = event.get('errorCode', '')
        error_message = event.get('errorMessage', '')
        
        # Parse timestamp
        try:
            timestamp = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
        except:
            timestamp = datetime.now()
            
        # Determine user
        user = self._extract_user_identity(user_identity)
        
        # Determine severity
        severity = "info"
        if error_code:
            severity = "warning"
        if event_name in self.HIGH_RISK_APIS:
            severity = "warning"
        if error_code in self.SUSPICIOUS_ERROR_CODES:
            severity = "critical"
            
        # Build message
        message = f"{event_name} by {user} from {source_ip}"
        if error_code:
            message += f" - ERROR: {error_code}"
            
        entry = ParsedEntry(
            timestamp=timestamp,
            source=source_ip,
            event_type="aws_api_call",
            severity=severity,
            message=message,
            raw_data=event
        )
        
        entry.parsed_data = {
            'event_name': event_name,
            'event_source': event_source,
            'user': user,
            'user_type': user_identity.get('type', 'Unknown'),
            'account_id': user_identity.get('accountId', 'Unknown'),
            'access_key_id': user_identity.get('accessKeyId', 'Unknown'),
            'session_context': user_identity.get('sessionContext', {}),
            'source_ip': source_ip,
            'user_agent': user_agent,
            'aws_region': event.get('awsRegion', 'Unknown'),
            'error_code': error_code,
            'error_message': error_message,
            'request_parameters': event.get('requestParameters', {}),
            'response_elements': event.get('responseElements', {}),
            'event_id': event.get('eventID', f'idx_{idx}')
        }
        
        # Add tags
        if event_name in self.HIGH_RISK_APIS:
            entry.tags.append("high_risk_api")
            entry.tags.append(self.HIGH_RISK_APIS[event_name].lower().replace(' ', '_'))
            
        if error_code:
            entry.tags.append("error")
            if error_code in self.SUSPICIOUS_ERROR_CODES:
                entry.tags.append("suspicious_error")
                
        return entry
        
    def _extract_user_identity(self, user_identity: Dict) -> str:
        """Extract user identifier from userIdentity object"""
        # Try different fields
        if 'userName' in user_identity:
            return user_identity['userName']
        elif 'arn' in user_identity:
            # Extract user from ARN
            arn = user_identity['arn']
            if '//' in arn:
                return arn.split('//')[-1]
            elif '/' in arn:
                return arn.split('/')[-1]
            return arn
        elif 'principalId' in user_identity:
            return user_identity['principalId']
        elif 'accountId' in user_identity:
            return f"Account-{user_identity['accountId']}"
        else:
            return 'Unknown'
            
    async def _categorize_event(self, entry: ParsedEntry, event: Dict):
        """Categorize event for analysis"""
        data = entry.parsed_data
        
        # Track by user
        user = data['user']
        self.events_by_user[user].append(entry)
        
        # Track by IP
        ip = data['source_ip']
        self.events_by_ip[ip].append(entry)
        
        # Track API calls
        self.api_call_stats[data['event_name']] += 1
        
        # Track errors
        if data['error_code']:
            self.error_events.append(entry)
            
        # Identify high-risk events
        if data['event_name'] in self.HIGH_RISK_APIS:
            risk_entry = ParsedEntry(
                timestamp=entry.timestamp,
                source=entry.source,
                event_type="security_alert",
                severity="warning",
                message=f"High-risk API call: {data['event_name']} - {self.HIGH_RISK_APIS[data['event_name']]}",
                raw_data=entry.raw_data
            )
            risk_entry.tags = ["high_risk", "aws_security", data['event_name'].lower()]
            risk_entry.parsed_data = entry.parsed_data.copy()
            
            self.high_risk_events.append(risk_entry)
            
    async def _detect_suspicious_patterns(self):
        """Detect suspicious activity patterns"""
        # Check each user's activity
        for user, events in self.events_by_user.items():
            # Sort events by time
            events.sort(key=lambda x: x.timestamp)
            
            # Check for enumeration
            await self._check_enumeration(user, events)
            
            # Check for privilege escalation
            await self._check_privilege_escalation(user, events)
            
            # Check for defense evasion
            await self._check_defense_evasion(user, events)
            
            # Check for rapid API calls
            await self._check_rapid_calls(user, events)
            
        # Check for distributed attacks
        await self._check_distributed_activity()
        
    async def _check_enumeration(self, user: str, events: List[ParsedEntry]):
        """Check for enumeration patterns"""
        enum_events = []
        
        for event in events:
            event_name = event.parsed_data['event_name']
            
            # Check if it's an enumeration API
            if any(event_name.startswith(prefix) for prefix in self.SUSPICIOUS_PATTERNS['enumeration']):
                enum_events.append(event)
                
        # If many enumeration calls in short time
        if len(enum_events) >= 10:
            time_window = (enum_events[-1].timestamp - enum_events[0].timestamp).total_seconds()
            
            if time_window < 300:  # 5 minutes
                alert = ParsedEntry(
                    timestamp=enum_events[0].timestamp,
                    source=enum_events[0].source,
                    event_type="security_alert",
                    severity="warning",
                    message=f"Enumeration activity detected: {user} made {len(enum_events)} discovery calls in {time_window:.0f} seconds",
                    raw_data={
                        'user': user,
                        'event_count': len(enum_events),
                        'time_window': time_window,
                        'api_calls': [e.parsed_data['event_name'] for e in enum_events[:10]]
                    }
                )
                alert.tags = ["enumeration", "reconnaissance", "suspicious_pattern"]
                self.suspicious_sequences.append(alert)
                
    async def _check_privilege_escalation(self, user: str, events: List[ParsedEntry]):
        """Check for privilege escalation attempts"""
        priv_esc_sequence = []
        
        for event in events:
            event_name = event.parsed_data['event_name']
            
            # Check for IAM modifications
            if event_name in ['AttachUserPolicy', 'PutUserPolicy', 'AttachRolePolicy', 
                            'PutRolePolicy', 'CreateAccessKey', 'CreateLoginProfile']:
                priv_esc_sequence.append(event)
                
        if len(priv_esc_sequence) >= 3:
            alert = ParsedEntry(
                timestamp=priv_esc_sequence[0].timestamp,
                source=priv_esc_sequence[0].source,
                event_type="security_alert",
                severity="critical",
                message=f"Potential privilege escalation: {user} performed {len(priv_esc_sequence)} permission modifications",
                raw_data={
                    'user': user,
                    'actions': [e.parsed_data['event_name'] for e in priv_esc_sequence],
                    'targets': [e.parsed_data.get('request_parameters', {}) for e in priv_esc_sequence[:5]]
                }
            )
            alert.tags = ["privilege_escalation", "iam_abuse", "critical"]
            self.suspicious_sequences.append(alert)
            
    async def _check_defense_evasion(self, user: str, events: List[ParsedEntry]):
        """Check for defense evasion tactics"""
        evasion_events = []
        
        for event in events:
            event_name = event.parsed_data['event_name']
            
            if event_name in self.SUSPICIOUS_PATTERNS['defense_evasion']:
                evasion_events.append(event)
                
        if evasion_events:
            alert = ParsedEntry(
                timestamp=evasion_events[0].timestamp,
                source=evasion_events[0].source,
                event_type="security_alert",
                severity="critical",
                message=f"Defense evasion detected: {user} attempted to disable logging/monitoring",
                raw_data={
                    'user': user,
                    'evasion_actions': [e.parsed_data['event_name'] for e in evasion_events]
                }
            )
            alert.tags = ["defense_evasion", "anti_forensics", "critical"]
            self.suspicious_sequences.append(alert)
            
    async def _check_rapid_calls(self, user: str, events: List[ParsedEntry]):
        """Check for rapid API calls indicating automation"""
        if len(events) < 10:
            return
            
        # Check for bursts of activity
        for i in range(len(events) - 10):
            window = events[i:i+10]
            time_span = (window[-1].timestamp - window[0].timestamp).total_seconds()
            
            if time_span < 10:  # 10 calls in 10 seconds
                alert = ParsedEntry(
                    timestamp=window[0].timestamp,
                    source=window[0].source,
                    event_type="security_alert",
                    severity="warning",
                    message=f"Rapid API calls detected: {user} made 10 calls in {time_span:.1f} seconds",
                    raw_data={
                        'user': user,
                        'calls_per_second': 10 / max(time_span, 1),
                        'api_calls': [e.parsed_data['event_name'] for e in window]
                    }
                )
                alert.tags = ["automation", "api_abuse", "suspicious_pattern"]
                self.suspicious_sequences.append(alert)
                break
                
    async def _check_distributed_activity(self):
        """Check for distributed attacks from multiple IPs"""
        # Group similar activities across IPs
        activity_patterns = defaultdict(list)
        
        for ip, events in self.events_by_ip.items():
            if len(events) > 5:
                # Create activity signature
                api_calls = [e.parsed_data['event_name'] for e in events[:10]]
                signature = ','.join(sorted(set(api_calls)))
                activity_patterns[signature].append(ip)
                
        # Check for same pattern from multiple IPs
        for pattern, ips in activity_patterns.items():
            if len(ips) >= 5:
                alert = ParsedEntry(
                    timestamp=datetime.now(),
                    source="multiple",
                    event_type="security_alert",
                    severity="critical",
                    message=f"Distributed activity detected: Same pattern from {len(ips)} different IPs",
                    raw_data={
                        'pattern': pattern,
                        'source_ips': ips[:10],
                        'ip_count': len(ips)
                    }
                )
                alert.tags = ["distributed_attack", "coordinated_activity", "critical"]
                self.suspicious_sequences.append(alert)
                
    def _extract_cloudtrail_iocs(self, entry: ParsedEntry) -> IOCs:
        """Extract IOCs from CloudTrail event"""
        iocs = IOCs()
        data = entry.parsed_data
        
        # Add source IP
        if data['source_ip'] and data['source_ip'] != 'Unknown':
            iocs.ips.add(data['source_ip'])
            
        # Extract from request parameters
        params = data.get('request_parameters', {})
        params_str = json.dumps(params)
        
        # Look for IPs in parameters
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        for ip in re.findall(ip_pattern, params_str):
            iocs.ips.add(ip)
            
        # Look for domains
        domain_pattern = r'([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.)+[a-zA-Z]{2,}'
        for domain in re.findall(domain_pattern, params_str):
            if not domain.endswith('.amazonaws.com'):
                iocs.domains.add(domain)
                
        # Look for S3 buckets
        bucket_pattern = r's3://([a-z0-9][a-z0-9\-\.]*[a-z0-9])'
        for bucket in re.findall(bucket_pattern, params_str):
            iocs.domains.add(f"{bucket}.s3.amazonaws.com")
            
        # Extract access key IDs (partial)
        if data.get('access_key_id') and data['access_key_id'] != 'Unknown':
            # Only store partial for security
            key_id = data['access_key_id']
            if len(key_id) > 4:
                iocs.file_paths.add(f"AWS_KEY_{key_id[:4]}...{key_id[-4:]}")
                
        return iocs
        
    def _get_top_users(self, limit: int = 10) -> List[Dict]:
        """Get most active users"""
        user_activity = []
        
        for user, events in self.events_by_user.items():
            error_count = sum(1 for e in events if e.parsed_data['error_code'])
            high_risk_count = sum(1 for e in events if e.parsed_data['event_name'] in self.HIGH_RISK_APIS)
            
            user_activity.append({
                'user': user,
                'total_events': len(events),
                'error_events': error_count,
                'high_risk_events': high_risk_count,
                'unique_ips': len(set(e.parsed_data['source_ip'] for e in events)),
                'event_sources': list(set(e.parsed_data['event_source'] for e in events))[:5]
            })
            
        # Sort by total events
        user_activity.sort(key=lambda x: x['total_events'], reverse=True)
        
        return user_activity[:limit]
        
    def _get_top_api_calls(self, limit: int = 20) -> List[Dict]:
        """Get most frequent API calls"""
        api_list = []
        
        for api_name, count in self.api_call_stats.items():
            risk_level = "high" if api_name in self.HIGH_RISK_APIS else "normal"
            
            api_list.append({
                'api_name': api_name,
                'count': count,
                'risk_level': risk_level,
                'risk_description': self.HIGH_RISK_APIS.get(api_name, '')
            })
            
        # Sort by count
        api_list.sort(key=lambda x: x['count'], reverse=True)
        
        return api_list[:limit]
        
    def _generate_risk_summary(self) -> Dict:
        """Generate risk summary"""
        total_events = sum(len(events) for events in self.events_by_user.values())
        
        return {
            'total_events': total_events,
            'high_risk_percentage': (len(self.high_risk_events) / max(total_events, 1)) * 100,
            'error_rate': (len(self.error_events) / max(total_events, 1)) * 100,
            'users_with_errors': sum(1 for events in self.events_by_user.values() 
                                   if any(e.parsed_data['error_code'] for e in events)),
            'suspicious_patterns_detected': len(self.suspicious_sequences),
            'top_risks': self._identify_top_risks()
        }
        
    def _identify_top_risks(self) -> List[str]:
        """Identify top security risks"""
        risks = []
        
        # Check for specific high-risk patterns
        if any('StopLogging' in e.parsed_data['event_name'] for e in self.high_risk_events):
            risks.append("CloudTrail logging disabled")
            
        if any('CreateAccessKey' in e.parsed_data['event_name'] for e in self.high_risk_events):
            risks.append("New access keys created")
            
        if any('privilege_escalation' in s.tags for s in self.suspicious_sequences):
            risks.append("Privilege escalation attempts")
            
        if any('defense_evasion' in s.tags for s in self.suspicious_sequences):
            risks.append("Defense evasion detected")
            
        if len(self.events_by_ip) > 50:
            risks.append("Activity from many different IPs")
            
        return risks
        
    def _get_geographic_summary(self) -> Dict[str, int]:
        """Get geographic distribution of activity"""
        regions = defaultdict(int)
        
        for events in self.events_by_user.values():
            for event in events:
                region = event.parsed_data.get('aws_region', 'unknown')
                regions[region] += 1
                
        return dict(regions)