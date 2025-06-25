"""
Sigma Rule Engine - Detects threats in log data using Sigma rules

This module provides Sigma rule-based analysis for various log formats,
converting Sigma rules to appropriate query formats for detection.
"""

import os
import logging
import asyncio
from typing import Dict, List, Optional, Any, Set, Union
from pathlib import Path
import yaml
import json
import re
from datetime import datetime
from dataclasses import dataclass
from collections import defaultdict
import fnmatch

from parsers.base_parser import ParsedEntry

logger = logging.getLogger(__name__)

@dataclass
class SigmaRule:
    """Represents a parsed Sigma rule"""
    title: str
    id: str
    status: str
    description: str
    references: List[str]
    tags: List[str]
    author: str
    date: str
    modified: str
    logsource: Dict[str, Any]
    detection: Dict[str, Any]
    falsepositives: List[str]
    level: str
    fields: List[str]
    raw_rule: Dict[str, Any]

class SigmaAnalyzer:
    """Sigma rule engine for log analysis"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.rules_path = Path(config.get("rules_path", "rules/sigma"))
        self.rules: Dict[str, SigmaRule] = {}
        self.rules_by_logsource: Dict[str, List[SigmaRule]] = defaultdict(list)
        self.field_mappings = config.get("field_mappings", {})
        self.custom_pipelines = config.get("custom_pipelines", {})
        
        # Performance settings
        self.batch_size = config.get("batch_size", 1000)
        self.parallel_detection = config.get("parallel_detection", True)
        
        # Detection settings
        self.case_insensitive = config.get("case_insensitive", True)
        self.wildcard_support = config.get("wildcard_support", True)
        
        # Load rules
        self._load_rules()
    
    def _load_rules(self):
        """Load Sigma rules from configured paths"""
        rule_count = 0
        
        # Check if rules directory exists
        if not self.rules_path.exists():
            logger.warning(f"Sigma rules directory not found: {self.rules_path}")
            self._create_default_rules()
            return
        
        # Load all YAML/YML rule files
        for rule_file in self.rules_path.rglob("*.yml"):
            self._load_rule_file(rule_file)
            rule_count += 1
            
        for rule_file in self.rules_path.rglob("*.yaml"):
            self._load_rule_file(rule_file)
            rule_count += 1
        
        if rule_count == 0:
            logger.warning("No Sigma rules found, loading defaults")
            self._create_default_rules()
        else:
            logger.info(f"Loaded {len(self.rules)} Sigma rules from {rule_count} files")
            
        # Organize rules by log source
        self._organize_rules_by_logsource()
    
    def _load_rule_file(self, rule_file: Path):
        """Load a single Sigma rule file"""
        try:
            with open(rule_file, 'r', encoding='utf-8') as f:
                # Handle multiple documents in one file
                for doc in yaml.safe_load_all(f):
                    if doc and isinstance(doc, dict):
                        rule = self._parse_sigma_rule(doc)
                        if rule:
                            self.rules[rule.id] = rule
                            
        except Exception as e:
            logger.error(f"Failed to load Sigma rule {rule_file}: {e}")
    
    def _parse_sigma_rule(self, rule_dict: Dict[str, Any]) -> Optional[SigmaRule]:
        """Parse a Sigma rule from dictionary format"""
        try:
            # Extract required fields
            title = rule_dict.get("title", "Untitled")
            rule_id = rule_dict.get("id", "")
            
            # Generate ID if not present
            if not rule_id:
                import hashlib
                rule_id = hashlib.md5(title.encode()).hexdigest()
            
            rule = SigmaRule(
                title=title,
                id=rule_id,
                status=rule_dict.get("status", "experimental"),
                description=rule_dict.get("description", ""),
                references=rule_dict.get("references", []),
                tags=rule_dict.get("tags", []),
                author=rule_dict.get("author", "unknown"),
                date=rule_dict.get("date", ""),
                modified=rule_dict.get("modified", rule_dict.get("date", "")),
                logsource=rule_dict.get("logsource", {}),
                detection=rule_dict.get("detection", {}),
                falsepositives=rule_dict.get("falsepositives", []),
                level=rule_dict.get("level", "medium"),
                fields=rule_dict.get("fields", []),
                raw_rule=rule_dict
            )
            
            return rule
            
        except Exception as e:
            logger.error(f"Failed to parse Sigma rule: {e}")
            return None
    
    def _organize_rules_by_logsource(self):
        """Organize rules by log source for efficient matching"""
        for rule in self.rules.values():
            # Extract log source identifiers
            product = rule.logsource.get("product", "*")
            category = rule.logsource.get("category", "*")
            service = rule.logsource.get("service", "*")
            
            # Create composite keys for matching
            keys = [
                f"{product}:{category}:{service}",
                f"{product}:{category}:*",
                f"{product}:*:{service}",
                f"{product}:*:*",
                f"*:{category}:{service}",
                f"*:{category}:*",
                f"*:*:{service}",
                "*:*:*"
            ]
            
            for key in keys:
                self.rules_by_logsource[key].append(rule)
    
    def _create_default_rules(self):
        """Create default Sigma rules if none are found"""
        default_rules = [
            {
                "title": "Suspicious Process Creation",
                "id": "default-001",
                "status": "stable",
                "description": "Detects suspicious process creation patterns",
                "tags": ["attack.execution", "attack.t1059"],
                "logsource": {
                    "category": "process_creation",
                    "product": "windows"
                },
                "detection": {
                    "selection": {
                        "EventID": 1,
                        "Image|endswith": [
                            "\\powershell.exe",
                            "\\pwsh.exe",
                            "\\cmd.exe"
                        ],
                        "CommandLine|contains": [
                            "-EncodedCommand",
                            "Invoke-Expression",
                            "DownloadString"
                        ]
                    },
                    "condition": "selection"
                },
                "level": "high"
            },
            {
                "title": "Failed Logon Attempts",
                "id": "default-002",
                "status": "stable",
                "description": "Multiple failed logon attempts",
                "tags": ["attack.credential_access", "attack.t1110"],
                "logsource": {
                    "product": "windows",
                    "service": "security"
                },
                "detection": {
                    "selection": {
                        "EventID": [4625, 4771],
                        "Status": ["0xC000006D", "0xC0000064", "0xC0000234"]
                    },
                    "timeframe": "5m",
                    "condition": "selection | count() > 5"
                },
                "level": "medium"
            },
            {
                "title": "Web Shell Activity",
                "id": "default-003",
                "status": "stable",
                "description": "Detects potential web shell activity",
                "tags": ["attack.persistence", "attack.t1505.003"],
                "logsource": {
                    "category": "webserver"
                },
                "detection": {
                    "selection": {
                        "cs-method": "POST",
                        "c-uri|contains": [
                            ".jsp",
                            ".php",
                            ".asp",
                            ".aspx"
                        ],
                        "cs-uri-query|contains": [
                            "cmd=",
                            "exec=",
                            "command=",
                            "shell="
                        ]
                    },
                    "condition": "selection"
                },
                "level": "critical"
            },
            {
                "title": "Linux Privilege Escalation",
                "id": "default-004",
                "status": "experimental",
                "description": "Detects potential privilege escalation on Linux",
                "tags": ["attack.privilege_escalation", "attack.t1068"],
                "logsource": {
                    "product": "linux",
                    "service": "auditd"
                },
                "detection": {
                    "selection1": {
                        "type": "EXECVE",
                        "a0": ["/usr/bin/sudo", "/bin/su"]
                    },
                    "selection2": {
                        "type": "SYSCALL",
                        "syscall": ["setuid", "setgid"],
                        "success": "yes"
                    },
                    "condition": "selection1 or selection2"
                },
                "level": "high"
            },
            {
                "title": "Network Scanning Activity",
                "id": "default-005",
                "status": "stable",
                "description": "Detects network scanning patterns",
                "tags": ["attack.discovery", "attack.t1046"],
                "logsource": {
                    "category": "firewall"
                },
                "detection": {
                    "selection": {
                        "action": ["drop", "deny"],
                        "dst_port": {"min": 1, "max": 1024}
                    },
                    "timeframe": "1m",
                    "condition": "selection | count(by dst_ip) > 50"
                },
                "level": "medium"
            }
        ]
        
        # Load default rules
        for rule_dict in default_rules:
            rule = self._parse_sigma_rule(rule_dict)
            if rule:
                self.rules[rule.id] = rule
        
        self._organize_rules_by_logsource()
        logger.info(f"Created {len(default_rules)} default Sigma rules")
    
    async def analyze_entries(self, entries: List[ParsedEntry], 
                            log_type: str) -> List[Dict[str, Any]]:
        """
        Analyze log entries using Sigma rules
        
        Args:
            entries: Parsed log entries
            log_type: Type of log (e.g., 'syslog', 'windows_event', etc.)
            
        Returns:
            List of Sigma rule matches
        """
        if not entries:
            return []
        
        # Determine applicable rules based on log type
        applicable_rules = self._get_applicable_rules(log_type, entries)
        
        if not applicable_rules:
            logger.debug(f"No applicable Sigma rules for log type: {log_type}")
            return []
        
        logger.info(f"Checking {len(entries)} entries against {len(applicable_rules)} Sigma rules")
        
        # Process entries in batches
        all_matches = []
        
        if self.parallel_detection and len(entries) > self.batch_size:
            # Process in parallel for large datasets
            tasks = []
            for i in range(0, len(entries), self.batch_size):
                batch = entries[i:i + self.batch_size]
                task = self._detect_batch(batch, applicable_rules, log_type)
                tasks.append(task)
            
            batch_results = await asyncio.gather(*tasks)
            for matches in batch_results:
                all_matches.extend(matches)
        else:
            # Process sequentially
            all_matches = await self._detect_batch(entries, applicable_rules, log_type)
        
        # Deduplicate and enrich matches
        return self._process_matches(all_matches)
    
    def _get_applicable_rules(self, log_type: str, 
                             entries: List[ParsedEntry]) -> List[SigmaRule]:
        """Determine which rules apply to the given log type"""
        applicable = []
        
        # Map log types to Sigma log sources
        log_type_mapping = {
            "syslog": ("linux", "syslog", "*"),
            "windows_event": ("windows", "*", "*"),
            "apache": ("*", "webserver", "apache"),
            "nginx": ("*", "webserver", "nginx"),
            "firewall": ("*", "firewall", "*"),
            "aws_cloudtrail": ("aws", "cloudtrail", "*"),
            "pcap": ("*", "network", "*"),
            "netflow": ("*", "netflow", "*")
        }
        
        # Get mapped values or use wildcards
        product, category, service = log_type_mapping.get(log_type, ("*", "*", "*"))
        
        # Also check entries for more specific categorization
        if entries and len(entries) > 0:
            sample_entry = entries[0]
            # Windows event log detection
            if hasattr(sample_entry, 'additional') and sample_entry.additional.get("EventID"):
                product = "windows"
                if sample_entry.additional.get("Channel") == "Security":
                    service = "security"
                elif sample_entry.additional.get("Channel") == "System":
                    service = "system"
        
        # Find matching rules
        key = f"{product}:{category}:{service}"
        applicable.extend(self.rules_by_logsource.get(key, []))
        
        # Also check wildcard matches
        wildcard_keys = [
            f"{product}:{category}:*",
            f"{product}:*:{service}",
            f"{product}:*:*",
            f"*:{category}:*",
            f"*:*:{service}"
        ]
        
        for wkey in wildcard_keys:
            if wkey != key:  # Avoid duplicates
                applicable.extend(self.rules_by_logsource.get(wkey, []))
        
        # Remove duplicates
        seen = set()
        unique_rules = []
        for rule in applicable:
            if rule.id not in seen:
                seen.add(rule.id)
                unique_rules.append(rule)
        
        return unique_rules
    
    async def _detect_batch(self, entries: List[ParsedEntry], 
                          rules: List[SigmaRule], log_type: str) -> List[Dict[str, Any]]:
        """Detect rule matches in a batch of entries"""
        matches = []
        
        for rule in rules:
            try:
                # Check each entry against the rule
                rule_matches = self._check_rule(entries, rule, log_type)
                
                if rule_matches:
                    for match in rule_matches:
                        matches.append({
                            "rule_id": rule.id,
                            "title": rule.title,
                            "description": rule.description,
                            "level": rule.level,
                            "tags": rule.tags,
                            "matched_entries": match["entries"],
                            "matched_fields": match["fields"],
                            "confidence": match["confidence"],
                            "attack_id": self._extract_attack_id(rule.tags),
                            "timestamp": datetime.utcnow().isoformat()
                        })
                        
            except Exception as e:
                logger.error(f"Error checking rule {rule.id}: {e}")
        
        return matches
    
    def _check_rule(self, entries: List[ParsedEntry], rule: SigmaRule, 
                   log_type: str) -> List[Dict[str, Any]]:
        """Check if entries match a Sigma rule"""
        detection = rule.detection
        condition = detection.get("condition", "")
        
        if not condition:
            return []
        
        # Convert entries to field dictionaries
        entry_dicts = []
        for entry in entries:
            entry_dict = self._entry_to_dict(entry, log_type)
            if entry_dict:
                entry_dicts.append((entry, entry_dict))
        
        # Parse and evaluate condition
        matches = []
        
        # Handle simple conditions
        if condition == "selection":
            selection = detection.get("selection", {})
            matched = self._match_selection(entry_dicts, selection)
            if matched:
                matches.append({
                    "entries": [e[0] for e in matched],
                    "fields": list(selection.keys()),
                    "confidence": 0.9
                })
                
        elif condition.startswith("selection"):
            # Handle complex conditions (AND, OR, NOT)
            matched = self._evaluate_complex_condition(entry_dicts, detection, condition)
            if matched:
                matches.append({
                    "entries": [e[0] for e in matched],
                    "fields": self._extract_fields_from_detection(detection),
                    "confidence": 0.8
                })
        
        # Handle aggregation conditions (count, sum, etc.)
        elif "count(" in condition or "sum(" in condition:
            matched = self._evaluate_aggregation(entry_dicts, detection, condition)
            if matched:
                matches.append({
                    "entries": [e[0] for e in matched],
                    "fields": self._extract_fields_from_detection(detection),
                    "confidence": 0.85
                })
        
        return matches
    
    def _entry_to_dict(self, entry: ParsedEntry, log_type: str) -> Dict[str, Any]:
        """Convert ParsedEntry to dictionary for Sigma matching"""
        # Start with base fields
        entry_dict = {
            "message": entry.message,
            "severity": entry.severity,
            "timestamp": entry.timestamp.isoformat() if entry.timestamp else ""
        }
        
        # Add additional fields
        if entry.additional:
            entry_dict.update(entry.additional)
        
        # Apply field mappings for the log type
        if log_type in self.field_mappings:
            mappings = self.field_mappings[log_type]
            for sigma_field, entry_field in mappings.items():
                if entry_field in entry_dict:
                    entry_dict[sigma_field] = entry_dict[entry_field]
        
        return entry_dict
    
    def _match_selection(self, entry_dicts: List[tuple], 
                        selection: Dict[str, Any]) -> List[tuple]:
        """Match entries against a selection criteria"""
        matched = []
        
        for entry, entry_dict in entry_dicts:
            if self._match_single_entry(entry_dict, selection):
                matched.append((entry, entry_dict))
        
        return matched
    
    def _match_single_entry(self, entry_dict: Dict[str, Any], 
                           criteria: Dict[str, Any]) -> bool:
        """Check if a single entry matches selection criteria"""
        for field, expected in criteria.items():
            # Handle field modifiers
            if "|" in field:
                field_name, modifier = field.split("|", 1)
            else:
                field_name = field
                modifier = None
            
            # Get actual value
            actual = entry_dict.get(field_name)
            if actual is None:
                return False
            
            # Apply modifier and check match
            if not self._check_field_match(actual, expected, modifier):
                return False
        
        return True
    
    def _check_field_match(self, actual: Any, expected: Any, 
                          modifier: Optional[str]) -> bool:
        """Check if field value matches expected value with modifier"""
        # Convert to strings for comparison
        actual_str = str(actual).lower() if self.case_insensitive else str(actual)
        
        # Handle list of expected values
        if isinstance(expected, list):
            return any(self._check_field_match(actual, e, modifier) for e in expected)
        
        expected_str = str(expected).lower() if self.case_insensitive else str(expected)
        
        # Apply modifiers
        if modifier == "contains":
            return expected_str in actual_str
        elif modifier == "startswith":
            return actual_str.startswith(expected_str)
        elif modifier == "endswith":
            return actual_str.endswith(expected_str)
        elif modifier == "regex":
            try:
                return bool(re.search(expected_str, actual_str))
            except:
                return False
        elif modifier == "gt":
            try:
                return float(actual) > float(expected)
            except:
                return False
        elif modifier == "lt":
            try:
                return float(actual) < float(expected)
            except:
                return False
        elif modifier == "gte":
            try:
                return float(actual) >= float(expected)
            except:
                return False
        elif modifier == "lte":
            try:
                return float(actual) <= float(expected)
            except:
                return False
        else:
            # No modifier - exact match or wildcard
            if self.wildcard_support and ("*" in expected_str or "?" in expected_str):
                return fnmatch.fnmatch(actual_str, expected_str)
            else:
                return actual_str == expected_str
    
    def _evaluate_complex_condition(self, entry_dicts: List[tuple], 
                                  detection: Dict[str, Any], 
                                  condition: str) -> List[tuple]:
        """Evaluate complex conditions with AND, OR, NOT"""
        # Parse condition
        condition_lower = condition.lower()
        
        # Extract selection names
        selections = {}
        for key, value in detection.items():
            if key.startswith("selection") and key != "condition":
                selections[key] = value
        
        # Simple AND
        if " and " in condition_lower:
            parts = condition_lower.split(" and ")
            results = []
            
            for part in parts:
                part = part.strip()
                if part in selections:
                    matched = self._match_selection(entry_dicts, selections[part])
                    if not matched:
                        return []
                    results.append(set(id(e[0]) for e in matched))
            
            # Intersection of all results
            if results:
                common_ids = set.intersection(*results)
                return [(e, d) for e, d in entry_dicts if id(e) in common_ids]
        
        # Simple OR
        elif " or " in condition_lower:
            parts = condition_lower.split(" or ")
            all_matched = []
            
            for part in parts:
                part = part.strip()
                if part in selections:
                    matched = self._match_selection(entry_dicts, selections[part])
                    all_matched.extend(matched)
            
            # Remove duplicates
            seen = set()
            unique = []
            for e, d in all_matched:
                if id(e) not in seen:
                    seen.add(id(e))
                    unique.append((e, d))
            
            return unique
        
        # NOT
        elif condition_lower.startswith("not "):
            selection_name = condition_lower[4:].strip()
            if selection_name in selections:
                matched = self._match_selection(entry_dicts, selections[selection_name])
                matched_ids = set(id(e[0]) for e in matched)
                return [(e, d) for e, d in entry_dicts if id(e) not in matched_ids]
        
        # Single selection
        elif condition in selections:
            return self._match_selection(entry_dicts, selections[condition])
        
        return []
    
    def _evaluate_aggregation(self, entry_dicts: List[tuple], 
                            detection: Dict[str, Any], 
                            condition: str) -> List[tuple]:
        """Evaluate aggregation conditions (count, sum, etc.)"""
        # Extract aggregation details
        import re
        
        # Match patterns like "selection | count() > 5"
        pattern = r'(\w+)\s*\|\s*(count|sum|avg|min|max)\((.*?)\)\s*([><=]+)\s*(\d+)'
        match = re.search(pattern, condition)
        
        if not match:
            return []
        
        selection_name = match.group(1)
        agg_func = match.group(2)
        agg_field = match.group(3).strip() if match.group(3) else None
        operator = match.group(4)
        threshold = int(match.group(5))
        
        # Get matching entries
        if selection_name not in detection:
            return []
        
        matched = self._match_selection(entry_dicts, detection[selection_name])
        
        if not matched:
            return []
        
        # Apply aggregation
        if agg_func == "count":
            value = len(matched)
        elif agg_func == "sum" and agg_field:
            value = sum(float(e[1].get(agg_field, 0)) for e in matched)
        elif agg_func == "avg" and agg_field:
            values = [float(e[1].get(agg_field, 0)) for e in matched]
            value = sum(values) / len(values) if values else 0
        elif agg_func == "min" and agg_field:
            values = [float(e[1].get(agg_field, 0)) for e in matched]
            value = min(values) if values else 0
        elif agg_func == "max" and agg_field:
            values = [float(e[1].get(agg_field, 0)) for e in matched]
            value = max(values) if values else 0
        else:
            return []
        
        # Check threshold
        if operator == ">":
            meets_threshold = value > threshold
        elif operator == ">=":
            meets_threshold = value >= threshold
        elif operator == "<":
            meets_threshold = value < threshold
        elif operator == "<=":
            meets_threshold = value <= threshold
        elif operator == "=":
            meets_threshold = value == threshold
        else:
            meets_threshold = False
        
        return matched if meets_threshold else []
    
    def _extract_fields_from_detection(self, detection: Dict[str, Any]) -> List[str]:
        """Extract all field names from detection logic"""
        fields = set()
        
        for key, value in detection.items():
            if key != "condition" and isinstance(value, dict):
                for field in value.keys():
                    # Remove modifiers
                    field_name = field.split("|")[0]
                    fields.add(field_name)
        
        return list(fields)
    
    def _extract_attack_id(self, tags: List[str]) -> str:
        """Extract MITRE ATT&CK ID from tags"""
        for tag in tags:
            if tag.startswith("attack.t"):
                return tag.replace("attack.", "").upper()
        return ""
    
    def _process_matches(self, matches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process and deduplicate matches"""
        # Group matches by rule
        rule_groups = defaultdict(list)
        
        for match in matches:
            key = match["rule_id"]
            rule_groups[key].append(match)
        
        # Consolidate matches for each rule
        processed = []
        
        for rule_id, rule_matches in rule_groups.items():
            if not rule_matches:
                continue
            
            # Get unique entries
            all_entries = []
            for match in rule_matches:
                all_entries.extend(match["matched_entries"])
            
            # Remove duplicates while preserving order
            seen = set()
            unique_entries = []
            for entry in all_entries:
                if id(entry) not in seen:
                    seen.add(id(entry))
                    unique_entries.append(entry)
            
            # Create consolidated match
            consolidated = rule_matches[0].copy()
            consolidated["matched_entries"] = unique_entries
            consolidated["match_count"] = len(unique_entries)
            
            # Calculate overall confidence
            confidences = [m["confidence"] for m in rule_matches]
            consolidated["confidence"] = max(confidences)
            
            processed.append(consolidated)
        
        return processed
    
    async def test_rule(self, rule_content: str, test_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Test a Sigma rule against sample data"""
        try:
            # Parse rule
            rule_dict = yaml.safe_load(rule_content)
            rule = self._parse_sigma_rule(rule_dict)
            
            if not rule:
                return {"success": False, "error": "Invalid rule format"}
            
            # Convert test data to ParsedEntry format
            entries = []
            for data in test_data:
                entry = ParsedEntry(
                    timestamp=datetime.fromisoformat(data.get("timestamp", datetime.utcnow().isoformat())),
                    message=data.get("message", ""),
                    severity=data.get("severity", "info"),
                    additional=data
                )
                entries.append(entry)
            
            # Test rule
            matches = self._check_rule(entries, rule, "test")
            
            return {
                "success": True,
                "matches": len(matches),
                "matched_entries": [
                    {
                        "message": e.message,
                        "fields": m["fields"]
                    }
                    for m in matches
                    for e in m["entries"][:5]  # Limit to 5 examples
                ]
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_rule_stats(self) -> Dict[str, Any]:
        """Get statistics about loaded Sigma rules"""
        stats = {
            "total_rules": len(self.rules),
            "rules_by_level": defaultdict(int),
            "rules_by_status": defaultdict(int),
            "rules_by_logsource": defaultdict(int),
            "mitre_coverage": set()
        }
        
        for rule in self.rules.values():
            # Level distribution
            stats["rules_by_level"][rule.level] += 1
            
            # Status distribution
            stats["rules_by_status"][rule.status] += 1
            
            # Log source distribution
            product = rule.logsource.get("product", "unknown")
            stats["rules_by_logsource"][product] += 1
            
            # MITRE coverage
            for tag in rule.tags:
                if tag.startswith("attack.t"):
                    technique = tag.replace("attack.", "").upper()
                    stats["mitre_coverage"].add(technique)
        
        stats["rules_by_level"] = dict(stats["rules_by_level"])
        stats["rules_by_status"] = dict(stats["rules_by_status"])
        stats["rules_by_logsource"] = dict(stats["rules_by_logsource"])
        stats["mitre_coverage"] = list(stats["mitre_coverage"])
        
        return stats