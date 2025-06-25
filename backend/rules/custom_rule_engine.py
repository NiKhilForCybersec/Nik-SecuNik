# backend/rules/custom_rule_engine.py
"""
Custom Rule Engine - Executes custom detection rules
Provides a flexible rule execution framework for non-YARA/Sigma rules
"""

import ast
import re
import json
import operator
from typing import Dict, List, Any, Optional, Callable, Union, Set
from datetime import datetime, timedelta
from collections import defaultdict
import ipaddress
import fnmatch
from dataclasses import dataclass
from enum import Enum

from parsers import ParseResult

class RuleOperator(Enum):
    """Supported rule operators"""
    # Comparison
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    GREATER_EQUAL = "greater_equal"
    LESS_EQUAL = "less_equal"
    
    # String operations
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    MATCHES = "matches"  # Regex
    
    # List operations
    IN = "in"
    NOT_IN = "not_in"
    ANY_OF = "any_of"
    ALL_OF = "all_of"
    
    # Logical
    AND = "and"
    OR = "or"
    NOT = "not"
    
    # Special
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"
    IS_NULL = "is_null"
    IS_NOT_NULL = "is_not_null"
    
    # Network
    IN_CIDR = "in_cidr"
    IS_PRIVATE_IP = "is_private_ip"
    IS_PUBLIC_IP = "is_public_ip"
    
    # Time
    WITHIN_LAST = "within_last"
    OLDER_THAN = "older_than"
    BETWEEN_TIMES = "between_times"

@dataclass
class RuleCondition:
    """Single rule condition"""
    field: str
    operator: RuleOperator
    value: Any
    case_sensitive: bool = False
    negate: bool = False

@dataclass
class RuleAction:
    """Action to take when rule matches"""
    type: str  # alert, tag, extract, enrich
    parameters: Dict[str, Any]

@dataclass
class CustomRule:
    """Custom rule definition"""
    id: str
    name: str
    description: str
    conditions: Union[RuleCondition, Dict[str, Any]]  # Single condition or logic tree
    actions: List[RuleAction]
    enabled: bool = True
    severity: str = "medium"
    tags: List[str] = None
    metadata: Dict[str, Any] = None

class CustomRuleEngine:
    """Executes custom detection rules"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.rules: Dict[str, CustomRule] = {}
        self.field_extractors: Dict[str, Callable] = {}
        self.action_handlers: Dict[str, Callable] = {}
        self._setup_default_extractors()
        self._setup_default_handlers()
        
    def _setup_default_extractors(self):
        """Setup default field extractors"""
        # Basic extractors
        self.field_extractors['event_type'] = lambda e: e.get('event_type')
        self.field_extractors['timestamp'] = lambda e: e.get('timestamp')
        self.field_extractors['source'] = lambda e: e.get('source')
        self.field_extractors['destination'] = lambda e: e.get('destination')
        self.field_extractors['user'] = lambda e: e.get('user', e.get('username'))
        
        # Nested field extractor
        self.field_extractors['_nested'] = self._extract_nested_field
        
        # Special extractors
        self.field_extractors['event_count'] = lambda e: e.get('_count', 1)
        self.field_extractors['event_size'] = lambda e: len(json.dumps(e))
        
    def _setup_default_handlers(self):
        """Setup default action handlers"""
        self.action_handlers['alert'] = self._handle_alert_action
        self.action_handlers['tag'] = self._handle_tag_action
        self.action_handlers['extract'] = self._handle_extract_action
        self.action_handlers['enrich'] = self._handle_enrich_action
        self.action_handlers['aggregate'] = self._handle_aggregate_action
        
    def add_rule(self, rule: CustomRule):
        """Add rule to engine"""
        self.rules[rule.id] = rule
        
    def remove_rule(self, rule_id: str):
        """Remove rule from engine"""
        if rule_id in self.rules:
            del self.rules[rule_id]
            
    def add_field_extractor(self, name: str, extractor: Callable):
        """Add custom field extractor"""
        self.field_extractors[name] = extractor
        
    def add_action_handler(self, name: str, handler: Callable):
        """Add custom action handler"""
        self.action_handlers[name] = handler
        
    async def analyze(
        self,
        parse_result: ParseResult,
        rule_ids: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Analyze events with custom rules"""
        results = {
            'matches': [],
            'total_matches': 0,
            'rules_evaluated': 0,
            'alerts': [],
            'tags': set(),
            'enrichments': {},
            'aggregations': {},
            'execution_time': 0
        }
        
        start_time = datetime.now()
        
        # Select rules to run
        rules_to_run = []
        if rule_ids:
            rules_to_run = [self.rules[rid] for rid in rule_ids if rid in self.rules]
        else:
            rules_to_run = [r for r in self.rules.values() if r.enabled]
            
        results['rules_evaluated'] = len(rules_to_run)
        
        # Process each event
        for event in parse_result.events:
            for rule in rules_to_run:
                try:
                    if self._evaluate_rule(rule, event):
                        # Rule matched
                        match_result = {
                            'rule_id': rule.id,
                            'rule_name': rule.name,
                            'severity': rule.severity,
                            'event': event,
                            'timestamp': datetime.now(),
                            'actions_executed': []
                        }
                        
                        # Execute actions
                        for action in rule.actions:
                            action_result = await self._execute_action(
                                action, event, rule
                            )
                            match_result['actions_executed'].append({
                                'type': action.type,
                                'result': action_result
                            })
                            
                            # Collect results
                            if action.type == 'alert':
                                results['alerts'].append(action_result)
                            elif action.type == 'tag':
                                results['tags'].update(action_result)
                            elif action.type == 'enrich':
                                event.update(action_result)
                            elif action.type == 'aggregate':
                                self._update_aggregation(
                                    results['aggregations'],
                                    action_result
                                )
                                
                        results['matches'].append(match_result)
                        results['total_matches'] += 1
                        
                except Exception as e:
                    # Log error but continue
                    print(f"Error evaluating rule {rule.id}: {str(e)}")
                    
        # Convert tags set to list
        results['tags'] = list(results['tags'])
        
        # Calculate execution time
        results['execution_time'] = (datetime.now() - start_time).total_seconds()
        
        return results
        
    def _evaluate_rule(self, rule: CustomRule, event: Dict[str, Any]) -> bool:
        """Evaluate if rule matches event"""
        if isinstance(rule.conditions, RuleCondition):
            # Single condition
            return self._evaluate_condition(rule.conditions, event)
        else:
            # Complex logic tree
            return self._evaluate_logic_tree(rule.conditions, event)
            
    def _evaluate_condition(
        self,
        condition: RuleCondition,
        event: Dict[str, Any]
    ) -> bool:
        """Evaluate single condition"""
        # Extract field value
        field_value = self._extract_field_value(condition.field, event)
        
        # Get operator function
        op_func = self._get_operator_function(condition.operator)
        
        # Evaluate
        try:
            result = op_func(field_value, condition.value, condition)
            return not result if condition.negate else result
        except Exception:
            return False
            
    def _evaluate_logic_tree(
        self,
        logic_tree: Dict[str, Any],
        event: Dict[str, Any]
    ) -> bool:
        """Evaluate complex logic tree"""
        operator = logic_tree.get('operator', 'and').lower()
        conditions = logic_tree.get('conditions', [])
        
        if operator == 'and':
            return all(
                self._evaluate_logic_node(cond, event)
                for cond in conditions
            )
        elif operator == 'or':
            return any(
                self._evaluate_logic_node(cond, event)
                for cond in conditions
            )
        elif operator == 'not':
            if conditions:
                return not self._evaluate_logic_node(conditions[0], event)
            return True
        else:
            # Unknown operator, default to AND
            return all(
                self._evaluate_logic_node(cond, event)
                for cond in conditions
            )
            
    def _evaluate_logic_node(
        self,
        node: Union[Dict[str, Any], RuleCondition],
        event: Dict[str, Any]
    ) -> bool:
        """Evaluate single node in logic tree"""
        if isinstance(node, RuleCondition):
            return self._evaluate_condition(node, event)
        elif isinstance(node, dict):
            if 'operator' in node:
                # Nested logic tree
                return self._evaluate_logic_tree(node, event)
            else:
                # Convert to condition
                condition = RuleCondition(
                    field=node.get('field', ''),
                    operator=RuleOperator(node.get('operator', 'equals')),
                    value=node.get('value'),
                    case_sensitive=node.get('case_sensitive', False),
                    negate=node.get('negate', False)
                )
                return self._evaluate_condition(condition, event)
        return False
        
    def _extract_field_value(self, field_path: str, event: Dict[str, Any]) -> Any:
        """Extract field value from event"""
        # Check for custom extractor
        if field_path in self.field_extractors:
            return self.field_extractors[field_path](event)
            
        # Handle nested fields (e.g., "data.user.name")
        if '.' in field_path:
            return self._extract_nested_field(field_path, event)
            
        # Direct field access
        return event.get(field_path)
        
    def _extract_nested_field(self, field_path: str, event: Dict[str, Any]) -> Any:
        """Extract nested field value"""
        parts = field_path.split('.')
        value = event
        
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                return None
                
        return value
        
    def _get_operator_function(self, operator: RuleOperator) -> Callable:
        """Get function for operator"""
        operator_map = {
            # Comparison
            RuleOperator.EQUALS: self._op_equals,
            RuleOperator.NOT_EQUALS: self._op_not_equals,
            RuleOperator.GREATER_THAN: self._op_greater_than,
            RuleOperator.LESS_THAN: self._op_less_than,
            RuleOperator.GREATER_EQUAL: self._op_greater_equal,
            RuleOperator.LESS_EQUAL: self._op_less_equal,
            
            # String
            RuleOperator.CONTAINS: self._op_contains,
            RuleOperator.NOT_CONTAINS: self._op_not_contains,
            RuleOperator.STARTS_WITH: self._op_starts_with,
            RuleOperator.ENDS_WITH: self._op_ends_with,
            RuleOperator.MATCHES: self._op_matches,
            
            # List
            RuleOperator.IN: self._op_in,
            RuleOperator.NOT_IN: self._op_not_in,
            RuleOperator.ANY_OF: self._op_any_of,
            RuleOperator.ALL_OF: self._op_all_of,
            
            # Special
            RuleOperator.EXISTS: self._op_exists,
            RuleOperator.NOT_EXISTS: self._op_not_exists,
            RuleOperator.IS_NULL: self._op_is_null,
            RuleOperator.IS_NOT_NULL: self._op_is_not_null,
            
            # Network
            RuleOperator.IN_CIDR: self._op_in_cidr,
            RuleOperator.IS_PRIVATE_IP: self._op_is_private_ip,
            RuleOperator.IS_PUBLIC_IP: self._op_is_public_ip,
            
            # Time
            RuleOperator.WITHIN_LAST: self._op_within_last,
            RuleOperator.OLDER_THAN: self._op_older_than,
            RuleOperator.BETWEEN_TIMES: self._op_between_times,
        }
        
        return operator_map.get(operator, self._op_equals)
        
    # Operator implementations
    def _op_equals(self, field_value: Any, rule_value: Any, condition: RuleCondition) -> bool:
        """Equals operator"""
        if field_value is None:
            return False
            
        if isinstance(field_value, str) and isinstance(rule_value, str):
            if condition.case_sensitive:
                return field_value == rule_value
            else:
                return field_value.lower() == rule_value.lower()
        else:
            return field_value == rule_value
            
    def _op_not_equals(self, field_value: Any, rule_value: Any, condition: RuleCondition) -> bool:
        """Not equals operator"""
        return not self._op_equals(field_value, rule_value, condition)
        
    def _op_greater_than(self, field_value: Any, rule_value: Any, condition: RuleCondition) -> bool:
        """Greater than operator"""
        try:
            return float(field_value) > float(rule_value)
        except (TypeError, ValueError):
            return False
            
    def _op_less_than(self, field_value: Any, rule_value: Any, condition: RuleCondition) -> bool:
        """Less than operator"""
        try:
            return float(field_value) < float(rule_value)
        except (TypeError, ValueError):
            return False
            
    def _op_greater_equal(self, field_value: Any, rule_value: Any, condition: RuleCondition) -> bool:
        """Greater or equal operator"""
        try:
            return float(field_value) >= float(rule_value)
        except (TypeError, ValueError):
            return False
            
    def _op_less_equal(self, field_value: Any, rule_value: Any, condition: RuleCondition) -> bool:
        """Less or equal operator"""
        try:
            return float(field_value) <= float(rule_value)
        except (TypeError, ValueError):
            return False
            
    def _op_contains(self, field_value: Any, rule_value: Any, condition: RuleCondition) -> bool:
        """Contains operator"""
        if field_value is None:
            return False
            
        field_str = str(field_value)
        rule_str = str(rule_value)
        
        if not condition.case_sensitive:
            field_str = field_str.lower()
            rule_str = rule_str.lower()
            
        return rule_str in field_str
        
    def _op_not_contains(self, field_value: Any, rule_value: Any, condition: RuleCondition) -> bool:
        """Not contains operator"""
        return not self._op_contains(field_value, rule_value, condition)
        
    def _op_starts_with(self, field_value: Any, rule_value: Any, condition: RuleCondition) -> bool:
        """Starts with operator"""
        if field_value is None:
            return False
            
        field_str = str(field_value)
        rule_str = str(rule_value)
        
        if not condition.case_sensitive:
            field_str = field_str.lower()
            rule_str = rule_str.lower()
            
        return field_str.startswith(rule_str)
        
    def _op_ends_with(self, field_value: Any, rule_value: Any, condition: RuleCondition) -> bool:
        """Ends with operator"""
        if field_value is None:
            return False
            
        field_str = str(field_value)
        rule_str = str(rule_value)
        
        if not condition.case_sensitive:
            field_str = field_str.lower()
            rule_str = rule_str.lower()
            
        return field_str.endswith(rule_str)
        
    def _op_matches(self, field_value: Any, rule_value: Any, condition: RuleCondition) -> bool:
        """Regex match operator"""
        if field_value is None:
            return False
            
        try:
            flags = 0 if condition.case_sensitive else re.IGNORECASE
            pattern = re.compile(rule_value, flags)
            return bool(pattern.search(str(field_value)))
        except re.error:
            return False
            
    def _op_in(self, field_value: Any, rule_value: Any, condition: RuleCondition) -> bool:
        """In operator"""
        if field_value is None:
            return False
            
        if not isinstance(rule_value, (list, tuple, set)):
            rule_value = [rule_value]
            
        if condition.case_sensitive or not isinstance(field_value, str):
            return field_value in rule_value
        else:
            field_lower = field_value.lower()
            return any(
                field_lower == str(v).lower()
                for v in rule_value
            )
            
    def _op_not_in(self, field_value: Any, rule_value: Any, condition: RuleCondition) -> bool:
        """Not in operator"""
        return not self._op_in(field_value, rule_value, condition)
        
    def _op_any_of(self, field_value: Any, rule_value: Any, condition: RuleCondition) -> bool:
        """Any of operator (field is list)"""
        if not isinstance(field_value, (list, tuple, set)):
            return False
            
        if not isinstance(rule_value, (list, tuple, set)):
            rule_value = [rule_value]
            
        for field_item in field_value:
            if self._op_in(field_item, rule_value, condition):
                return True
                
        return False
        
    def _op_all_of(self, field_value: Any, rule_value: Any, condition: RuleCondition) -> bool:
        """All of operator (field is list)"""
        if not isinstance(field_value, (list, tuple, set)):
            return False
            
        if not isinstance(rule_value, (list, tuple, set)):
            rule_value = [rule_value]
            
        for rule_item in rule_value:
            if not self._op_in(rule_item, field_value, condition):
                return False
                
        return True
        
    def _op_exists(self, field_value: Any, rule_value: Any, condition: RuleCondition) -> bool:
        """Exists operator"""
        return field_value is not None
        
    def _op_not_exists(self, field_value: Any, rule_value: Any, condition: RuleCondition) -> bool:
        """Not exists operator"""
        return field_value is None
        
    def _op_is_null(self, field_value: Any, rule_value: Any, condition: RuleCondition) -> bool:
        """Is null operator"""
        return field_value is None or field_value == ""
        
    def _op_is_not_null(self, field_value: Any, rule_value: Any, condition: RuleCondition) -> bool:
        """Is not null operator"""
        return field_value is not None and field_value != ""
        
    def _op_in_cidr(self, field_value: Any, rule_value: Any, condition: RuleCondition) -> bool:
        """IP in CIDR operator"""
        if field_value is None:
            return False
            
        try:
            ip = ipaddress.ip_address(field_value)
            network = ipaddress.ip_network(rule_value)
            return ip in network
        except (ValueError, TypeError):
            return False
            
    def _op_is_private_ip(self, field_value: Any, rule_value: Any, condition: RuleCondition) -> bool:
        """Is private IP operator"""
        if field_value is None:
            return False
            
        try:
            ip = ipaddress.ip_address(field_value)
            return ip.is_private
        except (ValueError, TypeError):
            return False
            
    def _op_is_public_ip(self, field_value: Any, rule_value: Any, condition: RuleCondition) -> bool:
        """Is public IP operator"""
        if field_value is None:
            return False
            
        try:
            ip = ipaddress.ip_address(field_value)
            return not ip.is_private and not ip.is_loopback
        except (ValueError, TypeError):
            return False
            
    def _op_within_last(self, field_value: Any, rule_value: Any, condition: RuleCondition) -> bool:
        """Within last time period operator"""
        if field_value is None:
            return False
            
        try:
            # Parse field value as datetime
            if isinstance(field_value, str):
                field_dt = datetime.fromisoformat(field_value)
            elif isinstance(field_value, datetime):
                field_dt = field_value
            else:
                return False
                
            # Parse duration (e.g., "1h", "30m", "7d")
            duration = self._parse_duration(rule_value)
            if not duration:
                return False
                
            # Check if within duration
            now = datetime.now()
            return now - field_dt <= duration
            
        except (ValueError, TypeError):
            return False
            
    def _op_older_than(self, field_value: Any, rule_value: Any, condition: RuleCondition) -> bool:
        """Older than time period operator"""
        if field_value is None:
            return False
            
        try:
            # Parse field value as datetime
            if isinstance(field_value, str):
                field_dt = datetime.fromisoformat(field_value)
            elif isinstance(field_value, datetime):
                field_dt = field_value
            else:
                return False
                
            # Parse duration
            duration = self._parse_duration(rule_value)
            if not duration:
                return False
                
            # Check if older than duration
            now = datetime.now()
            return now - field_dt > duration
            
        except (ValueError, TypeError):
            return False
            
    def _op_between_times(self, field_value: Any, rule_value: Any, condition: RuleCondition) -> bool:
        """Between times operator"""
        if field_value is None or not isinstance(rule_value, dict):
            return False
            
        try:
            # Parse field value as datetime
            if isinstance(field_value, str):
                field_dt = datetime.fromisoformat(field_value)
            elif isinstance(field_value, datetime):
                field_dt = field_value
            else:
                return False
                
            # Get start and end times
            start = rule_value.get('start')
            end = rule_value.get('end')
            
            if isinstance(start, str):
                start = datetime.fromisoformat(start)
            if isinstance(end, str):
                end = datetime.fromisoformat(end)
                
            # Check if between
            return start <= field_dt <= end
            
        except (ValueError, TypeError):
            return False
            
    def _parse_duration(self, duration_str: str) -> Optional[timedelta]:
        """Parse duration string to timedelta"""
        if not isinstance(duration_str, str):
            return None
            
        # Pattern: 1d, 2h, 30m, 45s
        match = re.match(r'^(\d+)([dhms])$', duration_str.lower())
        if not match:
            return None
            
        value = int(match.group(1))
        unit = match.group(2)
        
        if unit == 'd':
            return timedelta(days=value)
        elif unit == 'h':
            return timedelta(hours=value)
        elif unit == 'm':
            return timedelta(minutes=value)
        elif unit == 's':
            return timedelta(seconds=value)
            
        return None
        
    # Action handlers
    async def _execute_action(
        self,
        action: RuleAction,
        event: Dict[str, Any],
        rule: CustomRule
    ) -> Any:
        """Execute rule action"""
        handler = self.action_handlers.get(action.type)
        if handler:
            return await handler(action, event, rule)
        return None
        
    async def _handle_alert_action(
        self,
        action: RuleAction,
        event: Dict[str, Any],
        rule: CustomRule
    ) -> Dict[str, Any]:
        """Handle alert action"""
        alert = {
            'rule_id': rule.id,
            'rule_name': rule.name,
            'severity': action.parameters.get('severity', rule.severity),
            'title': action.parameters.get('title', f"Rule '{rule.name}' matched"),
            'description': action.parameters.get('description', rule.description),
            'event': event,
            'timestamp': datetime.now(),
            'tags': rule.tags or [],
            'metadata': {
                **rule.metadata,
                **action.parameters.get('metadata', {})
            }
        }
        
        # Template substitution
        if 'title_template' in action.parameters:
            alert['title'] = self._substitute_template(
                action.parameters['title_template'],
                event
            )
            
        if 'description_template' in action.parameters:
            alert['description'] = self._substitute_template(
                action.parameters['description_template'],
                event
            )
            
        return alert
        
    async def _handle_tag_action(
        self,
        action: RuleAction,
        event: Dict[str, Any],
        rule: CustomRule
    ) -> Set[str]:
        """Handle tag action"""
        tags = set()
        
        # Static tags
        if 'tags' in action.parameters:
            tags.update(action.parameters['tags'])
            
        # Dynamic tags from template
        if 'tag_template' in action.parameters:
            tag = self._substitute_template(
                action.parameters['tag_template'],
                event
            )
            tags.add(tag)
            
        # Add rule tags
        if rule.tags:
            tags.update(rule.tags)
            
        return tags
        
    async def _handle_extract_action(
        self,
        action: RuleAction,
        event: Dict[str, Any],
        rule: CustomRule
    ) -> Dict[str, Any]:
        """Handle extract action"""
        extracted = {}
        
        # Extract fields
        for extract_name, field_path in action.parameters.get('fields', {}).items():
            value = self._extract_field_value(field_path, event)
            if value is not None:
                extracted[extract_name] = value
                
        # Extract with regex
        if 'regex_extracts' in action.parameters:
            for extract_name, regex_config in action.parameters['regex_extracts'].items():
                pattern = regex_config.get('pattern')
                field = regex_config.get('field', 'message')
                
                field_value = self._extract_field_value(field, event)
                if field_value and pattern:
                    match = re.search(pattern, str(field_value))
                    if match:
                        if match.groups():
                            extracted[extract_name] = match.group(1)
                        else:
                            extracted[extract_name] = match.group(0)
                            
        return extracted
        
    async def _handle_enrich_action(
        self,
        action: RuleAction,
        event: Dict[str, Any],
        rule: CustomRule
    ) -> Dict[str, Any]:
        """Handle enrich action"""
        enrichments = {}
        
        # Static enrichments
        if 'fields' in action.parameters:
            enrichments.update(action.parameters['fields'])
            
        # Dynamic enrichments
        if 'computed_fields' in action.parameters:
            for field_name, computation in action.parameters['computed_fields'].items():
                if isinstance(computation, str):
                    # Template substitution
                    enrichments[field_name] = self._substitute_template(
                        computation,
                        event
                    )
                elif isinstance(computation, dict):
                    # Complex computation
                    comp_type = computation.get('type')
                    if comp_type == 'lookup':
                        # Lookup table enrichment
                        lookup_value = self._extract_field_value(
                            computation.get('field', ''),
                            event
                        )
                        lookup_table = computation.get('table', {})
                        enrichments[field_name] = lookup_table.get(
                            lookup_value,
                            computation.get('default')
                        )
                    elif comp_type == 'transform':
                        # Value transformation
                        value = self._extract_field_value(
                            computation.get('field', ''),
                            event
                        )
                        transform = computation.get('transform', 'none')
                        enrichments[field_name] = self._apply_transform(
                            value,
                            transform
                        )
                        
        # Add rule metadata
        enrichments['_rule_id'] = rule.id
        enrichments['_rule_name'] = rule.name
        enrichments['_rule_severity'] = rule.severity
        
        return enrichments
        
    async def _handle_aggregate_action(
        self,
        action: RuleAction,
        event: Dict[str, Any],
        rule: CustomRule
    ) -> Dict[str, Any]:
        """Handle aggregate action"""
        aggregation = {
            'type': action.parameters.get('type', 'count'),
            'field': action.parameters.get('field'),
            'group_by': action.parameters.get('group_by'),
            'value': None
        }
        
        # Extract value to aggregate
        if aggregation['field']:
            value = self._extract_field_value(aggregation['field'], event)
            
            if aggregation['type'] == 'count':
                aggregation['value'] = 1
            elif aggregation['type'] == 'sum' and value is not None:
                try:
                    aggregation['value'] = float(value)
                except (TypeError, ValueError):
                    aggregation['value'] = 0
            elif aggregation['type'] == 'unique':
                aggregation['value'] = value
                
        return aggregation
        
    def _substitute_template(self, template: str, event: Dict[str, Any]) -> str:
        """Substitute template variables with event values"""
        result = template
        
        # Find all template variables {field_name}
        variables = re.findall(r'\{([^}]+)\}', template)
        
        for var in variables:
            value = self._extract_field_value(var, event)
            if value is not None:
                result = result.replace(f"{{{var}}}", str(value))
                
        return result
        
    def _apply_transform(self, value: Any, transform: str) -> Any:
        """Apply transformation to value"""
        if value is None:
            return None
            
        if transform == 'upper':
            return str(value).upper()
        elif transform == 'lower':
            return str(value).lower()
        elif transform == 'md5':
            return hashlib.md5(str(value).encode()).hexdigest()
        elif transform == 'sha256':
            return hashlib.sha256(str(value).encode()).hexdigest()
        elif transform == 'base64':
            import base64
            return base64.b64encode(str(value).encode()).decode()
        elif transform == 'reverse':
            return str(value)[::-1]
        elif transform == 'length':
            return len(str(value))
        else:
            return value
            
    def _update_aggregation(
        self,
        aggregations: Dict[str, Any],
        new_agg: Dict[str, Any]
    ):
        """Update aggregation results"""
        agg_type = new_agg['type']
        field = new_agg.get('field', '_default')
        group_by = new_agg.get('group_by')
        value = new_agg.get('value')
        
        if value is None:
            return
            
        # Create aggregation key
        if group_by:
            agg_key = f"{agg_type}_{field}_by_{group_by}"
        else:
            agg_key = f"{agg_type}_{field}"
            
        if agg_key not in aggregations:
            aggregations[agg_key] = {
                'type': agg_type,
                'field': field,
                'group_by': group_by,
                'values': {}
            }
            
        agg = aggregations[agg_key]
        
        if agg_type == 'count':
            agg['values']['total'] = agg['values'].get('total', 0) + 1
        elif agg_type == 'sum':
            agg['values']['sum'] = agg['values'].get('sum', 0) + value
        elif agg_type == 'unique':
            if 'unique_values' not in agg['values']:
                agg['values']['unique_values'] = set()
            agg['values']['unique_values'].add(value)
            
    def compile_rule(self, rule_definition: Dict[str, Any]) -> CustomRule:
        """Compile rule definition into CustomRule object"""
        # Parse conditions
        conditions = self._parse_conditions(rule_definition.get('conditions', {}))
        
        # Parse actions
        actions = []
        for action_def in rule_definition.get('actions', []):
            action = RuleAction(
                type=action_def.get('type', 'alert'),
                parameters=action_def.get('parameters', {})
            )
            actions.append(action)
            
        # Create rule
        rule = CustomRule(
            id=rule_definition.get('id', ''),
            name=rule_definition.get('name', ''),
            description=rule_definition.get('description', ''),
            conditions=conditions,
            actions=actions,
            enabled=rule_definition.get('enabled', True),
            severity=rule_definition.get('severity', 'medium'),
            tags=rule_definition.get('tags', []),
            metadata=rule_definition.get('metadata', {})
        )
        
        return rule
        
    def _parse_conditions(
        self,
        conditions_def: Union[Dict[str, Any], List[Dict[str, Any]]]
    ) -> Union[RuleCondition, Dict[str, Any]]:
        """Parse conditions from definition"""
        if isinstance(conditions_def, list):
            # Simple list of conditions (AND)
            return {
                'operator': 'and',
                'conditions': [
                    self._parse_single_condition(cond)
                    for cond in conditions_def
                ]
            }
        elif isinstance(conditions_def, dict):
            if 'operator' in conditions_def:
                # Logic tree
                return {
                    'operator': conditions_def['operator'],
                    'conditions': [
                        self._parse_conditions(cond)
                        for cond in conditions_def.get('conditions', [])
                    ]
                }
            else:
                # Single condition
                return self._parse_single_condition(conditions_def)
                
        return None
        
    def _parse_single_condition(self, cond_def: Dict[str, Any]) -> RuleCondition:
        """Parse single condition from definition"""
        return RuleCondition(
            field=cond_def.get('field', ''),
            operator=RuleOperator(cond_def.get('operator', 'equals')),
            value=cond_def.get('value'),
            case_sensitive=cond_def.get('case_sensitive', False),
            negate=cond_def.get('negate', False)
        )


# Example usage
def create_example_rule() -> CustomRule:
    """Create example custom rule"""
    return CustomRule(
        id="suspicious_login",
        name="Suspicious Login Detection",
        description="Detects suspicious login patterns",
        conditions={
            'operator': 'and',
            'conditions': [
                {
                    'field': 'event_type',
                    'operator': 'equals',
                    'value': 'login'
                },
                {
                    'operator': 'or',
                    'conditions': [
                        {
                            'field': 'source_ip',
                            'operator': 'is_public_ip',
                            'value': True
                        },
                        {
                            'field': 'login_hour',
                            'operator': 'not_in',
                            'value': [8, 9, 10, 11, 12, 13, 14, 15, 16, 17]
                        },
                        {
                            'field': 'failed_attempts',
                            'operator': 'greater_than',
                            'value': 3
                        }
                    ]
                }
            ]
        },
        actions=[
            RuleAction(
                type='alert',
                parameters={
                    'severity': 'high',
                    'title_template': 'Suspicious login from {source_ip}',
                    'description_template': 'User {username} logged in from {source_ip} at {timestamp}'
                }
            ),
            RuleAction(
                type='tag',
                parameters={
                    'tags': ['suspicious', 'login'],
                    'tag_template': 'login_{source_ip}'
                }
            ),
            RuleAction(
                type='enrich',
                parameters={
                    'fields': {
                        'risk_score': 75,
                        'requires_review': True
                    }
                }
            )
        ],
        severity='high',
        tags=['authentication', 'suspicious']
    )