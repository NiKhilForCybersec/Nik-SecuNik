"""
Rule Validator - Syntax validation for detection rules
Validates YARA, Sigma, and custom rule formats
"""

import re
import json
import yaml
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
import yara
from datetime import datetime
import ast

@dataclass
class ValidationResult:
    """Rule validation result"""
    valid: bool
    errors: List[str]
    warnings: List[str]
    suggestions: List[str]
    metadata: Dict[str, Any]

class RuleValidator:
    """Validates detection rule syntax and logic"""
    
    def __init__(self):
        self.yara_keywords = {
            'rule', 'meta', 'strings', 'condition', 'and', 'or', 'not',
            'any', 'all', 'of', 'them', 'in', 'at', 'filesize', 'entrypoint',
            'int8', 'int16', 'int32', 'uint8', 'uint16', 'uint32',
            'private', 'global', 'ascii', 'wide', 'nocase', 'fullword'
        }
        
        self.sigma_required_fields = {'title', 'detection'}
        self.sigma_optional_fields = {
            'id', 'status', 'description', 'references', 'author',
            'date', 'modified', 'tags', 'logsource', 'level',
            'falsepositives', 'fields'
        }
        
        self.severity_levels = ['informational', 'low', 'medium', 'high', 'critical']
        
    async def validate_rule(
        self,
        content: str,
        rule_type: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> ValidationResult:
        """Validate rule based on type"""
        if rule_type == 'yara':
            return await self.validate_yara_rule(content, metadata)
        elif rule_type == 'sigma':
            return await self.validate_sigma_rule(content, metadata)
        elif rule_type == 'custom':
            return await self.validate_custom_rule(content, metadata)
        else:
            return ValidationResult(
                valid=False,
                errors=[f"Unknown rule type: {rule_type}"],
                warnings=[],
                suggestions=[],
                metadata={}
            )
            
    async def validate_yara_rule(
        self,
        content: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> ValidationResult:
        """Validate YARA rule syntax"""
        errors = []
        warnings = []
        suggestions = []
        rule_metadata = {}
        
        try:
            # Try to compile the rule
            rules = yara.compile(source=content)
            
            # Extract rule names
            rule_names = self._extract_yara_rule_names(content)
            rule_metadata['rule_names'] = rule_names
            rule_metadata['rule_count'] = len(rule_names)
            
            # Check for best practices
            # 1. Rule naming convention
            for name in rule_names:
                if not re.match(r'^[A-Za-z][A-Za-z0-9_]*$', name):
                    warnings.append(f"Rule name '{name}' doesn't follow naming convention")
                    
            # 2. Check for metadata
            if 'meta:' not in content:
                warnings.append("No metadata section found")
                suggestions.append("Add metadata section with description, author, date")
                
            # 3. Check for meaningful variable names
            string_vars = re.findall(r'\$(\w+)\s*=', content)
            for var in string_vars:
                if len(var) < 3 or var.lower() in ['a', 'b', 'c', 's1', 's2']:
                    suggestions.append(f"Use more descriptive name for variable ${var}")
                    
            # 4. Check for performance issues
            if content.count('*') > 10:
                warnings.append("Many wildcards detected, may impact performance")
                
            # 5. Check condition complexity
            conditions = re.findall(r'condition:\s*([^}]+)', content, re.DOTALL)
            for condition in conditions:
                if condition.count('(') > 10:
                    warnings.append("Complex condition detected, consider simplifying")
                    
            # 6. Check for hex strings without comments
            hex_strings = re.findall(r'\{[0-9a-fA-F\s\?]+\}', content)
            if len(hex_strings) > 5:
                suggestions.append("Consider adding comments to explain hex patterns")
                
            # Extract metadata from rule
            meta_section = re.search(r'meta:\s*([^:]+?)(?:strings:|condition:)', content, re.DOTALL)
            if meta_section:
                meta_text = meta_section.group(1)
                for line in meta_text.strip().split('\n'):
                    if '=' in line:
                        key, value = line.split('=', 1)
                        rule_metadata[f"meta_{key.strip()}"] = value.strip().strip('"')
                        
        except yara.SyntaxError as e:
            errors.append(f"YARA syntax error: {str(e)}")
            
            # Try to provide helpful error context
            error_match = re.search(r'line (\d+)', str(e))
            if error_match:
                line_num = int(error_match.group(1))
                lines = content.split('\n')
                if 0 <= line_num - 1 < len(lines):
                    errors.append(f"Error at line {line_num}: {lines[line_num - 1].strip()}")
                    
        except yara.Error as e:
            errors.append(f"YARA compilation error: {str(e)}")
            
        except Exception as e:
            errors.append(f"Unexpected error: {str(e)}")
            
        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            suggestions=suggestions,
            metadata=rule_metadata
        )
        
    async def validate_sigma_rule(
        self,
        content: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> ValidationResult:
        """Validate Sigma rule syntax"""
        errors = []
        warnings = []
        suggestions = []
        rule_metadata = {}
        
        try:
            # Parse YAML
            rule = yaml.safe_load(content)
            
            if not isinstance(rule, dict):
                errors.append("Rule must be a valid YAML dictionary")
                return ValidationResult(False, errors, warnings, suggestions, rule_metadata)
                
            # Check required fields
            missing_fields = self.sigma_required_fields - set(rule.keys())
            if missing_fields:
                errors.append(f"Missing required fields: {', '.join(missing_fields)}")
                
            # Validate title
            if 'title' in rule:
                if not isinstance(rule['title'], str) or len(rule['title']) < 5:
                    errors.append("Title must be a descriptive string (min 5 chars)")
                rule_metadata['title'] = rule.get('title', '')
                
            # Validate detection section
            if 'detection' in rule:
                detection = rule['detection']
                if not isinstance(detection, dict):
                    errors.append("Detection must be a dictionary")
                else:
                    # Check for selection and condition
                    if 'condition' not in detection:
                        errors.append("Detection must have a condition")
                    else:
                        # Validate condition syntax
                        condition_errors = self._validate_sigma_condition(
                            detection['condition'],
                            detection
                        )
                        errors.extend(condition_errors)
                        
                    # Check selections
                    selections = [k for k in detection.keys() if k.startswith('selection')]
                    if not selections and 'condition' in detection:
                        if 'selection' not in detection['condition']:
                            warnings.append("No selection criteria defined")
                            
            # Validate logsource
            if 'logsource' in rule:
                logsource = rule['logsource']
                if not isinstance(logsource, dict):
                    errors.append("Logsource must be a dictionary")
                else:
                    # Check for required logsource fields
                    if not any(k in logsource for k in ['product', 'service', 'category']):
                        warnings.append("Logsource should specify product, service, or category")
                        
            # Validate level
            if 'level' in rule:
                if rule['level'] not in self.severity_levels:
                    warnings.append(f"Invalid severity level. Use: {', '.join(self.severity_levels)}")
                rule_metadata['severity'] = rule.get('level', 'medium')
                
            # Validate date fields
            for date_field in ['date', 'modified']:
                if date_field in rule:
                    try:
                        datetime.fromisoformat(rule[date_field].replace('/', '-'))
                    except:
                        warnings.append(f"Invalid {date_field} format. Use YYYY-MM-DD")
                        
            # Check for ID (UUID)
            if 'id' in rule:
                import uuid
                try:
                    uuid.UUID(rule['id'])
                except ValueError:
                    warnings.append("ID should be a valid UUID")
                    
            # Best practices
            if 'description' not in rule:
                suggestions.append("Add a description field")
                
            if 'references' not in rule:
                suggestions.append("Consider adding references")
                
            if 'falsepositives' not in rule:
                suggestions.append("Document potential false positives")
                
            # Extract metadata
            rule_metadata.update({
                'rule_id': rule.get('id'),
                'author': rule.get('author'),
                'tags': rule.get('tags', []),
                'references': rule.get('references', [])
            })
            
        except yaml.YAMLError as e:
            errors.append(f"YAML parsing error: {str(e)}")
        except Exception as e:
            errors.append(f"Validation error: {str(e)}")
            
        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            suggestions=suggestions,
            metadata=rule_metadata
        )
        
    async def validate_custom_rule(
        self,
        content: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> ValidationResult:
        """Validate custom rule format"""
        errors = []
        warnings = []
        suggestions = []
        rule_metadata = {}
        
        try:
            # Try to parse as JSON
            rule = json.loads(content)
            
            # Check required fields for custom rules
            required_fields = {'name', 'type', 'logic'}
            missing_fields = required_fields - set(rule.keys())
            if missing_fields:
                errors.append(f"Missing required fields: {', '.join(missing_fields)}")
                
            # Validate logic field
            if 'logic' in rule:
                logic = rule['logic']
                if isinstance(logic, str):
                    # Validate as Python expression
                    try:
                        ast.parse(logic, mode='eval')
                    except SyntaxError as e:
                        errors.append(f"Invalid logic expression: {str(e)}")
                elif isinstance(logic, dict):
                    # Validate structured logic
                    if 'operator' not in logic:
                        errors.append("Logic dict must have 'operator' field")
                    if 'conditions' not in logic:
                        errors.append("Logic dict must have 'conditions' field")
                else:
                    errors.append("Logic must be string expression or dict")
                    
            # Validate patterns
            if 'patterns' in rule:
                if not isinstance(rule['patterns'], list):
                    errors.append("Patterns must be a list")
                else:
                    for i, pattern in enumerate(rule['patterns']):
                        if isinstance(pattern, dict):
                            if 'regex' in pattern:
                                # Validate regex
                                try:
                                    re.compile(pattern['regex'])
                                except re.error as e:
                                    errors.append(f"Invalid regex in pattern {i}: {str(e)}")
                                    
            # Extract metadata
            rule_metadata = {
                'name': rule.get('name'),
                'type': rule.get('type'),
                'severity': rule.get('severity', 'medium'),
                'tags': rule.get('tags', [])
            }
            
        except json.JSONDecodeError as e:
            errors.append(f"Invalid JSON: {str(e)}")
        except Exception as e:
            errors.append(f"Validation error: {str(e)}")
            
        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            suggestions=suggestions,
            metadata=rule_metadata
        )
        
    def _extract_yara_rule_names(self, content: str) -> List[str]:
        """Extract rule names from YARA content"""
        rule_names = []
        rule_pattern = r'rule\s+(\w+)'
        matches = re.finditer(rule_pattern, content)
        for match in matches:
            rule_names.append(match.group(1))
        return rule_names
        
    def _validate_sigma_condition(
        self,
        condition: str,
        detection: Dict[str, Any]
    ) -> List[str]:
        """Validate Sigma condition syntax"""
        errors = []
        
        # Check for basic syntax
        if not condition.strip():
            errors.append("Condition cannot be empty")
            return errors
            
        # Extract referenced selections
        words = re.findall(r'\b\w+\b', condition)
        
        # Check if referenced selections exist
        for word in words:
            if word.startswith('selection') or word in ['filter', 'timeframe']:
                if word not in detection:
                    errors.append(f"Condition references undefined selection: {word}")
                    
        # Check for valid operators
        valid_operators = {'and', 'or', 'not', 'all', 'of', 'them', '|'}
        
        # Basic parentheses check
        if condition.count('(') != condition.count(')'):
            errors.append("Unbalanced parentheses in condition")
            
        # Check for common mistakes
        if '==' in condition:
            errors.append("Use single '=' for equality in Sigma")
            
        if 'AND' in condition or 'OR' in condition:
            errors.append("Use lowercase 'and'/'or' in conditions")
            
        return errors
        
    async def validate_rule_set(
        self,
        rules: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Validate a set of rules for conflicts and dependencies"""
        results = {
            'total': len(rules),
            'valid': 0,
            'invalid': 0,
            'conflicts': [],
            'duplicates': [],
            'coverage_gaps': []
        }
        
        rule_signatures = {}
        rule_names = set()
        
        for i, rule in enumerate(rules):
            # Validate individual rule
            result = await self.validate_rule(
                rule.get('content', ''),
                rule.get('type', 'custom'),
                rule.get('metadata')
            )
            
            if result.valid:
                results['valid'] += 1
            else:
                results['invalid'] += 1
                
            # Check for duplicates
            rule_name = rule.get('name', f'rule_{i}')
            if rule_name in rule_names:
                results['duplicates'].append({
                    'name': rule_name,
                    'indices': [j for j, r in enumerate(rules) if r.get('name') == rule_name]
                })
            rule_names.add(rule_name)
            
            # Create signature for similarity check
            if rule.get('type') == 'yara' and 'content' in rule:
                # Extract strings from YARA rule
                strings = re.findall(r'\$\w+\s*=\s*"([^"]+)"', rule['content'])
                signature = '|'.join(sorted(strings))
                
                # Check for similar rules
                for existing_sig, existing_rule in rule_signatures.items():
                    similarity = self._calculate_similarity(signature, existing_sig)
                    if similarity > 0.8:
                        results['conflicts'].append({
                            'rule1': existing_rule['name'],
                            'rule2': rule_name,
                            'similarity': similarity,
                            'type': 'pattern_overlap'
                        })
                        
                rule_signatures[signature] = rule
                
        # Check for coverage gaps
        covered_categories = set()
        covered_severities = set()
        
        for rule in rules:
            if 'category' in rule:
                covered_categories.add(rule['category'])
            if 'severity' in rule:
                covered_severities.add(rule['severity'])
                
        # Suggest missing coverage
        expected_categories = {'malware', 'exploits', 'suspicious', 'network', 'system'}
        missing_categories = expected_categories - covered_categories
        if missing_categories:
            results['coverage_gaps'].append({
                'type': 'category',
                'missing': list(missing_categories)
            })
            
        return results
        
    def _calculate_similarity(self, sig1: str, sig2: str) -> float:
        """Calculate similarity between two signatures"""
        if not sig1 or not sig2:
            return 0.0
            
        # Simple Jaccard similarity
        set1 = set(sig1.split('|'))
        set2 = set(sig2.split('|'))
        
        if not set1 and not set2:
            return 1.0
            
        intersection = set1 & set2
        union = set1 | set2
        
        return len(intersection) / len(union) if union else 0.0
        
    async def generate_rule_template(
        self,
        rule_type: str,
        parameters: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generate rule template based on type"""
        if rule_type == 'yara':
            return self._generate_yara_template(parameters)
        elif rule_type == 'sigma':
            return self._generate_sigma_template(parameters)
        elif rule_type == 'custom':
            return self._generate_custom_template(parameters)
        else:
            raise ValueError(f"Unknown rule type: {rule_type}")
            
    def _generate_yara_template(self, params: Optional[Dict[str, Any]] = None) -> str:
        """Generate YARA rule template"""
        params = params or {}
        
        template = f"""rule {params.get('name', 'RULE_NAME')}
{{
    meta:
        description = "{params.get('description', 'Rule description')}"
        author = "{params.get('author', 'Your name')}"
        date = "{datetime.now().strftime('%Y-%m-%d')}"
        reference = "{params.get('reference', 'https://example.com')}"
        severity = "{params.get('severity', 'medium')}"
        
    strings:
        $string1 = "suspicious string" nocase
        $string2 = {{48 65 6C 6C 6F}} // Hex pattern
        $regex1 = /[a-z]{{5,10}}\\.exe/
        
    condition:
        any of them
}}"""
        return template
        
    def _generate_sigma_template(self, params: Optional[Dict[str, Any]] = None) -> str:
        """Generate Sigma rule template"""
        params = params or {}
        
        template = {
            'title': params.get('title', 'Rule Title'),
            'id': str(uuid.uuid4()) if params.get('generate_id', True) else 'UUID',
            'status': params.get('status', 'experimental'),
            'description': params.get('description', 'Detects suspicious activity'),
            'references': params.get('references', ['https://example.com']),
            'author': params.get('author', 'Your name'),
            'date': datetime.now().strftime('%Y/%m/%d'),
            'tags': params.get('tags', ['attack.t1059']),
            'logsource': params.get('logsource', {
                'category': 'process_creation',
                'product': 'windows'
            }),
            'detection': {
                'selection': {
                    'EventID': 4688,
                    'CommandLine|contains': 'suspicious.exe'
                },
                'condition': 'selection'
            },
            'falsepositives': params.get('falsepositives', ['Unknown']),
            'level': params.get('level', 'medium')
        }
        
        return yaml.dump(template, default_flow_style=False, sort_keys=False)
        
    def _generate_custom_template(self, params: Optional[Dict[str, Any]] = None) -> str:
        """Generate custom rule template"""
        params = params or {}
        
        template = {
            'name': params.get('name', 'Custom Rule Name'),
            'type': 'custom',
            'description': params.get('description', 'Detects specific pattern'),
            'severity': params.get('severity', 'medium'),
            'author': params.get('author', 'Your name'),
            'created_at': datetime.now().isoformat(),
            'tags': params.get('tags', ['custom', 'detection']),
            'patterns': [
                {
                    'name': 'pattern1',
                    'regex': r'suspicious.*pattern',
                    'flags': ['IGNORECASE']
                }
            ],
            'logic': {
                'operator': 'AND',
                'conditions': [
                    {
                        'field': 'message',
                        'operator': 'contains',
                        'value': 'error'
                    },
                    {
                        'field': 'severity',
                        'operator': 'in',
                        'value': ['high', 'critical']
                    }
                ]
            },
            'actions': params.get('actions', ['alert', 'log']),
            'metadata': params.get('metadata', {})
        }
        
        return json.dumps(template, indent=2)