"""
Rule Manager - CRUD operations for detection rules
Manages YARA, Sigma, and custom rules with versioning
"""

import os
import json
import shutil
import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
import yaml
import hashlib
from dataclasses import dataclass, asdict
import aiofiles
import uuid

@dataclass
class Rule:
    """Detection rule model"""
    id: str
    name: str
    type: str  # yara, sigma, custom
    category: str
    description: str
    content: str
    author: str
    created_at: datetime
    updated_at: datetime
    version: str
    tags: List[str]
    severity: str
    enabled: bool
    metadata: Dict[str, Any]
    references: List[str]
    false_positive: List[str]
    mitre_attack: List[str]

class RuleManager:
    """Manages detection rules with file-based storage"""
    
    def __init__(self, rules_dir: str = "./rules"):
        self.rules_dir = Path(rules_dir)
        self._ensure_directories()
        self.index_file = self.rules_dir / "index.json"
        self.rules_cache: Dict[str, Rule] = {}
        self.lock = asyncio.Lock()
        
    def _ensure_directories(self):
        """Create rule directory structure"""
        dirs = [
            self.rules_dir,
            self.rules_dir / "yara",
            self.rules_dir / "yara" / "malware",
            self.rules_dir / "yara" / "exploits",
            self.rules_dir / "yara" / "suspicious",
            self.rules_dir / "sigma",
            self.rules_dir / "sigma" / "windows",
            self.rules_dir / "sigma" / "linux",
            self.rules_dir / "sigma" / "network",
            self.rules_dir / "sigma" / "cloud",
            self.rules_dir / "custom",
            self.rules_dir / "mitre",
            self.rules_dir / "backup"
        ]
        for dir_path in dirs:
            dir_path.mkdir(parents=True, exist_ok=True)
            
    async def load_index(self) -> Dict[str, Dict]:
        """Load rule index from disk"""
        if not self.index_file.exists():
            await self._create_default_index()
            
        async with self.lock:
            async with aiofiles.open(self.index_file, 'r') as f:
                return json.loads(await f.read())
                
    async def save_index(self, index: Dict[str, Dict]):
        """Save rule index to disk"""
        async with self.lock:
            async with aiofiles.open(self.index_file, 'w') as f:
                await f.write(json.dumps(index, indent=2, default=str))
                
    async def _create_default_index(self):
        """Create initial rule index"""
        index = {
            "rules": {},
            "categories": {
                "yara": ["malware", "exploits", "suspicious", "custom"],
                "sigma": ["windows", "linux", "network", "cloud", "custom"],
                "custom": ["general", "specific"]
            },
            "metadata": {
                "version": "1.0.0",
                "created_at": datetime.now().isoformat(),
                "total_rules": 0
            }
        }
        await self.save_index(index)
        
    async def create_rule(self, rule_data: Dict[str, Any]) -> Rule:
        """Create new detection rule"""
        # Generate rule ID
        rule_id = rule_data.get('id') or str(uuid.uuid4())
        
        # Create rule object
        rule = Rule(
            id=rule_id,
            name=rule_data['name'],
            type=rule_data['type'],
            category=rule_data.get('category', 'custom'),
            description=rule_data.get('description', ''),
            content=rule_data['content'],
            author=rule_data.get('author', 'Unknown'),
            created_at=datetime.now(),
            updated_at=datetime.now(),
            version=rule_data.get('version', '1.0.0'),
            tags=rule_data.get('tags', []),
            severity=rule_data.get('severity', 'medium'),
            enabled=rule_data.get('enabled', True),
            metadata=rule_data.get('metadata', {}),
            references=rule_data.get('references', []),
            false_positive=rule_data.get('false_positive', []),
            mitre_attack=rule_data.get('mitre_attack', [])
        )
        
        # Save rule file
        await self._save_rule_file(rule)
        
        # Update index
        index = await self.load_index()
        index['rules'][rule_id] = {
            'name': rule.name,
            'type': rule.type,
            'category': rule.category,
            'severity': rule.severity,
            'enabled': rule.enabled,
            'created_at': rule.created_at.isoformat(),
            'updated_at': rule.updated_at.isoformat(),
            'file_path': self._get_rule_path(rule)
        }
        index['metadata']['total_rules'] = len(index['rules'])
        await self.save_index(index)
        
        # Cache rule
        self.rules_cache[rule_id] = rule
        
        return rule
        
    async def update_rule(self, rule_id: str, updates: Dict[str, Any]) -> Optional[Rule]:
        """Update existing rule"""
        rule = await self.get_rule(rule_id)
        if not rule:
            return None
            
        # Backup current version
        await self._backup_rule(rule)
        
        # Update fields
        for key, value in updates.items():
            if hasattr(rule, key) and key not in ['id', 'created_at']:
                setattr(rule, key, value)
                
        rule.updated_at = datetime.now()
        
        # Increment version
        version_parts = rule.version.split('.')
        version_parts[-1] = str(int(version_parts[-1]) + 1)
        rule.version = '.'.join(version_parts)
        
        # Save updated rule
        await self._save_rule_file(rule)
        
        # Update index
        index = await self.load_index()
        if rule_id in index['rules']:
            index['rules'][rule_id].update({
                'name': rule.name,
                'category': rule.category,
                'severity': rule.severity,
                'enabled': rule.enabled,
                'updated_at': rule.updated_at.isoformat()
            })
            await self.save_index(index)
            
        # Update cache
        self.rules_cache[rule_id] = rule
        
        return rule
        
    async def delete_rule(self, rule_id: str) -> bool:
        """Delete rule (soft delete with backup)"""
        rule = await self.get_rule(rule_id)
        if not rule:
            return False
            
        # Backup before deletion
        await self._backup_rule(rule)
        
        # Remove rule file
        rule_path = Path(self._get_rule_path(rule))
        if rule_path.exists():
            rule_path.unlink()
            
        # Update index
        index = await self.load_index()
        if rule_id in index['rules']:
            del index['rules'][rule_id]
            index['metadata']['total_rules'] = len(index['rules'])
            await self.save_index(index)
            
        # Remove from cache
        if rule_id in self.rules_cache:
            del self.rules_cache[rule_id]
            
        return True
        
    async def get_rule(self, rule_id: str) -> Optional[Rule]:
        """Get rule by ID"""
        # Check cache first
        if rule_id in self.rules_cache:
            return self.rules_cache[rule_id]
            
        # Load from index
        index = await self.load_index()
        if rule_id not in index['rules']:
            return None
            
        rule_info = index['rules'][rule_id]
        rule_path = Path(rule_info['file_path'])
        
        if not rule_path.exists():
            return None
            
        # Load rule file
        async with aiofiles.open(rule_path, 'r') as f:
            rule_data = json.loads(await f.read())
            
        # Convert to Rule object
        rule = Rule(**rule_data)
        rule.created_at = datetime.fromisoformat(rule_data['created_at'])
        rule.updated_at = datetime.fromisoformat(rule_data['updated_at'])
        
        # Cache rule
        self.rules_cache[rule_id] = rule
        
        return rule
        
    async def list_rules(
        self,
        rule_type: Optional[str] = None,
        category: Optional[str] = None,
        enabled_only: bool = False,
        tags: Optional[List[str]] = None,
        severity: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> Dict[str, Any]:
        """List rules with filtering and pagination"""
        index = await self.load_index()
        all_rules = []
        
        # Filter rules
        for rule_id, rule_info in index['rules'].items():
            # Type filter
            if rule_type and rule_info['type'] != rule_type:
                continue
                
            # Category filter
            if category and rule_info['category'] != category:
                continue
                
            # Enabled filter
            if enabled_only and not rule_info['enabled']:
                continue
                
            # Severity filter
            if severity and rule_info['severity'] != severity:
                continue
                
            # Load full rule for advanced filtering
            if tags or search:
                rule = await self.get_rule(rule_id)
                if not rule:
                    continue
                    
                # Tag filter
                if tags and not any(tag in rule.tags for tag in tags):
                    continue
                    
                # Search filter
                if search:
                    search_lower = search.lower()
                    if not any(
                        search_lower in str(getattr(rule, field, '')).lower()
                        for field in ['name', 'description', 'content', 'tags']
                    ):
                        continue
                        
            # Add to results
            all_rules.append({
                'id': rule_id,
                **rule_info
            })
            
        # Sort by updated_at descending
        all_rules.sort(
            key=lambda x: x.get('updated_at', ''),
            reverse=True
        )
        
        # Pagination
        total = len(all_rules)
        rules = all_rules[offset:offset + limit]
        
        return {
            'rules': rules,
            'total': total,
            'limit': limit,
            'offset': offset,
            'has_more': offset + limit < total
        }
        
    async def import_rules(self, file_path: str, rule_type: str) -> Dict[str, Any]:
        """Import rules from file"""
        imported = []
        errors = []
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
                
            if rule_type == 'yara':
                # Parse YARA rules
                rules = self._parse_yara_import(content)
            elif rule_type == 'sigma':
                # Parse Sigma rules
                rules = self._parse_sigma_import(content)
            else:
                # Parse custom JSON rules
                rules = json.loads(content)
                if not isinstance(rules, list):
                    rules = [rules]
                    
            # Import each rule
            for rule_data in rules:
                try:
                    rule_data['type'] = rule_type
                    rule = await self.create_rule(rule_data)
                    imported.append(rule.id)
                except Exception as e:
                    errors.append({
                        'rule': rule_data.get('name', 'Unknown'),
                        'error': str(e)
                    })
                    
        except Exception as e:
            errors.append({
                'file': file_path,
                'error': str(e)
            })
            
        return {
            'imported': len(imported),
            'imported_ids': imported,
            'errors': errors,
            'success': len(errors) == 0
        }
        
    async def export_rules(
        self,
        rule_ids: Optional[List[str]] = None,
        rule_type: Optional[str] = None,
        format: str = 'json'
    ) -> str:
        """Export rules to file"""
        rules_to_export = []
        
        if rule_ids:
            # Export specific rules
            for rule_id in rule_ids:
                rule = await self.get_rule(rule_id)
                if rule:
                    rules_to_export.append(rule)
        else:
            # Export all rules of type
            result = await self.list_rules(
                rule_type=rule_type,
                limit=10000
            )
            for rule_info in result['rules']:
                rule = await self.get_rule(rule_info['id'])
                if rule:
                    rules_to_export.append(rule)
                    
        # Format output
        if format == 'json':
            output = json.dumps(
                [asdict(rule) for rule in rules_to_export],
                indent=2,
                default=str
            )
        elif format == 'yaml':
            output = yaml.dump(
                [asdict(rule) for rule in rules_to_export],
                default_flow_style=False
            )
        else:
            # Raw format (concatenated rule content)
            output = '\n\n'.join(rule.content for rule in rules_to_export)
            
        # Save to temp file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        export_path = f"/tmp/rules_export_{timestamp}.{format}"
        
        async with aiofiles.open(export_path, 'w') as f:
            await f.write(output)
            
        return export_path
        
    async def get_rule_stats(self) -> Dict[str, Any]:
        """Get rule statistics"""
        index = await self.load_index()
        stats = {
            'total_rules': len(index['rules']),
            'by_type': {},
            'by_category': {},
            'by_severity': {},
            'enabled': 0,
            'disabled': 0,
            'recent_updates': []
        }
        
        # Calculate stats
        for rule_info in index['rules'].values():
            # By type
            rule_type = rule_info['type']
            stats['by_type'][rule_type] = stats['by_type'].get(rule_type, 0) + 1
            
            # By category
            category = rule_info['category']
            stats['by_category'][category] = stats['by_category'].get(category, 0) + 1
            
            # By severity
            severity = rule_info['severity']
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
            
            # Enabled/disabled
            if rule_info['enabled']:
                stats['enabled'] += 1
            else:
                stats['disabled'] += 1
                
        # Get recent updates
        sorted_rules = sorted(
            index['rules'].items(),
            key=lambda x: x[1].get('updated_at', ''),
            reverse=True
        )
        stats['recent_updates'] = [
            {
                'id': rule_id,
                'name': info['name'],
                'updated_at': info['updated_at']
            }
            for rule_id, info in sorted_rules[:10]
        ]
        
        return stats
        
    async def test_rule(self, rule_id: str, test_data: Dict[str, Any]) -> Dict[str, Any]:
        """Test rule against sample data"""
        rule = await self.get_rule(rule_id)
        if not rule:
            return {'error': 'Rule not found'}
            
        # Import appropriate analyzer
        if rule.type == 'yara':
            from ..analyzers.yara_analyzer import YaraAnalyzer
            analyzer = YaraAnalyzer({})
            
            # Create temp rule file for testing
            temp_rule = f"/tmp/test_rule_{rule_id}.yar"
            async with aiofiles.open(temp_rule, 'w') as f:
                await f.write(rule.content)
                
            try:
                # Run YARA test
                result = await analyzer._scan_with_yara(
                    temp_rule,
                    test_data.get('content', '').encode()
                )
                return {
                    'matched': len(result) > 0,
                    'results': result
                }
            finally:
                if os.path.exists(temp_rule):
                    os.unlink(temp_rule)
                    
        elif rule.type == 'sigma':
            from ..analyzers.sigma_analyzer import SigmaAnalyzer
            analyzer = SigmaAnalyzer({})
            
            # Parse rule
            sigma_rule = yaml.safe_load(rule.content)
            
            # Test against log entries
            matches = []
            for entry in test_data.get('logs', []):
                if analyzer._check_detection_logic(entry, sigma_rule.get('detection', {})):
                    matches.append(entry)
                    
            return {
                'matched': len(matches) > 0,
                'matches': matches,
                'total_tested': len(test_data.get('logs', []))
            }
            
        else:
            # Custom rule testing
            return {
                'error': 'Custom rule testing not implemented',
                'rule_type': rule.type
            }
            
    def _get_rule_path(self, rule: Rule) -> str:
        """Get file path for rule"""
        if rule.type == 'yara':
            return str(self.rules_dir / 'yara' / rule.category / f"{rule.id}.json")
        elif rule.type == 'sigma':
            return str(self.rules_dir / 'sigma' / rule.category / f"{rule.id}.json")
        else:
            return str(self.rules_dir / 'custom' / f"{rule.id}.json")
            
    async def _save_rule_file(self, rule: Rule):
        """Save rule to file"""
        rule_path = Path(self._get_rule_path(rule))
        rule_path.parent.mkdir(parents=True, exist_ok=True)
        
        rule_data = asdict(rule)
        rule_data['created_at'] = rule.created_at.isoformat()
        rule_data['updated_at'] = rule.updated_at.isoformat()
        
        async with aiofiles.open(rule_path, 'w') as f:
            await f.write(json.dumps(rule_data, indent=2))
            
    async def _backup_rule(self, rule: Rule):
        """Backup rule before modification"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_name = f"{rule.id}_{rule.version}_{timestamp}.json"
        backup_path = self.rules_dir / 'backup' / backup_name
        
        rule_data = asdict(rule)
        rule_data['created_at'] = rule.created_at.isoformat()
        rule_data['updated_at'] = rule.updated_at.isoformat()
        
        async with aiofiles.open(backup_path, 'w') as f:
            await f.write(json.dumps(rule_data, indent=2))
            
    def _parse_yara_import(self, content: str) -> List[Dict]:
        """Parse YARA rules from import"""
        rules = []
        
        # Simple YARA parser (production would use yara-python)
        import re
        
        # Find all rules
        rule_pattern = r'rule\s+(\w+)(?:\s*:\s*([\w\s]+))?\s*\{([^}]+)\}'
        matches = re.finditer(rule_pattern, content, re.DOTALL)
        
        for match in matches:
            rule_name = match.group(1)
            tags = match.group(2).split() if match.group(2) else []
            rule_body = match.group(3)
            
            # Extract metadata
            meta_pattern = r'meta:\s*([^:]+?)(?:strings:|condition:)'
            meta_match = re.search(meta_pattern, rule_body, re.DOTALL)
            
            metadata = {}
            if meta_match:
                meta_text = meta_match.group(1)
                # Parse metadata lines
                for line in meta_text.strip().split('\n'):
                    if '=' in line:
                        key, value = line.split('=', 1)
                        metadata[key.strip()] = value.strip().strip('"')
                        
            rules.append({
                'name': rule_name,
                'content': match.group(0),
                'tags': tags,
                'category': 'imported',
                'description': metadata.get('description', ''),
                'author': metadata.get('author', 'Unknown'),
                'metadata': metadata
            })
            
        return rules
        
    def _parse_sigma_import(self, content: str) -> List[Dict]:
        """Parse Sigma rules from import"""
        rules = []
        
        # Parse YAML documents
        import yaml
        
        # Handle multiple documents
        docs = list(yaml.safe_load_all(content))
        
        for doc in docs:
            if isinstance(doc, dict) and 'title' in doc:
                rules.append({
                    'name': doc.get('title'),
                    'content': yaml.dump(doc),
                    'description': doc.get('description', ''),
                    'author': doc.get('author', 'Unknown'),
                    'tags': doc.get('tags', []),
                    'category': doc.get('logsource', {}).get('product', 'general'),
                    'severity': doc.get('level', 'medium'),
                    'references': doc.get('references', []),
                    'false_positive': doc.get('falsepositives', []),
                    'metadata': {
                        'id': doc.get('id'),
                        'status': doc.get('status'),
                        'date': doc.get('date')
                    }
                })
                
        return rules


# Initialization function
async def initialize_rule_manager(config: Dict[str, Any]) -> RuleManager:
    """Initialize rule manager with default rules"""
    manager = RuleManager(config.get('rules_dir', './rules'))
    
    # Load default rules if needed
    stats = await manager.get_rule_stats()
    if stats['total_rules'] == 0:
        # Import default YARA rules
        default_yara = Path(__file__).parent.parent / 'rules' / 'yara' / 'default.yar'
        if default_yara.exists():
            await manager.import_rules(str(default_yara), 'yara')
            
        # Import default Sigma rules
        default_sigma = Path(__file__).parent.parent / 'rules' / 'sigma' / 'default.yml'
        if default_sigma.exists():
            await manager.import_rules(str(default_sigma), 'sigma')
            
    return manager