# backend/rules/rule_importer.py

"""
Rule Importer - Advanced rule import functionality
Handles bulk imports, rule packs, and various rule formats
"""

import os
import json
import yaml
import zipfile
import tarfile
import tempfile
import shutil
import asyncio
import aiohttp
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
import csv

from .rule_manager import RuleManager, Rule
from .rule_validator import RuleValidator

@dataclass
class ImportResult:
    """Rule import result"""
    total_processed: int
    successful: int
    failed: int
    skipped: int
    imported_rules: List[Rule]
    errors: List[Dict[str, str]]
    warnings: List[str]
    import_time: datetime
    source: str

class RuleImporter:
    """Advanced rule import system"""
    
    def __init__(self, rule_manager: RuleManager):
        self.rule_manager = rule_manager
        self.validator = RuleValidator()
        self.supported_formats = {
            '.yar': 'yara',
            '.yara': 'yara',
            '.yml': 'sigma',
            '.yaml': 'sigma',
            '.json': 'json',
            '.xml': 'xml',
            '.csv': 'csv',
            '.zip': 'archive',
            '.tar': 'archive',
            '.gz': 'archive',
            '.tar.gz': 'archive',
            '.tgz': 'archive'
        }
        self.rule_sources = {
            'github': 'https://api.github.com/repos/{repo}/contents/{path}',
            'yara-rules': 'https://github.com/Yara-Rules/rules/archive/master.zip',
            'sigma': 'https://github.com/SigmaHQ/sigma/archive/master.zip',
            'elastic': 'https://github.com/elastic/detection-rules/archive/main.zip'
        }
        
    async def import_from_file(
        self,
        file_path: str,
        rule_type: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> ImportResult:
        """Import rules from a file"""
        options = options or {}
        file_path = Path(file_path)
        
        if not file_path.exists():
            return ImportResult(
                total_processed=0,
                successful=0,
                failed=0,
                skipped=0,
                imported_rules=[],
                errors=[{'file': str(file_path), 'error': 'File not found'}],
                warnings=[],
                import_time=datetime.now(),
                source=str(file_path)
            )
            
        # Detect format
        extension = ''.join(file_path.suffixes).lower()
        detected_format = self.supported_formats.get(extension, 'unknown')
        
        # Override with specified type
        if rule_type:
            detected_format = rule_type
            
        # Handle different formats
        if detected_format == 'archive':
            return await self._import_archive(file_path, options)
        elif detected_format == 'yara':
            return await self._import_yara_file(file_path, options)
        elif detected_format == 'sigma':
            return await self._import_sigma_file(file_path, options)
        elif detected_format == 'json':
            return await self._import_json_file(file_path, options)
        elif detected_format == 'xml':
            return await self._import_xml_file(file_path, options)
        elif detected_format == 'csv':
            return await self._import_csv_file(file_path, options)
        else:
            return ImportResult(
                total_processed=0,
                successful=0,
                failed=1,
                skipped=0,
                imported_rules=[],
                errors=[{'file': str(file_path), 'error': f'Unsupported format: {extension}'}],
                warnings=[],
                import_time=datetime.now(),
                source=str(file_path)
            )
            
    async def import_from_url(
        self,
        url: str,
        rule_type: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> ImportResult:
        """Import rules from URL"""
        options = options or {}
        
        try:
            # Download file
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=30) as response:
                    if response.status != 200:
                        raise Exception(f"HTTP {response.status}")
                        
                    content = await response.read()
                    
            # Save to temp file
            with tempfile.NamedTemporaryFile(delete=False, suffix='.download') as tmp:
                tmp.write(content)
                tmp_path = tmp.name
                
            try:
                # Detect format from URL or content type
                if not rule_type:
                    content_type = response.headers.get('content-type', '')
                    if 'yaml' in content_type or url.endswith(('.yml', '.yaml')):
                        rule_type = 'sigma'
                    elif url.endswith(('.yar', '.yara')):
                        rule_type = 'yara'
                    elif 'json' in content_type or url.endswith('.json'):
                        rule_type = 'json'
                    elif 'zip' in content_type or url.endswith('.zip'):
                        rule_type = 'archive'
                        
                # Import from temp file
                result = await self.import_from_file(tmp_path, rule_type, options)
                result.source = url
                return result
                
            finally:
                # Clean up
                os.unlink(tmp_path)
                
        except Exception as e:
            return ImportResult(
                total_processed=0,
                successful=0,
                failed=1,
                skipped=0,
                imported_rules=[],
                errors=[{'url': url, 'error': str(e)}],
                warnings=[],
                import_time=datetime.now(),
                source=url
            )
            
    async def import_from_github(
        self,
        repo: str,
        path: str = '',
        branch: str = 'main',
        options: Optional[Dict[str, Any]] = None
    ) -> ImportResult:
        """Import rules from GitHub repository"""
        options = options or {}
        
        # Construct GitHub API URL
        api_url = f"https://api.github.com/repos/{repo}/contents/{path}"
        if branch != 'main':
            api_url += f"?ref={branch}"
            
        try:
            # Get repository contents
            async with aiohttp.ClientSession() as session:
                headers = {}
                if 'github_token' in options:
                    headers['Authorization'] = f"token {options['github_token']}"
                    
                async with session.get(api_url, headers=headers) as response:
                    if response.status != 200:
                        raise Exception(f"GitHub API error: {response.status}")
                        
                    contents = await response.json()
                    
            # Process files
            all_results = []
            
            if isinstance(contents, list):
                # Directory listing
                for item in contents:
                    if item['type'] == 'file' and self._is_rule_file(item['name']):
                        # Download and import file
                        file_result = await self.import_from_url(
                            item['download_url'],
                            options=options
                        )
                        all_results.append(file_result)
                        
            else:
                # Single file
                if contents['type'] == 'file':
                    file_result = await self.import_from_url(
                        contents['download_url'],
                        options=options
                    )
                    all_results.append(file_result)
                    
            # Merge results
            return self._merge_import_results(all_results, f"github:{repo}/{path}")
            
        except Exception as e:
            return ImportResult(
                total_processed=0,
                successful=0,
                failed=1,
                skipped=0,
                imported_rules=[],
                errors=[{'github': f"{repo}/{path}", 'error': str(e)}],
                warnings=[],
                import_time=datetime.now(),
                source=f"github:{repo}/{path}"
            )
            
    async def import_rule_pack(
        self,
        pack_name: str,
        options: Optional[Dict[str, Any]] = None
    ) -> ImportResult:
        """Import predefined rule pack"""
        options = options or {}
        
        if pack_name not in self.rule_sources:
            return ImportResult(
                total_processed=0,
                successful=0,
                failed=1,
                skipped=0,
                imported_rules=[],
                errors=[{'pack': pack_name, 'error': 'Unknown rule pack'}],
                warnings=[],
                import_time=datetime.now(),
                source=f"pack:{pack_name}"
            )
            
        # Get pack URL
        pack_url = self.rule_sources[pack_name]
        
        # Special handling for different packs
        if pack_name == 'yara-rules':
            return await self._import_yara_rules_pack(pack_url, options)
        elif pack_name == 'sigma':
            return await self._import_sigma_pack(pack_url, options)
        elif pack_name == 'elastic':
            return await self._import_elastic_pack(pack_url, options)
        else:
            return await self.import_from_url(pack_url, options=options)
            
    async def _import_archive(
        self,
        archive_path: Path,
        options: Dict[str, Any]
    ) -> ImportResult:
        """Import rules from archive file"""
        temp_dir = tempfile.mkdtemp()
        
        try:
            # Extract archive
            if archive_path.suffix == '.zip':
                with zipfile.ZipFile(archive_path, 'r') as zf:
                    zf.extractall(temp_dir)
            elif archive_path.suffix in ['.tar', '.gz', '.tgz']:
                with tarfile.open(archive_path, 'r:*') as tf:
                    tf.extractall(temp_dir)
            else:
                raise ValueError(f"Unsupported archive format: {archive_path.suffix}")
                
            # Import all rule files
            all_results = []
            
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    if self._is_rule_file(file):
                        file_path = os.path.join(root, file)
                        result = await self.import_from_file(file_path, options=options)
                        all_results.append(result)
                        
            # Merge results
            return self._merge_import_results(all_results, str(archive_path))
            
        except Exception as e:
            return ImportResult(
                total_processed=0,
                successful=0,
                failed=1,
                skipped=0,
                imported_rules=[],
                errors=[{'archive': str(archive_path), 'error': str(e)}],
                warnings=[],
                import_time=datetime.now(),
                source=str(archive_path)
            )
        finally:
            # Clean up
            shutil.rmtree(temp_dir)
            
    async def _import_yara_file(
        self,
        file_path: Path,
        options: Dict[str, Any]
    ) -> ImportResult:
        """Import YARA rules from file"""
        imported_rules = []
        errors = []
        warnings = []
        skipped = 0
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
                
            # Parse YARA rules
            rules = self._parse_yara_content(content)
            
            for rule_data in rules:
                try:
                    # Validate rule
                    validation = await self.validator.validate_yara_rule(rule_data['content'])
                    
                    if not validation.valid:
                        if options.get('skip_invalid', False):
                            skipped += 1
                            warnings.append(f"Skipped invalid rule: {rule_data['name']}")
                            continue
                        else:
                            errors.append({
                                'rule': rule_data['name'],
                                'errors': validation.errors
                            })
                            continue
                            
                    # Check for duplicates
                    if options.get('skip_duplicates', True):
                        existing = await self._check_duplicate(rule_data)
                        if existing:
                            skipped += 1
                            warnings.append(f"Skipped duplicate rule: {rule_data['name']}")
                            continue
                            
                    # Create rule
                    rule = await self.rule_manager.create_rule(rule_data)
                    imported_rules.append(rule)
                    
                except Exception as e:
                    errors.append({
                        'rule': rule_data.get('name', 'Unknown'),
                        'error': str(e)
                    })
                    
        except Exception as e:
            errors.append({
                'file': str(file_path),
                'error': str(e)
            })
            
        return ImportResult(
            total_processed=len(rules) if 'rules' in locals() else 0,
            successful=len(imported_rules),
            failed=len(errors),
            skipped=skipped,
            imported_rules=imported_rules,
            errors=errors,
            warnings=warnings,
            import_time=datetime.now(),
            source=str(file_path)
        )
        
    async def _import_sigma_file(
        self,
        file_path: Path,
        options: Dict[str, Any]
    ) -> ImportResult:
        """Import Sigma rules from file"""
        imported_rules = []
        errors = []
        warnings = []
        skipped = 0
        
        try:
            # Load YAML file(s)
            with open(file_path, 'r') as f:
                documents = list(yaml.safe_load_all(f))
                
            for doc_idx, doc in enumerate(documents):
                if not isinstance(doc, dict):
                    continue
                    
                try:
                    # Convert to rule data
                    rule_data = {
                        'name': doc.get('title', f'Sigma Rule {doc_idx}'),
                        'type': 'sigma',
                        'content': yaml.dump(doc),
                        'category': self._get_sigma_category(doc),
                        'description': doc.get('description', ''),
                        'author': doc.get('author', 'Unknown'),
                        'tags': doc.get('tags', []),
                        'severity': doc.get('level', 'medium'),
                        'references': doc.get('references', []),
                        'false_positive': doc.get('falsepositives', []),
                        'metadata': {
                            'sigma_id': doc.get('id'),
                            'status': doc.get('status'),
                            'date': doc.get('date')
                        }
                    }
                    
                    # Validate rule
                    validation = await self.validator.validate_sigma_rule(rule_data['content'])
                    
                    if not validation.valid:
                        if options.get('skip_invalid', False):
                            skipped += 1
                            warnings.append(f"Skipped invalid rule: {rule_data['name']}")
                            continue
                        else:
                            errors.append({
                                'rule': rule_data['name'],
                                'errors': validation.errors
                            })
                            continue
                            
                    # Check for duplicates
                    if options.get('skip_duplicates', True):
                        existing = await self._check_duplicate(rule_data)
                        if existing:
                            skipped += 1
                            warnings.append(f"Skipped duplicate rule: {rule_data['name']}")
                            continue
                            
                    # Create rule
                    rule = await self.rule_manager.create_rule(rule_data)
                    imported_rules.append(rule)
                    
                except Exception as e:
                    errors.append({
                        'rule': doc.get('title', f'Document {doc_idx}'),
                        'error': str(e)
                    })
                    
        except Exception as e:
            errors.append({
                'file': str(file_path),
                'error': str(e)
            })
            
        return ImportResult(
            total_processed=len(documents) if 'documents' in locals() else 0,
            successful=len(imported_rules),
            failed=len(errors),
            skipped=skipped,
            imported_rules=imported_rules,
            errors=errors,
            warnings=warnings,
            import_time=datetime.now(),
            source=str(file_path)
        )
        
    async def _import_json_file(
        self,
        file_path: Path,
        options: Dict[str, Any]
    ) -> ImportResult:
        """Import rules from JSON file"""
        imported_rules = []
        errors = []
        warnings = []
        skipped = 0
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                
            # Handle single rule or array of rules
            if isinstance(data, dict):
                rules_data = [data]
            elif isinstance(data, list):
                rules_data = data
            else:
                raise ValueError("JSON must contain rule object or array of rules")
                
            for rule_data in rules_data:
                try:
                    # Ensure required fields
                    if 'name' not in rule_data or 'content' not in rule_data:
                        errors.append({
                            'rule': rule_data.get('name', 'Unknown'),
                            'error': 'Missing required fields: name, content'
                        })
                        continue
                        
                    # Set defaults
                    rule_data.setdefault('type', options.get('default_type', 'custom'))
                    rule_data.setdefault('category', 'imported')
                    rule_data.setdefault('severity', 'medium')
                    
                    # Validate based on type
                    if rule_data['type'] == 'yara':
                        validation = await self.validator.validate_yara_rule(rule_data['content'])
                    elif rule_data['type'] == 'sigma':
                        validation = await self.validator.validate_sigma_rule(rule_data['content'])
                    else:
                        validation = await self.validator.validate_custom_rule(rule_data['content'])
                        
                    if not validation.valid and not options.get('skip_invalid', False):
                        errors.append({
                            'rule': rule_data['name'],
                            'errors': validation.errors
                        })
                        continue
                        
                    # Check for duplicates
                    if options.get('skip_duplicates', True):
                        existing = await self._check_duplicate(rule_data)
                        if existing:
                            skipped += 1
                            warnings.append(f"Skipped duplicate rule: {rule_data['name']}")
                            continue
                            
                    # Create rule
                    rule = await self.rule_manager.create_rule(rule_data)
                    imported_rules.append(rule)
                    
                except Exception as e:
                    errors.append({
                        'rule': rule_data.get('name', 'Unknown'),
                        'error': str(e)
                    })
                    
        except Exception as e:
            errors.append({
                'file': str(file_path),
                'error': str(e)
            })
            
        return ImportResult(
            total_processed=len(rules_data) if 'rules_data' in locals() else 0,
            successful=len(imported_rules),
            failed=len(errors),
            skipped=skipped,
            imported_rules=imported_rules,
            errors=errors,
            warnings=warnings,
            import_time=datetime.now(),
            source=str(file_path)
        )
        
    async def _import_xml_file(
        self,
        file_path: Path,
        options: Dict[str, Any]
    ) -> ImportResult:
        """Import rules from XML file"""
        imported_rules = []
        errors = []
        warnings = []
        skipped = 0
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Find rule elements
            rules_data = []
            
            # Common XML structures
            for rule_elem in root.findall('.//rule'):
                rule_data = self._parse_xml_rule(rule_elem)
                if rule_data:
                    rules_data.append(rule_data)
                    
            # Snort/Suricata format
            for rule_elem in root.findall('.//snort-rule'):
                rule_data = self._parse_snort_xml(rule_elem)
                if rule_data:
                    rules_data.append(rule_data)
                    
            # Process rules
            for rule_data in rules_data:
                try:
                    # Create rule
                    rule = await self.rule_manager.create_rule(rule_data)
                    imported_rules.append(rule)
                    
                except Exception as e:
                    errors.append({
                        'rule': rule_data.get('name', 'Unknown'),
                        'error': str(e)
                    })
                    
        except Exception as e:
            errors.append({
                'file': str(file_path),
                'error': str(e)
            })
            
        return ImportResult(
            total_processed=len(rules_data) if 'rules_data' in locals() else 0,
            successful=len(imported_rules),
            failed=len(errors),
            skipped=skipped,
            imported_rules=imported_rules,
            errors=errors,
            warnings=warnings,
            import_time=datetime.now(),
            source=str(file_path)
        )
        
    async def _import_csv_file(
        self,
        file_path: Path,
        options: Dict[str, Any]
    ) -> ImportResult:
        """Import rules from CSV file"""
        imported_rules = []
        errors = []
        warnings = []
        skipped = 0
        
        try:
            with open(file_path, 'r', newline='') as f:
                reader = csv.DictReader(f)
                
                for row_idx, row in enumerate(reader):
                    try:
                        # Map CSV columns to rule fields
                        rule_data = {
                            'name': row.get('name', row.get('rule_name', f'Rule {row_idx}')),
                            'type': row.get('type', options.get('default_type', 'custom')),
                            'content': row.get('content', row.get('rule', '')),
                            'category': row.get('category', 'imported'),
                            'description': row.get('description', ''),
                            'severity': row.get('severity', row.get('level', 'medium')),
                            'tags': [t.strip() for t in row.get('tags', '').split(',') if t.strip()],
                            'enabled': row.get('enabled', 'true').lower() == 'true'
                        }
                        
                        if not rule_data['content']:
                            errors.append({
                                'row': row_idx + 2,  # Account for header
                                'error': 'No rule content found'
                            })
                            continue
                            
                        # Create rule
                        rule = await self.rule_manager.create_rule(rule_data)
                        imported_rules.append(rule)
                        
                    except Exception as e:
                        errors.append({
                            'row': row_idx + 2,
                            'error': str(e)
                        })
                        
        except Exception as e:
            errors.append({
                'file': str(file_path),
                'error': str(e)
            })
            
        return ImportResult(
            total_processed=row_idx + 1 if 'row_idx' in locals() else 0,
            successful=len(imported_rules),
            failed=len(errors),
            skipped=skipped,
            imported_rules=imported_rules,
            errors=errors,
            warnings=warnings,
            import_time=datetime.now(),
            source=str(file_path)
        )
        
    async def _import_yara_rules_pack(
        self,
        pack_url: str,
        options: Dict[str, Any]
    ) -> ImportResult:
        """Import YARA rules pack"""
        # Download and extract
        temp_dir = tempfile.mkdtemp()
        
        try:
            # Download pack
            async with aiohttp.ClientSession() as session:
                async with session.get(pack_url) as response:
                    content = await response.read()
                    
            # Save and extract
            zip_path = os.path.join(temp_dir, 'yara-rules.zip')
            with open(zip_path, 'wb') as f:
                f.write(content)
                
            with zipfile.ZipFile(zip_path, 'r') as zf:
                zf.extractall(temp_dir)
                
            # Import specific categories
            categories = options.get('categories', ['malware', 'exploit_kits', 'cve_rules'])
            all_results = []
            
            for category in categories:
                category_path = os.path.join(temp_dir, 'rules-master', category)
                if os.path.exists(category_path):
                    for file in os.listdir(category_path):
                        if file.endswith(('.yar', '.yara')):
                            file_path = os.path.join(category_path, file)
                            result = await self.import_from_file(file_path, 'yara', options)
                            all_results.append(result)
                            
            return self._merge_import_results(all_results, "pack:yara-rules")
            
        finally:
            shutil.rmtree(temp_dir)
            
    async def _import_sigma_pack(
        self,
        pack_url: str,
        options: Dict[str, Any]
    ) -> ImportResult:
        """Import Sigma rules pack"""
        # Similar to YARA pack but for Sigma rules
        temp_dir = tempfile.mkdtemp()
        
        try:
            # Download pack
            async with aiohttp.ClientSession() as session:
                async with session.get(pack_url) as response:
                    content = await response.read()
                    
            # Save and extract
            zip_path = os.path.join(temp_dir, 'sigma.zip')
            with open(zip_path, 'wb') as f:
                f.write(content)
                
            with zipfile.ZipFile(zip_path, 'r') as zf:
                zf.extractall(temp_dir)
                
            # Import rules from specific directories
            categories = options.get('categories', ['windows', 'linux', 'network'])
            all_results = []
            
            rules_dir = os.path.join(temp_dir, 'sigma-master', 'rules')
            for category in categories:
                category_path = os.path.join(rules_dir, category)
                if os.path.exists(category_path):
                    for root, dirs, files in os.walk(category_path):
                        for file in files:
                            if file.endswith(('.yml', '.yaml')):
                                file_path = os.path.join(root, file)
                                result = await self.import_from_file(file_path, 'sigma', options)
                                all_results.append(result)
                                
            return self._merge_import_results(all_results, "pack:sigma")
            
        finally:
            shutil.rmtree(temp_dir)
            
    async def _import_elastic_pack(
        self,
        pack_url: str,
        options: Dict[str, Any]
    ) -> ImportResult:
        """Import Elastic detection rules"""
        # Implementation for Elastic rules
        # These are typically in TOML format with KQL queries
        return ImportResult(
            total_processed=0,
            successful=0,
            failed=0,
            skipped=0,
            imported_rules=[],
            errors=[{'pack': 'elastic', 'error': 'Elastic pack import not yet implemented'}],
            warnings=[],
            import_time=datetime.now(),
            source="pack:elastic"
        )
        
    def _parse_yara_content(self, content: str) -> List[Dict[str, Any]]:
        """Parse YARA rules from content"""
        rules = []
        
        # Regular expression for YARA rules
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
            description = ''
            author = 'Unknown'
            
            if meta_match:
                meta_text = meta_match.group(1)
                for line in meta_text.strip().split('\n'):
                    if '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip().strip('"')
                        metadata[key] = value
                        
                        if key == 'description':
                            description = value
                        elif key == 'author':
                            author = value
                            
            rules.append({
                'name': rule_name,
                'type': 'yara',
                'content': match.group(0),
                'category': metadata.get('category', 'general'),
                'description': description,
                'author': author,
                'tags': tags,
                'severity': metadata.get('severity', 'medium'),
                'metadata': metadata
            })
            
        return rules
        
    def _get_sigma_category(self, sigma_rule: Dict[str, Any]) -> str:
        """Determine category for Sigma rule"""
        logsource = sigma_rule.get('logsource', {})
        
        if 'product' in logsource:
            return logsource['product']
        elif 'service' in logsource:
            return logsource['service']
        elif 'category' in logsource:
            return logsource['category']
        else:
            return 'general'
            
    def _parse_xml_rule(self, rule_elem: ET.Element) -> Optional[Dict[str, Any]]:
        """Parse generic XML rule element"""
        rule_data = {
            'type': 'custom',
            'category': 'imported'
        }
        
        # Common XML attribute/element names
        name_attrs = ['name', 'id', 'title']
        content_attrs = ['content', 'rule', 'pattern', 'query']
        
        # Extract name
        for attr in name_attrs:
            if attr in rule_elem.attrib:
                rule_data['name'] = rule_elem.attrib[attr]
                break
            elem = rule_elem.find(attr)
            if elem is not None and elem.text:
                rule_data['name'] = elem.text
                break
                
        # Extract content
        for attr in content_attrs:
            if attr in rule_elem.attrib:
                rule_data['content'] = rule_elem.attrib[attr]
                break
            elem = rule_elem.find(attr)
            if elem is not None and elem.text:
                rule_data['content'] = elem.text
                break
                
        # Extract other fields
        if rule_elem.find('description') is not None:
            rule_data['description'] = rule_elem.find('description').text or ''
            
        if rule_elem.find('severity') is not None:
            rule_data['severity'] = rule_elem.find('severity').text or 'medium'
            
        if rule_elem.find('tags') is not None:
            tags_elem = rule_elem.find('tags')
            if tags_elem.text:
                rule_data['tags'] = [t.strip() for t in tags_elem.text.split(',')]
                
        # Only return if we have minimum required fields
        if 'name' in rule_data and 'content' in rule_data:
            return rule_data
            
        return None
        
    def _parse_snort_xml(self, rule_elem: ET.Element) -> Optional[Dict[str, Any]]:
        """Parse Snort/Suricata XML rule"""
        # Implementation for Snort/Suricata specific XML format
        return None
        
    def _is_rule_file(self, filename: str) -> bool:
        """Check if file is likely a rule file"""
        rule_extensions = ['.yar', '.yara', '.yml', '.yaml', '.json', '.xml', '.rules']
        return any(filename.lower().endswith(ext) for ext in rule_extensions)
        
    async def _check_duplicate(self, rule_data: Dict[str, Any]) -> bool:
        """Check if rule already exists"""
        # Calculate content hash
        content_hash = hashlib.sha256(
            rule_data['content'].encode('utf-8')
        ).hexdigest()
        
        # Search for existing rules with same hash
        existing_rules = await self.rule_manager.list_rules(
            search=content_hash,
            limit=1
        )
        
        return existing_rules['total'] > 0
        
    def _merge_import_results(
        self,
        results: List[ImportResult],
        source: str
    ) -> ImportResult:
        """Merge multiple import results"""
        total_processed = sum(r.total_processed for r in results)
        successful = sum(r.successful for r in results)
        failed = sum(r.failed for r in results)
        skipped = sum(r.skipped for r in results)
        
        imported_rules = []
        errors = []
        warnings = []
        
        for result in results:
            imported_rules.extend(result.imported_rules)
            errors.extend(result.errors)
            warnings.extend(result.warnings)
            
        return ImportResult(
            total_processed=total_processed,
            successful=successful,
            failed=failed,
            skipped=skipped,
            imported_rules=imported_rules,
            errors=errors,
            warnings=warnings,
            import_time=datetime.now(),
            source=source
        )


# Convenience functions
async def import_rules(
    source: str,
    rule_manager: RuleManager,
    options: Optional[Dict[str, Any]] = None
) -> ImportResult:
    """Import rules from various sources"""
    importer = RuleImporter(rule_manager)
    
    # Determine source type
    if source.startswith(('http://', 'https://')):
        return await importer.import_from_url(source, options=options)
    elif source.startswith('github:'):
        # Parse github:owner/repo/path
        parts = source[7:].split('/', 2)
        repo = f"{parts[0]}/{parts[1]}"
        path = parts[2] if len(parts) > 2 else ''
        return await importer.import_from_github(repo, path, options=options)
    elif source.startswith('pack:'):
        pack_name = source[5:]
        return await importer.import_rule_pack(pack_name, options=options)
    else:
        # Assume file path
        return await importer.import_from_file(source, options=options)

async def validate_import_file(
    file_path: str,
    rule_type: Optional[str] = None
) -> Dict[str, Any]:
    """Validate rules in file before import"""
    validator = RuleValidator()
    importer = RuleImporter(None)  # Don't need manager for validation
    
    # Parse file
    extension = Path(file_path).suffix.lower()
    
    if extension in ['.yar', '.yara'] or rule_type == 'yara':
        with open(file_path, 'r') as f:
            content = f.read()
        rules = importer._parse_yara_content(content)
        
        validation_results = []
        for rule in rules:
            result = await validator.validate_yara_rule(rule['content'])
            validation_results.append({
                'name': rule['name'],
                'valid': result.valid,
                'errors': result.errors,
                'warnings': result.warnings
            })
            
    elif extension in ['.yml', '.yaml'] or rule_type == 'sigma':
        with open(file_path, 'r') as f:
            documents = list(yaml.safe_load_all(f))
            
        validation_results = []
        for doc in documents:
            if isinstance(doc, dict):
                result = await validator.validate_sigma_rule(yaml.dump(doc))
                validation_results.append({
                    'name': doc.get('title', 'Unnamed'),
                    'valid': result.valid,
                    'errors': result.errors,
                    'warnings': result.warnings
                })
                
    else:
        validation_results = []
        
    return {
        'file': file_path,
        'total_rules': len(validation_results),
        'valid_rules': sum(1 for r in validation_results if r['valid']),
        'invalid_rules': sum(1 for r in validation_results if not r['valid']),
        'results': validation_results
    }