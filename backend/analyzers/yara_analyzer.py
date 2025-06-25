"""
YARA Rule Engine - Detects malware and suspicious patterns using YARA rules

This module provides YARA-based analysis capabilities for file content,
memory dumps, and extracted strings.
"""

import os
import logging
import asyncio
from typing import Dict, List, Optional, Any, Set
from pathlib import Path
import yara
import json
from datetime import datetime
import hashlib
from concurrent.futures import ThreadPoolExecutor
import mmap
import tempfile

logger = logging.getLogger(__name__)

class YARAAnalyzer:
    """YARA rule engine for malware and pattern detection"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.rules_path = Path(config.get("rules_path", "rules/yara"))
        self.compiled_rules = None
        self.rule_metadata = {}
        self.external_vars = config.get("external_vars", {})
        self.scan_timeout = config.get("scan_timeout", 120)  # seconds
        self.max_file_size = config.get("max_file_size", 500 * 1024 * 1024)  # 500MB
        self.fast_mode = config.get("fast_mode", False)
        
        # Thread pool for CPU-intensive YARA scanning
        self.executor = ThreadPoolExecutor(max_workers=config.get("workers", 2))
        
        # Performance optimizations
        self.enable_profiling = config.get("enable_profiling", False)
        self.match_limit = config.get("match_limit", 1000)
        
        # Initialize rules
        self._load_rules()
    
    def _load_rules(self):
        """Load and compile YARA rules from configured paths"""
        try:
            rule_files = {}
            rule_count = 0
            
            # Scan for YARA rule files
            for rule_file in self.rules_path.rglob("*.yar"):
                namespace = rule_file.stem
                rule_files[namespace] = str(rule_file)
                rule_count += 1
                
                # Extract rule metadata
                self._extract_rule_metadata(rule_file)
            
            # Also check for .yara files
            for rule_file in self.rules_path.rglob("*.yara"):
                namespace = rule_file.stem
                rule_files[namespace] = str(rule_file)
                rule_count += 1
                self._extract_rule_metadata(rule_file)
            
            if not rule_files:
                logger.warning(f"No YARA rules found in {self.rules_path}")
                # Load default rules
                self._create_default_rules()
                return
            
            # Compile rules
            self.compiled_rules = yara.compile(filepaths=rule_files)
            logger.info(f"Loaded {rule_count} YARA rule files")
            
        except Exception as e:
            logger.error(f"Failed to load YARA rules: {e}")
            # Fall back to default rules
            self._create_default_rules()
    
    def _extract_rule_metadata(self, rule_file: Path):
        """Extract metadata from YARA rule file"""
        try:
            with open(rule_file, 'r') as f:
                content = f.read()
                
            # Simple extraction of rule names and metadata
            import re
            rule_pattern = r'rule\s+(\w+).*?{(.*?)}'
            matches = re.finditer(rule_pattern, content, re.DOTALL)
            
            for match in matches:
                rule_name = match.group(1)
                rule_body = match.group(2)
                
                # Extract metadata section
                meta_pattern = r'meta:(.*?)(?:strings:|condition:)'
                meta_match = re.search(meta_pattern, rule_body, re.DOTALL)
                
                if meta_match:
                    metadata = {}
                    meta_content = meta_match.group(1)
                    
                    # Parse metadata fields
                    field_pattern = r'(\w+)\s*=\s*"([^"]*)"'
                    for field in re.finditer(field_pattern, meta_content):
                        metadata[field.group(1)] = field.group(2)
                    
                    self.rule_metadata[rule_name] = metadata
                    
        except Exception as e:
            logger.debug(f"Could not extract metadata from {rule_file}: {e}")
    
    def _create_default_rules(self):
        """Create default YARA rules if none are found"""
        logger.info("Creating default YARA rules")
        
        default_rules = '''
        rule Suspicious_PowerShell_Command
        {
            meta:
                description = "Detects suspicious PowerShell commands"
                severity = "high"
                category = "execution"
                mitre = "T1059.001"
            
            strings:
                $ps1 = "powershell" nocase
                $ps2 = "pwsh" nocase
                $cmd1 = "-EncodedCommand" nocase
                $cmd2 = "-ExecutionPolicy Bypass" nocase
                $cmd3 = "Invoke-Expression" nocase
                $cmd4 = "IEX" nocase
                $cmd5 = "DownloadString" nocase
                $cmd6 = "FromBase64String" nocase
                
            condition:
                any of ($ps*) and any of ($cmd*)
        }
        
        rule Ransomware_FileExtensions
        {
            meta:
                description = "Detects common ransomware file extensions"
                severity = "critical"
                category = "ransomware"
                mitre = "T1486"
            
            strings:
                $ext1 = ".locked" nocase
                $ext2 = ".encrypted" nocase
                $ext3 = ".crypto" nocase
                $ext4 = ".enc" nocase
                $ext5 = ".lock" nocase
                $ext6 = ".cerber" nocase
                $ext7 = ".locky" nocase
                $ext8 = ".zepto" nocase
                $ext9 = ".odin" nocase
                $ext10 = ".aesir" nocase
                $ext11 = ".WNCRY" nocase
                
            condition:
                3 of them
        }
        
        rule Malicious_Document_Macros
        {
            meta:
                description = "Detects potentially malicious document macros"
                severity = "high"
                category = "macro"
                mitre = "T1566.001"
            
            strings:
                $macro1 = "AutoOpen"
                $macro2 = "AutoExec"
                $macro3 = "AutoClose"
                $macro4 = "Document_Open"
                $macro5 = "DocumentOpen"
                $shell1 = "Shell"
                $shell2 = "CreateObject"
                $shell3 = "WScript.Shell"
                $shell4 = "cmd.exe"
                $download = "URLDownloadToFile"
                
            condition:
                any of ($macro*) and any of ($shell*) or $download
        }
        
        rule Suspicious_Network_Commands
        {
            meta:
                description = "Detects suspicious network reconnaissance commands"
                severity = "medium"
                category = "recon"
                mitre = "T1018"
            
            strings:
                $net1 = "net view" nocase
                $net2 = "net user" nocase
                $net3 = "net group" nocase
                $net4 = "net localgroup" nocase
                $net5 = "netstat -an" nocase
                $net6 = "ipconfig /all" nocase
                $net7 = "arp -a" nocase
                $net8 = "nslookup" nocase
                $net9 = "ping -n" nocase
                $net10 = "tracert" nocase
                
            condition:
                3 of them
        }
        
        rule Cryptocurrency_Miner
        {
            meta:
                description = "Detects cryptocurrency mining indicators"
                severity = "high"
                category = "cryptominer"
                mitre = "T1496"
            
            strings:
                $miner1 = "stratum+tcp://" nocase
                $miner2 = "\"pool_address\"" nocase
                $miner3 = "\"wallet_address\"" nocase
                $miner4 = "xmrig" nocase
                $miner5 = "minerd" nocase
                $miner6 = "cpuminer" nocase
                $miner7 = "\"mining.pool\"" nocase
                $crypto1 = "monero" nocase
                $crypto2 = "bitcoin" nocase
                $crypto3 = "ethereum" nocase
                
            condition:
                2 of ($miner*) or (any of ($miner*) and any of ($crypto*))
        }
        
        rule Webshell_Indicators
        {
            meta:
                description = "Detects potential webshell code"
                severity = "critical"
                category = "webshell"
                mitre = "T1505.003"
            
            strings:
                $php1 = "<?php" nocase
                $asp1 = "<%eval" nocase
                $jsp1 = "<%@page" nocase
                $exec1 = "exec(" nocase
                $exec2 = "system(" nocase
                $exec3 = "shell_exec(" nocase
                $exec4 = "passthru(" nocase
                $exec5 = "eval(" nocase
                $upload = "move_uploaded_file" nocase
                $assert = "assert(" nocase
                
            condition:
                (any of ($php*) or any of ($asp*) or any of ($jsp*)) and 
                (2 of ($exec*) or $upload or $assert)
        }
        
        rule Data_Exfiltration_Pattern
        {
            meta:
                description = "Detects potential data exfiltration patterns"
                severity = "high"
                category = "exfiltration"
                mitre = "T1041"
            
            strings:
                $curl = "curl" nocase
                $wget = "wget" nocase
                $post1 = "POST /" nocase
                $post2 = "Content-Type: multipart/form-data"
                $upload1 = "upload.php"
                $upload2 = "/upload/"
                $base64 = "base64" nocase
                $zip = "7z a -p" nocase
                $tar = "tar -czf" nocase
                
            condition:
                (any of ($curl, $wget) and any of ($post*, $upload*)) or
                ($base64 and any of ($curl, $wget)) or
                (any of ($zip, $tar) and any of ($curl, $wget))
        }
        
        rule Persistence_Registry_Keys
        {
            meta:
                description = "Detects Windows registry persistence mechanisms"
                severity = "high"
                category = "persistence"
                mitre = "T1547.001"
            
            strings:
                $reg1 = "CurrentVersion\\\\Run" nocase
                $reg2 = "CurrentVersion\\\\RunOnce" nocase
                $reg3 = "CurrentVersion\\\\RunServices" nocase
                $reg4 = "CurrentVersion\\\\RunServicesOnce" nocase
                $reg5 = "CurrentVersion\\\\Policies\\\\Explorer\\\\Run" nocase
                $reg6 = "CurrentControlSet\\\\Services" nocase
                $reg7 = "Software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon" nocase
                $cmd1 = "reg add" nocase
                $cmd2 = "regedit" nocase
                
            condition:
                any of ($cmd*) and any of ($reg*)
        }
        
        rule Credential_Dumping
        {
            meta:
                description = "Detects credential dumping tools and techniques"
                severity = "critical"
                category = "credential_access"
                mitre = "T1003"
            
            strings:
                $tool1 = "mimikatz" nocase
                $tool2 = "lazagne" nocase
                $tool3 = "pwdump" nocase
                $tool4 = "gsecdump" nocase
                $lsass1 = "lsass.exe" nocase
                $lsass2 = "sekurlsa::" nocase
                $lsass3 = "privilege::debug" nocase
                $sam = "sam.hive" nocase
                $ntds = "ntds.dit" nocase
                
            condition:
                any of ($tool*) or 
                (2 of ($lsass*)) or 
                ($sam and $ntds)
        }
        
        rule Suspicious_Script_Obfuscation
        {
            meta:
                description = "Detects obfuscated scripts and commands"
                severity = "medium"
                category = "obfuscation"
                mitre = "T1027"
            
            strings:
                $enc1 = "FromBase64String" nocase
                $enc2 = "Convert.ToBase64String" nocase
                $enc3 = "[System.Text.Encoding]::UTF8.GetString" nocase
                $enc4 = "gzip" nocase
                $enc5 = "-EncodedCommand" nocase
                $obf1 = /[a-zA-Z0-9+\/]{50,}=/ // Base64 pattern
                $obf2 = /%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}/ // URL encoding
                
            condition:
                2 of ($enc*) or 
                (any of ($enc*) and any of ($obf*))
        }
        '''
        
        # Compile default rules
        self.compiled_rules = yara.compile(source=default_rules)
        
        # Extract metadata from default rules
        for rule in ["Suspicious_PowerShell_Command", "Ransomware_FileExtensions",
                    "Malicious_Document_Macros", "Suspicious_Network_Commands",
                    "Cryptocurrency_Miner", "Webshell_Indicators",
                    "Data_Exfiltration_Pattern", "Persistence_Registry_Keys",
                    "Credential_Dumping", "Suspicious_Script_Obfuscation"]:
            self.rule_metadata[rule] = {
                "source": "default",
                "created": datetime.utcnow().isoformat()
            }
    
    async def analyze_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Analyze a file using YARA rules
        
        Args:
            file_path: Path to file to analyze
            
        Returns:
            List of YARA matches with metadata
        """
        if not self.compiled_rules:
            logger.error("No YARA rules loaded")
            return []
        
        file_path = Path(file_path)
        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            return []
        
        # Check file size
        file_size = file_path.stat().st_size
        if file_size > self.max_file_size:
            logger.warning(f"File too large for YARA scan: {file_size} bytes")
            return await self._analyze_large_file(file_path)
        
        # Run YARA scan in thread pool
        loop = asyncio.get_event_loop()
        matches = await loop.run_in_executor(
            self.executor,
            self._scan_file,
            str(file_path)
        )
        
        return self._process_matches(matches, str(file_path))
    
    def _scan_file(self, file_path: str) -> List:
        """Perform YARA scan on file (runs in thread pool)"""
        try:
            # Use memory-mapped file for better performance
            with open(file_path, 'rb') as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mmapped_file:
                    matches = self.compiled_rules.match(
                        data=mmapped_file,
                        timeout=self.scan_timeout,
                        externals=self.external_vars
                    )
            return matches
            
        except yara.TimeoutError:
            logger.warning(f"YARA scan timeout for {file_path}")
            return []
        except Exception as e:
            logger.error(f"YARA scan error for {file_path}: {e}")
            return []
    
    async def _analyze_large_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Analyze large files in chunks"""
        matches = []
        chunk_size = 50 * 1024 * 1024  # 50MB chunks
        
        try:
            with open(file_path, 'rb') as f:
                chunk_num = 0
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    
                    # Scan chunk
                    chunk_matches = await self._scan_data(chunk, f"chunk_{chunk_num}")
                    for match in chunk_matches:
                        match["chunk"] = chunk_num
                        match["offset"] += chunk_num * chunk_size
                    matches.extend(chunk_matches)
                    
                    chunk_num += 1
                    
                    # Limit scanning for very large files
                    if chunk_num > 20:  # Max 1GB
                        logger.warning("File too large, truncating YARA analysis")
                        break
                        
        except Exception as e:
            logger.error(f"Error analyzing large file: {e}")
        
        return matches
    
    async def analyze_strings(self, strings: List[str]) -> List[Dict[str, Any]]:
        """
        Analyze extracted strings using YARA rules
        
        Args:
            strings: List of strings to analyze
            
        Returns:
            List of YARA matches
        """
        if not self.compiled_rules or not strings:
            return []
        
        # Combine strings for analysis
        combined_data = "\n".join(strings)
        
        # Analyze combined data
        return await self._scan_data(combined_data.encode(), "strings")
    
    async def _scan_data(self, data: bytes, identifier: str) -> List[Dict[str, Any]]:
        """Scan raw data with YARA rules"""
        loop = asyncio.get_event_loop()
        
        # Create temporary file for data
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name
        
        try:
            matches = await loop.run_in_executor(
                self.executor,
                self._scan_file,
                tmp_path
            )
            return self._process_matches(matches, identifier)
        finally:
            os.unlink(tmp_path)
    
    def _process_matches(self, matches: List, identifier: str) -> List[Dict[str, Any]]:
        """Process YARA matches and enrich with metadata"""
        results = []
        
        for match in matches:
            # Get rule metadata
            metadata = self.rule_metadata.get(match.rule, {})
            
            # Determine severity
            severity = metadata.get("severity", "medium")
            if match.rule in ["Ransomware_FileExtensions", "Webshell_Indicators", 
                             "Credential_Dumping"]:
                severity = "critical"
            
            # Build match result
            result = {
                "rule": match.rule,
                "namespace": match.namespace,
                "tags": match.tags,
                "severity": severity,
                "confidence": self._calculate_confidence(match),
                "description": metadata.get("description", f"YARA rule {match.rule} matched"),
                "category": metadata.get("category", "unknown"),
                "mitre_technique": metadata.get("mitre", ""),
                "identifier": identifier,
                "matches": []
            }
            
            # Add string matches
            for string_match in match.strings:
                offset, identifier, data = string_match
                
                # Safely decode data
                try:
                    if isinstance(data, bytes):
                        decoded_data = data.decode('utf-8', errors='replace')
                    else:
                        decoded_data = str(data)
                except:
                    decoded_data = repr(data)
                
                result["matches"].append({
                    "offset": offset,
                    "identifier": identifier,
                    "data": decoded_data[:200]  # Limit match data
                })
            
            # Add metadata from rule
            if hasattr(match, 'meta'):
                result["rule_metadata"] = match.meta
            
            results.append(result)
        
        return results
    
    def _calculate_confidence(self, match) -> float:
        """Calculate confidence score for a YARA match"""
        confidence = 0.8  # Base confidence
        
        # Adjust based on number of string matches
        if len(match.strings) > 5:
            confidence += 0.1
        elif len(match.strings) > 10:
            confidence += 0.15
        
        # Adjust based on rule tags
        if "APT" in match.tags:
            confidence += 0.1
        if "experimental" in match.tags:
            confidence -= 0.2
        
        # Cap at 1.0
        return min(1.0, confidence)
    
    async def update_rules(self, rule_source: str, rule_content: str) -> bool:
        """
        Update YARA rules from external source
        
        Args:
            rule_source: Source identifier (e.g., 'custom', 'community')
            rule_content: YARA rule content
            
        Returns:
            True if rules updated successfully
        """
        try:
            # Validate rules by compiling
            test_rules = yara.compile(source=rule_content)
            
            # Save to rules directory
            rule_file = self.rules_path / f"{rule_source}.yar"
            with open(rule_file, 'w') as f:
                f.write(rule_content)
            
            # Reload all rules
            self._load_rules()
            
            logger.info(f"Updated YARA rules from {rule_source}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update YARA rules: {e}")
            return False
    
    def get_rule_stats(self) -> Dict[str, Any]:
        """Get statistics about loaded YARA rules"""
        stats = {
            "total_rules": len(self.rule_metadata),
            "rule_categories": {},
            "severity_distribution": {},
            "mitre_coverage": set()
        }
        
        for rule_name, metadata in self.rule_metadata.items():
            # Category stats
            category = metadata.get("category", "unknown")
            stats["rule_categories"][category] = stats["rule_categories"].get(category, 0) + 1
            
            # Severity stats
            severity = metadata.get("severity", "medium")
            stats["severity_distribution"][severity] = stats["severity_distribution"].get(severity, 0) + 1
            
            # MITRE coverage
            if metadata.get("mitre"):
                stats["mitre_coverage"].add(metadata["mitre"])
        
        stats["mitre_coverage"] = list(stats["mitre_coverage"])
        
        return stats
    
    async def scan_memory_dump(self, dump_path: str) -> List[Dict[str, Any]]:
        """Specialized scanning for memory dumps"""
        # Use fast mode for memory dumps
        original_fast_mode = self.fast_mode
        self.fast_mode = True
        
        try:
            # Scan with adjusted timeout
            results = await self.analyze_file(dump_path)
            
            # Post-process for memory-specific patterns
            for result in results:
                result["source_type"] = "memory_dump"
                # Adjust confidence for memory artifacts
                if result["category"] in ["ransomware", "rootkit", "injected_code"]:
                    result["confidence"] *= 1.2
                    result["confidence"] = min(1.0, result["confidence"])
            
            return results
            
        finally:
            self.fast_mode = original_fast_mode
    
    def cleanup(self):
        """Cleanup resources"""
        self.executor.shutdown(wait=True)