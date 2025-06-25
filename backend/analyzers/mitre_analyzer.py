"""
MITRE ATT&CK Analyzer - Maps security findings to MITRE ATT&CK framework

This module provides mapping of detected threats, IOCs, and behaviors
to MITRE ATT&CK tactics, techniques, and sub-techniques.
"""

import logging
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime
from pathlib import Path
import json
from collections import defaultdict
import re

from parsers.base_parser import ParsedEntry

logger = logging.getLogger(__name__)

class MITREAnalyzer:
    """Maps security findings to MITRE ATT&CK framework"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.attack_data_path = Path(config.get("attack_data_path", "rules/mitre"))
        self.techniques: Dict[str, Dict[str, Any]] = {}
        self.tactics: Dict[str, Dict[str, Any]] = {}
        self.mitigations: Dict[str, Dict[str, Any]] = {}
        self.groups: Dict[str, Dict[str, Any]] = {}
        self.software: Dict[str, Dict[str, Any]] = {}
        
        # Mapping configurations
        self.confidence_threshold = config.get("confidence_threshold", 0.6)
        self.enable_sub_techniques = config.get("enable_sub_techniques", True)
        
        # Pattern mappings for automatic detection
        self.ioc_technique_mappings = self._build_ioc_mappings()
        self.behavior_technique_mappings = self._build_behavior_mappings()
        self.tool_technique_mappings = self._build_tool_mappings()
        
        # Load MITRE ATT&CK data
        self._load_attack_data()
    
    def _load_attack_data(self):
        """Load MITRE ATT&CK data from files or use defaults"""
        try:
            # Try to load from files
            techniques_file = self.attack_data_path / "techniques.json"
            if techniques_file.exists():
                with open(techniques_file, 'r') as f:
                    self.techniques = json.load(f)
                logger.info(f"Loaded {len(self.techniques)} MITRE techniques")
            else:
                self._load_default_techniques()
                
        except Exception as e:
            logger.error(f"Failed to load MITRE data: {e}")
            self._load_default_techniques()
    
    def _load_default_techniques(self):
        """Load default MITRE ATT&CK techniques"""
        self.techniques = {
            "T1059": {
                "name": "Command and Scripting Interpreter",
                "description": "Adversaries may abuse command and script interpreters",
                "tactics": ["Execution"],
                "platforms": ["Windows", "Linux", "macOS"],
                "data_sources": ["Command", "Process", "Script"],
                "sub_techniques": {
                    "T1059.001": "PowerShell",
                    "T1059.003": "Windows Command Shell",
                    "T1059.004": "Unix Shell",
                    "T1059.005": "Visual Basic",
                    "T1059.006": "Python",
                    "T1059.007": "JavaScript"
                }
            },
            "T1055": {
                "name": "Process Injection",
                "description": "Adversaries may inject code into processes",
                "tactics": ["Defense Evasion", "Privilege Escalation"],
                "platforms": ["Windows", "Linux", "macOS"],
                "data_sources": ["Process", "OS API"],
                "sub_techniques": {
                    "T1055.001": "Dynamic-link Library Injection",
                    "T1055.002": "Portable Executable Injection",
                    "T1055.003": "Thread Execution Hijacking"
                }
            },
            "T1003": {
                "name": "OS Credential Dumping",
                "description": "Adversaries may attempt to dump credentials",
                "tactics": ["Credential Access"],
                "platforms": ["Windows", "Linux", "macOS"],
                "data_sources": ["Process", "Windows Registry"],
                "sub_techniques": {
                    "T1003.001": "LSASS Memory",
                    "T1003.002": "Security Account Manager",
                    "T1003.003": "NTDS",
                    "T1003.008": "/etc/passwd and /etc/shadow"
                }
            },
            "T1053": {
                "name": "Scheduled Task/Job",
                "description": "Adversaries may abuse task scheduling",
                "tactics": ["Execution", "Persistence", "Privilege Escalation"],
                "platforms": ["Windows", "Linux", "macOS"],
                "data_sources": ["Scheduled Job", "Process", "Command"],
                "sub_techniques": {
                    "T1053.002": "At",
                    "T1053.003": "Cron",
                    "T1053.005": "Scheduled Task"
                }
            },
            "T1547": {
                "name": "Boot or Logon Autostart Execution",
                "description": "Adversaries may configure system settings to execute programs during boot",
                "tactics": ["Persistence", "Privilege Escalation"],
                "platforms": ["Windows", "Linux", "macOS"],
                "data_sources": ["Windows Registry", "File", "Process"],
                "sub_techniques": {
                    "T1547.001": "Registry Run Keys / Startup Folder",
                    "T1547.004": "Winlogon Helper DLL",
                    "T1547.009": "Shortcut Modification"
                }
            },
            "T1110": {
                "name": "Brute Force",
                "description": "Adversaries may use brute force techniques",
                "tactics": ["Credential Access"],
                "platforms": ["Windows", "Linux", "macOS", "Cloud"],
                "data_sources": ["Authentication logs", "Application Log"],
                "sub_techniques": {
                    "T1110.001": "Password Guessing",
                    "T1110.002": "Password Cracking",
                    "T1110.003": "Password Spraying",
                    "T1110.004": "Credential Stuffing"
                }
            },
            "T1505": {
                "name": "Server Software Component",
                "description": "Adversaries may abuse legitimate server software components",
                "tactics": ["Persistence"],
                "platforms": ["Windows", "Linux", "macOS"],
                "data_sources": ["Application Log", "File", "Process"],
                "sub_techniques": {
                    "T1505.003": "Web Shell",
                    "T1505.004": "IIS Components",
                    "T1505.005": "Terminal Services DLL"
                }
            },
            "T1486": {
                "name": "Data Encrypted for Impact",
                "description": "Adversaries may encrypt data to interrupt availability",
                "tactics": ["Impact"],
                "platforms": ["Windows", "Linux", "macOS"],
                "data_sources": ["File", "Process", "Cloud Storage"],
                "sub_techniques": {}
            },
            "T1041": {
                "name": "Exfiltration Over C2 Channel",
                "description": "Adversaries may steal data by exfiltrating it over command and control channel",
                "tactics": ["Exfiltration"],
                "platforms": ["Windows", "Linux", "macOS"],
                "data_sources": ["Network Traffic", "Command"],
                "sub_techniques": {}
            },
            "T1071": {
                "name": "Application Layer Protocol",
                "description": "Adversaries may communicate using application layer protocols",
                "tactics": ["Command and Control"],
                "platforms": ["Windows", "Linux", "macOS"],
                "data_sources": ["Network Traffic"],
                "sub_techniques": {
                    "T1071.001": "Web Protocols",
                    "T1071.002": "File Transfer Protocols",
                    "T1071.003": "Mail Protocols",
                    "T1071.004": "DNS"
                }
            },
            "T1018": {
                "name": "Remote System Discovery",
                "description": "Adversaries may attempt to get a listing of systems",
                "tactics": ["Discovery"],
                "platforms": ["Windows", "Linux", "macOS"],
                "data_sources": ["Network Traffic", "Process", "Command"],
                "sub_techniques": {}
            },
            "T1046": {
                "name": "Network Service Discovery",
                "description": "Adversaries may attempt to get a listing of services",
                "tactics": ["Discovery"],
                "platforms": ["Windows", "Linux", "macOS"],
                "data_sources": ["Network Traffic", "Process", "Command"],
                "sub_techniques": {}
            },
            "T1068": {
                "name": "Exploitation for Privilege Escalation",
                "description": "Adversaries may exploit software vulnerabilities",
                "tactics": ["Privilege Escalation"],
                "platforms": ["Windows", "Linux", "macOS"],
                "data_sources": ["Process", "Application Log"],
                "sub_techniques": {}
            },
            "T1566": {
                "name": "Phishing",
                "description": "Adversaries may send phishing messages",
                "tactics": ["Initial Access"],
                "platforms": ["Windows", "Linux", "macOS"],
                "data_sources": ["Application Log", "Network Traffic", "File"],
                "sub_techniques": {
                    "T1566.001": "Spearphishing Attachment",
                    "T1566.002": "Spearphishing Link",
                    "T1566.003": "Spearphishing via Service"
                }
            },
            "T1496": {
                "name": "Resource Hijacking",
                "description": "Adversaries may leverage resources for cryptocurrency mining",
                "tactics": ["Impact"],
                "platforms": ["Windows", "Linux", "macOS", "Cloud"],
                "data_sources": ["Process", "Network Traffic", "Sensor Health"],
                "sub_techniques": {}
            }
        }
        
        # Build tactics
        self.tactics = {
            "TA0001": {"name": "Initial Access", "techniques": ["T1566"]},
            "TA0002": {"name": "Execution", "techniques": ["T1059", "T1053"]},
            "TA0003": {"name": "Persistence", "techniques": ["T1053", "T1547", "T1505"]},
            "TA0004": {"name": "Privilege Escalation", "techniques": ["T1055", "T1053", "T1547", "T1068"]},
            "TA0005": {"name": "Defense Evasion", "techniques": ["T1055"]},
            "TA0006": {"name": "Credential Access", "techniques": ["T1003", "T1110"]},
            "TA0007": {"name": "Discovery", "techniques": ["T1018", "T1046"]},
            "TA0008": {"name": "Lateral Movement", "techniques": []},
            "TA0009": {"name": "Collection", "techniques": []},
            "TA0010": {"name": "Exfiltration", "techniques": ["T1041"]},
            "TA0011": {"name": "Command and Control", "techniques": ["T1071"]},
            "TA0040": {"name": "Impact", "techniques": ["T1486", "T1496"]}
        }
    
    def _build_ioc_mappings(self) -> Dict[str, List[Tuple[str, float]]]:
        """Build mappings from IOC patterns to techniques"""
        return {
            # IP patterns
            "tor_exit_node": [("T1090.003", 0.8)],  # Proxy: Multi-hop Proxy
            "known_c2": [("T1071", 0.9), ("T1041", 0.7)],  # Application Layer Protocol
            
            # Domain patterns
            "dga_domain": [("T1568.002", 0.9)],  # Dynamic Resolution: Domain Generation Algorithms
            "phishing_domain": [("T1566", 0.9)],  # Phishing
            "typosquatting": [("T1566.002", 0.8)],  # Spearphishing Link
            
            # File patterns
            "malicious_script": [("T1059", 0.9)],  # Command and Scripting Interpreter
            "webshell": [("T1505.003", 0.95)],  # Web Shell
            "ransomware": [("T1486", 0.95)],  # Data Encrypted for Impact
            
            # Hash patterns
            "known_malware": [("T1204", 0.8)],  # User Execution
            "cryptominer": [("T1496", 0.9)],  # Resource Hijacking
            
            # URL patterns
            "malware_download": [("T1105", 0.9)],  # Ingress Tool Transfer
            "exfiltration_url": [("T1041", 0.85), ("T1567", 0.7)]  # Exfiltration
        }
    
    def _build_behavior_mappings(self) -> Dict[str, List[Tuple[str, float]]]:
        """Build mappings from behaviors to techniques"""
        return {
            # Process behaviors
            "process_injection": [("T1055", 0.95)],
            "credential_dumping": [("T1003", 0.95)],
            "privilege_escalation": [("T1068", 0.8), ("T1053", 0.7)],
            
            # Network behaviors
            "port_scanning": [("T1046", 0.9)],
            "lateral_movement": [("T1021", 0.8)],  # Remote Services
            "data_exfiltration": [("T1041", 0.9), ("T1048", 0.8)],
            
            # File behaviors
            "persistence_mechanism": [("T1547", 0.85), ("T1053", 0.8)],
            "defense_evasion": [("T1027", 0.8), ("T1070", 0.7)],
            
            # System behaviors
            "registry_modification": [("T1547.001", 0.9), ("T1112", 0.8)],
            "service_creation": [("T1543.003", 0.9)],  # Windows Service
            
            # Authentication behaviors
            "brute_force": [("T1110", 0.95)],
            "password_spraying": [("T1110.003", 0.95)],
            
            # Command patterns
            "recon_commands": [("T1018", 0.8), ("T1016", 0.8)],
            "collection_commands": [("T1119", 0.8), ("T1005", 0.7)]
        }
    
    def _build_tool_mappings(self) -> Dict[str, List[Tuple[str, float]]]:
        """Build mappings from tools to techniques"""
        return {
            # Credential tools
            "mimikatz": [("T1003.001", 0.95), ("T1003", 0.9)],
            "lazagne": [("T1555", 0.9), ("T1003", 0.8)],
            "pwdump": [("T1003.002", 0.95)],
            
            # Remote access tools
            "psexec": [("T1021.002", 0.95), ("T1570", 0.8)],
            "cobalt_strike": [("T1071", 0.9), ("T1055", 0.85)],
            "metasploit": [("T1210", 0.8), ("T1055", 0.8)],
            
            # Persistence tools
            "empire": [("T1547", 0.85), ("T1053", 0.8)],
            "schtasks": [("T1053.005", 0.95)],
            
            # Scanning tools
            "nmap": [("T1046", 0.95), ("T1018", 0.8)],
            "masscan": [("T1046", 0.95)],
            
            # Exfiltration tools
            "rclone": [("T1567.002", 0.9)],  # Exfiltration to Cloud Storage
            "curl": [("T1041", 0.7), ("T1105", 0.7)],
            "wget": [("T1105", 0.8)]
        }
    
    async def map_findings(self, entries: List[ParsedEntry], 
                          iocs: Dict[str, List[str]],
                          yara_results: List[Dict[str, Any]],
                          sigma_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Map all findings to MITRE ATT&CK framework
        
        Args:
            entries: Parsed log entries
            iocs: Extracted IOCs
            yara_results: YARA detection results
            sigma_results: Sigma detection results
            
        Returns:
            MITRE ATT&CK mapping with techniques, tactics, and confidence scores
        """
        technique_scores: Dict[str, float] = defaultdict(float)
        technique_evidence: Dict[str, List[str]] = defaultdict(list)
        
        # Map IOCs to techniques
        ioc_techniques = self._map_iocs_to_techniques(iocs)
        for tech_id, confidence, evidence in ioc_techniques:
            technique_scores[tech_id] = max(technique_scores[tech_id], confidence)
            technique_evidence[tech_id].append(evidence)
        
        # Map behaviors from log entries
        behavior_techniques = self._map_behaviors_to_techniques(entries)
        for tech_id, confidence, evidence in behavior_techniques:
            technique_scores[tech_id] = max(technique_scores[tech_id], confidence)
            technique_evidence[tech_id].append(evidence)
        
        # Map YARA results
        yara_techniques = self._map_yara_to_techniques(yara_results)
        for tech_id, confidence, evidence in yara_techniques:
            technique_scores[tech_id] = max(technique_scores[tech_id], confidence)
            technique_evidence[tech_id].append(evidence)
        
        # Map Sigma results
        sigma_techniques = self._map_sigma_to_techniques(sigma_results)
        for tech_id, confidence, evidence in sigma_techniques:
            technique_scores[tech_id] = max(technique_scores[tech_id], confidence)
            technique_evidence[tech_id].append(evidence)
        
        # Build final mapping
        techniques = []
        tactics_used = set()
        
        for tech_id, confidence in technique_scores.items():
            if confidence >= self.confidence_threshold:
                technique = self.techniques.get(tech_id, {})
                if technique:
                    tech_info = {
                        "id": tech_id,
                        "name": technique.get("name", "Unknown"),
                        "description": technique.get("description", ""),
                        "confidence": round(confidence, 2),
                        "evidence": technique_evidence[tech_id],
                        "tactics": technique.get("tactics", []),
                        "sub_techniques": []
                    }
                    
                    # Add sub-techniques if enabled
                    if self.enable_sub_techniques:
                        for sub_id, sub_name in technique.get("sub_techniques", {}).items():
                            if sub_id in technique_scores:
                                tech_info["sub_techniques"].append({
                                    "id": sub_id,
                                    "name": sub_name,
                                    "confidence": round(technique_scores[sub_id], 2)
                                })
                    
                    techniques.append(tech_info)
                    tactics_used.update(technique.get("tactics", []))
        
        # Sort techniques by confidence
        techniques.sort(key=lambda x: x["confidence"], reverse=True)
        
        # Build tactics summary
        tactics_summary = []
        for tactic_id, tactic_info in self.tactics.items():
            if tactic_info["name"] in tactics_used:
                tactic_techniques = [t for t in techniques if tactic_info["name"] in t["tactics"]]
                tactics_summary.append({
                    "id": tactic_id,
                    "name": tactic_info["name"],
                    "technique_count": len(tactic_techniques),
                    "techniques": [t["id"] for t in tactic_techniques]
                })
        
        # Generate attack chain
        attack_chain = self._generate_attack_chain(techniques, entries)
        
        # Calculate overall threat assessment
        threat_assessment = self._calculate_threat_assessment(techniques, tactics_summary)
        
        return {
            "techniques": techniques,
            "tactics": tactics_summary,
            "attack_chain": attack_chain,
            "threat_assessment": threat_assessment,
            "technique_count": len(techniques),
            "tactic_count": len(tactics_summary),
            "highest_confidence": max(technique_scores.values()) if technique_scores else 0,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def _map_iocs_to_techniques(self, iocs: Dict[str, List[str]]) -> List[Tuple[str, float, str]]:
        """Map IOCs to MITRE techniques"""
        mappings = []
        
        # Check IPs
        for ip in iocs.get("ips", []):
            # Check for known patterns
            if self._is_tor_exit_node(ip):
                mappings.append(("T1090.003", 0.8, f"Tor exit node: {ip}"))
            if self._is_known_c2(ip):
                mappings.append(("T1071", 0.9, f"Known C2 IP: {ip}"))
                mappings.append(("T1041", 0.7, f"Potential exfiltration to: {ip}"))
        
        # Check domains
        for domain in iocs.get("domains", []):
            if self._is_dga_domain(domain):
                mappings.append(("T1568.002", 0.9, f"DGA domain: {domain}"))
            if self._is_phishing_domain(domain):
                mappings.append(("T1566", 0.9, f"Phishing domain: {domain}"))
        
        # Check URLs
        for url in iocs.get("urls", []):
            if "download" in url.lower() or "update" in url.lower():
                mappings.append(("T1105", 0.7, f"Download URL: {url}"))
            if any(ext in url.lower() for ext in [".ps1", ".vbs", ".js", ".bat"]):
                mappings.append(("T1059", 0.8, f"Script URL: {url}"))
        
        # Check file paths
        for path in iocs.get("file_paths", []):
            if "temp" in path.lower():
                mappings.append(("T1036", 0.6, f"Suspicious temp path: {path}"))
            if any(p in path.lower() for p in ["startup", "run", "autostart"]):
                mappings.append(("T1547.001", 0.8, f"Persistence path: {path}"))
        
        # Check hashes
        for hash_val in iocs.get("hashes", []):
            # In real implementation, would check against threat intel
            if len(hash_val) in [32, 40, 64]:  # MD5, SHA1, SHA256
                mappings.append(("T1204", 0.5, f"File hash: {hash_val}"))
        
        return mappings
    
    def _map_behaviors_to_techniques(self, entries: List[ParsedEntry]) -> List[Tuple[str, float, str]]:
        """Map behaviors from log entries to techniques"""
        mappings = []
        behavior_counts = defaultdict(int)
        
        for entry in entries:
            message_lower = entry.message.lower()
            
            # Process injection indicators
            if any(ind in message_lower for ind in ["createremotethread", "setthreadcontext", "writeprocessmemory"]):
                behavior_counts["process_injection"] += 1
                
            # Credential dumping
            if any(ind in message_lower for ind in ["lsass", "sam.hive", "ntds.dit", "hashdump"]):
                behavior_counts["credential_dumping"] += 1
            
            # Network scanning
            if re.search(r"port\s+scan|nmap|masscan|portscan", message_lower):
                behavior_counts["port_scanning"] += 1
            
            # Persistence
            if any(ind in message_lower for ind in ["registry.*run", "schtasks", "scheduled task", "crontab"]):
                behavior_counts["persistence_mechanism"] += 1
            
            # Brute force
            if "failed login" in message_lower or "authentication failure" in message_lower:
                behavior_counts["brute_force"] += 1
            
            # Data exfiltration
            if any(ind in message_lower for ind in ["large data transfer", "unusual upload", "data sent"]):
                behavior_counts["data_exfiltration"] += 1
            
            # Recon commands
            if any(cmd in message_lower for cmd in ["net view", "net user", "whoami", "ipconfig", "ifconfig"]):
                behavior_counts["recon_commands"] += 1
        
        # Convert counts to technique mappings
        for behavior, count in behavior_counts.items():
            if behavior in self.behavior_technique_mappings:
                for tech_id, base_confidence in self.behavior_technique_mappings[behavior]:
                    # Adjust confidence based on count
                    confidence = min(base_confidence + (count * 0.05), 1.0)
                    mappings.append((tech_id, confidence, f"{behavior} detected {count} times"))
        
        return mappings
    
    def _map_yara_to_techniques(self, yara_results: List[Dict[str, Any]]) -> List[Tuple[str, float, str]]:
        """Map YARA results to techniques"""
        mappings = []
        
        for result in yara_results:
            rule_name = result.get("rule", "").lower()
            
            # Direct technique mapping from YARA metadata
            if result.get("mitre_technique"):
                tech_id = result["mitre_technique"]
                confidence = result.get("confidence", 0.8)
                mappings.append((tech_id, confidence, f"YARA: {result['rule']}"))
            
            # Pattern-based mapping
            elif "powershell" in rule_name:
                mappings.append(("T1059.001", 0.9, f"YARA: {result['rule']}"))
            elif "ransomware" in rule_name:
                mappings.append(("T1486", 0.95, f"YARA: {result['rule']}"))
            elif "webshell" in rule_name:
                mappings.append(("T1505.003", 0.95, f"YARA: {result['rule']}"))
            elif "credential" in rule_name:
                mappings.append(("T1003", 0.9, f"YARA: {result['rule']}"))
            elif "persistence" in rule_name:
                mappings.append(("T1547", 0.85, f"YARA: {result['rule']}"))
            elif "cryptominer" in rule_name or "miner" in rule_name:
                mappings.append(("T1496", 0.9, f"YARA: {result['rule']}"))
        
        return mappings
    
    def _map_sigma_to_techniques(self, sigma_results: List[Dict[str, Any]]) -> List[Tuple[str, float, str]]:
        """Map Sigma results to techniques"""
        mappings = []
        
        for result in sigma_results:
            # Direct mapping from attack_id
            if result.get("attack_id"):
                tech_id = result["attack_id"]
                confidence = result.get("confidence", 0.8)
                mappings.append((tech_id, confidence, f"Sigma: {result['title']}"))
            
            # Tag-based mapping
            for tag in result.get("tags", []):
                if tag.startswith("attack.t"):
                    tech_id = tag.replace("attack.", "").upper()
                    confidence = result.get("confidence", 0.8)
                    mappings.append((tech_id, confidence, f"Sigma: {result['title']}"))
        
        return mappings
    
    def _generate_attack_chain(self, techniques: List[Dict[str, Any]], 
                              entries: List[ParsedEntry]) -> List[Dict[str, Any]]:
        """Generate likely attack chain based on techniques and timeline"""
        chain = []
        
        # Define typical attack progression
        tactic_order = [
            "Initial Access", "Execution", "Persistence", "Privilege Escalation",
            "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
            "Collection", "Command and Control", "Exfiltration", "Impact"
        ]
        
        # Group techniques by tactics
        techniques_by_tactic = defaultdict(list)
        for tech in techniques:
            for tactic in tech["tactics"]:
                techniques_by_tactic[tactic].append(tech)
        
        # Build chain following tactic order
        for tactic in tactic_order:
            if tactic in techniques_by_tactic:
                # Get highest confidence technique for this tactic
                tactic_techs = sorted(techniques_by_tactic[tactic], 
                                    key=lambda x: x["confidence"], reverse=True)
                
                chain.append({
                    "stage": tactic,
                    "technique": tactic_techs[0]["id"],
                    "technique_name": tactic_techs[0]["name"],
                    "confidence": tactic_techs[0]["confidence"],
                    "evidence": tactic_techs[0]["evidence"][0] if tactic_techs[0]["evidence"] else ""
                })
        
        return chain
    
    def _calculate_threat_assessment(self, techniques: List[Dict[str, Any]], 
                                   tactics: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate overall threat assessment"""
        assessment = {
            "severity": "low",
            "sophistication": "low",
            "impact_potential": "low",
            "detection_confidence": "low",
            "recommendations": []
        }
        
        # Calculate severity based on techniques
        critical_techniques = ["T1486", "T1003", "T1055", "T1505.003"]
        high_techniques = ["T1059", "T1053", "T1547", "T1110"]
        
        critical_count = sum(1 for t in techniques if t["id"] in critical_techniques)
        high_count = sum(1 for t in techniques if t["id"] in high_techniques)
        
        if critical_count > 0:
            assessment["severity"] = "critical"
        elif high_count >= 2:
            assessment["severity"] = "high"
        elif high_count >= 1 or len(techniques) >= 3:
            assessment["severity"] = "medium"
        
        # Calculate sophistication
        if len(tactics) >= 5:
            assessment["sophistication"] = "high"
        elif len(tactics) >= 3:
            assessment["sophistication"] = "medium"
        
        # Calculate impact potential
        impact_techniques = ["T1486", "T1496", "T1041"]
        if any(t["id"] in impact_techniques for t in techniques):
            assessment["impact_potential"] = "high"
        elif len(techniques) >= 5:
            assessment["impact_potential"] = "medium"
        
        # Calculate detection confidence
        avg_confidence = sum(t["confidence"] for t in techniques) / len(techniques) if techniques else 0
        if avg_confidence >= 0.85:
            assessment["detection_confidence"] = "high"
        elif avg_confidence >= 0.7:
            assessment["detection_confidence"] = "medium"
        
        # Generate recommendations
        if assessment["severity"] in ["critical", "high"]:
            assessment["recommendations"].append("Immediate incident response required")
            assessment["recommendations"].append("Isolate affected systems")
        
        if any(t["id"] == "T1003" for t in techniques):
            assessment["recommendations"].append("Reset all credentials immediately")
        
        if any(t["id"] == "T1486" for t in techniques):
            assessment["recommendations"].append("Check and secure backups")
            assessment["recommendations"].append("Implement ransomware protection")
        
        if any(t["id"] in ["T1053", "T1547"] for t in techniques):
            assessment["recommendations"].append("Audit persistence mechanisms")
        
        return assessment
    
    def _is_tor_exit_node(self, ip: str) -> bool:
        """Check if IP is a Tor exit node"""
        # In real implementation, would check against Tor exit node list
        # For now, simple pattern matching
        return ip.startswith("192.168.") or ip.startswith("10.")
    
    def _is_known_c2(self, ip: str) -> bool:
        """Check if IP is a known C2 server"""
        # In real implementation, would check against threat intel
        # For now, return False
        return False
    
    def _is_dga_domain(self, domain: str) -> bool:
        """Check if domain appears to be DGA-generated"""
        # Simple heuristic: high consonant ratio, unusual length
        if len(domain) > 15:
            consonants = sum(1 for c in domain if c.lower() in "bcdfghjklmnpqrstvwxyz")
            ratio = consonants / len(domain)
            return ratio > 0.75
        return False
    
    def _is_phishing_domain(self, domain: str) -> bool:
        """Check if domain appears to be phishing"""
        # Check for common phishing patterns
        phishing_patterns = [
            "secure", "account", "verify", "update", "confirm",
            "paypal", "amazon", "microsoft", "google", "apple"
        ]
        domain_lower = domain.lower()
        
        # Check for typosquatting or suspicious patterns
        for pattern in phishing_patterns:
            if pattern in domain_lower and not domain_lower.endswith(f"{pattern}.com"):
                return True
        
        return False
    
    def get_technique_details(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific technique"""
        return self.techniques.get(technique_id)
    
    def get_mitigation_recommendations(self, technique_ids: List[str]) -> List[Dict[str, Any]]:
        """Get mitigation recommendations for detected techniques"""
        recommendations = []
        
        # Basic mitigation mappings
        mitigations = {
            "T1059": ["Application control", "Code signing", "Execution prevention"],
            "T1055": ["Behavior monitoring", "Privileged account management"],
            "T1003": ["Credential access protection", "Password policies", "Privileged account management"],
            "T1053": ["Audit", "Operating system configuration", "Privileged account management"],
            "T1547": ["Audit", "User account management"],
            "T1110": ["Account use policies", "Multi-factor authentication", "Password policies"],
            "T1505.003": ["Audit", "File monitoring", "Update software"],
            "T1486": ["Data backup", "User training"],
            "T1041": ["Data loss prevention", "Network intrusion prevention"],
            "T1496": ["Resource monitoring", "User account management"]
        }
        
        applied_mitigations = set()
        
        for tech_id in technique_ids:
            if tech_id in mitigations:
                for mitigation in mitigations[tech_id]:
                    if mitigation not in applied_mitigations:
                        applied_mitigations.add(mitigation)
                        recommendations.append({
                            "mitigation": mitigation,
                            "techniques_addressed": [tech_id],
                            "priority": "high" if tech_id in ["T1003", "T1486"] else "medium"
                        })
        
        return sorted(recommendations, key=lambda x: x["priority"], reverse=True)