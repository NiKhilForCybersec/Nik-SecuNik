"""
Main Analysis Engine - Orchestrates all security analysis components

This module coordinates the execution of various analyzers (YARA, Sigma, MITRE, AI, etc.)
on parsed file data and generates comprehensive security reports.
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime
from dataclasses import dataclass, field
from pathlib import Path
import json
import hashlib
from collections import defaultdict
import time

from core.parser_factory import ParseResult
from core.storage_manager import StorageManager
from backend.analyzers.yara_analyzer import YARAAnalyzer
from backend.analyzers.sigma_analyzer import SigmaAnalyzer
from backend.analyzers.mitre_analyzer import MITREAnalyzer
from backend.analyzers.ai_analyzer import AIAnalyzer
from backend.analyzers.ioc_extractor import AdvancedIOCExtractor
from backend.analyzers.pattern_analyzer import PatternAnalyzer
from backend.analyzers.anomaly_detector import AnomalyDetector
from backend.analyzers.correlation_engine import CorrelationEngine
from backend.integrations.virustotal_client import VirusTotalClient
from backend.api.websocket import WebSocketManager

logger = logging.getLogger(__name__)

@dataclass
class AnalysisResult:
    """Complete analysis result from all analyzers"""
    analysis_id: str
    file_path: str
    file_hash: str
    timestamp: datetime
    
    # Individual analyzer results
    yara_results: List[Dict[str, Any]] = field(default_factory=list)
    sigma_results: List[Dict[str, Any]] = field(default_factory=list)
    mitre_results: Dict[str, Any] = field(default_factory=dict)
    ai_insights: Dict[str, Any] = field(default_factory=dict)
    advanced_iocs: Dict[str, List[str]] = field(default_factory=dict)
    patterns: List[Dict[str, Any]] = field(default_factory=list)
    anomalies: List[Dict[str, Any]] = field(default_factory=list)
    correlations: List[Dict[str, Any]] = field(default_factory=list)
    virustotal_results: Dict[str, Any] = field(default_factory=dict)
    
    # Aggregate scores and findings
    threat_score: int = 0  # 0-100
    confidence_level: float = 0.0  # 0-1
    severity: str = "low"  # low, medium, high, critical
    
    # Key findings
    malware_indicators: List[str] = field(default_factory=list)
    attack_techniques: List[str] = field(default_factory=list)
    suspicious_behaviors: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    # Executive summary
    executive_summary: str = ""
    
    # Processing metadata
    analysis_duration: float = 0.0
    analyzers_run: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

class AnalysisEngine:
    """Main analysis orchestrator that coordinates all security analyzers"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.storage_manager = StorageManager(config["storage_path"])
        self.ws_manager = WebSocketManager()
        
        # Initialize analyzers
        self.yara_analyzer = YARAAnalyzer(config.get("yara", {}))
        self.sigma_analyzer = SigmaAnalyzer(config.get("sigma", {}))
        self.mitre_analyzer = MITREAnalyzer(config.get("mitre", {}))
        self.ai_analyzer = AIAnalyzer(config.get("openai", {}))
        self.ioc_extractor = AdvancedIOCExtractor()
        self.pattern_analyzer = PatternAnalyzer()
        self.anomaly_detector = AnomalyDetector()
        self.correlation_engine = CorrelationEngine()
        
        # External integrations
        self.vt_client = None
        if config.get("virustotal", {}).get("api_key"):
            self.vt_client = VirusTotalClient(config["virustotal"]["api_key"])
        
        # Analysis settings
        self.parallel_analysis = config.get("parallel_analysis", True)
        self.max_workers = config.get("max_workers", 4)
        self.enable_ai = config.get("enable_ai", True)
        self.enable_vt = config.get("enable_virustotal", True)
        
        # Cache for analysis results
        self._analysis_cache: Dict[str, AnalysisResult] = {}
        
    async def analyze_file(self, file_path: str, parse_result: ParseResult,
                          analysis_options: Optional[Dict[str, Any]] = None) -> AnalysisResult:
        """
        Perform comprehensive security analysis on a parsed file
        
        Args:
            file_path: Path to the original file
            parse_result: Parsed data from the parser framework
            analysis_options: Optional analysis configuration
            
        Returns:
            AnalysisResult with findings from all analyzers
        """
        start_time = time.time()
        analysis_id = self._generate_analysis_id(file_path)
        
        # Send initial WebSocket update
        await self.ws_manager.send_update({
            "type": "analysis_started",
            "analysis_id": analysis_id,
            "file": file_path,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        # Initialize result
        result = AnalysisResult(
            analysis_id=analysis_id,
            file_path=file_path,
            file_hash=await self._calculate_file_hash(file_path),
            timestamp=datetime.utcnow()
        )
        
        # Prepare analysis tasks
        tasks = []
        
        # Core analyzers (always run)
        tasks.extend([
            self._run_yara_analysis(file_path, parse_result, result),
            self._run_sigma_analysis(parse_result, result),
            self._run_mitre_mapping(parse_result, result),
            self._run_advanced_ioc_extraction(parse_result, result),
            self._run_pattern_analysis(parse_result, result),
            self._run_anomaly_detection(parse_result, result)
        ])
        
        # Optional analyzers
        if self.enable_ai and self.ai_analyzer.is_configured():
            tasks.append(self._run_ai_analysis(parse_result, result))
            
        if self.enable_vt and self.vt_client:
            tasks.append(self._run_virustotal_analysis(file_path, result))
        
        # Execute analysis
        if self.parallel_analysis:
            # Run analyzers in parallel
            await asyncio.gather(*tasks, return_exceptions=True)
        else:
            # Run analyzers sequentially
            for task in tasks:
                try:
                    await task
                except Exception as e:
                    logger.error(f"Analyzer failed: {e}")
                    result.errors.append(str(e))
        
        # Run correlation analysis after individual analyzers
        await self._run_correlation_analysis(result)
        
        # Calculate aggregate scores and generate summary
        self._calculate_threat_score(result)
        self._generate_executive_summary(result)
        self._generate_recommendations(result)
        
        # Record analysis duration
        result.analysis_duration = time.time() - start_time
        
        # Store analysis result
        await self._store_analysis_result(result)
        
        # Send completion WebSocket update
        await self.ws_manager.send_update({
            "type": "analysis_completed",
            "analysis_id": analysis_id,
            "threat_score": result.threat_score,
            "severity": result.severity,
            "duration": result.analysis_duration,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        # Cache result
        self._analysis_cache[analysis_id] = result
        
        return result
    
    async def _run_yara_analysis(self, file_path: str, parse_result: ParseResult,
                                result: AnalysisResult) -> None:
        """Run YARA rules against file content"""
        try:
            logger.info(f"Running YARA analysis on {file_path}")
            
            # Send progress update
            await self.ws_manager.send_update({
                "type": "analyzer_progress",
                "analysis_id": result.analysis_id,
                "analyzer": "yara",
                "status": "running"
            })
            
            # Run YARA analysis
            yara_matches = await self.yara_analyzer.analyze_file(file_path)
            
            # Also analyze extracted strings and patterns
            if parse_result.metadata.additional.get("extracted_strings"):
                string_matches = await self.yara_analyzer.analyze_strings(
                    parse_result.metadata.additional["extracted_strings"]
                )
                yara_matches.extend(string_matches)
            
            result.yara_results = yara_matches
            result.analyzers_run.append("yara")
            
            # Extract malware indicators
            for match in yara_matches:
                if match["severity"] in ["high", "critical"]:
                    result.malware_indicators.append(
                        f"YARA: {match['rule']} - {match['description']}"
                    )
                    
        except Exception as e:
            logger.error(f"YARA analysis failed: {e}")
            result.errors.append(f"YARA analysis error: {str(e)}")
    
    async def _run_sigma_analysis(self, parse_result: ParseResult,
                                 result: AnalysisResult) -> None:
        """Run Sigma rules against log entries"""
        try:
            logger.info("Running Sigma analysis on parsed entries")
            
            await self.ws_manager.send_update({
                "type": "analyzer_progress",
                "analysis_id": result.analysis_id,
                "analyzer": "sigma",
                "status": "running"
            })
            
            # Convert entries to Sigma-compatible format
            sigma_matches = await self.sigma_analyzer.analyze_entries(
                parse_result.entries,
                parse_result.metadata.parser_type
            )
            
            result.sigma_results = sigma_matches
            result.analyzers_run.append("sigma")
            
            # Extract attack techniques
            for match in sigma_matches:
                if match["confidence"] > 0.7:
                    result.attack_techniques.append(
                        f"Sigma: {match['title']} ({match['attack_id']})"
                    )
                    
        except Exception as e:
            logger.error(f"Sigma analysis failed: {e}")
            result.errors.append(f"Sigma analysis error: {str(e)}")
    
    async def _run_mitre_mapping(self, parse_result: ParseResult,
                                result: AnalysisResult) -> None:
        """Map findings to MITRE ATT&CK framework"""
        try:
            logger.info("Mapping to MITRE ATT&CK framework")
            
            await self.ws_manager.send_update({
                "type": "analyzer_progress",
                "analysis_id": result.analysis_id,
                "analyzer": "mitre",
                "status": "running"
            })
            
            # Map findings to MITRE techniques
            mitre_mapping = await self.mitre_analyzer.map_findings(
                entries=parse_result.entries,
                iocs=parse_result.iocs,
                yara_results=result.yara_results,
                sigma_results=result.sigma_results
            )
            
            result.mitre_results = mitre_mapping
            result.analyzers_run.append("mitre")
            
            # Add high-confidence techniques to findings
            for technique in mitre_mapping.get("techniques", []):
                if technique["confidence"] > 0.8:
                    result.attack_techniques.append(
                        f"MITRE: {technique['id']} - {technique['name']}"
                    )
                    
        except Exception as e:
            logger.error(f"MITRE mapping failed: {e}")
            result.errors.append(f"MITRE mapping error: {str(e)}")
    
    async def _run_ai_analysis(self, parse_result: ParseResult,
                              result: AnalysisResult) -> None:
        """Run AI-powered analysis for advanced insights"""
        try:
            logger.info("Running AI analysis")
            
            await self.ws_manager.send_update({
                "type": "analyzer_progress",
                "analysis_id": result.analysis_id,
                "analyzer": "ai",
                "status": "running"
            })
            
            # Prepare context for AI analysis
            context = {
                "file_type": parse_result.metadata.parser_type,
                "entry_count": len(parse_result.entries),
                "ioc_summary": {k: len(v) for k, v in parse_result.iocs.items()},
                "severity_distribution": self._get_severity_distribution(parse_result),
                "yara_matches": len(result.yara_results),
                "sigma_matches": len(result.sigma_results)
            }
            
            # Get AI insights
            ai_insights = await self.ai_analyzer.analyze_security_context(
                parse_result=parse_result,
                analysis_context=context
            )
            
            result.ai_insights = ai_insights
            result.analyzers_run.append("ai")
            
            # Extract AI-identified behaviors
            if ai_insights.get("suspicious_behaviors"):
                result.suspicious_behaviors.extend(
                    ai_insights["suspicious_behaviors"]
                )
                
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            result.errors.append(f"AI analysis error: {str(e)}")
    
    async def _run_advanced_ioc_extraction(self, parse_result: ParseResult,
                                         result: AnalysisResult) -> None:
        """Extract advanced IOCs using context-aware analysis"""
        try:
            logger.info("Running advanced IOC extraction")
            
            # Extract advanced IOCs with context
            advanced_iocs = await self.ioc_extractor.extract_advanced(
                parse_result=parse_result,
                file_type=parse_result.metadata.parser_type
            )
            
            result.advanced_iocs = advanced_iocs
            result.analyzers_run.append("advanced_ioc")
            
        except Exception as e:
            logger.error(f"Advanced IOC extraction failed: {e}")
            result.errors.append(f"IOC extraction error: {str(e)}")
    
    async def _run_pattern_analysis(self, parse_result: ParseResult,
                                   result: AnalysisResult) -> None:
        """Detect suspicious patterns in the data"""
        try:
            logger.info("Running pattern analysis")
            
            # Analyze patterns
            patterns = await self.pattern_analyzer.analyze_patterns(
                entries=parse_result.entries,
                iocs=parse_result.iocs,
                metadata=parse_result.metadata
            )
            
            result.patterns = patterns
            result.analyzers_run.append("pattern")
            
            # Extract suspicious behaviors from patterns
            for pattern in patterns:
                if pattern["confidence"] > 0.75:
                    result.suspicious_behaviors.append(
                        f"Pattern: {pattern['description']}"
                    )
                    
        except Exception as e:
            logger.error(f"Pattern analysis failed: {e}")
            result.errors.append(f"Pattern analysis error: {str(e)}")
    
    async def _run_anomaly_detection(self, parse_result: ParseResult,
                                    result: AnalysisResult) -> None:
        """Detect anomalies in the data"""
        try:
            logger.info("Running anomaly detection")
            
            # Detect anomalies
            anomalies = await self.anomaly_detector.detect_anomalies(
                entries=parse_result.entries,
                file_type=parse_result.metadata.parser_type
            )
            
            result.anomalies = anomalies
            result.analyzers_run.append("anomaly")
            
        except Exception as e:
            logger.error(f"Anomaly detection failed: {e}")
            result.errors.append(f"Anomaly detection error: {str(e)}")
    
    async def _run_virustotal_analysis(self, file_path: str,
                                      result: AnalysisResult) -> None:
        """Check file hash and IOCs against VirusTotal"""
        try:
            logger.info("Running VirusTotal analysis")
            
            await self.ws_manager.send_update({
                "type": "analyzer_progress",
                "analysis_id": result.analysis_id,
                "analyzer": "virustotal",
                "status": "running"
            })
            
            # Check file hash
            vt_results = await self.vt_client.check_file_hash(result.file_hash)
            
            # Check top IOCs
            if result.advanced_iocs:
                # Check suspicious IPs
                for ip in list(result.advanced_iocs.get("ips", []))[:10]:
                    ip_result = await self.vt_client.check_ip(ip)
                    if ip_result:
                        vt_results["ioc_results"] = vt_results.get("ioc_results", {})
                        vt_results["ioc_results"][ip] = ip_result
                
                # Check suspicious domains
                for domain in list(result.advanced_iocs.get("domains", []))[:10]:
                    domain_result = await self.vt_client.check_domain(domain)
                    if domain_result:
                        vt_results["ioc_results"] = vt_results.get("ioc_results", {})
                        vt_results["ioc_results"][domain] = domain_result
            
            result.virustotal_results = vt_results
            result.analyzers_run.append("virustotal")
            
            # Add VT findings to malware indicators
            if vt_results.get("malicious", 0) > 0:
                result.malware_indicators.append(
                    f"VirusTotal: {vt_results['malicious']}/{vt_results.get('total', 0)} detections"
                )
                
        except Exception as e:
            logger.error(f"VirusTotal analysis failed: {e}")
            result.errors.append(f"VirusTotal error: {str(e)}")
    
    async def _run_correlation_analysis(self, result: AnalysisResult) -> None:
        """Correlate findings across all analyzers"""
        try:
            logger.info("Running correlation analysis")
            
            # Correlate all findings
            correlations = await self.correlation_engine.correlate_findings(
                yara_results=result.yara_results,
                sigma_results=result.sigma_results,
                mitre_results=result.mitre_results,
                patterns=result.patterns,
                anomalies=result.anomalies,
                iocs=result.advanced_iocs
            )
            
            result.correlations = correlations
            result.analyzers_run.append("correlation")
            
        except Exception as e:
            logger.error(f"Correlation analysis failed: {e}")
            result.errors.append(f"Correlation error: {str(e)}")
    
    def _calculate_threat_score(self, result: AnalysisResult) -> None:
        """Calculate overall threat score based on all findings"""
        score = 0
        confidence_scores = []
        
        # YARA matches
        for match in result.yara_results:
            if match["severity"] == "critical":
                score += 20
            elif match["severity"] == "high":
                score += 15
            elif match["severity"] == "medium":
                score += 10
            elif match["severity"] == "low":
                score += 5
            confidence_scores.append(match.get("confidence", 0.8))
        
        # Sigma matches
        for match in result.sigma_results:
            if match["level"] == "critical":
                score += 18
            elif match["level"] == "high":
                score += 13
            elif match["level"] == "medium":
                score += 8
            elif match["level"] == "low":
                score += 3
            confidence_scores.append(match.get("confidence", 0.7))
        
        # MITRE techniques
        high_severity_techniques = ["T1055", "T1003", "T1053", "T1547", "T1218"]
        for technique in result.mitre_results.get("techniques", []):
            if technique["id"] in high_severity_techniques:
                score += 15
            else:
                score += 8
            confidence_scores.append(technique.get("confidence", 0.7))
        
        # Pattern and anomaly findings
        score += len(result.patterns) * 5
        score += len(result.anomalies) * 3
        
        # VirusTotal results
        if result.virustotal_results:
            vt_score = result.virustotal_results.get("malicious", 0)
            if vt_score > 10:
                score += 25
            elif vt_score > 5:
                score += 15
            elif vt_score > 0:
                score += 10
        
        # AI insights severity
        if result.ai_insights.get("threat_level") == "critical":
            score += 20
        elif result.ai_insights.get("threat_level") == "high":
            score += 15
        elif result.ai_insights.get("threat_level") == "medium":
            score += 10
        
        # Cap score at 100
        result.threat_score = min(100, score)
        
        # Calculate confidence level
        if confidence_scores:
            result.confidence_level = sum(confidence_scores) / len(confidence_scores)
        else:
            result.confidence_level = 0.5
        
        # Determine severity
        if result.threat_score >= 75:
            result.severity = "critical"
        elif result.threat_score >= 50:
            result.severity = "high"
        elif result.threat_score >= 25:
            result.severity = "medium"
        else:
            result.severity = "low"
    
    def _generate_executive_summary(self, result: AnalysisResult) -> None:
        """Generate executive summary of findings"""
        summary_parts = []
        
        # Overview
        summary_parts.append(
            f"Security analysis completed with threat score: {result.threat_score}/100 "
            f"(Severity: {result.severity.upper()}, Confidence: {result.confidence_level:.1%})"
        )
        
        # Key findings
        if result.malware_indicators:
            summary_parts.append(
                f"\nMALWARE DETECTED: {len(result.malware_indicators)} indicator(s) found:"
            )
            for indicator in result.malware_indicators[:3]:
                summary_parts.append(f"  • {indicator}")
        
        if result.attack_techniques:
            summary_parts.append(
                f"\nATTACK TECHNIQUES: {len(result.attack_techniques)} technique(s) identified:"
            )
            for technique in result.attack_techniques[:3]:
                summary_parts.append(f"  • {technique}")
        
        if result.suspicious_behaviors:
            summary_parts.append(
                f"\nSUSPICIOUS BEHAVIORS: {len(result.suspicious_behaviors)} behavior(s) detected:"
            )
            for behavior in result.suspicious_behaviors[:3]:
                summary_parts.append(f"  • {behavior}")
        
        # Analyzer summary
        summary_parts.append(f"\nAnalysis completed using {len(result.analyzers_run)} analyzers:")
        summary_parts.append(f"  • YARA: {len(result.yara_results)} matches")
        summary_parts.append(f"  • Sigma: {len(result.sigma_results)} detections")
        summary_parts.append(f"  • Patterns: {len(result.patterns)} identified")
        summary_parts.append(f"  • Anomalies: {len(result.anomalies)} detected")
        
        if result.virustotal_results:
            vt_detections = result.virustotal_results.get("malicious", 0)
            vt_total = result.virustotal_results.get("total", 0)
            summary_parts.append(f"  • VirusTotal: {vt_detections}/{vt_total} detections")
        
        # AI insights
        if result.ai_insights.get("summary"):
            summary_parts.append(f"\nAI ANALYSIS: {result.ai_insights['summary']}")
        
        result.executive_summary = "\n".join(summary_parts)
    
    def _generate_recommendations(self, result: AnalysisResult) -> None:
        """Generate actionable recommendations based on findings"""
        recommendations = []
        
        # Critical severity recommendations
        if result.severity == "critical":
            recommendations.extend([
                "IMMEDIATE ACTION REQUIRED: Isolate affected systems immediately",
                "Initiate incident response procedures",
                "Preserve evidence for forensic analysis",
                "Check for lateral movement to other systems"
            ])
        
        # High severity recommendations
        elif result.severity == "high":
            recommendations.extend([
                "Investigate identified threats promptly",
                "Review system logs for related activity",
                "Update security tools and signatures",
                "Consider enhanced monitoring"
            ])
        
        # Specific recommendations based on findings
        if any("ransomware" in ind.lower() for ind in result.malware_indicators):
            recommendations.append("Check and secure backups immediately")
            recommendations.append("Review file encryption activity")
        
        if any("persistence" in tech.lower() for tech in result.attack_techniques):
            recommendations.append("Audit startup items and scheduled tasks")
            recommendations.append("Check for unauthorized registry modifications")
        
        if any("exfiltration" in beh.lower() for beh in result.suspicious_behaviors):
            recommendations.append("Review outbound network connections")
            recommendations.append("Check for unauthorized data transfers")
        
        # IOC-based recommendations
        if result.advanced_iocs.get("malicious_ips"):
            recommendations.append("Block identified malicious IP addresses")
        
        if result.advanced_iocs.get("malicious_domains"):
            recommendations.append("Add malicious domains to DNS blacklist")
        
        # General recommendations
        if result.threat_score > 0:
            recommendations.extend([
                "Document all findings for future reference",
                "Update threat intelligence feeds",
                "Consider threat hunting for similar indicators"
            ])
        
        result.recommendations = recommendations[:10]  # Top 10 recommendations
    
    async def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def _generate_analysis_id(self, file_path: str) -> str:
        """Generate unique analysis ID"""
        timestamp = datetime.utcnow().isoformat()
        unique_string = f"{file_path}:{timestamp}"
        return hashlib.md5(unique_string.encode()).hexdigest()
    
    def _get_severity_distribution(self, parse_result: ParseResult) -> Dict[str, int]:
        """Get distribution of entry severities"""
        distribution = defaultdict(int)
        for entry in parse_result.entries:
            distribution[entry.severity] += 1
        return dict(distribution)
    
    async def _store_analysis_result(self, result: AnalysisResult) -> None:
        """Store analysis result to disk"""
        try:
            # Convert to JSON-serializable format
            result_dict = {
                "analysis_id": result.analysis_id,
                "file_path": result.file_path,
                "file_hash": result.file_hash,
                "timestamp": result.timestamp.isoformat(),
                "threat_score": result.threat_score,
                "confidence_level": result.confidence_level,
                "severity": result.severity,
                "executive_summary": result.executive_summary,
                "malware_indicators": result.malware_indicators,
                "attack_techniques": result.attack_techniques,
                "suspicious_behaviors": result.suspicious_behaviors,
                "recommendations": result.recommendations,
                "yara_results": result.yara_results,
                "sigma_results": result.sigma_results,
                "mitre_results": result.mitre_results,
                "ai_insights": result.ai_insights,
                "advanced_iocs": result.advanced_iocs,
                "patterns": result.patterns,
                "anomalies": result.anomalies,
                "correlations": result.correlations,
                "virustotal_results": result.virustotal_results,
                "analysis_duration": result.analysis_duration,
                "analyzers_run": result.analyzers_run,
                "errors": result.errors
            }
            
            # Store to analysis directory
            analysis_path = Path(self.storage_manager.analysis_dir) / f"{result.analysis_id}.json"
            with open(analysis_path, 'w') as f:
                json.dump(result_dict, f, indent=2)
                
            logger.info(f"Analysis result stored: {analysis_path}")
            
        except Exception as e:
            logger.error(f"Failed to store analysis result: {e}")
    
    async def get_analysis_result(self, analysis_id: str) -> Optional[AnalysisResult]:
        """Retrieve analysis result by ID"""
        # Check cache first
        if analysis_id in self._analysis_cache:
            return self._analysis_cache[analysis_id]
        
        # Load from disk
        analysis_path = Path(self.storage_manager.analysis_dir) / f"{analysis_id}.json"
        if analysis_path.exists():
            with open(analysis_path, 'r') as f:
                data = json.load(f)
                # Reconstruct AnalysisResult object
                result = AnalysisResult(
                    analysis_id=data["analysis_id"],
                    file_path=data["file_path"],
                    file_hash=data["file_hash"],
                    timestamp=datetime.fromisoformat(data["timestamp"]),
                    threat_score=data["threat_score"],
                    confidence_level=data["confidence_level"],
                    severity=data["severity"],
                    executive_summary=data["executive_summary"],
                    malware_indicators=data["malware_indicators"],
                    attack_techniques=data["attack_techniques"],
                    suspicious_behaviors=data["suspicious_behaviors"],
                    recommendations=data["recommendations"],
                    yara_results=data["yara_results"],
                    sigma_results=data["sigma_results"],
                    mitre_results=data["mitre_results"],
                    ai_insights=data["ai_insights"],
                    advanced_iocs=data["advanced_iocs"],
                    patterns=data["patterns"],
                    anomalies=data["anomalies"],
                    correlations=data["correlations"],
                    virustotal_results=data["virustotal_results"],
                    analysis_duration=data["analysis_duration"],
                    analyzers_run=data["analyzers_run"],
                    errors=data["errors"]
                )
                # Cache it
                self._analysis_cache[analysis_id] = result
                return result
        
        return None
    
    async def batch_analyze(self, file_analyses: List[Tuple[str, ParseResult]],
                           progress_callback=None) -> List[AnalysisResult]:
        """Analyze multiple files in batch"""
        results = []
        total_files = len(file_analyses)
        
        for idx, (file_path, parse_result) in enumerate(file_analyses):
            try:
                # Update progress
                if progress_callback:
                    await progress_callback(idx + 1, total_files, file_path)
                
                # Analyze file
                result = await self.analyze_file(file_path, parse_result)
                results.append(result)
                
            except Exception as e:
                logger.error(f"Failed to analyze {file_path}: {e}")
                # Create error result
                error_result = AnalysisResult(
                    analysis_id=self._generate_analysis_id(file_path),
                    file_path=file_path,
                    file_hash="error",
                    timestamp=datetime.utcnow(),
                    errors=[str(e)]
                )
                results.append(error_result)
        
        return results