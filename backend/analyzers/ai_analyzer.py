"""
AI-Powered Security Analyzer - Uses OpenAI for advanced threat analysis

This module provides AI-driven analysis of security data using LLMs
to identify complex patterns, generate insights, and provide recommendations.
"""

import logging
import asyncio
from typing import Dict, List, Optional, Any, Set
from datetime import datetime
import json
import hashlib
from dataclasses import dataclass
import re

from parsers.base_parser import ParseResult, ParsedEntry
from backend.integrations.openai_client import OpenAIClient

logger = logging.getLogger(__name__)

@dataclass
class AIInsight:
    """Represents an AI-generated security insight"""
    category: str  # threat_assessment, anomaly, recommendation, etc.
    severity: str  # low, medium, high, critical
    confidence: float  # 0-1
    title: str
    description: str
    evidence: List[str]
    recommendations: List[str]
    technical_details: Dict[str, Any]

class AIAnalyzer:
    """AI-powered security analysis using LLMs"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.openai_client = OpenAIClient(config)
        
        # Analysis settings
        self.enable_threat_analysis = config.get("enable_threat_analysis", True)
        self.enable_anomaly_detection = config.get("enable_anomaly_detection", True)
        self.enable_pattern_recognition = config.get("enable_pattern_recognition", True)
        self.enable_recommendations = config.get("enable_recommendations", True)
        
        # Performance settings
        self.max_entries_per_analysis = config.get("max_entries_per_analysis", 100)
        self.chunk_size = config.get("chunk_size", 50)
        self.temperature = config.get("temperature", 0.3)  # Lower for more consistent analysis
        
        # Caching
        self._analysis_cache: Dict[str, Dict[str, Any]] = {}
        self.cache_ttl = config.get("cache_ttl", 3600)  # 1 hour
        
        # Prompt templates
        self.prompts = self._load_prompt_templates()
    
    def _load_prompt_templates(self) -> Dict[str, str]:
        """Load analysis prompt templates"""
        return {
            "threat_analysis": """Analyze the following security data for potential threats and attacks.
Focus on identifying:
1. Attack patterns and techniques
2. Indicators of compromise
3. Threat actor behaviors
4. Security vulnerabilities exploited
5. Timeline of suspicious activities

Data type: {data_type}
Entry count: {entry_count}
Time range: {time_range}

Key findings from automated analysis:
{automated_findings}

Sample log entries:
{sample_entries}

Provide a detailed threat analysis including:
- Threat classification and severity
- Attack methodology identified
- Confidence level in the assessment
- Evidence supporting your conclusions
- Potential threat actor profile

Format your response as JSON with the following structure:
{{
    "threat_level": "low|medium|high|critical",
    "attack_type": "string",
    "confidence": 0.0-1.0,
    "summary": "string",
    "attack_stages": ["string"],
    "threat_actors": {{"profile": "string", "sophistication": "string"}},
    "suspicious_behaviors": ["string"],
    "evidence": ["string"]
}}""",

            "anomaly_detection": """Analyze the following data for anomalies and unusual patterns that may indicate security incidents.

Data statistics:
{data_stats}

Normal baseline patterns:
{baseline_patterns}

Current data sample:
{data_sample}

Identify:
1. Statistical anomalies
2. Behavioral anomalies
3. Temporal anomalies
4. Contextual anomalies

Format response as JSON:
{{
    "anomalies": [
        {{
            "type": "string",
            "description": "string",
            "severity": "low|medium|high",
            "confidence": 0.0-1.0,
            "indicators": ["string"]
        }}
    ],
    "risk_score": 0-100,
    "recommended_actions": ["string"]
}}""",

            "pattern_recognition": """Analyze the security data to identify complex patterns that may indicate advanced threats.

Data context: {context}
IOC summary: {ioc_summary}
Behavioral indicators: {behaviors}

Identify:
1. Multi-stage attack patterns
2. Lateral movement indicators
3. Data exfiltration patterns
4. Command and control patterns
5. Persistence mechanisms

Provide pattern analysis as JSON:
{{
    "patterns": [
        {{
            "name": "string",
            "type": "string",
            "stages": ["string"],
            "confidence": 0.0-1.0,
            "mitre_techniques": ["string"]
        }}
    ],
    "attack_chain": ["string"],
    "next_likely_actions": ["string"]
}}""",

            "security_recommendations": """Based on the security findings below, provide actionable recommendations.

Threat summary: {threat_summary}
Vulnerabilities identified: {vulnerabilities}
Current security posture: {security_posture}

Provide prioritized recommendations:
{{
    "immediate_actions": [
        {{
            "action": "string",
            "rationale": "string",
            "priority": "critical|high|medium|low"
        }}
    ],
    "short_term_recommendations": ["string"],
    "long_term_improvements": ["string"],
    "monitoring_focus": ["string"]
}}""",

            "ioc_context_analysis": """Analyze these Indicators of Compromise (IOCs) in context to determine their significance.

IOCs found:
{iocs}

Context from logs:
{context}

Determine:
1. Which IOCs are most concerning and why
2. Relationships between IOCs
3. Potential false positives
4. Attribution indicators

Format as JSON:
{{
    "high_priority_iocs": [
        {{
            "ioc": "string",
            "type": "string",
            "threat_level": "string",
            "context": "string",
            "related_activity": ["string"]
        }}
    ],
    "ioc_relationships": ["string"],
    "attribution_indicators": ["string"],
    "false_positive_candidates": ["string"]
}}"""
        }
    
    def is_configured(self) -> bool:
        """Check if AI analyzer is properly configured"""
        return self.openai_client.is_configured()
    
    async def analyze_security_context(self, parse_result: ParseResult,
                                     analysis_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform comprehensive AI-powered security analysis
        
        Args:
            parse_result: Parsed data from files
            analysis_context: Additional context from other analyzers
            
        Returns:
            AI-generated insights and recommendations
        """
        if not self.is_configured():
            logger.warning("AI analyzer not configured")
            return {"error": "AI analyzer not configured"}
        
        # Check cache
        cache_key = self._generate_cache_key(parse_result, analysis_context)
        if cache_key in self._analysis_cache:
            cached = self._analysis_cache[cache_key]
            if (datetime.utcnow() - cached["timestamp"]).seconds < self.cache_ttl:
                logger.info("Returning cached AI analysis")
                return cached["result"]
        
        insights = {}
        
        try:
            # Prepare data for analysis
            prepared_data = self._prepare_data_for_analysis(parse_result, analysis_context)
            
            # Run different types of analysis in parallel
            tasks = []
            
            if self.enable_threat_analysis:
                tasks.append(self._analyze_threats(prepared_data))
            
            if self.enable_anomaly_detection:
                tasks.append(self._detect_anomalies(prepared_data))
            
            if self.enable_pattern_recognition:
                tasks.append(self._recognize_patterns(prepared_data))
            
            if self.enable_recommendations:
                tasks.append(self._generate_recommendations(prepared_data))
            
            # Execute all analysis tasks
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            if self.enable_threat_analysis and not isinstance(results[0], Exception):
                insights["threat_analysis"] = results[0]
            
            task_idx = 1
            if self.enable_anomaly_detection:
                if not isinstance(results[task_idx], Exception):
                    insights["anomalies"] = results[task_idx]
                task_idx += 1
            
            if self.enable_pattern_recognition:
                if not isinstance(results[task_idx], Exception):
                    insights["patterns"] = results[task_idx]
                task_idx += 1
            
            if self.enable_recommendations:
                if not isinstance(results[task_idx], Exception):
                    insights["recommendations"] = results[task_idx]
            
            # Analyze IOCs in context
            if prepared_data["iocs"]:
                ioc_analysis = await self._analyze_iocs_in_context(prepared_data)
                insights["ioc_analysis"] = ioc_analysis
            
            # Generate executive summary
            insights["summary"] = self._generate_executive_summary(insights)
            insights["threat_level"] = self._calculate_overall_threat_level(insights)
            insights["confidence_score"] = self._calculate_confidence_score(insights)
            
            # Extract suspicious behaviors for main analysis
            insights["suspicious_behaviors"] = self._extract_suspicious_behaviors(insights)
            
            # Cache results
            self._analysis_cache[cache_key] = {
                "result": insights,
                "timestamp": datetime.utcnow()
            }
            
            return insights
            
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            return {"error": str(e), "threat_level": "unknown"}
    
    def _prepare_data_for_analysis(self, parse_result: ParseResult,
                                  analysis_context: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare and structure data for AI analysis"""
        # Sample entries for analysis
        entries = parse_result.entries[:self.max_entries_per_analysis]
        
        # Calculate time range
        if entries:
            timestamps = [e.timestamp for e in entries if e.timestamp]
            if timestamps:
                time_range = f"{min(timestamps)} to {max(timestamps)}"
            else:
                time_range = "Unknown"
        else:
            time_range = "No entries"
        
        # Extract key patterns
        severity_dist = {}
        message_samples = []
        
        for entry in entries[:50]:  # First 50 for sampling
            severity_dist[entry.severity] = severity_dist.get(entry.severity, 0) + 1
            if entry.severity in ["error", "critical", "warning"]:
                message_samples.append({
                    "severity": entry.severity,
                    "message": entry.message[:200],  # Truncate long messages
                    "tags": entry.tags
                })
        
        # Prepare IOC summary
        ioc_summary = {
            ioc_type: len(iocs) for ioc_type, iocs in parse_result.iocs.items()
        }
        
        # Get automated findings
        automated_findings = {
            "yara_matches": len(analysis_context.get("yara_matches", 0)),
            "sigma_matches": len(analysis_context.get("sigma_matches", 0)),
            "file_type": parse_result.metadata.parser_type,
            "total_entries": len(parse_result.entries),
            "severity_distribution": severity_dist
        }
        
        return {
            "data_type": parse_result.metadata.parser_type,
            "entry_count": len(entries),
            "time_range": time_range,
            "automated_findings": automated_findings,
            "sample_entries": message_samples,
            "iocs": parse_result.iocs,
            "ioc_summary": ioc_summary,
            "severity_distribution": severity_dist,
            "analysis_context": analysis_context,
            "metadata": parse_result.metadata.additional
        }
    
    async def _analyze_threats(self, prepared_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform threat analysis using AI"""
        prompt = self.prompts["threat_analysis"].format(
            data_type=prepared_data["data_type"],
            entry_count=prepared_data["entry_count"],
            time_range=prepared_data["time_range"],
            automated_findings=json.dumps(prepared_data["automated_findings"], indent=2),
            sample_entries=json.dumps(prepared_data["sample_entries"][:20], indent=2)
        )
        
        response = await self.openai_client.analyze_security_data(
            prompt,
            temperature=self.temperature,
            response_format="json"
        )
        
        try:
            return json.loads(response)
        except:
            # Fallback parsing
            return self._parse_threat_response(response)
    
    async def _detect_anomalies(self, prepared_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect anomalies using AI analysis"""
        # Calculate baseline patterns
        baseline = self._calculate_baseline_patterns(prepared_data)
        
        # Prepare statistics
        data_stats = {
            "entry_count": prepared_data["entry_count"],
            "severity_distribution": prepared_data["severity_distribution"],
            "unique_sources": len(set(e.get("source", "") for e in prepared_data.get("sample_entries", []))),
            "time_span": prepared_data["time_range"],
            "error_rate": prepared_data["severity_distribution"].get("error", 0) / max(prepared_data["entry_count"], 1)
        }
        
        prompt = self.prompts["anomaly_detection"].format(
            data_stats=json.dumps(data_stats, indent=2),
            baseline_patterns=json.dumps(baseline, indent=2),
            data_sample=json.dumps(prepared_data["sample_entries"][:30], indent=2)
        )
        
        response = await self.openai_client.analyze_security_data(
            prompt,
            temperature=self.temperature,
            response_format="json"
        )
        
        try:
            return json.loads(response)
        except:
            return {"anomalies": [], "risk_score": 0}
    
    async def _recognize_patterns(self, prepared_data: Dict[str, Any]) -> Dict[str, Any]:
        """Recognize complex attack patterns"""
        # Extract behavioral indicators
        behaviors = self._extract_behavioral_indicators(prepared_data)
        
        context = {
            "file_type": prepared_data["data_type"],
            "time_range": prepared_data["time_range"],
            "entry_types": list(prepared_data["severity_distribution"].keys())
        }
        
        prompt = self.prompts["pattern_recognition"].format(
            context=json.dumps(context, indent=2),
            ioc_summary=json.dumps(prepared_data["ioc_summary"], indent=2),
            behaviors=json.dumps(behaviors, indent=2)
        )
        
        response = await self.openai_client.analyze_security_data(
            prompt,
            temperature=self.temperature,
            response_format="json"
        )
        
        try:
            return json.loads(response)
        except:
            return {"patterns": [], "attack_chain": []}
    
    async def _generate_recommendations(self, prepared_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate security recommendations"""
        # Summarize threats
        threat_summary = {
            "severity_levels": prepared_data["severity_distribution"],
            "ioc_types_found": list(prepared_data["ioc_summary"].keys()),
            "high_risk_indicators": self._identify_high_risk_indicators(prepared_data)
        }
        
        # Identify vulnerabilities
        vulnerabilities = self._identify_vulnerabilities(prepared_data)
        
        # Assess security posture
        security_posture = self._assess_security_posture(prepared_data)
        
        prompt = self.prompts["security_recommendations"].format(
            threat_summary=json.dumps(threat_summary, indent=2),
            vulnerabilities=json.dumps(vulnerabilities, indent=2),
            security_posture=json.dumps(security_posture, indent=2)
        )
        
        response = await self.openai_client.analyze_security_data(
            prompt,
            temperature=self.temperature,
            response_format="json"
        )
        
        try:
            return json.loads(response)
        except:
            return {"immediate_actions": [], "short_term_recommendations": []}
    
    async def _analyze_iocs_in_context(self, prepared_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze IOCs with contextual information"""
        # Prepare IOC data
        ioc_data = []
        for ioc_type, iocs in prepared_data["iocs"].items():
            for ioc in iocs[:10]:  # Limit to top 10 per type
                ioc_data.append({
                    "type": ioc_type,
                    "value": ioc,
                    "context": self._find_ioc_context(ioc, prepared_data["sample_entries"])
                })
        
        # Get relevant context
        context_entries = [
            {
                "message": e["message"],
                "severity": e["severity"]
            }
            for e in prepared_data["sample_entries"]
            if any(ioc["value"] in e["message"] for ioc in ioc_data)
        ][:20]
        
        prompt = self.prompts["ioc_context_analysis"].format(
            iocs=json.dumps(ioc_data, indent=2),
            context=json.dumps(context_entries, indent=2)
        )
        
        response = await self.openai_client.analyze_security_data(
            prompt,
            temperature=self.temperature,
            response_format="json"
        )
        
        try:
            return json.loads(response)
        except:
            return {"high_priority_iocs": [], "ioc_relationships": []}
    
    def _calculate_baseline_patterns(self, prepared_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate baseline patterns for anomaly detection"""
        # Simple baseline calculation
        total_entries = max(prepared_data["entry_count"], 1)
        
        return {
            "normal_severity_distribution": {
                "info": 0.7,
                "warning": 0.2,
                "error": 0.08,
                "critical": 0.02
            },
            "expected_error_rate": 0.1,
            "expected_patterns": [
                "Regular authentication events",
                "Routine system operations",
                "Standard network traffic"
            ]
        }
    
    def _extract_behavioral_indicators(self, prepared_data: Dict[str, Any]) -> List[str]:
        """Extract behavioral indicators from the data"""
        indicators = []
        
        # Check for specific patterns in messages
        suspicious_patterns = [
            (r"failed.*login|authentication.*failed", "Multiple failed authentication attempts"),
            (r"scan|scanning|nmap", "Network scanning activity"),
            (r"download|wget|curl.*http", "File download activity"),
            (r"cmd\.exe|powershell|/bin/sh", "Command execution"),
            (r"encrypt|ransom|locked", "Possible ransomware activity"),
            (r"exfil|upload.*data|transfer.*large", "Potential data exfiltration")
        ]
        
        for entry in prepared_data.get("sample_entries", []):
            message_lower = entry["message"].lower()
            for pattern, description in suspicious_patterns:
                if re.search(pattern, message_lower):
                    indicators.append(description)
        
        # Add IOC-based indicators
        if prepared_data["ioc_summary"].get("ips", 0) > 10:
            indicators.append("Multiple suspicious IP addresses detected")
        
        if prepared_data["ioc_summary"].get("domains", 0) > 5:
            indicators.append("Multiple suspicious domains detected")
        
        return list(set(indicators))  # Remove duplicates
    
    def _identify_high_risk_indicators(self, prepared_data: Dict[str, Any]) -> List[str]:
        """Identify high-risk security indicators"""
        high_risk = []
        
        # Check severity distribution
        if prepared_data["severity_distribution"].get("critical", 0) > 0:
            high_risk.append("Critical severity events detected")
        
        if prepared_data["severity_distribution"].get("error", 0) > 10:
            high_risk.append("High number of error events")
        
        # Check for specific IOC patterns
        for ioc_type, iocs in prepared_data["iocs"].items():
            if ioc_type == "ips" and len(iocs) > 20:
                high_risk.append("Excessive number of IP addresses")
            elif ioc_type == "hashes" and len(iocs) > 5:
                high_risk.append("Multiple file hashes detected")
        
        return high_risk
    
    def _identify_vulnerabilities(self, prepared_data: Dict[str, Any]) -> List[str]:
        """Identify potential vulnerabilities"""
        vulnerabilities = []
        
        # Check for common vulnerability patterns
        for entry in prepared_data.get("sample_entries", []):
            message_lower = entry["message"].lower()
            
            if "unpatched" in message_lower or "outdated" in message_lower:
                vulnerabilities.append("Unpatched or outdated software detected")
            
            if "weak password" in message_lower or "default password" in message_lower:
                vulnerabilities.append("Weak or default passwords in use")
            
            if "open port" in message_lower or "exposed service" in message_lower:
                vulnerabilities.append("Exposed services or open ports")
        
        return list(set(vulnerabilities))
    
    def _assess_security_posture(self, prepared_data: Dict[str, Any]) -> Dict[str, Any]:
        """Assess overall security posture"""
        # Simple scoring based on indicators
        score = 100
        
        # Deduct points for issues
        score -= prepared_data["severity_distribution"].get("critical", 0) * 10
        score -= prepared_data["severity_distribution"].get("error", 0) * 2
        score -= min(len(prepared_data.get("iocs", {}).get("ips", [])), 20)
        
        score = max(0, score)
        
        if score >= 80:
            posture = "strong"
        elif score >= 60:
            posture = "moderate"
        elif score >= 40:
            posture = "weak"
        else:
            posture = "critical"
        
        return {
            "score": score,
            "rating": posture,
            "key_concerns": self._identify_high_risk_indicators(prepared_data)
        }
    
    def _find_ioc_context(self, ioc: str, entries: List[Dict[str, Any]]) -> str:
        """Find context for an IOC in log entries"""
        for entry in entries:
            if ioc in entry["message"]:
                return entry["message"][:100] + "..."
        return "No direct context found"
    
    def _parse_threat_response(self, response: str) -> Dict[str, Any]:
        """Parse threat analysis response if JSON parsing fails"""
        # Fallback parser for non-JSON responses
        result = {
            "threat_level": "unknown",
            "attack_type": "unknown",
            "confidence": 0.5,
            "summary": response[:500] if isinstance(response, str) else "",
            "attack_stages": [],
            "threat_actors": {},
            "suspicious_behaviors": [],
            "evidence": []
        }
        
        # Try to extract threat level
        if "critical" in response.lower():
            result["threat_level"] = "critical"
        elif "high" in response.lower():
            result["threat_level"] = "high"
        elif "medium" in response.lower():
            result["threat_level"] = "medium"
        elif "low" in response.lower():
            result["threat_level"] = "low"
        
        return result
    
    def _generate_executive_summary(self, insights: Dict[str, Any]) -> str:
        """Generate executive summary from all insights"""
        summary_parts = []
        
        # Threat analysis summary
        if "threat_analysis" in insights:
            threat = insights["threat_analysis"]
            summary_parts.append(
                f"Threat Level: {threat.get('threat_level', 'unknown').upper()}. "
                f"{threat.get('summary', 'No specific threats identified.')}"
            )
        
        # Anomaly summary
        if "anomalies" in insights:
            anomalies = insights["anomalies"]
            if anomalies.get("anomalies"):
                summary_parts.append(
                    f"Detected {len(anomalies['anomalies'])} anomalies with risk score: "
                    f"{anomalies.get('risk_score', 0)}/100"
                )
        
        # Pattern summary
        if "patterns" in insights:
            patterns = insights["patterns"]
            if patterns.get("patterns"):
                summary_parts.append(
                    f"Identified {len(patterns['patterns'])} attack patterns"
                )
        
        # IOC summary
        if "ioc_analysis" in insights:
            ioc = insights["ioc_analysis"]
            high_priority = len(ioc.get("high_priority_iocs", []))
            if high_priority > 0:
                summary_parts.append(f"{high_priority} high-priority IOCs require immediate attention")
        
        return " ".join(summary_parts) if summary_parts else "No significant security concerns identified."
    
    def _calculate_overall_threat_level(self, insights: Dict[str, Any]) -> str:
        """Calculate overall threat level from all insights"""
        threat_scores = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1,
            "unknown": 0
        }
        
        scores = []
        
        # Get threat level from threat analysis
        if "threat_analysis" in insights:
            level = insights["threat_analysis"].get("threat_level", "unknown")
            scores.append(threat_scores.get(level, 0))
        
        # Get risk from anomalies
        if "anomalies" in insights:
            risk_score = insights["anomalies"].get("risk_score", 0)
            if risk_score >= 80:
                scores.append(4)
            elif risk_score >= 60:
                scores.append(3)
            elif risk_score >= 40:
                scores.append(2)
            else:
                scores.append(1)
        
        # Consider high-priority IOCs
        if "ioc_analysis" in insights:
            high_priority_count = len(insights["ioc_analysis"].get("high_priority_iocs", []))
            if high_priority_count >= 5:
                scores.append(4)
            elif high_priority_count >= 2:
                scores.append(3)
            elif high_priority_count >= 1:
                scores.append(2)
        
        # Calculate average and map to threat level
        if not scores:
            return "unknown"
        
        avg_score = sum(scores) / len(scores)
        
        if avg_score >= 3.5:
            return "critical"
        elif avg_score >= 2.5:
            return "high"
        elif avg_score >= 1.5:
            return "medium"
        else:
            return "low"
    
    def _calculate_confidence_score(self, insights: Dict[str, Any]) -> float:
        """Calculate overall confidence in the analysis"""
        confidences = []
        
        # Get confidence from different analyses
        if "threat_analysis" in insights:
            conf = insights["threat_analysis"].get("confidence", 0.5)
            confidences.append(conf)
        
        # Anomaly detection confidence (based on anomaly count)
        if "anomalies" in insights:
            anomaly_count = len(insights["anomalies"].get("anomalies", []))
            if anomaly_count > 0:
                confidences.append(min(0.6 + (anomaly_count * 0.1), 0.95))
        
        # Pattern recognition confidence
        if "patterns" in insights:
            pattern_count = len(insights["patterns"].get("patterns", []))
            if pattern_count > 0:
                avg_pattern_conf = sum(
                    p.get("confidence", 0.5) 
                    for p in insights["patterns"]["patterns"]
                ) / pattern_count
                confidences.append(avg_pattern_conf)
        
        return sum(confidences) / len(confidences) if confidences else 0.5
    
    def _extract_suspicious_behaviors(self, insights: Dict[str, Any]) -> List[str]:
        """Extract all suspicious behaviors from insights"""
        behaviors = []
        
        # From threat analysis
        if "threat_analysis" in insights:
            behaviors.extend(insights["threat_analysis"].get("suspicious_behaviors", []))
        
        # From anomalies
        if "anomalies" in insights:
            for anomaly in insights["anomalies"].get("anomalies", []):
                behaviors.append(f"Anomaly: {anomaly.get('description', 'Unknown anomaly')}")
        
        # From patterns
        if "patterns" in insights:
            for pattern in insights["patterns"].get("patterns", []):
                behaviors.append(f"Pattern: {pattern.get('name', 'Unknown pattern')}")
        
        return list(set(behaviors))  # Remove duplicates
    
    def _generate_cache_key(self, parse_result: ParseResult, 
                           analysis_context: Dict[str, Any]) -> str:
        """Generate cache key for analysis results"""
        # Create a unique key based on data characteristics
        key_parts = [
            parse_result.metadata.parser_type,
            str(len(parse_result.entries)),
            str(len(parse_result.iocs)),
            json.dumps(sorted(analysis_context.keys()))
        ]
        
        key_string = "|".join(key_parts)
        return hashlib.md5(key_string.encode()).hexdigest()
    
    async def analyze_specific_threat(self, threat_type: str, 
                                    evidence: List[str]) -> Dict[str, Any]:
        """Analyze a specific threat type with given evidence"""
        prompt = f"""Analyze the following evidence for {threat_type}:

Evidence:
{json.dumps(evidence, indent=2)}

Provide:
1. Confirmation of threat type
2. Severity assessment
3. Attack methodology
4. Recommended immediate actions

Format as JSON."""
        
        response = await self.openai_client.analyze_security_data(
            prompt,
            temperature=0.3,
            response_format="json"
        )
        
        try:
            return json.loads(response)
        except:
            return {"error": "Failed to parse response"}