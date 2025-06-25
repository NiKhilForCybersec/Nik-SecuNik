"""
OpenAI API Client - Integrates with OpenAI for AI-powered security analysis

This module provides integration with OpenAI's API for advanced security
analysis, threat detection, and intelligent recommendations.
"""

import logging
import asyncio
import aiohttp
from typing import Dict, List, Optional, Any, Union
import json
from datetime import datetime, timedelta
import tiktoken
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class ModelConfig:
    """Configuration for different OpenAI models"""
    name: str
    max_tokens: int
    cost_per_1k_input: float
    cost_per_1k_output: float
    context_window: int
    supports_json: bool
    supports_functions: bool

class OpenAIClient:
    """Client for OpenAI API integration"""
    
    # Model configurations
    MODELS = {
        "gpt-4-turbo": ModelConfig(
            name="gpt-4-turbo-preview",
            max_tokens=4096,
            cost_per_1k_input=0.01,
            cost_per_1k_output=0.03,
            context_window=128000,
            supports_json=True,
            supports_functions=True
        ),
        "gpt-4": ModelConfig(
            name="gpt-4",
            max_tokens=4096,
            cost_per_1k_input=0.03,
            cost_per_1k_output=0.06,
            context_window=8192,
            supports_json=False,
            supports_functions=True
        ),
        "gpt-3.5-turbo": ModelConfig(
            name="gpt-3.5-turbo",
            max_tokens=4096,
            cost_per_1k_input=0.001,
            cost_per_1k_output=0.002,
            context_window=16385,
            supports_json=True,
            supports_functions=True
        )
    }
    
    def __init__(self, config: Dict[str, Any]):
        self.api_key = config.get("api_key", "")
        self.organization = config.get("organization", "")
        self.model_name = config.get("model", "gpt-3.5-turbo")
        self.model_config = self.MODELS.get(self.model_name, self.MODELS["gpt-3.5-turbo"])
        
        # API settings
        self.base_url = "https://api.openai.com/v1"
        self.timeout = config.get("timeout", 60)
        self.max_retries = config.get("max_retries", 3)
        self.retry_delay = config.get("retry_delay", 1)
        
        # Cost tracking
        self.total_tokens_used = 0
        self.total_cost = 0.0
        
        # Rate limiting
        self.rate_limit = config.get("rate_limit", 60)  # requests per minute
        self.request_times: List[datetime] = []
        
        # Session
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Headers
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        if self.organization:
            self.headers["OpenAI-Organization"] = self.organization
        
        # Token encoder
        try:
            self.encoder = tiktoken.encoding_for_model(self.model_config.name)
        except:
            self.encoder = tiktoken.get_encoding("cl100k_base")
    
    def is_configured(self) -> bool:
        """Check if client is properly configured"""
        return bool(self.api_key)
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(headers=self.headers)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def _ensure_session(self):
        """Ensure aiohttp session exists"""
        if not self.session:
            self.session = aiohttp.ClientSession(headers=self.headers)
    
    async def _rate_limit_check(self):
        """Check and enforce rate limiting"""
        now = datetime.utcnow()
        
        # Remove old requests
        self.request_times = [
            t for t in self.request_times 
            if (now - t).total_seconds() < 60
        ]
        
        # Check if we've hit the limit
        if len(self.request_times) >= self.rate_limit:
            wait_time = 60 - (now - self.request_times[0]).total_seconds()
            if wait_time > 0:
                logger.info(f"Rate limit reached, waiting {wait_time:.1f} seconds")
                await asyncio.sleep(wait_time)
        
        self.request_times.append(now)
    
    def count_tokens(self, text: str) -> int:
        """Count tokens in text"""
        return len(self.encoder.encode(text))
    
    def estimate_cost(self, input_tokens: int, output_tokens: int) -> float:
        """Estimate cost for API call"""
        input_cost = (input_tokens / 1000) * self.model_config.cost_per_1k_input
        output_cost = (output_tokens / 1000) * self.model_config.cost_per_1k_output
        return input_cost + output_cost
    
    async def _make_request(self, endpoint: str, data: Dict[str, Any], 
                          retry_count: int = 0) -> Optional[Dict[str, Any]]:
        """Make API request with retry logic"""
        await self._ensure_session()
        await self._rate_limit_check()
        
        url = f"{self.base_url}/{endpoint}"
        
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with self.session.post(url, json=data, timeout=timeout) as response:
                if response.status == 200:
                    result = await response.json()
                    
                    # Track usage
                    if "usage" in result:
                        usage = result["usage"]
                        self.total_tokens_used += usage.get("total_tokens", 0)
                        self.total_cost += self.estimate_cost(
                            usage.get("prompt_tokens", 0),
                            usage.get("completion_tokens", 0)
                        )
                    
                    return result
                    
                elif response.status == 429:  # Rate limit
                    if retry_count < self.max_retries:
                        wait_time = self.retry_delay * (2 ** retry_count)
                        logger.warning(f"Rate limited, retrying in {wait_time}s")
                        await asyncio.sleep(wait_time)
                        return await self._make_request(endpoint, data, retry_count + 1)
                    else:
                        logger.error("Max retries exceeded for rate limit")
                        return None
                        
                else:
                    error_text = await response.text()
                    logger.error(f"OpenAI API error {response.status}: {error_text}")
                    
                    # Retry on server errors
                    if response.status >= 500 and retry_count < self.max_retries:
                        wait_time = self.retry_delay * (2 ** retry_count)
                        await asyncio.sleep(wait_time)
                        return await self._make_request(endpoint, data, retry_count + 1)
                    
                    return None
                    
        except asyncio.TimeoutError:
            logger.error(f"Timeout calling OpenAI API: {endpoint}")
            if retry_count < self.max_retries:
                return await self._make_request(endpoint, data, retry_count + 1)
            return None
            
        except Exception as e:
            logger.error(f"Error calling OpenAI API: {e}")
            return None
    
    async def analyze_security_data(self, prompt: str, temperature: float = 0.3,
                                  max_tokens: Optional[int] = None,
                                  response_format: Optional[str] = None) -> Optional[str]:
        """
        Analyze security data using OpenAI
        
        Args:
            prompt: Analysis prompt
            temperature: Sampling temperature (0-1)
            max_tokens: Maximum tokens in response
            response_format: "json" for JSON mode (if supported)
            
        Returns:
            AI analysis response
        """
        if not self.is_configured():
            logger.error("OpenAI client not configured")
            return None
        
        # Check token limits
        prompt_tokens = self.count_tokens(prompt)
        if prompt_tokens > self.model_config.context_window - 1000:
            logger.warning(f"Prompt too long: {prompt_tokens} tokens")
            # Truncate prompt
            prompt = self._truncate_prompt(prompt, self.model_config.context_window - 1000)
        
        # Build request
        messages = [
            {
                "role": "system",
                "content": """You are an expert cybersecurity analyst specializing in threat detection, 
                incident response, and security log analysis. Analyze the provided data carefully and 
                provide detailed, actionable insights. Focus on identifying threats, attack patterns, 
                and security risks. Be specific and technical in your analysis."""
            },
            {
                "role": "user",
                "content": prompt
            }
        ]
        
        data = {
            "model": self.model_config.name,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens or self.model_config.max_tokens
        }
        
        # Add JSON mode if supported and requested
        if response_format == "json" and self.model_config.supports_json:
            data["response_format"] = {"type": "json_object"}
        
        # Make request
        result = await self._make_request("chat/completions", data)
        
        if result and "choices" in result:
            return result["choices"][0]["message"]["content"]
        
        return None
    
    async def analyze_with_functions(self, prompt: str, functions: List[Dict[str, Any]],
                                   temperature: float = 0.3) -> Optional[Dict[str, Any]]:
        """
        Analyze using function calling capabilities
        
        Args:
            prompt: Analysis prompt
            functions: Function definitions
            temperature: Sampling temperature
            
        Returns:
            Function call or text response
        """
        if not self.model_config.supports_functions:
            logger.warning(f"Model {self.model_config.name} doesn't support functions")
            return None
        
        messages = [
            {
                "role": "system",
                "content": "You are a security analyst. Use the provided functions to analyze security data."
            },
            {
                "role": "user",
                "content": prompt
            }
        ]
        
        data = {
            "model": self.model_config.name,
            "messages": messages,
            "functions": functions,
            "function_call": "auto",
            "temperature": temperature
        }
        
        result = await self._make_request("chat/completions", data)
        
        if result and "choices" in result:
            choice = result["choices"][0]
            message = choice["message"]
            
            if "function_call" in message:
                return {
                    "type": "function",
                    "function": message["function_call"]["name"],
                    "arguments": json.loads(message["function_call"]["arguments"])
                }
            else:
                return {
                    "type": "text",
                    "content": message["content"]
                }
        
        return None
    
    async def generate_security_report(self, analysis_data: Dict[str, Any]) -> Optional[str]:
        """Generate a comprehensive security report"""
        prompt = f"""Generate a comprehensive security report based on the following analysis:

Threat Score: {analysis_data.get('threat_score', 'Unknown')}
Severity: {analysis_data.get('severity', 'Unknown')}

Key Findings:
- Malware Indicators: {len(analysis_data.get('malware_indicators', []))}
- Attack Techniques: {len(analysis_data.get('attack_techniques', []))}
- Suspicious Behaviors: {len(analysis_data.get('suspicious_behaviors', []))}

YARA Matches: {len(analysis_data.get('yara_results', []))}
Sigma Rules Triggered: {len(analysis_data.get('sigma_results', []))}
MITRE Techniques: {analysis_data.get('mitre_results', {}).get('technique_count', 0)}

Top Threats:
{json.dumps(analysis_data.get('malware_indicators', [])[:5], indent=2)}

Create a structured report with:
1. Executive Summary
2. Threat Assessment
3. Technical Details
4. Impact Analysis
5. Recommendations
6. Next Steps

Format the report in clear sections with markdown formatting."""

        response = await self.analyze_security_data(
            prompt,
            temperature=0.5,
            max_tokens=2000
        )
        
        return response
    
    async def analyze_ioc_context(self, ioc: str, ioc_type: str, 
                                context: List[str]) -> Optional[Dict[str, Any]]:
        """Analyze an IOC with surrounding context"""
        prompt = f"""Analyze this {ioc_type} IOC with its context:

IOC: {ioc}
Type: {ioc_type}

Context (surrounding log entries):
{chr(10).join(context[:10])}

Determine:
1. Is this IOC malicious, suspicious, or benign?
2. What activity is associated with this IOC?
3. What is the confidence level (0-1)?
4. What are the recommended actions?

Respond in JSON format:
{{
    "classification": "malicious|suspicious|benign",
    "confidence": 0.0-1.0,
    "activity": "description",
    "threat_type": "type",
    "recommendations": ["action1", "action2"]
}}"""

        response = await self.analyze_security_data(
            prompt,
            temperature=0.3,
            response_format="json"
        )
        
        if response:
            try:
                return json.loads(response)
            except:
                return {"error": "Failed to parse response"}
        
        return None
    
    async def suggest_detection_rules(self, attack_pattern: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Suggest detection rules for an attack pattern"""
        prompt = f"""Based on this detected attack pattern, suggest detection rules:

Pattern: {attack_pattern.get('name', 'Unknown')}
Type: {attack_pattern.get('type', 'Unknown')}
Evidence: {json.dumps(attack_pattern.get('evidence', [])[:3], indent=2)}

Generate:
1. A YARA rule to detect this pattern
2. A Sigma rule for log detection
3. Network detection signatures
4. Behavioral indicators to monitor

Format as JSON with rule content."""

        response = await self.analyze_security_data(
            prompt,
            temperature=0.5,
            response_format="json"
        )
        
        if response:
            try:
                return json.loads(response)
            except:
                return None
        
        return None
    
    async def explain_attack_technique(self, technique_id: str, 
                                     evidence: List[str]) -> Optional[str]:
        """Explain a MITRE ATT&CK technique with evidence"""
        prompt = f"""Explain MITRE ATT&CK technique {technique_id} in the context of this evidence:

Evidence:
{chr(10).join(evidence[:5])}

Provide:
1. What this technique does
2. How it's being used in this case
3. Potential impact
4. Detection methods
5. Mitigation strategies

Keep the explanation technical but clear."""

        return await self.analyze_security_data(prompt, temperature=0.5)
    
    async def correlate_events(self, events: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Correlate multiple security events"""
        # Limit events to prevent token overflow
        limited_events = events[:20]
        
        prompt = f"""Analyze these security events for correlations and patterns:

Events:
{json.dumps(limited_events, indent=2)}

Identify:
1. Related events that form an attack chain
2. Timeline of the potential attack
3. Common IOCs or techniques
4. Overall threat narrative

Respond in JSON format with your analysis."""

        response = await self.analyze_security_data(
            prompt,
            temperature=0.3,
            response_format="json"
        )
        
        if response:
            try:
                return json.loads(response)
            except:
                return None
        
        return None
    
    async def prioritize_alerts(self, alerts: List[Dict[str, Any]]) -> Optional[List[Dict[str, Any]]]:
        """Prioritize security alerts using AI"""
        prompt = f"""Prioritize these security alerts based on risk and urgency:

Alerts:
{json.dumps(alerts[:30], indent=2)}

For each alert, assign:
1. Priority: critical, high, medium, low
2. Risk score: 0-100
3. Reason for prioritization
4. Recommended response time

Return a JSON array of prioritized alerts."""

        response = await self.analyze_security_data(
            prompt,
            temperature=0.3,
            response_format="json"
        )
        
        if response:
            try:
                result = json.loads(response)
                if isinstance(result, list):
                    return result
                elif isinstance(result, dict) and "alerts" in result:
                    return result["alerts"]
            except:
                pass
        
        return None
    
    async def generate_incident_summary(self, incident_data: Dict[str, Any]) -> Optional[str]:
        """Generate an incident summary for reporting"""
        prompt = f"""Create a concise incident summary based on this data:

Incident Type: {incident_data.get('type', 'Unknown')}
Severity: {incident_data.get('severity', 'Unknown')}
Affected Systems: {incident_data.get('affected_systems', 'Unknown')}
Time Range: {incident_data.get('time_range', 'Unknown')}

Key Indicators:
{json.dumps(incident_data.get('indicators', [])[:10], indent=2)}

Create a 2-3 paragraph summary suitable for:
1. Executive briefing
2. Incident ticket
3. Stakeholder communication

Include impact, current status, and next steps."""

        return await self.analyze_security_data(prompt, temperature=0.5)
    
    def _truncate_prompt(self, prompt: str, max_tokens: int) -> str:
        """Truncate prompt to fit token limit"""
        tokens = self.encoder.encode(prompt)
        if len(tokens) <= max_tokens:
            return prompt
        
        # Truncate and decode
        truncated_tokens = tokens[:max_tokens]
        truncated_text = self.encoder.decode(truncated_tokens)
        
        # Add truncation indicator
        return truncated_text + "\n\n[Content truncated due to length...]"
    
    async def analyze_anomaly(self, anomaly_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Analyze an anomaly for security implications"""
        prompt = f"""Analyze this anomaly for security implications:

Anomaly Type: {anomaly_data.get('type', 'Unknown')}
Description: {anomaly_data.get('description', '')}
Confidence: {anomaly_data.get('confidence', 0)}

Context:
{json.dumps(anomaly_data.get('context', {}), indent=2)}

Determine:
1. Is this security-relevant?
2. What could cause this anomaly?
3. Risk level (low/medium/high/critical)
4. Investigation steps

Respond in JSON format."""

        response = await self.analyze_security_data(
            prompt,
            temperature=0.3,
            response_format="json"
        )
        
        if response:
            try:
                return json.loads(response)
            except:
                return None
        
        return None
    
    def get_usage_stats(self) -> Dict[str, Any]:
        """Get usage statistics"""
        return {
            "total_tokens": self.total_tokens_used,
            "total_cost": round(self.total_cost, 4),
            "model": self.model_config.name,
            "requests_made": len(self.request_times)
        }
    
    async def close(self):
        """Close the client session"""
        if self.session:
            await self.session.close()
            self.session = None