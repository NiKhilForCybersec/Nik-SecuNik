"""
Threat Intelligence Client - Integrates with multiple threat intel sources

This module provides integration with various threat intelligence APIs and feeds
including AbuseIPDB, AlienVault OTX, Shodan, and custom threat feeds.
"""

import logging
import asyncio
import aiohttp
from typing import Dict, List, Optional, Any, Set, Union
from datetime import datetime, timedelta
import json
import hashlib
from dataclasses import dataclass
from collections import defaultdict
import ipaddress

logger = logging.getLogger(__name__)

@dataclass
class ThreatIntelResult:
    """Unified threat intelligence result"""
    source: str
    ioc_type: str
    ioc_value: str
    is_malicious: bool
    confidence: float
    threat_score: int  # 0-100
    threat_types: List[str]
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    tags: List[str]
    raw_data: Dict[str, Any]
    references: List[str]

class ThreatIntelClient:
    """Aggregates threat intelligence from multiple sources"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
        # API keys for various services
        self.abuseipdb_key = config.get("abuseipdb_api_key", "")
        self.otx_key = config.get("alienvault_otx_key", "")
        self.shodan_key = config.get("shodan_api_key", "")
        self.threatcrowd_enabled = config.get("threatcrowd_enabled", True)
        
        # Custom threat feeds
        self.custom_feeds = config.get("custom_feeds", [])
        
        # Caching
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.cache_ttl = timedelta(hours=config.get("cache_hours", 24))
        
        # Rate limiting per service
        self.rate_limits = {
            "abuseipdb": {"limit": 1000, "window": 86400},  # 1000/day
            "otx": {"limit": 10000, "window": 3600},  # 10000/hour
            "shodan": {"limit": 100, "window": 60},  # 100/minute
            "threatcrowd": {"limit": 60, "window": 60}  # 60/minute
        }
        self.request_counts: Dict[str, List[datetime]] = defaultdict(list)
        
        # Local threat lists
        self.local_threats = self._load_local_threats()
        
        # Session
        self.session: Optional[aiohttp.ClientSession] = None
    
    def _load_local_threats(self) -> Dict[str, Set[str]]:
        """Load local threat intelligence lists"""
        return {
            "malicious_ips": set([
                # Known C2 servers, botnet IPs, etc.
                "192.0.2.1",  # Example - would be real threat IPs
            ]),
            "malicious_domains": set([
                # Known malicious domains
                "malware-c2.example.com",  # Example
            ]),
            "malicious_hashes": set([
                # Known malware hashes
            ]),
            "suspicious_user_agents": set([
                "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)",
                "Python-urllib/2.7",
                "curl/7.35.0",
                "Wget/1.15",
            ]),
            "tor_exit_nodes": set(),  # Would be populated from Tor project
            "vpn_servers": set(),  # Known VPN provider IPs
            "cloud_providers": set(),  # AWS, Azure, GCP ranges
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def _ensure_session(self):
        """Ensure aiohttp session exists"""
        if not self.session:
            self.session = aiohttp.ClientSession()
    
    async def _check_rate_limit(self, service: str) -> bool:
        """Check if rate limit allows request"""
        if service not in self.rate_limits:
            return True
        
        limit_config = self.rate_limits[service]
        now = datetime.utcnow()
        window = timedelta(seconds=limit_config["window"])
        
        # Clean old requests
        self.request_counts[service] = [
            t for t in self.request_counts[service]
            if now - t < window
        ]
        
        # Check limit
        if len(self.request_counts[service]) >= limit_config["limit"]:
            return False
        
        # Record request
        self.request_counts[service].append(now)
        return True
    
    def _get_cache_key(self, source: str, ioc_type: str, ioc_value: str) -> str:
        """Generate cache key"""
        return f"{source}:{ioc_type}:{ioc_value}"
    
    def _get_from_cache(self, source: str, ioc_type: str, ioc_value: str) -> Optional[ThreatIntelResult]:
        """Get result from cache if valid"""
        cache_key = self._get_cache_key(source, ioc_type, ioc_value)
        
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            if datetime.utcnow() - cached["timestamp"] < self.cache_ttl:
                return cached["result"]
            else:
                del self.cache[cache_key]
        
        return None
    
    def _save_to_cache(self, result: ThreatIntelResult):
        """Save result to cache"""
        cache_key = self._get_cache_key(result.source, result.ioc_type, result.ioc_value)
        self.cache[cache_key] = {
            "result": result,
            "timestamp": datetime.utcnow()
        }
    
    async def check_ioc(self, ioc_type: str, ioc_value: str, 
                       sources: Optional[List[str]] = None) -> List[ThreatIntelResult]:
        """
        Check an IOC against multiple threat intelligence sources
        
        Args:
            ioc_type: Type of IOC (ip, domain, hash, url, email)
            ioc_value: The IOC value to check
            sources: Optional list of sources to check (default: all available)
            
        Returns:
            List of threat intelligence results from various sources
        """
        results = []
        
        # Determine which sources to check
        if not sources:
            sources = self._get_available_sources()
        
        # Check each source
        tasks = []
        
        if "local" in sources:
            result = self._check_local_threats(ioc_type, ioc_value)
            if result:
                results.append(result)
        
        if "abuseipdb" in sources and self.abuseipdb_key and ioc_type == "ip":
            tasks.append(self._check_abuseipdb(ioc_value))
        
        if "otx" in sources and self.otx_key:
            tasks.append(self._check_alienvault_otx(ioc_type, ioc_value))
        
        if "shodan" in sources and self.shodan_key and ioc_type == "ip":
            tasks.append(self._check_shodan(ioc_value))
        
        if "threatcrowd" in sources and self.threatcrowd_enabled:
            tasks.append(self._check_threatcrowd(ioc_type, ioc_value))
        
        if "custom" in sources:
            for feed in self.custom_feeds:
                tasks.append(self._check_custom_feed(feed, ioc_type, ioc_value))
        
        # Execute all checks in parallel
        if tasks:
            task_results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in task_results:
                if isinstance(result, ThreatIntelResult):
                    results.append(result)
                    self._save_to_cache(result)
        
        return results
    
    def _get_available_sources(self) -> List[str]:
        """Get list of available threat intel sources"""
        sources = ["local"]
        
        if self.abuseipdb_key:
            sources.append("abuseipdb")
        if self.otx_key:
            sources.append("otx")
        if self.shodan_key:
            sources.append("shodan")
        if self.threatcrowd_enabled:
            sources.append("threatcrowd")
        if self.custom_feeds:
            sources.append("custom")
        
        return sources
    
    def _check_local_threats(self, ioc_type: str, ioc_value: str) -> Optional[ThreatIntelResult]:
        """Check IOC against local threat lists"""
        threat_types = []
        tags = []
        
        if ioc_type == "ip":
            if ioc_value in self.local_threats["malicious_ips"]:
                threat_types.append("known_malicious")
                tags.append("blacklist")
            
            if ioc_value in self.local_threats["tor_exit_nodes"]:
                threat_types.append("tor_exit")
                tags.append("anonymizer")
            
            if ioc_value in self.local_threats["vpn_servers"]:
                threat_types.append("vpn")
                tags.append("anonymizer")
        
        elif ioc_type == "domain":
            if ioc_value in self.local_threats["malicious_domains"]:
                threat_types.append("known_malicious")
                tags.append("blacklist")
        
        elif ioc_type == "hash":
            if ioc_value in self.local_threats["malicious_hashes"]:
                threat_types.append("known_malware")
                tags.append("malware")
        
        if threat_types:
            return ThreatIntelResult(
                source="local",
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                is_malicious=True,
                confidence=0.95,
                threat_score=80,
                threat_types=threat_types,
                first_seen=None,
                last_seen=datetime.utcnow(),
                tags=tags,
                raw_data={},
                references=[]
            )
        
        return None
    
    async def _check_abuseipdb(self, ip: str) -> Optional[ThreatIntelResult]:
        """Check IP against AbuseIPDB"""
        # Check cache
        cached = self._get_from_cache("abuseipdb", "ip", ip)
        if cached:
            return cached
        
        # Check rate limit
        if not await self._check_rate_limit("abuseipdb"):
            logger.warning("AbuseIPDB rate limit reached")
            return None
        
        await self._ensure_session()
        
        url = f"https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": self.abuseipdb_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": True
        }
        
        try:
            async with self.session.get(url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    result_data = data.get("data", {})
                    
                    abuse_score = result_data.get("abuseConfidenceScore", 0)
                    is_malicious = abuse_score > 25
                    
                    threat_types = []
                    if result_data.get("usageType") == "Data Center":
                        threat_types.append("datacenter")
                    
                    categories = result_data.get("reports", [])
                    if categories:
                        # Map AbuseIPDB categories to threat types
                        for report in categories[:5]:
                            for cat in report.get("categories", []):
                                if cat in [3, 4, 5, 6, 7, 8, 9, 10, 11]:  # Various attack categories
                                    threat_types.append("scanner")
                                elif cat in [14, 15, 16, 17]:  # Hacking categories
                                    threat_types.append("attacker")
                                elif cat in [18, 19, 20, 21]:  # Malware categories
                                    threat_types.append("malware")
                    
                    return ThreatIntelResult(
                        source="abuseipdb",
                        ioc_type="ip",
                        ioc_value=ip,
                        is_malicious=is_malicious,
                        confidence=abuse_score / 100,
                        threat_score=abuse_score,
                        threat_types=list(set(threat_types)),
                        first_seen=None,
                        last_seen=datetime.utcnow(),
                        tags=[result_data.get("usageType", "unknown")],
                        raw_data=result_data,
                        references=[f"https://www.abuseipdb.com/check/{ip}"]
                    )
                    
        except Exception as e:
            logger.error(f"AbuseIPDB API error: {e}")
        
        return None
    
    async def _check_alienvault_otx(self, ioc_type: str, ioc_value: str) -> Optional[ThreatIntelResult]:
        """Check IOC against AlienVault OTX"""
        # Check cache
        cached = self._get_from_cache("otx", ioc_type, ioc_value)
        if cached:
            return cached
        
        # Check rate limit
        if not await self._check_rate_limit("otx"):
            return None
        
        await self._ensure_session()
        
        # Map IOC types to OTX endpoints
        endpoint_map = {
            "ip": f"indicators/IPv4/{ioc_value}/general",
            "domain": f"indicators/domain/{ioc_value}/general",
            "hash": f"indicators/file/{ioc_value}/general",
            "url": f"indicators/url/{ioc_value}/general"
        }
        
        if ioc_type not in endpoint_map:
            return None
        
        url = f"https://otx.alienvault.com/api/v1/{endpoint_map[ioc_type]}"
        headers = {"X-OTX-API-KEY": self.otx_key}
        
        try:
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    pulse_count = data.get("pulse_info", {}).get("count", 0)
                    is_malicious = pulse_count > 0
                    
                    threat_types = []
                    tags = []
                    
                    # Extract threat info from pulses
                    pulses = data.get("pulse_info", {}).get("pulses", [])
                    for pulse in pulses[:5]:
                        tags.extend(pulse.get("tags", []))
                        
                        # Analyze pulse names for threat types
                        name_lower = pulse.get("name", "").lower()
                        if "malware" in name_lower:
                            threat_types.append("malware")
                        elif "phishing" in name_lower:
                            threat_types.append("phishing")
                        elif "botnet" in name_lower:
                            threat_types.append("botnet")
                        elif "c2" in name_lower or "command" in name_lower:
                            threat_types.append("c2")
                    
                    threat_score = min(pulse_count * 10, 100)
                    
                    return ThreatIntelResult(
                        source="alienvault_otx",
                        ioc_type=ioc_type,
                        ioc_value=ioc_value,
                        is_malicious=is_malicious,
                        confidence=min(pulse_count / 10, 1.0),
                        threat_score=threat_score,
                        threat_types=list(set(threat_types)),
                        first_seen=None,
                        last_seen=datetime.utcnow(),
                        tags=list(set(tags))[:10],
                        raw_data=data,
                        references=[f"https://otx.alienvault.com/indicator/{ioc_type}/{ioc_value}"]
                    )
                    
        except Exception as e:
            logger.error(f"AlienVault OTX API error: {e}")
        
        return None
    
    async def _check_shodan(self, ip: str) -> Optional[ThreatIntelResult]:
        """Check IP against Shodan"""
        # Check cache
        cached = self._get_from_cache("shodan", "ip", ip)
        if cached:
            return cached
        
        # Check rate limit
        if not await self._check_rate_limit("shodan"):
            return None
        
        await self._ensure_session()
        
        url = f"https://api.shodan.io/shodan/host/{ip}"
        params = {"key": self.shodan_key}
        
        try:
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    threat_types = []
                    tags = data.get("tags", [])
                    
                    # Analyze open ports and services
                    services = data.get("data", [])
                    vulnerable_services = 0
                    
                    for service in services:
                        port = service.get("port", 0)
                        product = service.get("product", "")
                        
                        # Check for vulnerable services
                        if port in [23, 2323, 5555]:  # Telnet, common IoT ports
                            threat_types.append("vulnerable_service")
                            vulnerable_services += 1
                        
                        if "vulns" in service:
                            threat_types.append("known_vulnerabilities")
                            vulnerable_services += 1
                        
                        # Check for malware indicators
                        if any(mal in str(service).lower() for mal in ["mirai", "botnet", "malware"]):
                            threat_types.append("infected")
                    
                    # Calculate threat score
                    threat_score = 0
                    if vulnerable_services > 0:
                        threat_score += vulnerable_services * 20
                    if "compromised" in tags:
                        threat_score += 40
                    if "malware" in tags:
                        threat_score += 50
                    
                    threat_score = min(threat_score, 100)
                    is_malicious = threat_score > 30
                    
                    return ThreatIntelResult(
                        source="shodan",
                        ioc_type="ip",
                        ioc_value=ip,
                        is_malicious=is_malicious,
                        confidence=0.8,
                        threat_score=threat_score,
                        threat_types=list(set(threat_types)),
                        first_seen=None,
                        last_seen=datetime.utcnow(),
                        tags=tags,
                        raw_data=data,
                        references=[f"https://www.shodan.io/host/{ip}"]
                    )
                    
        except Exception as e:
            logger.error(f"Shodan API error: {e}")
        
        return None
    
    async def _check_threatcrowd(self, ioc_type: str, ioc_value: str) -> Optional[ThreatIntelResult]:
        """Check IOC against ThreatCrowd (free service)"""
        # Check cache
        cached = self._get_from_cache("threatcrowd", ioc_type, ioc_value)
        if cached:
            return cached
        
        # Check rate limit
        if not await self._check_rate_limit("threatcrowd"):
            return None
        
        await self._ensure_session()
        
        # Map IOC types to ThreatCrowd endpoints
        endpoint_map = {
            "ip": f"https://www.threatcrowd.org/searchApi/v2/ip/report/?ip={ioc_value}",
            "domain": f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={ioc_value}",
            "hash": f"https://www.threatcrowd.org/searchApi/v2/file/report/?resource={ioc_value}",
            "email": f"https://www.threatcrowd.org/searchApi/v2/email/report/?email={ioc_value}"
        }
        
        if ioc_type not in endpoint_map:
            return None
        
        url = endpoint_map[ioc_type]
        
        try:
            async with self.session.get(url, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    # ThreatCrowd returns vote: -1 (malicious), 0 (unknown), 1 (clean)
                    votes = data.get("votes", 0)
                    is_malicious = votes < 0
                    
                    threat_types = []
                    references = data.get("references", [])
                    
                    # Analyze associated data
                    if ioc_type == "domain":
                        # Check for suspicious subdomains
                        subdomains = data.get("subdomains", [])
                        if len(subdomains) > 50:
                            threat_types.append("suspicious_infrastructure")
                        
                        # Check resolutions
                        resolutions = data.get("resolutions", [])
                        if len(resolutions) > 20:
                            threat_types.append("fast_flux")
                    
                    elif ioc_type == "ip":
                        # Check domains hosted
                        domains = data.get("resolutions", [])
                        malicious_domains = sum(1 for d in domains if d.get("domain", "").count(".") > 3)
                        if malicious_domains > 5:
                            threat_types.append("malicious_hosting")
                    
                    # Calculate threat score
                    threat_score = 50 if votes == 0 else (80 if votes < 0 else 20)
                    
                    return ThreatIntelResult(
                        source="threatcrowd",
                        ioc_type=ioc_type,
                        ioc_value=ioc_value,
                        is_malicious=is_malicious,
                        confidence=0.6,
                        threat_score=threat_score,
                        threat_types=threat_types,
                        first_seen=None,
                        last_seen=datetime.utcnow(),
                        tags=[],
                        raw_data=data,
                        references=references[:5]
                    )
                    
        except Exception as e:
            logger.error(f"ThreatCrowd API error: {e}")
        
        return None
    
    async def _check_custom_feed(self, feed_config: Dict[str, Any], 
                                ioc_type: str, ioc_value: str) -> Optional[ThreatIntelResult]:
        """Check IOC against custom threat feed"""
        if feed_config.get("type") != ioc_type:
            return None
        
        await self._ensure_session()
        
        url = feed_config["url"]
        headers = feed_config.get("headers", {})
        
        # Replace placeholders in URL
        url = url.replace("{ioc}", ioc_value)
        
        try:
            async with self.session.get(url, headers=headers, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    # Parse based on feed format
                    parser = feed_config.get("parser", "default")
                    
                    if parser == "default":
                        is_malicious = data.get("malicious", False)
                        threat_score = data.get("score", 50)
                        threat_types = data.get("types", [])
                    else:
                        # Custom parser logic
                        is_malicious = False
                        threat_score = 0
                        threat_types = []
                    
                    return ThreatIntelResult(
                        source=feed_config["name"],
                        ioc_type=ioc_type,
                        ioc_value=ioc_value,
                        is_malicious=is_malicious,
                        confidence=feed_config.get("confidence", 0.7),
                        threat_score=threat_score,
                        threat_types=threat_types,
                        first_seen=None,
                        last_seen=datetime.utcnow(),
                        tags=[],
                        raw_data=data,
                        references=[]
                    )
                    
        except Exception as e:
            logger.error(f"Custom feed {feed_config['name']} error: {e}")
        
        return None
    
    async def get_ioc_context(self, ioc_type: str, ioc_value: str) -> Dict[str, Any]:
        """Get comprehensive context for an IOC"""
        # Check multiple sources
        results = await self.check_ioc(ioc_type, ioc_value)
        
        # Aggregate results
        context = {
            "ioc": ioc_value,
            "type": ioc_type,
            "sources_checked": len(results),
            "is_malicious": any(r.is_malicious for r in results),
            "max_threat_score": max((r.threat_score for r in results), default=0),
            "threat_types": list(set(t for r in results for t in r.threat_types)),
            "tags": list(set(tag for r in results for tag in r.tags)),
            "sources": {}
        }
        
        # Add per-source results
        for result in results:
            context["sources"][result.source] = {
                "malicious": result.is_malicious,
                "score": result.threat_score,
                "confidence": result.confidence,
                "types": result.threat_types
            }
        
        # Add enrichment data
        if ioc_type == "ip":
            context["enrichment"] = await self._enrich_ip(ioc_value)
        elif ioc_type == "domain":
            context["enrichment"] = await self._enrich_domain(ioc_value)
        
        return context
    
    async def _enrich_ip(self, ip: str) -> Dict[str, Any]:
        """Enrich IP with additional context"""
        enrichment = {}
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            enrichment["is_private"] = ip_obj.is_private
            enrichment["is_global"] = ip_obj.is_global
            enrichment["is_multicast"] = ip_obj.is_multicast
            enrichment["version"] = ip_obj.version
            
            # Check if it's in cloud provider ranges
            # This would check against real cloud provider IP ranges
            enrichment["cloud_provider"] = None
            
        except:
            pass
        
        return enrichment
    
    async def _enrich_domain(self, domain: str) -> Dict[str, Any]:
        """Enrich domain with additional context"""
        enrichment = {}
        
        # Extract domain parts
        parts = domain.split(".")
        
        enrichment["tld"] = parts[-1] if parts else ""
        enrichment["subdomain_levels"] = len(parts) - 2
        
        # Check for suspicious patterns
        enrichment["suspicious_tld"] = enrichment["tld"] in ["tk", "ml", "ga", "cf"]
        enrichment["excessive_subdomains"] = enrichment["subdomain_levels"] > 3
        
        return enrichment
    
    async def batch_check_iocs(self, iocs: Dict[str, List[str]], 
                             max_checks: int = 50) -> Dict[str, List[ThreatIntelResult]]:
        """Batch check multiple IOCs"""
        all_results = {
            "ips": [],
            "domains": [],
            "hashes": [],
            "urls": [],
            "emails": []
        }
        
        total_checks = 0
        
        for ioc_type, ioc_list in iocs.items():
            type_key = ioc_type.rstrip("s")  # Remove plural
            
            for ioc in ioc_list:
                if total_checks >= max_checks:
                    break
                
                results = await self.check_ioc(type_key, ioc)
                all_results[ioc_type].extend(results)
                total_checks += 1
        
        return all_results
    
    def get_threat_summary(self, results: List[ThreatIntelResult]) -> Dict[str, Any]:
        """Generate summary from threat intel results"""
        if not results:
            return {
                "verdict": "clean",
                "confidence": 0,
                "threat_score": 0,
                "threat_types": [],
                "recommendations": []
            }
        
        # Calculate aggregate scores
        malicious_sources = sum(1 for r in results if r.is_malicious)
        total_sources = len(results)
        max_score = max(r.threat_score for r in results)
        avg_confidence = sum(r.confidence for r in results) / total_sources
        
        # Determine verdict
        if malicious_sources >= total_sources * 0.7:
            verdict = "malicious"
        elif malicious_sources >= total_sources * 0.3:
            verdict = "suspicious"
        else:
            verdict = "clean"
        
        # Collect all threat types
        all_threat_types = list(set(t for r in results for t in r.threat_types))
        
        # Generate recommendations
        recommendations = []
        if verdict == "malicious":
            recommendations.append("Block this IOC immediately")
            recommendations.append("Check for related IOCs")
            recommendations.append("Review logs for historical activity")
        elif verdict == "suspicious":
            recommendations.append("Monitor activity from this IOC")
            recommendations.append("Consider additional investigation")
        
        return {
            "verdict": verdict,
            "confidence": avg_confidence,
            "threat_score": max_score,
            "threat_types": all_threat_types,
            "sources_reporting_malicious": malicious_sources,
            "total_sources": total_sources,
            "recommendations": recommendations
        }
    
    async def close(self):
        """Close the client session"""
        if self.session:
            await self.session.close()
            self.session = None