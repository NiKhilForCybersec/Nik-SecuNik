"""
VirusTotal API Client - Integrates with VirusTotal for threat intelligence

This module provides integration with VirusTotal API v3 for checking
file hashes, IPs, domains, and URLs against threat intelligence.
"""

import logging
import asyncio
import aiohttp
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timedelta
import hashlib
import base64
from urllib.parse import quote
import json

logger = logging.getLogger(__name__)

class VirusTotalClient:
    """Client for VirusTotal API v3 integration"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        
        # Rate limiting (VT free tier: 4 requests/minute)
        self.rate_limit = 4
        self.rate_window = 60  # seconds
        self.request_times: List[datetime] = []
        
        # Caching
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.cache_ttl = timedelta(hours=24)  # Cache for 24 hours
        
        # Request session
        self.session: Optional[aiohttp.ClientSession] = None
        
        # API headers
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
    
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
        
        # Remove old requests outside the window
        self.request_times = [
            t for t in self.request_times 
            if (now - t).total_seconds() < self.rate_window
        ]
        
        # Check if we've hit the limit
        if len(self.request_times) >= self.rate_limit:
            # Calculate wait time
            oldest_request = min(self.request_times)
            wait_time = self.rate_window - (now - oldest_request).total_seconds()
            
            if wait_time > 0:
                logger.info(f"Rate limit reached, waiting {wait_time:.1f} seconds")
                await asyncio.sleep(wait_time)
                # Retry the check
                await self._rate_limit_check()
        
        # Record this request
        self.request_times.append(now)
    
    def _get_cache_key(self, resource_type: str, resource_value: str) -> str:
        """Generate cache key"""
        return f"{resource_type}:{resource_value}"
    
    def _get_from_cache(self, resource_type: str, resource_value: str) -> Optional[Dict[str, Any]]:
        """Get result from cache if valid"""
        cache_key = self._get_cache_key(resource_type, resource_value)
        
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            if datetime.utcnow() - cached["timestamp"] < self.cache_ttl:
                logger.debug(f"Cache hit for {cache_key}")
                return cached["data"]
            else:
                # Expired
                del self.cache[cache_key]
        
        return None
    
    def _save_to_cache(self, resource_type: str, resource_value: str, data: Dict[str, Any]):
        """Save result to cache"""
        cache_key = self._get_cache_key(resource_type, resource_value)
        self.cache[cache_key] = {
            "data": data,
            "timestamp": datetime.utcnow()
        }
    
    async def _make_request(self, endpoint: str, method: str = "GET", 
                          data: Optional[Dict] = None) -> Optional[Dict[str, Any]]:
        """Make API request with error handling"""
        await self._ensure_session()
        await self._rate_limit_check()
        
        url = f"{self.base_url}/{endpoint}"
        
        try:
            async with self.session.request(method, url, json=data) as response:
                if response.status == 200:
                    return await response.json()
                elif response.status == 204:
                    return {"status": "no_content"}
                elif response.status == 404:
                    logger.info(f"Resource not found: {endpoint}")
                    return None
                elif response.status == 429:
                    logger.warning("Rate limit exceeded, despite our checks")
                    return None
                else:
                    error_text = await response.text()
                    logger.error(f"VT API error {response.status}: {error_text}")
                    return None
                    
        except asyncio.TimeoutError:
            logger.error(f"Timeout accessing VT API: {endpoint}")
            return None
        except Exception as e:
            logger.error(f"Error accessing VT API: {e}")
            return None
    
    async def check_file_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Check file hash against VirusTotal
        
        Args:
            file_hash: MD5, SHA1, or SHA256 hash
            
        Returns:
            Dictionary with detection results
        """
        # Check cache first
        cached = self._get_from_cache("file", file_hash)
        if cached:
            return cached
        
        # Make API request
        endpoint = f"files/{file_hash}"
        result = await self._make_request(endpoint)
        
        if not result:
            return {
                "found": False,
                "hash": file_hash,
                "error": "Not found or API error"
            }
        
        # Parse results
        data = result.get("data", {})
        attributes = data.get("attributes", {})
        
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        last_analysis_results = attributes.get("last_analysis_results", {})
        
        # Build response
        response = {
            "found": True,
            "hash": file_hash,
            "md5": attributes.get("md5", ""),
            "sha1": attributes.get("sha1", ""),
            "sha256": attributes.get("sha256", ""),
            "type_description": attributes.get("type_description", "Unknown"),
            "size": attributes.get("size", 0),
            "first_seen": attributes.get("first_submission_date", ""),
            "last_seen": attributes.get("last_submission_date", ""),
            "names": attributes.get("names", [])[:5],  # Top 5 names
            "malicious": last_analysis_stats.get("malicious", 0),
            "suspicious": last_analysis_stats.get("suspicious", 0),
            "undetected": last_analysis_stats.get("undetected", 0),
            "harmless": last_analysis_stats.get("harmless", 0),
            "total": sum(last_analysis_stats.values()),
            "detection_rate": self._calculate_detection_rate(last_analysis_stats),
            "community_score": attributes.get("reputation", 0),
            "tags": attributes.get("tags", []),
            "threat_names": self._extract_threat_names(last_analysis_results),
            "sandbox_verdicts": attributes.get("sandbox_verdicts", {}),
            "sigma_rules": self._extract_sigma_matches(attributes),
            "yara_rules": self._extract_yara_matches(attributes),
            "threat_severity": self._calculate_threat_severity(last_analysis_stats, attributes)
        }
        
        # Cache the result
        self._save_to_cache("file", file_hash, response)
        
        return response
    
    async def check_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Check IP address against VirusTotal
        
        Args:
            ip_address: IP address to check
            
        Returns:
            Dictionary with IP reputation data
        """
        # Check cache
        cached = self._get_from_cache("ip", ip_address)
        if cached:
            return cached
        
        # Make API request
        endpoint = f"ip_addresses/{ip_address}"
        result = await self._make_request(endpoint)
        
        if not result:
            return {
                "found": False,
                "ip": ip_address,
                "error": "Not found or API error"
            }
        
        # Parse results
        data = result.get("data", {})
        attributes = data.get("attributes", {})
        
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        
        # Build response
        response = {
            "found": True,
            "ip": ip_address,
            "country": attributes.get("country", "Unknown"),
            "as_owner": attributes.get("as_owner", "Unknown"),
            "asn": attributes.get("asn", 0),
            "malicious": last_analysis_stats.get("malicious", 0),
            "suspicious": last_analysis_stats.get("suspicious", 0),
            "harmless": last_analysis_stats.get("harmless", 0),
            "undetected": last_analysis_stats.get("undetected", 0),
            "total": sum(last_analysis_stats.values()),
            "reputation": attributes.get("reputation", 0),
            "network": f"{attributes.get('network', 'Unknown')}",
            "tags": attributes.get("tags", []),
            "last_analysis_date": attributes.get("last_analysis_date", ""),
            "threat_categories": self._extract_threat_categories(attributes),
            "malware_samples": await self._get_communicating_samples(ip_address),
            "urls_detected": await self._get_detected_urls(ip_address),
            "passive_dns": await self._get_passive_dns(ip_address),
            "threat_severity": self._calculate_ip_threat_severity(last_analysis_stats, attributes)
        }
        
        # Cache the result
        self._save_to_cache("ip", ip_address, response)
        
        return response
    
    async def check_domain(self, domain: str) -> Dict[str, Any]:
        """
        Check domain against VirusTotal
        
        Args:
            domain: Domain name to check
            
        Returns:
            Dictionary with domain reputation data
        """
        # Normalize domain
        domain = domain.lower().strip()
        
        # Check cache
        cached = self._get_from_cache("domain", domain)
        if cached:
            return cached
        
        # Make API request
        endpoint = f"domains/{domain}"
        result = await self._make_request(endpoint)
        
        if not result:
            return {
                "found": False,
                "domain": domain,
                "error": "Not found or API error"
            }
        
        # Parse results
        data = result.get("data", {})
        attributes = data.get("attributes", {})
        
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        
        # Build response
        response = {
            "found": True,
            "domain": domain,
            "creation_date": attributes.get("creation_date", ""),
            "last_update_date": attributes.get("last_update_date", ""),
            "registrar": attributes.get("registrar", "Unknown"),
            "malicious": last_analysis_stats.get("malicious", 0),
            "suspicious": last_analysis_stats.get("suspicious", 0),
            "harmless": last_analysis_stats.get("harmless", 0),
            "undetected": last_analysis_stats.get("undetected", 0),
            "total": sum(last_analysis_stats.values()),
            "reputation": attributes.get("reputation", 0),
            "categories": attributes.get("categories", {}),
            "tags": attributes.get("tags", []),
            "last_analysis_date": attributes.get("last_analysis_date", ""),
            "dns_records": self._extract_dns_records(attributes),
            "subdomains": await self._get_subdomains(domain),
            "communicating_samples": await self._get_communicating_samples(domain),
            "detected_urls": await self._get_detected_urls(domain),
            "whois": attributes.get("whois", ""),
            "threat_severity": self._calculate_domain_threat_severity(last_analysis_stats, attributes)
        }
        
        # Cache the result
        self._save_to_cache("domain", domain, response)
        
        return response
    
    async def check_url(self, url: str) -> Dict[str, Any]:
        """
        Check URL against VirusTotal
        
        Args:
            url: URL to check
            
        Returns:
            Dictionary with URL analysis results
        """
        # Generate URL ID (base64 encoded)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        # Check cache
        cached = self._get_from_cache("url", url)
        if cached:
            return cached
        
        # Make API request
        endpoint = f"urls/{url_id}"
        result = await self._make_request(endpoint)
        
        if not result:
            # URL might not be scanned yet, submit it
            scan_result = await self.scan_url(url)
            if scan_result:
                # Wait a bit and retry
                await asyncio.sleep(5)
                result = await self._make_request(endpoint)
        
        if not result:
            return {
                "found": False,
                "url": url,
                "error": "Not found or API error"
            }
        
        # Parse results
        data = result.get("data", {})
        attributes = data.get("attributes", {})
        
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        
        # Build response
        response = {
            "found": True,
            "url": url,
            "final_url": attributes.get("last_final_url", url),
            "title": attributes.get("title", ""),
            "malicious": last_analysis_stats.get("malicious", 0),
            "suspicious": last_analysis_stats.get("suspicious", 0),
            "harmless": last_analysis_stats.get("harmless", 0),
            "undetected": last_analysis_stats.get("undetected", 0),
            "total": sum(last_analysis_stats.values()),
            "categories": attributes.get("categories", {}),
            "tags": attributes.get("tags", []),
            "last_analysis_date": attributes.get("last_analysis_date", ""),
            "threat_names": self._extract_threat_names(attributes.get("last_analysis_results", {})),
            "response_info": {
                "status_code": attributes.get("last_http_response_code", 0),
                "content_type": attributes.get("last_http_response_content_type", ""),
                "content_length": attributes.get("last_http_response_content_length", 0)
            },
            "redirects": attributes.get("redirection_chain", []),
            "threat_severity": self._calculate_url_threat_severity(last_analysis_stats, attributes)
        }
        
        # Cache the result
        self._save_to_cache("url", url, response)
        
        return response
    
    async def scan_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Submit URL for scanning"""
        endpoint = "urls"
        data = {"url": url}
        
        result = await self._make_request(endpoint, method="POST", data=data)
        
        if result:
            return {
                "submitted": True,
                "id": result.get("data", {}).get("id", ""),
                "message": "URL submitted for scanning"
            }
        
        return None
    
    async def get_file_behavior(self, file_hash: str) -> Dict[str, Any]:
        """Get behavioral analysis for a file"""
        endpoint = f"files/{file_hash}/behaviour_summary"
        result = await self._make_request(endpoint)
        
        if not result:
            return {"found": False}
        
        data = result.get("data", {})
        
        return {
            "found": True,
            "processes": data.get("processes_created", []),
            "files_created": data.get("files_created", [])[:20],
            "files_modified": data.get("files_modified", [])[:20],
            "files_deleted": data.get("files_deleted", [])[:20],
            "registry_keys_created": data.get("registry_keys_created", [])[:20],
            "registry_keys_modified": data.get("registry_keys_modified", [])[:20],
            "network_connections": data.get("ip_traffic", [])[:20],
            "dns_queries": data.get("dns_lookups", [])[:20],
            "mutex_created": data.get("mutexes_created", [])[:20],
            "commands_executed": data.get("commands_executed", [])[:20],
            "attack_techniques": data.get("attack_techniques", []),
            "verdicts": data.get("verdicts", [])
        }
    
    async def get_file_network_traffic(self, file_hash: str) -> Dict[str, Any]:
        """Get network traffic from file analysis"""
        endpoint = f"files/{file_hash}/contacted_ips"
        result = await self._make_request(endpoint)
        
        if not result:
            return {"found": False}
        
        ips = []
        for item in result.get("data", [])[:20]:
            ip_data = item.get("attributes", {})
            ips.append({
                "ip": item.get("id", ""),
                "country": ip_data.get("country", ""),
                "as_owner": ip_data.get("as_owner", ""),
                "reputation": ip_data.get("reputation", 0)
            })
        
        return {
            "found": True,
            "contacted_ips": ips,
            "total": result.get("meta", {}).get("count", len(ips))
        }
    
    async def _get_communicating_samples(self, resource: str) -> List[Dict[str, Any]]:
        """Get malware samples communicating with IP/domain"""
        # For performance, return empty list in basic implementation
        # Full implementation would make additional API calls
        return []
    
    async def _get_detected_urls(self, resource: str) -> List[Dict[str, Any]]:
        """Get detected URLs for IP/domain"""
        # For performance, return empty list in basic implementation
        return []
    
    async def _get_passive_dns(self, ip: str) -> List[Dict[str, Any]]:
        """Get passive DNS records for IP"""
        # For performance, return empty list in basic implementation
        return []
    
    async def _get_subdomains(self, domain: str) -> List[str]:
        """Get subdomains for a domain"""
        # For performance, return empty list in basic implementation
        return []
    
    def _calculate_detection_rate(self, stats: Dict[str, int]) -> float:
        """Calculate detection rate percentage"""
        total = sum(stats.values())
        if total == 0:
            return 0.0
        
        malicious = stats.get("malicious", 0) + stats.get("suspicious", 0)
        return (malicious / total) * 100
    
    def _extract_threat_names(self, analysis_results: Dict[str, Any]) -> List[str]:
        """Extract unique threat names from analysis results"""
        threat_names = set()
        
        for engine, result in analysis_results.items():
            if result.get("category") in ["malicious", "suspicious"]:
                threat_name = result.get("result", "")
                if threat_name and threat_name != "malicious":
                    threat_names.add(threat_name)
        
        return sorted(list(threat_names))[:10]  # Top 10 threat names
    
    def _extract_threat_categories(self, attributes: Dict[str, Any]) -> List[str]:
        """Extract threat categories"""
        categories = set()
        
        # From tags
        for tag in attributes.get("tags", []):
            categories.add(tag)
        
        # From categories
        for cat in attributes.get("categories", {}).values():
            categories.add(cat)
        
        return sorted(list(categories))[:10]
    
    def _extract_dns_records(self, attributes: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract DNS records"""
        dns_records = {
            "A": [],
            "AAAA": [],
            "MX": [],
            "NS": [],
            "TXT": []
        }
        
        # Simplified extraction - full implementation would parse all records
        last_dns_records = attributes.get("last_dns_records", [])
        
        for record in last_dns_records:
            record_type = record.get("type", "")
            value = record.get("value", "")
            
            if record_type in dns_records and value:
                dns_records[record_type].append(value)
        
        return dns_records
    
    def _extract_sigma_matches(self, attributes: Dict[str, Any]) -> List[str]:
        """Extract Sigma rule matches"""
        # Would be in crowdsourced_sigma_analysis
        return []
    
    def _extract_yara_matches(self, attributes: Dict[str, Any]) -> List[str]:
        """Extract YARA rule matches"""
        # Would be in crowdsourced_yara_results
        return []
    
    def _calculate_threat_severity(self, stats: Dict[str, int], 
                                 attributes: Dict[str, Any]) -> str:
        """Calculate overall threat severity for files"""
        detection_rate = self._calculate_detection_rate(stats)
        reputation = attributes.get("reputation", 0)
        
        if detection_rate > 50 or reputation < -50:
            return "critical"
        elif detection_rate > 25 or reputation < -20:
            return "high"
        elif detection_rate > 10 or reputation < 0:
            return "medium"
        elif detection_rate > 0:
            return "low"
        else:
            return "clean"
    
    def _calculate_ip_threat_severity(self, stats: Dict[str, int], 
                                    attributes: Dict[str, Any]) -> str:
        """Calculate threat severity for IPs"""
        malicious = stats.get("malicious", 0)
        reputation = attributes.get("reputation", 0)
        
        if malicious > 5 or reputation < -50:
            return "critical"
        elif malicious > 2 or reputation < -20:
            return "high"
        elif malicious > 0 or reputation < 0:
            return "medium"
        else:
            return "clean"
    
    def _calculate_domain_threat_severity(self, stats: Dict[str, int], 
                                        attributes: Dict[str, Any]) -> str:
        """Calculate threat severity for domains"""
        return self._calculate_ip_threat_severity(stats, attributes)
    
    def _calculate_url_threat_severity(self, stats: Dict[str, int], 
                                     attributes: Dict[str, Any]) -> str:
        """Calculate threat severity for URLs"""
        detection_rate = self._calculate_detection_rate(stats)
        
        # Check for phishing/malware categories
        categories = attributes.get("categories", {})
        dangerous_categories = ["phishing", "malware", "malicious"]
        
        has_dangerous_category = any(
            cat in str(categories).lower() 
            for cat in dangerous_categories
        )
        
        if detection_rate > 30 or has_dangerous_category:
            return "critical"
        elif detection_rate > 15:
            return "high"
        elif detection_rate > 5:
            return "medium"
        elif detection_rate > 0:
            return "low"
        else:
            return "clean"
    
    async def batch_check_iocs(self, iocs: Dict[str, List[str]], 
                             max_checks: int = 20) -> Dict[str, List[Dict[str, Any]]]:
        """
        Batch check multiple IOCs
        
        Args:
            iocs: Dictionary of IOC types and values
            max_checks: Maximum number of checks to perform
            
        Returns:
            Results organized by IOC type
        """
        results = {
            "ips": [],
            "domains": [],
            "urls": [],
            "hashes": []
        }
        
        checks_performed = 0
        
        # Check IPs
        for ip in iocs.get("ips", [])[:max_checks]:
            if checks_performed >= max_checks:
                break
            result = await self.check_ip(ip)
            results["ips"].append(result)
            checks_performed += 1
        
        # Check domains
        for domain in iocs.get("domains", [])[:max_checks - checks_performed]:
            if checks_performed >= max_checks:
                break
            result = await self.check_domain(domain)
            results["domains"].append(result)
            checks_performed += 1
        
        # Check URLs
        for url in iocs.get("urls", [])[:max_checks - checks_performed]:
            if checks_performed >= max_checks:
                break
            result = await self.check_url(url)
            results["urls"].append(result)
            checks_performed += 1
        
        # Check hashes
        for hash_value in iocs.get("hashes", [])[:max_checks - checks_performed]:
            if checks_performed >= max_checks:
                break
            # Handle hash objects or strings
            if isinstance(hash_value, dict):
                hash_str = hash_value.get("value", "")
            else:
                hash_str = hash_value
            
            result = await self.check_file_hash(hash_str)
            results["hashes"].append(result)
            checks_performed += 1
        
        return results
    
    def get_vt_link(self, ioc_type: str, ioc_value: str) -> str:
        """Generate VirusTotal web interface link"""
        base_url = "https://www.virustotal.com/gui"
        
        if ioc_type == "hash":
            return f"{base_url}/file/{ioc_value}"
        elif ioc_type == "ip":
            return f"{base_url}/ip-address/{ioc_value}"
        elif ioc_type == "domain":
            return f"{base_url}/domain/{ioc_value}"
        elif ioc_type == "url":
            url_id = base64.urlsafe_b64encode(ioc_value.encode()).decode().strip("=")
            return f"{base_url}/url/{url_id}"
        else:
            return base_url
    
    async def close(self):
        """Close the client session"""
        if self.session:
            await self.session.close()
            self.session = None