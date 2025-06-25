"""
VirusTotal API - VirusTotal results endpoints
Provides access to VirusTotal scan results and reputation data
"""

from fastapi import APIRouter, HTTPException, Query, Path, Depends, BackgroundTasks
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, validator
from datetime import datetime, timedelta
import asyncio
import json
import aiofiles
import hashlib
from pathlib import Path as FilePath
from integrations.virustotal_client import VirusTotalClient
from config import settings

router = APIRouter(prefix="/api/virustotal", tags=["virustotal"])

# Pydantic models
class VTScanRequest(BaseModel):
    """VirusTotal scan request"""
    resource_type: str = Field(..., pattern="^(file|ip|domain|url)$")
    resource_value: str = Field(..., min_length=1)
    force_rescan: bool = False

class VTBulkScanRequest(BaseModel):
    """Bulk scan request"""
    resources: List[Dict[str, str]]  # [{"type": "ip", "value": "1.1.1.1"}, ...]
    force_rescan: bool = False

class VTReportResponse(BaseModel):
    """VirusTotal report response"""
    resource: str
    resource_type: str
    scan_date: Optional[datetime]
    positives: int
    total: int
    reputation_score: float
    malicious: bool
    suspicious: bool
    details: Dict[str, Any]
    permalink: Optional[str]
    cached: bool
    cache_date: Optional[datetime]

class VTQuotaResponse(BaseModel):
    """API quota information"""
    daily_quota: int
    daily_used: int
    daily_remaining: int
    hourly_quota: int
    hourly_used: int
    hourly_remaining: int
    minute_quota: int
    minute_used: int
    minute_remaining: int

# Cache Manager
class VTCacheManager:
    """Manages VirusTotal result caching"""
    
    def __init__(self, cache_dir: str = "./storage/vt_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_duration = timedelta(days=7)  # Cache for 7 days
        self.lock = asyncio.Lock()
        
    def _get_cache_key(self, resource_type: str, resource_value: str) -> str:
        """Generate cache key"""
        return hashlib.md5(f"{resource_type}:{resource_value}".encode()).hexdigest()
        
    async def get_cached(
        self,
        resource_type: str,
        resource_value: str
    ) -> Optional[Dict[str, Any]]:
        """Get cached result"""
        cache_key = self._get_cache_key(resource_type, resource_value)
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        if not cache_file.exists():
            return None
            
        async with self.lock:
            async with aiofiles.open(cache_file, 'r') as f:
                data = json.loads(await f.read())
                
        # Check if cache is still valid
        cache_date = datetime.fromisoformat(data['cache_date'])
        if datetime.now() - cache_date > self.cache_duration:
            # Cache expired
            cache_file.unlink()
            return None
            
        return data
        
    async def save_cache(
        self,
        resource_type: str,
        resource_value: str,
        result: Dict[str, Any]
    ):
        """Save result to cache"""
        cache_key = self._get_cache_key(resource_type, resource_value)
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        # Add cache metadata
        result['cache_date'] = datetime.now().isoformat()
        result['cached'] = True
        
        async with self.lock:
            async with aiofiles.open(cache_file, 'w') as f:
                await f.write(json.dumps(result, indent=2, default=str))
                
    async def clear_cache(self, older_than_days: Optional[int] = None):
        """Clear cache files"""
        count = 0
        
        for cache_file in self.cache_dir.glob("*.json"):
            if older_than_days:
                # Check file age
                stat = cache_file.stat()
                age = datetime.now() - datetime.fromtimestamp(stat.st_mtime)
                if age.days < older_than_days:
                    continue
                    
            cache_file.unlink()
            count += 1
            
        return count

# Quota Manager
class VTQuotaManager:
    """Manages API quota tracking"""
    
    def __init__(self, quota_file: str = "./storage/vt_quota.json"):
        self.quota_file = Path(quota_file)
        self.quota_file.parent.mkdir(parents=True, exist_ok=True)
        self.lock = asyncio.Lock()
        
        # Default quotas (adjust based on your VT plan)
        self.default_quotas = {
            'daily': 500,
            'hourly': 100,
            'minute': 4
        }
        
    async def load_quota(self) -> Dict[str, Any]:
        """Load quota data"""
        if not self.quota_file.exists():
            return self._create_default_quota()
            
        async with self.lock:
            async with aiofiles.open(self.quota_file, 'r') as f:
                return json.loads(await f.read())
                
    async def save_quota(self, quota_data: Dict[str, Any]):
        """Save quota data"""
        async with self.lock:
            async with aiofiles.open(self.quota_file, 'w') as f:
                await f.write(json.dumps(quota_data, indent=2, default=str))
                
    def _create_default_quota(self) -> Dict[str, Any]:
        """Create default quota structure"""
        now = datetime.now()
        return {
            'daily': {
                'limit': self.default_quotas['daily'],
                'used': 0,
                'reset_time': (now + timedelta(days=1)).replace(
                    hour=0, minute=0, second=0, microsecond=0
                ).isoformat()
            },
            'hourly': {
                'limit': self.default_quotas['hourly'],
                'used': 0,
                'reset_time': (now + timedelta(hours=1)).replace(
                    minute=0, second=0, microsecond=0
                ).isoformat()
            },
            'minute': {
                'limit': self.default_quotas['minute'],
                'used': 0,
                'reset_time': (now + timedelta(minutes=1)).replace(
                    second=0, microsecond=0
                ).isoformat()
            }
        }
        
    async def check_quota(self) -> bool:
        """Check if quota available"""
        quota = await self.load_quota()
        now = datetime.now()
        
        # Reset counters if needed
        for period in ['daily', 'hourly', 'minute']:
            reset_time = datetime.fromisoformat(quota[period]['reset_time'])
            if now >= reset_time:
                quota[period]['used'] = 0
                
                # Set next reset time
                if period == 'daily':
                    quota[period]['reset_time'] = (
                        now + timedelta(days=1)
                    ).replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
                elif period == 'hourly':
                    quota[period]['reset_time'] = (
                        now + timedelta(hours=1)
                    ).replace(minute=0, second=0, microsecond=0).isoformat()
                else:  # minute
                    quota[period]['reset_time'] = (
                        now + timedelta(minutes=1)
                    ).replace(second=0, microsecond=0).isoformat()
                    
        await self.save_quota(quota)
        
        # Check if any limit exceeded
        for period in ['minute', 'hourly', 'daily']:
            if quota[period]['used'] >= quota[period]['limit']:
                return False
                
        return True
        
    async def increment_usage(self):
        """Increment usage counters"""
        quota = await self.load_quota()
        
        for period in ['daily', 'hourly', 'minute']:
            quota[period]['used'] += 1
            
        await self.save_quota(quota)
        
    async def get_quota_status(self) -> Dict[str, Any]:
        """Get current quota status"""
        quota = await self.load_quota()
        now = datetime.now()
        
        status = {}
        for period in ['daily', 'hourly', 'minute']:
            reset_time = datetime.fromisoformat(quota[period]['reset_time'])
            
            # Reset if needed
            if now >= reset_time:
                quota[period]['used'] = 0
                
            status[f'{period}_quota'] = quota[period]['limit']
            status[f'{period}_used'] = quota[period]['used']
            status[f'{period}_remaining'] = max(
                0,
                quota[period]['limit'] - quota[period]['used']
            )
            
        return status

# Dependency injection
vt_client: Optional[VirusTotalClient] = None
cache_manager: Optional[VTCacheManager] = None
quota_manager: Optional[VTQuotaManager] = None

async def get_vt_client() -> VirusTotalClient:
    """Get VirusTotal client instance"""
    global vt_client
    if vt_client is None:
        settings = get_settings()
        vt_client = VirusTotalClient({'api_key': settings.virustotal_api_key})
    return vt_client

async def get_cache_manager() -> VTCacheManager:
    """Get cache manager instance"""
    global cache_manager
    if cache_manager is None:
        settings = get_settings()
        cache_manager = VTCacheManager(f"{settings.storage_dir}/vt_cache")
    return cache_manager

async def get_quota_manager() -> VTQuotaManager:
    """Get quota manager instance"""
    global quota_manager
    if quota_manager is None:
        settings = get_settings()
        quota_manager = VTQuotaManager(f"{settings.storage_dir}/vt_quota.json")
    return quota_manager

# API Endpoints
@router.post("/scan", response_model=VTReportResponse)
async def scan_resource(
    request: VTScanRequest,
    background_tasks: BackgroundTasks,
    client: VirusTotalClient = Depends(get_vt_client),
    cache: VTCacheManager = Depends(get_cache_manager),
    quota: VTQuotaManager = Depends(get_quota_manager)
):
    """Scan a resource with VirusTotal"""
    try:
        # Check cache first if not forcing rescan
        if not request.force_rescan:
            cached_result = await cache.get_cached(
                request.resource_type,
                request.resource_value
            )
            if cached_result:
                return VTReportResponse(**cached_result)
                
        # Check quota
        if not await quota.check_quota():
            raise HTTPException(
                status_code=429,
                detail="VirusTotal API quota exceeded. Please try again later."
            )
            
        # Perform scan based on resource type
        if request.resource_type == 'file':
            # For file, expect SHA256 hash
            result = await client.check_file_reputation(request.resource_value)
        elif request.resource_type == 'ip':
            result = await client.check_ip_reputation(request.resource_value)
        elif request.resource_type == 'domain':
            result = await client.check_domain_reputation(request.resource_value)
        elif request.resource_type == 'url':
            result = await client.check_url_reputation(request.resource_value)
        else:
            raise ValueError(f"Invalid resource type: {request.resource_type}")
            
        # Increment quota usage
        await quota.increment_usage()
        
        # Process result
        report = {
            'resource': request.resource_value,
            'resource_type': request.resource_type,
            'scan_date': result.get('scan_date'),
            'positives': result.get('positives', 0),
            'total': result.get('total', 0),
            'reputation_score': result.get('reputation_score', 0),
            'malicious': result.get('malicious', False),
            'suspicious': result.get('suspicious', False),
            'details': result,
            'permalink': result.get('permalink'),
            'cached': False,
            'cache_date': None
        }
        
        # Cache result in background
        background_tasks.add_task(
            cache.save_cache,
            request.resource_type,
            request.resource_value,
            report
        )
        
        return VTReportResponse(**report)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/scan/bulk")
async def bulk_scan(
    request: VTBulkScanRequest,
    background_tasks: BackgroundTasks,
    client: VirusTotalClient = Depends(get_vt_client),
    cache: VTCacheManager = Depends(get_cache_manager),
    quota: VTQuotaManager = Depends(get_quota_manager)
):
    """Scan multiple resources"""
    results = []
    errors = []
    
    for resource in request.resources:
        try:
            # Check cache first
            if not request.force_rescan:
                cached_result = await cache.get_cached(
                    resource['type'],
                    resource['value']
                )
                if cached_result:
                    results.append(cached_result)
                    continue
                    
            # Check quota
            if not await quota.check_quota():
                errors.append({
                    'resource': resource['value'],
                    'error': 'Quota exceeded'
                })
                continue
                
            # Scan resource
            scan_request = VTScanRequest(
                resource_type=resource['type'],
                resource_value=resource['value'],
                force_rescan=request.force_rescan
            )
            
            # Call scan endpoint
            result = await scan_resource(
                scan_request,
                background_tasks,
                client,
                cache,
                quota
            )
            
            results.append(result.dict())
            
            # Add small delay to respect rate limits
            await asyncio.sleep(0.25)  # 4 requests per second max
            
        except Exception as e:
            errors.append({
                'resource': resource['value'],
                'error': str(e)
            })
            
    return {
        'results': results,
        'errors': errors,
        'total_scanned': len(results),
        'total_errors': len(errors)
    }

@router.get("/report/{resource_type}/{resource_value}", response_model=VTReportResponse)
async def get_report(
    resource_type: str = Path(..., pattern="^(file|ip|domain|url)$"),
    resource_value: str = Path(..., min_length=1),
    use_cache: bool = True,
    cache: VTCacheManager = Depends(get_cache_manager)
):
    """Get cached VirusTotal report"""
    if not use_cache:
        raise HTTPException(
            status_code=400,
            detail="Use /scan endpoint for fresh scans"
        )
        
    # Check cache
    cached_result = await cache.get_cached(resource_type, resource_value)
    if not cached_result:
        raise HTTPException(
            status_code=404,
            detail="No cached report found. Use /scan to get fresh results."
        )
        
    return VTReportResponse(**cached_result)

@router.get("/quota", response_model=VTQuotaResponse)
async def get_quota_status(quota: VTQuotaManager = Depends(get_quota_manager)):
    """Get current API quota status"""
    status = await quota.get_quota_status()
    return VTQuotaResponse(**status)

@router.post("/cache/clear")
async def clear_cache(
    older_than_days: Optional[int] = Query(None, ge=1),
    cache: VTCacheManager = Depends(get_cache_manager)
):
    """Clear VirusTotal cache"""
    count = await cache.clear_cache(older_than_days)
    return {
        "message": f"Cleared {count} cache entries",
        "older_than_days": older_than_days
    }

@router.get("/stats")
async def get_vt_stats(
    days: int = Query(7, ge=1, le=30),
    cache: VTCacheManager = Depends(get_cache_manager)
):
    """Get VirusTotal usage statistics"""
    stats = {
        'total_cached': 0,
        'by_type': {},
        'malicious_count': 0,
        'suspicious_count': 0,
        'clean_count': 0,
        'avg_positives': 0,
        'top_threats': []
    }
    
    # Analyze cached results
    all_positives = []
    threat_counts = {}
    
    for cache_file in cache.cache_dir.glob("*.json"):
        try:
            # Check file age
            stat = cache_file.stat()
            age = datetime.now() - datetime.fromtimestamp(stat.st_mtime)
            if age.days > days:
                continue
                
            async with aiofiles.open(cache_file, 'r') as f:
                data = json.loads(await f.read())
                
            stats['total_cached'] += 1
            
            # Count by type
            resource_type = data.get('resource_type', 'unknown')
            stats['by_type'][resource_type] = stats['by_type'].get(resource_type, 0) + 1
            
            # Count by status
            if data.get('malicious'):
                stats['malicious_count'] += 1
            elif data.get('suspicious'):
                stats['suspicious_count'] += 1
            else:
                stats['clean_count'] += 1
                
            # Track positives
            positives = data.get('positives', 0)
            if positives > 0:
                all_positives.append(positives)
                
            # Track threats
            if 'details' in data and 'scans' in data['details']:
                for engine, result in data['details']['scans'].items():
                    if result.get('detected'):
                        threat = result.get('result', 'Unknown')
                        threat_counts[threat] = threat_counts.get(threat, 0) + 1
                        
        except Exception:
            continue
            
    # Calculate averages
    if all_positives:
        stats['avg_positives'] = sum(all_positives) / len(all_positives)
        
    # Top threats
    stats['top_threats'] = [
        {'threat': threat, 'count': count}
        for threat, count in sorted(
            threat_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
    ]
    
    return stats

@router.post("/iocs/extract")
async def extract_iocs_from_vt(
    file_hash: str,
    client: VirusTotalClient = Depends(get_vt_client),
    quota: VTQuotaManager = Depends(get_quota_manager)
):
    """Extract IOCs from VirusTotal behavioral analysis"""
    try:
        # Check quota
        if not await quota.check_quota():
            raise HTTPException(
                status_code=429,
                detail="VirusTotal API quota exceeded"
            )
            
        # Get behavioral analysis
        result = await client.get_file_behavior(file_hash)
        await quota.increment_usage()
        
        # Extract IOCs
        iocs = {
            'network': {
                'ips': [],
                'domains': [],
                'urls': []
            },
            'files': {
                'created': [],
                'modified': [],
                'deleted': []
            },
            'registry': {
                'created': [],
                'modified': [],
                'deleted': []
            },
            'processes': [],
            'mutexes': [],
            'signatures': []
        }
        
        # Parse behavioral data
        if 'behavior' in result:
            behavior = result['behavior']
            
            # Network IOCs
            if 'network' in behavior:
                for item in behavior['network'].get('dns', []):
                    if 'hostname' in item:
                        iocs['network']['domains'].append(item['hostname'])
                        
                for item in behavior['network'].get('http', []):
                    if 'url' in item:
                        iocs['network']['urls'].append(item['url'])
                        
                for item in behavior['network'].get('tcp', []):
                    if 'dst_ip' in item:
                        iocs['network']['ips'].append(item['dst_ip'])
                        
            # File IOCs
            if 'filesystem' in behavior:
                for action in ['created', 'modified', 'deleted']:
                    if action in behavior['filesystem']:
                        iocs['files'][action].extend(behavior['filesystem'][action])
                        
            # Registry IOCs
            if 'registry' in behavior:
                for action in ['created', 'modified', 'deleted']:
                    if action in behavior['registry']:
                        iocs['registry'][action].extend(behavior['registry'][action])
                        
            # Process IOCs
            if 'processes' in behavior:
                iocs['processes'] = behavior['processes']
                
            # Mutex IOCs
            if 'mutexes' in behavior:
                iocs['mutexes'] = behavior['mutexes']
                
        # Signatures
        if 'signatures' in result:
            iocs['signatures'] = result['signatures']
            
        return {
            'file_hash': file_hash,
            'iocs': iocs,
            'total_iocs': sum(
                len(v) if isinstance(v, list) else sum(len(vv) for vv in v.values())
                for v in iocs.values()
            )
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/reputation/batch")
async def batch_reputation_check(
    hashes: str = Query(..., description="Comma-separated file hashes"),
    client: VirusTotalClient = Depends(get_vt_client),
    cache: VTCacheManager = Depends(get_cache_manager),
    quota: VTQuotaManager = Depends(get_quota_manager)
):
    """Check reputation for multiple file hashes"""
    hash_list = [h.strip() for h in hashes.split(',') if h.strip()]
    
    if len(hash_list) > 25:
        raise HTTPException(
            status_code=400,
            detail="Maximum 25 hashes per request"
        )
        
    results = {}
    
    for file_hash in hash_list:
        # Check cache first
        cached = await cache.get_cached('file', file_hash)
        if cached:
            results[file_hash] = {
                'malicious': cached.get('malicious', False),
                'reputation_score': cached.get('reputation_score', 0),
                'cached': True
            }
            continue
            
        # Check quota
        if not await quota.check_quota():
            results[file_hash] = {'error': 'Quota exceeded'}
            continue
            
        try:
            # Get reputation
            vt_result = await client.check_file_reputation(file_hash)
            await quota.increment_usage()
            
            results[file_hash] = {
                'malicious': vt_result.get('malicious', False),
                'reputation_score': vt_result.get('reputation_score', 0),
                'positives': vt_result.get('positives', 0),
                'total': vt_result.get('total', 0),
                'cached': False
            }
            
            # Small delay
            await asyncio.sleep(0.25)
            
        except Exception as e:
            results[file_hash] = {'error': str(e)}
            
    return {
        'results': results,
        'total_checked': len(results)
    }