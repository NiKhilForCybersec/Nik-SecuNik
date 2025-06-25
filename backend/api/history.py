"""
History API - Analysis history endpoints
Provides access to historical analysis results
"""

from pathlib import Path as FilePath
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from collections import defaultdict
import json
import os
import aiofiles
import asyncio

from fastapi import APIRouter, Query, Path, Depends, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field

from config import settings

router = APIRouter(prefix="/api/history", tags=["history"])

# Pydantic models
class AnalysisHistoryItem(BaseModel):
    """History item model"""
    id: str
    file_name: str
    file_type: str
    file_size: int
    file_hash: str
    analysis_date: datetime
    threat_score: int
    severity: str
    analyzer_results: Dict[str, Any]
    iocs_found: int
    patterns_detected: int
    mitre_techniques: List[str]
    tags: List[str]
    notes: Optional[str] = None

class HistoryListResponse(BaseModel):
    """History list response"""
    items: List[Dict[str, Any]]
    total: int
    limit: int
    offset: int
    has_more: bool

class HistoryStatsResponse(BaseModel):
    """History statistics response"""
    total_analyses: int
    total_threats_found: int
    average_threat_score: float
    by_severity: Dict[str, int]
    by_file_type: Dict[str, int]
    by_date: Dict[str, int]
    top_iocs: List[Dict[str, Any]]
    top_techniques: List[Dict[str, Any]]
    recent_high_threats: List[Dict[str, Any]]

class HistoryFilterParams(BaseModel):
    """History filter parameters"""
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    min_threat_score: Optional[int] = Field(None, ge=0, le=100)
    severity: Optional[str] = Field(None, pattern="^(low|medium|high|critical)$")
    file_type: Optional[str] = None
    has_iocs: Optional[bool] = None
    search: Optional[str] = None

# History Manager
class HistoryManager:
    """Manages analysis history"""
    
    def __init__(self, storage_dir: str = "./storage"):
        self.storage_dir = Path(storage_dir)
        self.history_file = self.storage_dir / "history.json"
        self.analysis_dir = self.storage_dir / "analysis"
        self.lock = asyncio.Lock()
        self._ensure_directories()
        
    def _ensure_directories(self):
        """Ensure storage directories exist"""
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.analysis_dir.mkdir(parents=True, exist_ok=True)
        
    async def load_history(self) -> List[Dict[str, Any]]:
        """Load history index"""
        if not self.history_file.exists():
            return []
            
        async with self.lock:
            async with aiofiles.open(self.history_file, 'r') as f:
                content = await f.read()
                return json.loads(content) if content else []
                
    async def save_history(self, history: List[Dict[str, Any]]):
        """Save history index"""
        async with self.lock:
            async with aiofiles.open(self.history_file, 'w') as f:
                await f.write(json.dumps(history, indent=2, default=str))
                
    async def add_analysis(self, analysis_result: Dict[str, Any]) -> str:
        """Add new analysis to history"""
        # Generate analysis ID
        analysis_id = analysis_result.get('id', f"analysis_{datetime.now().timestamp()}")
        
        # Create history entry
        history_entry = {
            'id': analysis_id,
            'file_name': analysis_result.get('file_name', 'Unknown'),
            'file_type': analysis_result.get('file_type', 'Unknown'),
            'file_size': analysis_result.get('file_size', 0),
            'file_hash': analysis_result.get('file_hash', ''),
            'analysis_date': datetime.now().isoformat(),
            'threat_score': analysis_result.get('threat_score', 0),
            'severity': analysis_result.get('severity', 'low'),
            'iocs_found': len(analysis_result.get('iocs', [])),
            'patterns_detected': len(analysis_result.get('patterns', [])),
            'mitre_techniques': [t['technique_id'] for t in analysis_result.get('mitre_results', {}).get('techniques', [])],
            'tags': analysis_result.get('tags', [])
        }
        
        # Save full analysis result
        analysis_file = self.analysis_dir / f"{analysis_id}.json"
        async with aiofiles.open(analysis_file, 'w') as f:
            await f.write(json.dumps(analysis_result, indent=2, default=str))
            
        # Update history index
        history = await self.load_history()
        history.insert(0, history_entry)  # Add to beginning
        
        # Keep only last 10000 entries
        if len(history) > 10000:
            history = history[:10000]
            
        await self.save_history(history)
        
        return analysis_id
        
    async def get_analysis(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        """Get full analysis result"""
        analysis_file = self.analysis_dir / f"{analysis_id}.json"
        
        if not analysis_file.exists():
            return None
            
        async with aiofiles.open(analysis_file, 'r') as f:
            content = await f.read()
            return json.loads(content)
            
    async def delete_analysis(self, analysis_id: str) -> bool:
        """Delete analysis from history"""
        # Remove from index
        history = await self.load_history()
        history = [h for h in history if h['id'] != analysis_id]
        await self.save_history(history)
        
        # Remove analysis file
        analysis_file = self.analysis_dir / f"{analysis_id}.json"
        if analysis_file.exists():
            analysis_file.unlink()
            return True
            
        return False
        
    async def search_history(
        self,
        filters: HistoryFilterParams,
        limit: int = 50,
        offset: int = 0
    ) -> Dict[str, Any]:
        """Search history with filters"""
        history = await self.load_history()
        filtered = []
        
        for item in history:
            # Date filter
            if filters.start_date or filters.end_date:
                item_date = datetime.fromisoformat(item['analysis_date'])
                if filters.start_date and item_date < filters.start_date:
                    continue
                if filters.end_date and item_date > filters.end_date:
                    continue
                    
            # Threat score filter
            if filters.min_threat_score is not None:
                if item.get('threat_score', 0) < filters.min_threat_score:
                    continue
                    
            # Severity filter
            if filters.severity:
                if item.get('severity') != filters.severity:
                    continue
                    
            # File type filter
            if filters.file_type:
                if filters.file_type.lower() not in item.get('file_type', '').lower():
                    continue
                    
            # IOC filter
            if filters.has_iocs is not None:
                has_iocs = item.get('iocs_found', 0) > 0
                if has_iocs != filters.has_iocs:
                    continue
                    
            # Search filter
            if filters.search:
                search_lower = filters.search.lower()
                searchable = f"{item.get('file_name', '')} {item.get('file_hash', '')} {' '.join(item.get('tags', []))}"
                if search_lower not in searchable.lower():
                    continue
                    
            filtered.append(item)
            
        # Pagination
        total = len(filtered)
        items = filtered[offset:offset + limit]
        
        return {
            'items': items,
            'total': total,
            'limit': limit,
            'offset': offset,
            'has_more': offset + limit < total
        }
        
    async def get_statistics(
        self,
        days: int = 30
    ) -> Dict[str, Any]:
        """Get history statistics"""
        history = await self.load_history()
        
        # Filter by date range
        cutoff_date = datetime.now() - timedelta(days=days)
        recent_history = [
            h for h in history
            if datetime.fromisoformat(h['analysis_date']) >= cutoff_date
        ]
        
        # Calculate statistics
        stats = {
            'total_analyses': len(recent_history),
            'total_threats_found': sum(1 for h in recent_history if h.get('threat_score', 0) > 50),
            'average_threat_score': 0,
            'by_severity': defaultdict(int),
            'by_file_type': defaultdict(int),
            'by_date': defaultdict(int),
            'top_iocs': [],
            'top_techniques': [],
            'recent_high_threats': []
        }
        
        if recent_history:
            # Average threat score
            scores = [h.get('threat_score', 0) for h in recent_history]
            stats['average_threat_score'] = sum(scores) / len(scores)
            
            # Group by severity
            for h in recent_history:
                stats['by_severity'][h.get('severity', 'unknown')] += 1
                
            # Group by file type
            for h in recent_history:
                file_type = h.get('file_type', 'unknown').split('/')[0]
                stats['by_file_type'][file_type] += 1
                
            # Group by date
            for h in recent_history:
                date = datetime.fromisoformat(h['analysis_date']).date().isoformat()
                stats['by_date'][date] += 1
                
            # Top MITRE techniques
            technique_counts = defaultdict(int)
            for h in recent_history:
                for technique in h.get('mitre_techniques', []):
                    technique_counts[technique] += 1
                    
            stats['top_techniques'] = [
                {'technique': t, 'count': c}
                for t, c in sorted(
                    technique_counts.items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:10]
            ]
            
            # Recent high threats
            high_threats = [
                h for h in recent_history
                if h.get('severity') in ['high', 'critical']
            ]
            stats['recent_high_threats'] = sorted(
                high_threats,
                key=lambda x: x['analysis_date'],
                reverse=True
            )[:10]
            
        # Convert defaultdicts to regular dicts
        stats['by_severity'] = dict(stats['by_severity'])
        stats['by_file_type'] = dict(stats['by_file_type'])
        stats['by_date'] = dict(stats['by_date'])
        
        return stats
        
    async def export_history(
        self,
        format: str = 'json',
        filters: Optional[HistoryFilterParams] = None
    ) -> str:
        """Export history to file"""
        # Get filtered history
        if filters:
            result = await self.search_history(filters, limit=10000)
            history = result['items']
        else:
            history = await self.load_history()
            
        # Export based on format
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if format == 'json':
            export_path = f"/tmp/history_export_{timestamp}.json"
            async with aiofiles.open(export_path, 'w') as f:
                await f.write(json.dumps(history, indent=2, default=str))
                
        elif format == 'csv':
            import csv
            export_path = f"/tmp/history_export_{timestamp}.csv"
            
            if history:
                keys = history[0].keys()
                async with aiofiles.open(export_path, 'w') as f:
                    writer = csv.DictWriter(f, fieldnames=keys)
                    await f.write(','.join(keys) + '\n')
                    for item in history:
                        row = ','.join(str(item.get(k, '')) for k in keys)
                        await f.write(row + '\n')
                        
        else:
            raise ValueError(f"Unsupported format: {format}")
            
        return export_path

# Dependency injection
history_manager: Optional[HistoryManager] = None

async def get_history_manager() -> HistoryManager:
    """Get history manager instance"""
    global history_manager
    if history_manager is None:
        history_manager = HistoryManager(str(settings.STORAGE_PATH))  # FIXED
    return history_manager

# API Endpoints
@router.get("/", response_model=HistoryListResponse)
async def list_history(
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    min_threat_score: Optional[int] = Query(None, ge=0, le=100),
    severity: Optional[str] = Query(None, pattern="^(low|medium|high|critical)$"),
    file_type: Optional[str] = None,
    has_iocs: Optional[bool] = None,
    search: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    manager: HistoryManager = Depends(get_history_manager)
):
    """List analysis history with filters"""
    filters = HistoryFilterParams(
        start_date=start_date,
        end_date=end_date,
        min_threat_score=min_threat_score,
        severity=severity,
        file_type=file_type,
        has_iocs=has_iocs,
        search=search
    )
    
    result = await manager.search_history(filters, limit, offset)
    return HistoryListResponse(**result)

@router.get("/stats", response_model=HistoryStatsResponse)
async def get_history_stats(
    days: int = Query(30, ge=1, le=365),
    manager: HistoryManager = Depends(get_history_manager)
):
    """Get history statistics"""
    stats = await manager.get_statistics(days)
    return HistoryStatsResponse(**stats)

@router.get("/{analysis_id}")
async def get_analysis_detail(
    analysis_id: str,
    manager: HistoryManager = Depends(get_history_manager)
):
    """Get detailed analysis result"""
    analysis = await manager.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return analysis

@router.delete("/{analysis_id}")
async def delete_analysis(
    analysis_id: str,
    manager: HistoryManager = Depends(get_history_manager)
):
    """Delete analysis from history"""
    success = await manager.delete_analysis(analysis_id)
    if not success:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return {"message": "Analysis deleted successfully"}

@router.post("/{analysis_id}/tags")
async def add_tags(
    analysis_id: str,
    tags: List[str],
    manager: HistoryManager = Depends(get_history_manager)
):
    """Add tags to analysis"""
    # Load history
    history = await manager.load_history()
    
    # Find and update item
    updated = False
    for item in history:
        if item['id'] == analysis_id:
            current_tags = set(item.get('tags', []))
            current_tags.update(tags)
            item['tags'] = list(current_tags)
            updated = True
            break
            
    if not updated:
        raise HTTPException(status_code=404, detail="Analysis not found")
        
    # Save updated history
    await manager.save_history(history)
    
    return {"message": "Tags added successfully", "tags": item['tags']}

@router.put("/{analysis_id}/notes")
async def update_notes(
    analysis_id: str,
    notes: str,
    manager: HistoryManager = Depends(get_history_manager)
):
    """Update analysis notes"""
    # Load history
    history = await manager.load_history()
    
    # Find and update item
    updated = False
    for item in history:
        if item['id'] == analysis_id:
            item['notes'] = notes
            updated = True
            break
            
    if not updated:
        raise HTTPException(status_code=404, detail="Analysis not found")
        
    # Save updated history
    await manager.save_history(history)
    
    # Also update the full analysis file
    analysis = await manager.get_analysis(analysis_id)
    if analysis:
        analysis['notes'] = notes
        analysis_file = manager.analysis_dir / f"{analysis_id}.json"
        async with aiofiles.open(analysis_file, 'w') as f:
            await f.write(json.dumps(analysis, indent=2, default=str))
            
    return {"message": "Notes updated successfully"}

@router.get("/export/{format}")
async def export_history(
    format: str = Path(..., pattern="^(json|csv)$"),
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    min_threat_score: Optional[int] = Query(None, ge=0, le=100),
    severity: Optional[str] = Query(None, pattern="^(low|medium|high|critical)$"),
    manager: HistoryManager = Depends(get_history_manager)
):
    """Export history to file"""
    try:
        filters = None
        if any([start_date, end_date, min_threat_score, severity]):
            filters = HistoryFilterParams(
                start_date=start_date,
                end_date=end_date,
                min_threat_score=min_threat_score,
                severity=severity
            )
            
        export_path = await manager.export_history(format, filters)
        
        return {
            "export_path": export_path,
            "format": format,
            "message": "History exported successfully"
        }
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/compare")
async def compare_analyses(
    analysis_ids: List[str],
    manager: HistoryManager = Depends(get_history_manager)
):
    """Compare multiple analyses"""
    if len(analysis_ids) < 2:
        raise HTTPException(status_code=400, detail="At least 2 analyses required")
        
    analyses = []
    for analysis_id in analysis_ids:
        analysis = await manager.get_analysis(analysis_id)
        if not analysis:
            raise HTTPException(
                status_code=404,
                detail=f"Analysis {analysis_id} not found"
            )
        analyses.append(analysis)
        
    # Compare key metrics
    comparison = {
        'analysis_ids': analysis_ids,
        'threat_scores': {
            aid: a.get('threat_score', 0)
            for aid, a in zip(analysis_ids, analyses)
        },
        'severities': {
            aid: a.get('severity', 'unknown')
            for aid, a in zip(analysis_ids, analyses)
        },
        'ioc_counts': {
            aid: len(a.get('iocs', []))
            for aid, a in zip(analysis_ids, analyses)
        },
        'common_iocs': [],
        'common_techniques': [],
        'unique_findings': {}
    }
    
    # Find common IOCs
    all_iocs = [set(a.get('iocs', [])) for a in analyses]
    if all_iocs:
        common_iocs = set.intersection(*all_iocs)
        comparison['common_iocs'] = list(common_iocs)
        
    # Find common MITRE techniques
    all_techniques = [
        set(t['technique_id'] for t in a.get('mitre_results', {}).get('techniques', []))
        for a in analyses
    ]
    if all_techniques:
        common_techniques = set.intersection(*all_techniques)
        comparison['common_techniques'] = list(common_techniques)
        
    return comparison

@router.get("/timeline/events")
async def get_timeline(
    start_date: datetime,
    end_date: datetime,
    manager: HistoryManager = Depends(get_history_manager)
):
    """Get timeline of security events"""
    filters = HistoryFilterParams(
        start_date=start_date,
        end_date=end_date
    )
    
    result = await manager.search_history(filters, limit=1000)
    
    # Group events by date and severity
    timeline = defaultdict(lambda: {'total': 0, 'by_severity': defaultdict(int)})
    
    for item in result['items']:
        date = datetime.fromisoformat(item['analysis_date']).date().isoformat()
        timeline[date]['total'] += 1
        timeline[date]['by_severity'][item.get('severity', 'unknown')] += 1
        
    # Convert to list format
    timeline_data = [
        {
            'date': date,
            'total': data['total'],
            'by_severity': dict(data['by_severity'])
        }
        for date, data in sorted(timeline.items())
    ]
    
    return {
        'timeline': timeline_data,
        'start_date': start_date.isoformat(),
        'end_date': end_date.isoformat()
    }